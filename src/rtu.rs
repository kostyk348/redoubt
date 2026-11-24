//! Modbus RTU over RS-485 — the south side of Redoubt/1.
//!
//! The guard's north side stays Redoubt/1 over IP; the south side is what a plant actually
//! has: a two-wire RS-485 line with RTU frames. This module turns one RTU ADU into **one
//! operation** and back, and hands it to the *same* policy engine — a second authorisation
//! language for a second transport is how holes get shipped.
//!
//! ```text
//! ADU = unit(1) fc(1) data(n) crc16(2)      crc sent low byte first, poly 0xA001, init 0xFFFF
//! ```
//!
//! What is deliberately **not** here:
//!
//! - no serial port, no baud, no timing: those belong to the link layer. Frame boundaries on
//!   RS-485 come from silence (3.5 characters); this module receives what the link layer
//!   accumulated and refuses anything that is not exactly one ADU — `TrailingBytes` instead
//!   of guessing where the second frame starts.
//! - no broadcast: unit 0 addresses everyone, and "everyone" is not an authorisation
//!   subject. Fail closed (`BroadcastUnit`).
//! - no coil value other than `0x0000`/`0xFF00`: an in-between value is either a broken
//!   master or somebody probing; both get `BadValue`, neither reaches the controller.
//! - no guess-the-length: every function code has one exact payload shape, and anything
//!   else is an error rather than a best effort.

use crate::policy::{Request, Role};

/// RTU caps (Modbus over serial line): 256 bytes per ADU, hence 123 registers per write
/// (`1 + 1 + 4 + 1 + 246 + 2`). Everything above is refused, never truncated.
pub const MAX_ADU: usize = 256;
pub const MAX_WRITE_REGISTERS: usize = 123;
pub const MAX_READ_REGISTERS: usize = 125;

/// Why a frame did not become an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtuError {
    /// Fewer than `unit + fc + crc`.
    TooShort,
    /// Longer than [`MAX_ADU`] — refused, not truncated.
    TooLong,
    /// CRC does not match: line noise, or somebody tampering. Same answer either way.
    CrcMismatch,
    /// Bytes after the first ADU: the link layer must split on silence, not us guessing.
    TrailingBytes,
    /// Payload length does not match the function code's one shape.
    BadLength,
    /// `addr + qty` crosses 0xFFFF.
    AddressWrap,
    /// Unit 0 — broadcast is not an authorisation subject.
    BroadcastUnit,
    /// Function code this gate does not model (diagnostics, file records, …).
    UnsupportedFc,
    /// Coil write that is neither `0x0000` nor `0xFF00`.
    BadValue,
    /// `qty` is zero or above the standard cap.
    BadQuantity,
    /// Our own buffer cannot hold the frame.
    NoRoom,
}

impl core::fmt::Display for RtuError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            RtuError::TooShort => "rtu: frame shorter than unit+fc+crc",
            RtuError::TooLong => "rtu: frame longer than 256 bytes",
            RtuError::CrcMismatch => "rtu: crc mismatch",
            RtuError::TrailingBytes => "rtu: more than one frame in the buffer",
            RtuError::BadLength => "rtu: payload length does not match the function code",
            RtuError::AddressWrap => "rtu: address range crosses 0xffff",
            RtuError::BroadcastUnit => "rtu: unit 0 (broadcast) is not authorisable",
            RtuError::UnsupportedFc => "rtu: function code is not modelled",
            RtuError::BadValue => "rtu: coil value is neither 0x0000 nor 0xff00",
            RtuError::BadQuantity => "rtu: quantity is zero or above the standard cap",
            RtuError::NoRoom => "rtu: output buffer too small",
        };
        f.write_str(s)
    }
}

impl std::error::Error for RtuError {}

/// CRC-16/Modbus: poly 0xA001 reflected, init 0xFFFF, sent **low byte first**.
///
/// Reference vectors from the Modbus over serial line specification:
/// `01 03 00 00 00 01` → `84 0A`, and `11 03 00 6B 00 03` → `76 87`.
pub fn crc16(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for b in bytes {
        crc ^= u16::from(*b);
        for _ in 0..8 {
            let lsb = crc & 1;
            crc >>= 1;
            if lsb == 1 {
                crc ^= 0xA001;
            }
        }
    }
    crc
}

fn put(out: &mut [u8], n: &mut usize, b: u8) -> Result<(), RtuError> {
    if *n >= out.len() {
        return Err(RtuError::NoRoom);
    }
    out[*n] = b;
    *n += 1;
    Ok(())
}

fn put_be(out: &mut [u8], n: &mut usize, v: u16) -> Result<(), RtuError> {
    put(out, n, (v >> 8) as u8)?;
    put(out, n, (v & 0xFF) as u8)
}

/// Exactly one Modbus operation, decoded. Anything ambiguous stays an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// FC 1/2/3/4: `qty` bits (1/2) or registers (3/4) starting at `addr`.
    Read {
        unit: u8,
        fc: u8,
        addr: u16,
        qty: u16,
    },
    /// FC 5 (coil, `0x0000`/`0xFF00`) or FC 6 (holding register).
    WriteSingle {
        unit: u8,
        fc: u8,
        addr: u16,
        value: u16,
    },
    /// FC 16: consecutive holding registers.
    WriteMultiple {
        unit: u8,
        addr: u16,
        values: Vec<u16>,
    },
    /// A device said no: `fc` with its high bit set plus an exception code.
    Exception { unit: u8, fc: u8, code: u8 },
}

impl Op {
    /// The same request the Redoubt policy engine already judges on the north side —
    /// no second policy language for the serial line.
    pub fn request(&self, role: Role) -> Option<Request> {
        match self {
            Op::Read {
                unit,
                fc,
                addr,
                qty,
            } => Some(Request {
                fc: *fc,
                unit: *unit,
                addr: *addr,
                qty: *qty,
                value: None,
                role,
            }),
            Op::WriteSingle {
                unit,
                fc,
                addr,
                value,
            } => Some(Request {
                fc: *fc,
                unit: *unit,
                addr: *addr,
                qty: 1,
                value: Some(*value),
                role,
            }),
            Op::WriteMultiple { unit, addr, values } => {
                let qty = u16::try_from(values.len()).ok()?;
                Some(Request {
                    fc: 16,
                    unit: *unit,
                    addr: *addr,
                    qty,
                    value: values.first().copied(),
                    role,
                })
            }
            // An exception is an answer, not an intent: it is never authorised because it
            // is never forwarded as a request.
            Op::Exception { .. } => None,
        }
    }

    /// Unit this operation addresses (never 0 — see [`RtuError::BroadcastUnit`]).
    pub fn unit(&self) -> u8 {
        match self {
            Op::Read { unit, .. }
            | Op::WriteSingle { unit, .. }
            | Op::WriteMultiple { unit, .. }
            | Op::Exception { unit, .. } => *unit,
        }
    }

    /// Encode into `out`, returning how many bytes are the ADU (including CRC).
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, RtuError> {
        let mut n = 0usize;
        match self {
            Op::Read {
                unit,
                fc,
                addr,
                qty,
            } => {
                put(out, &mut n, *unit)?;
                put(out, &mut n, *fc)?;
                put_be(out, &mut n, *addr)?;
                put_be(out, &mut n, *qty)?;
            }
            Op::WriteSingle {
                unit,
                fc,
                addr,
                value,
            } => {
                put(out, &mut n, *unit)?;
                put(out, &mut n, *fc)?;
                put_be(out, &mut n, *addr)?;
                put_be(out, &mut n, *value)?;
            }
            Op::WriteMultiple { unit, addr, values } => {
                let qty = u16::try_from(values.len()).map_err(|_| RtuError::BadQuantity)?;
                put(out, &mut n, *unit)?;
                put(out, &mut n, 16)?;
                put_be(out, &mut n, *addr)?;
                put_be(out, &mut n, qty)?;
                put(out, &mut n, (qty.wrapping_mul(2)) as u8)?;
                for v in values {
                    put_be(out, &mut n, *v)?;
                }
            }
            Op::Exception { unit, fc, code } => {
                put(out, &mut n, *unit)?;
                put(out, &mut n, fc | 0x80)?;
                put(out, &mut n, *code)?;
            }
        }
        let crc = crc16(&out[..n]);
        put(out, &mut n, (crc & 0xFF) as u8)?;
        put(out, &mut n, (crc >> 8) as u8)?;
        Ok(n)
    }
}

/// Полная длина ADU по fc: 8 для 1–6, 9+2·count для 16, 5 для исключений.
/// Для fc 16 байт count лежит внутри CRC-защищённого тела, но длину буфера он
/// задаёт честно; несовпадение count с фактической длиной отсеется дальше.
fn expected_len(fc: u8, adu: &[u8]) -> Result<usize, RtuError> {
    if fc & 0x80 != 0 {
        return Ok(5);
    }
    match fc {
        1..=6 => Ok(8),
        16 => {
            if adu.len() < 7 {
                return Err(RtuError::BadLength);
            }
            Ok(9 + usize::from(adu[6]))
        }
        _ => Err(RtuError::UnsupportedFc),
    }
}

/// Decode exactly one ADU. Every bound is checked before it is indexed: a 256-byte line
/// buffer of attacker-chosen bytes must produce an error, never a panic.
pub fn parse(adu: &[u8]) -> Result<Op, RtuError> {
    if adu.len() < 4 {
        return Err(RtuError::TooShort);
    }
    if adu.len() > MAX_ADU {
        return Err(RtuError::TooLong);
    }
    // Длина кадра известна ДО проверки CRC: у фиксированных форм она выводится из
    // fc, у fc 16 — из защищённого CRC байта count. Лишние байты в буфере — это
    // второй кадр, который линк-слой обязан был отрезать тишиной: не угадываем.
    let fc = adu[1];
    let expected = expected_len(fc, adu)?;
    if adu.len() > expected {
        return Err(RtuError::TrailingBytes);
    }
    let split = adu.len() - 2;
    let body = &adu[..split];
    let want = u16::from_le_bytes([adu[split], adu[split + 1]]);
    if crc16(body) != want {
        return Err(RtuError::CrcMismatch);
    }
    if adu.len() < expected {
        return Err(RtuError::BadLength);
    }
    let unit = body[0];
    if unit == 0 {
        return Err(RtuError::BroadcastUnit);
    }
    let data = &body[2..];

    if fc & 0x80 != 0 {
        return match data {
            [code] => Ok(Op::Exception {
                unit,
                fc: fc & 0x7F,
                code: *code,
            }),
            _ => Err(RtuError::BadLength),
        };
    }
    match fc {
        1..=4 => match data {
            [a0, a1, q0, q1] => {
                let addr = u16::from_be_bytes([*a0, *a1]);
                let qty = u16::from_be_bytes([*q0, *q1]);
                if qty == 0 || usize::from(qty) > MAX_READ_REGISTERS {
                    return Err(RtuError::BadQuantity);
                }
                if no_wrap(addr, qty).not() {
                    return Err(RtuError::AddressWrap);
                }
                Ok(Op::Read {
                    unit,
                    fc,
                    addr,
                    qty,
                })
            }
            _ => Err(RtuError::BadLength),
        },
        5 => match data {
            [a0, a1, v0, v1] => {
                let addr = u16::from_be_bytes([*a0, *a1]);
                let value = u16::from_be_bytes([*v0, *v1]);
                if value != 0x0000 && value != 0xFF00 {
                    return Err(RtuError::BadValue);
                }
                Ok(Op::WriteSingle {
                    unit,
                    fc,
                    addr,
                    value,
                })
            }
            _ => Err(RtuError::BadLength),
        },
        6 => match data {
            [a0, a1, v0, v1] => Ok(Op::WriteSingle {
                unit,
                fc,
                addr: u16::from_be_bytes([*a0, *a1]),
                value: u16::from_be_bytes([*v0, *v1]),
            }),
            _ => Err(RtuError::BadLength),
        },
        16 => {
            // unit fc addr(2) qty(2) count(1) values(2*qty)
            if data.len() < 5 {
                return Err(RtuError::BadLength);
            }
            let addr = u16::from_be_bytes([data[0], data[1]]);
            let qty = u16::from_be_bytes([data[2], data[3]]);
            let count = usize::from(data[4]);
            if qty == 0 || usize::from(qty) > MAX_WRITE_REGISTERS {
                return Err(RtuError::BadQuantity);
            }
            if count != usize::from(qty) * 2 || count + 5 != data.len() {
                return Err(RtuError::BadLength);
            }
            if no_wrap(addr, qty).not() {
                return Err(RtuError::AddressWrap);
            }
            let mut values = Vec::with_capacity(usize::from(qty));
            let rest = &data[5..];
            for pair in rest.chunks_exact(2) {
                values.push(u16::from_be_bytes([pair[0], pair[1]]));
            }
            Ok(Op::WriteMultiple { unit, addr, values })
        }
        _ => Err(RtuError::UnsupportedFc),
    }
}

/// `addr + (qty - 1)` must stay inside the 16-bit register space.
fn no_wrap(addr: u16, qty: u16) -> bool {
    u32::from(addr) + u32::from(qty) - 1 <= u32::from(u16::MAX)
}

/// Small helper so the checks above read as English (`if no_wrap(..).not()`).
trait Not {
    fn not(self) -> bool;
}
impl Not for bool {
    fn not(self) -> bool {
        !self
    }
}

/// Ответ слейва — не запрос мастера: у FC3/4 на проводе байт-каунт и данные,
/// у FC5/6 — эхо запроса, у FC15/16 — эхо адреса и количества. Свои форма и разбор.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespOp {
    /// FC 1/2/3/4: сырые байты данных (биты — упакованные байты, регистры — BE-пары).
    Read { unit: u8, fc: u8, data: Vec<u8> },
    /// FC 5/6: устройство повторяет запрос (эхо) — так подтверждается запись.
    WriteEcho {
        unit: u8,
        fc: u8,
        addr: u16,
        value: u16,
    },
    /// FC 15/16: устройство повторяет адрес и количество.
    WriteAck { unit: u8, addr: u16, qty: u16 },
    /// Отказ устройства: fc|0x80 и код исключения.
    Exception { unit: u8, fc: u8, code: u8 },
}

impl RespOp {
    pub fn unit(&self) -> u8 {
        match self {
            RespOp::Read { unit, .. }
            | RespOp::WriteEcho { unit, .. }
            | RespOp::WriteAck { unit, .. }
            | RespOp::Exception { unit, .. } => *unit,
        }
    }
}

/// Полная длина ответа по fc: 5+count для 1–4, 8 для 5/6 и 15/16, 5 для исключений.
fn expected_resp_len(fc: u8, adu: &[u8]) -> Result<usize, RtuError> {
    if fc & 0x80 != 0 {
        return Ok(5);
    }
    match fc {
        1..=4 => {
            if adu.len() < 3 {
                return Err(RtuError::BadLength);
            }
            Ok(5 + usize::from(adu[2]))
        }
        5 | 6 | 15 | 16 => Ok(8),
        _ => Err(RtuError::UnsupportedFc),
    }
}

/// Разбор одного ответного ADU. Тот же контракт, что у [`parse`]: длина выводится
/// из fc до CRC, лишние байты — чужой кадр, а не «второй ответ».
pub fn parse_response(adu: &[u8]) -> Result<RespOp, RtuError> {
    if adu.len() < 4 {
        return Err(RtuError::TooShort);
    }
    if adu.len() > MAX_ADU {
        return Err(RtuError::TooLong);
    }
    let fc = adu[1];
    let expected = expected_resp_len(fc, adu)?;
    if adu.len() > expected {
        return Err(RtuError::TrailingBytes);
    }
    let split = adu.len() - 2;
    let body = &adu[..split];
    let want = u16::from_le_bytes([adu[split], adu[split + 1]]);
    if crc16(body) != want {
        return Err(RtuError::CrcMismatch);
    }
    if adu.len() < expected {
        return Err(RtuError::BadLength);
    }
    let unit = body[0];
    if unit == 0 {
        return Err(RtuError::BroadcastUnit);
    }
    let data = &body[2..];

    if fc & 0x80 != 0 {
        return match data {
            [code] => Ok(RespOp::Exception {
                unit,
                fc: fc & 0x7F,
                code: *code,
            }),
            _ => Err(RtuError::BadLength),
        };
    }
    match fc {
        1..=4 => {
            let count = usize::from(data[0]);
            if count + 1 != data.len() || count > 250 {
                return Err(RtuError::BadLength);
            }
            Ok(RespOp::Read {
                unit,
                fc,
                data: data[1..].to_vec(),
            })
        }
        5 | 6 => match data {
            [a0, a1, v0, v1] => Ok(RespOp::WriteEcho {
                unit,
                fc,
                addr: u16::from_be_bytes([*a0, *a1]),
                value: u16::from_be_bytes([*v0, *v1]),
            }),
            _ => Err(RtuError::BadLength),
        },
        _ => match data {
            [a0, a1, q0, q1] => Ok(RespOp::WriteAck {
                unit,
                addr: u16::from_be_bytes([*a0, *a1]),
                qty: u16::from_be_bytes([*q0, *q1]),
            }),
            _ => Err(RtuError::BadLength),
        },
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;

    /// Ответ слейва на FC3: unit, fc, count, значения, crc.
    fn fc3_response(unit: u8, values: &[u16]) -> Vec<u8> {
        let mut body = vec![unit, 3, (values.len() * 2) as u8];
        for v in values {
            body.push((v >> 8) as u8);
            body.push((v & 0xFF) as u8);
        }
        let crc = crc16(&body);
        body.push((crc & 0xFF) as u8);
        body.push((crc >> 8) as u8);
        body
    }

    #[test]
    fn a_register_response_decodes_with_its_values() {
        let resp = fc3_response(1, &[0x1234, 0x0055]);
        assert_eq!(
            parse_response(&resp),
            Ok(RespOp::Read {
                unit: 1,
                fc: 3,
                data: vec![0x12, 0x34, 0x00, 0x55]
            })
        );
    }

    #[test]
    fn an_echo_response_decodes_and_a_truncated_one_is_named() {
        let echo = Op::WriteSingle {
            unit: 2,
            fc: 6,
            addr: 10,
            value: 42,
        };
        let mut buf = [0u8; MAX_ADU];
        let n = echo.encode(&mut buf).unwrap_or(MAX_ADU);
        assert_eq!(
            parse_response(&buf[..n]),
            Ok(RespOp::WriteEcho {
                unit: 2,
                fc: 6,
                addr: 10,
                value: 42
            })
        );
        // тот же кадр как ЗАПРОС тоже разбирается — эхо симметрично
        assert_eq!(parse(&buf[..n]), Ok(echo));

        // оборванный ответ: count обещает больше, чем пришло
        let mut resp = fc3_response(1, &[1, 2, 3]);
        resp.truncate(resp.len() - 1);
        let crc = crc16(&resp[..resp.len() - 2]);
        let n = resp.len();
        resp[n - 2] = (crc & 0xFF) as u8;
        resp[n - 1] = (crc >> 8) as u8;
        assert_eq!(parse_response(&resp), Err(RtuError::BadLength));
    }

    #[test]
    fn an_exception_response_is_never_a_read() {
        let mut buf = [0u8; 5];
        let n = Op::Exception {
            unit: 7,
            fc: 3,
            code: 2,
        }
        .encode(&mut buf)
        .unwrap_or(MAX_ADU);
        assert_eq!(
            parse_response(&buf[..n]),
            Ok(RespOp::Exception {
                unit: 7,
                fc: 3,
                code: 2
            })
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_matches_the_specification_vectors() {
        assert_eq!(crc16(&[0x01, 0x03, 0x00, 0x00, 0x00, 0x01]), 0x0A84);
        assert_eq!(crc16(&[0x11, 0x03, 0x00, 0x6B, 0x00, 0x03]), 0x8776);
    }

    #[test]
    fn crc_is_sent_low_byte_first() {
        let mut buf = [0u8; 8];
        let n = Op::Read {
            unit: 1,
            fc: 3,
            addr: 0,
            qty: 1,
        }
        .encode(&mut buf)
        .unwrap_or(MAX_ADU);
        assert_eq!(&buf[..n], &[0x01, 0x03, 0x00, 0x00, 0x00, 0x01, 0x84, 0x0A]);
    }

    #[test]
    fn a_known_read_round_trips() {
        let mut buf = [0u8; MAX_ADU];
        let op = Op::Read {
            unit: 3,
            fc: 3,
            addr: 40001 - 40001,
            qty: 2,
        };
        let n = op.encode(&mut buf).unwrap_or(MAX_ADU);
        assert_eq!(parse(&buf[..n]), Ok(op));
    }

    #[test]
    fn a_tampered_byte_is_refused() {
        let mut buf = [0u8; MAX_ADU];
        let n = Op::WriteSingle {
            unit: 2,
            fc: 6,
            addr: 10,
            value: 42,
        }
        .encode(&mut buf)
        .unwrap_or(MAX_ADU);
        let pos = n - 3; // payload, not the crc we are checking
        buf[pos] ^= 0xFF;
        assert_eq!(parse(&buf[..n]), Err(RtuError::CrcMismatch));
    }

    #[test]
    fn trailing_bytes_are_refused_not_split() {
        let mut buf = [0u8; MAX_ADU];
        let n = Op::Read {
            unit: 1,
            fc: 3,
            addr: 0,
            qty: 1,
        }
        .encode(&mut buf)
        .unwrap_or(MAX_ADU);
        buf[n] = 0x01;
        buf[n + 1] = 0x03;
        assert_eq!(parse(&buf[..n + 2]), Err(RtuError::TrailingBytes));
        // а без лишних байтов тот же кадр разбирается
        assert_eq!(
            parse(&buf[..n]),
            Ok(Op::Read {
                unit: 1,
                fc: 3,
                addr: 0,
                qty: 1
            })
        );
    }

    #[test]
    fn degenerate_frames_are_refused() {
        assert_eq!(parse(&[0x01, 0x03, 0x00]), Err(RtuError::TooShort));
        // четырёх байт мало для fc 3 (нужно 8), CRC не сходится — мусор остаётся мусором
        assert_eq!(parse(&[0x00, 0x03, 0x00, 0x00]), Err(RtuError::CrcMismatch));
        // CRC сходитcя, но кадр короче формы fc 3 (нужно 8): честный BadLength
        let mut short = [0u8; 4];
        short[0] = 1;
        short[1] = 3;
        let crc = crc16(&short[..2]);
        short[2] = (crc & 0xFF) as u8;
        short[3] = (crc >> 8) as u8;
        assert_eq!(parse(&short), Err(RtuError::BadLength));
        let mut long = [0u8; MAX_ADU + 1];
        long[0] = 1;
        assert_eq!(parse(&long), Err(RtuError::TooLong));
    }
}
