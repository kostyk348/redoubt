//! The serial link itself: baud, silence, and a transaction over RS-485.
//!
//! [`crate::rtu`] says what one ADU means; this module says how it travels: bytes go out,
//! the answer comes back, and the **frame boundary is silence** — 3.5 character times
//! (T3.5), fixed at 1.75 ms above 19200 baud, exactly as the Modbus over serial line
//! specification says. No byte-count guessing, no CRC-flip "second frame" heuristics.
//!
//! The port is a trait, not a hard dependency: the default build of the library stays
//! dependency-free, tests script a virtual port with a virtual clock, and the OS adapter
//! (`serialport` crate) lives behind the `serial` feature — thin on purpose, it only maps
//! "block until a byte or the gap elapses" onto a real COM handle.

use crate::rtu;

/// Timing for one line. T3.5 = 3.5 character times; a character is 11 bits
/// (start + 8 data + parity + stop). Above 19200 baud the specification fixes
/// T3.5 at 1.75 ms because the real gap would fall below timer resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// Silence that ends a frame, microseconds.
    pub t35_us: u64,
    /// How long the master waits for the first byte of an answer.
    pub response_timeout_ms: u64,
}

impl Timing {
    pub fn for_baud(baud: u32, response_timeout_ms: u64) -> Timing {
        let t35_us = if baud > 19200 {
            1_750
        } else {
            // 3.5 chars * 11 bits / baud seconds -> microseconds
            (3_500_000u64 * 11) / u64::from(baud)
        };
        Timing {
            t35_us,
            response_timeout_ms,
        }
    }
}

/// What the library needs from a wire. `read_some` blocks until at least one byte
/// arrives **or** `gap_us` elapses with silence (`Ok(0)`) — that single contract is
/// what makes the link testable without hardware and without sleeps.
pub trait Port {
    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    fn read_some(&mut self, buf: &mut [u8], gap_us: u64) -> std::io::Result<usize>;
}

/// Why a transaction did not complete.
#[derive(Debug)]
pub enum SerialError {
    /// The request itself is not a well-formed ADU — never put garbage on the line.
    MalformedRequest(rtu::RtuError),
    /// The port failed.
    Port(std::io::Error),
    /// No byte of the answer arrived inside the response timeout.
    TimedOut,
    /// The answer did not fit the caller's buffer.
    AnswerTooLong,
    /// Silence fell before the frame was complete.
    TruncatedFrame,
    /// The answer is not one well-formed ADU (CRC, shape, wrap — whatever [`rtu::parse`] says).
    BadAnswer(rtu::RtuError),
    /// A *different* unit answered: on a multi-drop line that is a foreign device or noise.
    UnitMismatch { expected: u8, got: u8 },
}

impl core::fmt::Display for SerialError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SerialError::MalformedRequest(e) => write!(f, "serial: request is not one ADU: {e}"),
            SerialError::Port(e) => write!(f, "serial: port error: {e}"),
            SerialError::TimedOut => f.write_str("serial: no answer within the response timeout"),
            SerialError::AnswerTooLong => f.write_str("serial: answer longer than the buffer"),
            SerialError::TruncatedFrame => f.write_str("serial: silence fell inside a frame"),
            SerialError::BadAnswer(e) => write!(f, "serial: answer is not one ADU: {e}"),
            SerialError::UnitMismatch { expected, got } => {
                write!(f, "serial: unit {expected} asked, unit {got} answered")
            }
        }
    }
}

impl std::error::Error for SerialError {}

/// A Modbus RTU master transaction over one serial line.
pub struct SerialLink<P: Port> {
    port: P,
    timing: Timing,
}

impl<P: Port> SerialLink<P> {
    pub fn new(port: P, timing: Timing) -> SerialLink<P> {
        SerialLink { port, timing }
    }

    pub fn timing(&self) -> Timing {
        self.timing
    }

    /// Send one request ADU, read the answer up to the silence gap, decode it, and
    /// confirm it answers the unit that was asked. Returns the number of bytes of the
    /// answer ADU inside `answer`.
    pub fn transact(&mut self, request: &[u8], answer: &mut [u8]) -> Result<usize, SerialError> {
        // Only a well-formed request leaves the gate: same rule as everything else here.
        let op = rtu::parse(request).map_err(SerialError::MalformedRequest)?;
        let expected_unit = op.unit();
        self.port.write_all(request).map_err(SerialError::Port)?;

        // First byte: the response timeout is the budget, not the silence gap.
        let first = self
            .port
            .read_some(answer, self.timing.response_timeout_ms * 1_000)
            .map_err(SerialError::Port)?;
        if first == 0 {
            return Err(SerialError::TimedOut);
        }
        let mut total = first;
        // Rest of the frame: bytes keep coming while the line is not silent. A gap of
        // T3.5 ends the frame; a full buffer ends it with a refusal, never a truncation.
        loop {
            if total >= answer.len() {
                return Err(SerialError::AnswerTooLong);
            }
            let n = self
                .port
                .read_some(&mut answer[total..], self.timing.t35_us)
                .map_err(SerialError::Port)?;
            if n == 0 {
                break; // silence: the frame is over
            }
            total += n;
        }
        let got = rtu::parse_response(&answer[..total]).map_err(SerialError::BadAnswer)?;
        if got.unit() != expected_unit {
            return Err(SerialError::UnitMismatch {
                expected: expected_unit,
                got: got.unit(),
            });
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtu::Op;

    /// Для счастливых путей: ошибка транзакции — падение теста с причиной в сообщении.
    fn tx(r: Result<usize, SerialError>) -> usize {
        assert!(r.is_ok(), "transact failed: {:?}", r.as_ref().err());
        r.unwrap_or(0)
    }
    use std::cell::RefCell;

    /// Виртуальный порт: сценарий прибытий на виртуальных микросекундах.
    /// Никаких sleep'ов — время движется только когда порт решает, что байт «пришёл».
    struct MockPort {
        script: RefCell<Vec<(u64, u8)>>, // (время прибытия, байт)
        now: RefCell<u64>,
        writes: RefCell<Vec<u8>>,
    }

    impl MockPort {
        fn new(script: &[(u64, u8)]) -> MockPort {
            MockPort {
                script: RefCell::new(script.to_vec()),
                now: RefCell::new(0),
                writes: RefCell::new(Vec::new()),
            }
        }
    }

    impl Port for MockPort {
        fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            self.writes.borrow_mut().extend_from_slice(bytes);
            Ok(())
        }

        fn read_some(&mut self, buf: &mut [u8], gap_us: u64) -> std::io::Result<usize> {
            let mut script = self.script.borrow_mut();
            let now = *self.now.borrow();
            // байт доступен, только если он «прибыл» до конца окна тишины
            if let Some(&(at, b)) = script.first() {
                if at <= now + gap_us {
                    script.remove(0);
                    *self.now.borrow_mut() = at.max(now);
                    if !buf.is_empty() {
                        buf[0] = b;
                    }
                    return Ok(1);
                }
            }
            *self.now.borrow_mut() = now + gap_us;
            Ok(0)
        }
    }

    fn fc3_response(unit: u8, values: &[u16]) -> Vec<u8> {
        let mut body = vec![unit, 3, (values.len() * 2) as u8];
        for v in values {
            body.push((v >> 8) as u8);
            body.push((v & 0xFF) as u8);
        }
        let crc = rtu::crc16(&body);
        body.push((crc & 0xFF) as u8);
        body.push((crc >> 8) as u8);
        body
    }

    fn fc3_request(unit: u8, addr: u16, qty: u16) -> Vec<u8> {
        let op = Op::Read {
            unit,
            fc: 3,
            addr,
            qty,
        };
        let mut buf = [0u8; rtu::MAX_ADU];
        let n = op.encode(&mut buf).unwrap_or(0);
        buf[..n].to_vec()
    }

    #[test]
    fn a_transaction_round_trips_over_a_scripted_line() {
        let req = fc3_request(1, 0, 2);
        let resp = fc3_response(1, &[0x1234, 0x0055]);
        // байты ответа приходят с паузами внутри кадра (меньше T3.5), тишина после
        let mut script: Vec<(u64, u8)> = resp
            .iter()
            .enumerate()
            .map(|(i, b)| ((i as u64) * 500 + 1000, *b))
            .collect();
        script.push((u64::MAX, 0)); // дальше тишина
        let mut link = SerialLink::new(MockPort::new(&script), Timing::for_baud(9600, 100));
        let mut answer = [0u8; rtu::MAX_ADU];
        let n = tx(link.transact(&req, &mut answer));
        assert_eq!(n, resp.len());
        assert_eq!(&answer[..n], &resp[..]);
    }

    #[test]
    fn silence_splits_the_answer_not_the_inter_byte_gaps() {
        // кадр с паузой 2000 мкс > T3.5 на 9600 бод? T3.5(9600) = 3.5*11/9600 ≈ 4.01 мс.
        // Внутрикадровая пауза 2000 мкс < T3.5 — кадр не рвётся.
        let req = fc3_request(2, 10, 1);
        let resp = fc3_response(2, &[7]);
        let mut script: Vec<(u64, u8)> = resp
            .iter()
            .enumerate()
            .map(|(i, b)| ((i as u64) * 2000 + 500, *b))
            .collect();
        script.push((u64::MAX, 0));
        let mut link = SerialLink::new(MockPort::new(&script), Timing::for_baud(9600, 100));
        let mut answer = [0u8; rtu::MAX_ADU];
        let n = link.transact(&req, &mut answer).unwrap_or(0);
        assert_eq!(n, resp.len());
    }

    #[test]
    fn no_answer_is_a_timeout_not_a_hang() {
        let req = fc3_request(1, 0, 1);
        let mut link = SerialLink::new(MockPort::new(&[]), Timing::for_baud(9600, 5));
        let mut answer = [0u8; rtu::MAX_ADU];
        assert!(matches!(
            link.transact(&req, &mut answer),
            Err(SerialError::TimedOut)
        ));
    }

    #[test]
    fn a_foreign_unit_is_refused_by_name() {
        let req = fc3_request(1, 0, 1);
        let resp = fc3_response(9, &[1]); // отвечает не тот, кого спрашивали
        let script: Vec<(u64, u8)> = resp
            .iter()
            .enumerate()
            .map(|(i, b)| ((i as u64) * 100, *b))
            .chain(std::iter::once((u64::MAX, 0)))
            .collect();
        let mut link = SerialLink::new(MockPort::new(&script), Timing::for_baud(9600, 100));
        let mut answer = [0u8; rtu::MAX_ADU];
        assert!(matches!(
            link.transact(&req, &mut answer),
            Err(SerialError::UnitMismatch {
                expected: 1,
                got: 9
            })
        ));
    }

    #[test]
    fn garbage_never_leaves_the_gate() {
        let mut link = SerialLink::new(MockPort::new(&[]), Timing::for_baud(9600, 5));
        let mut answer = [0u8; rtu::MAX_ADU];
        assert!(matches!(
            link.transact(&[0x01, 0x03, 0x00], &mut answer),
            Err(SerialError::MalformedRequest(_))
        ));
    }

    #[test]
    fn t35_follows_the_specification() {
        // 3.5 символа по 11 бит: 9600 бод → ~4.01 мс; выше 19200 — фикс 1.75 мс
        assert_eq!(Timing::for_baud(9600, 100).t35_us, 4_010);
        assert_eq!(Timing::for_baud(19200, 100).t35_us, 2_005);
        assert_eq!(Timing::for_baud(115200, 100).t35_us, 1_750);
    }
}

/// Привязка к настоящему COM-порту: за фичей `serial`, чтобы дефолтная сборка
/// библиотеки оставалась без зависимостей. Адаптер тонкий по замыслу — единственная
/// его работа: перевести «байт или тишина через gap» в таймауты ОС.
#[cfg(feature = "serial")]
pub mod os {
    use super::{Port, SerialLink, Timing};
    use std::io;
    use std::time::Duration;

    /// Линия по умолчанию RTU: 8E1, без управления потоком.
    pub struct OsPort {
        port: Box<dyn serialport::SerialPort>,
    }

    impl OsPort {
        /// Открыть линию и получить готовый [`SerialLink`] с таймингами этой скорости.
        pub fn open(
            path: &str,
            baud: u32,
            parity: serialport::Parity,
            response_timeout_ms: u64,
        ) -> Result<SerialLink<OsPort>, serialport::Error> {
            let port = serialport::new(path, baud)
                .data_bits(serialport::DataBits::Eight)
                .parity(parity)
                .stop_bits(serialport::StopBits::One)
                .timeout(Duration::from_millis(1))
                .open()?;
            Ok(SerialLink::new(
                OsPort { port },
                Timing::for_baud(baud, response_timeout_ms),
            ))
        }
    }

    impl Port for OsPort {
        fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
            io::Write::write_all(&mut self.port, bytes)
        }

        fn read_some(&mut self, buf: &mut [u8], gap_us: u64) -> io::Result<usize> {
            self.port
                .set_timeout(Duration::from_micros(gap_us.max(1_000)))
                .map_err(io::Error::other)?;
            match self.port.read(buf) {
                Ok(n) => Ok(n),
                Err(e) if e.kind() == io::ErrorKind::TimedOut => Ok(0),
                Err(e) => Err(e),
            }
        }
    }
}
