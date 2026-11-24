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

/// Half-duplex bus direction. On a 2-wire RS-485 line the adapter must be told when it
/// may transmit; on a 4-wire line (or anything full-duplex) nobody listens to this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Transmit,
    Receive,
}

/// What the library needs from a wire. `read_some` blocks until at least one byte
/// arrives **or** `gap_us` elapses with silence (`Ok(0)`) — that single contract is
/// what makes the link testable without hardware and without sleeps. `drive` is a
/// no-op on full-duplex ports; a 2-wire adapter maps it to its DE/RE (RTS).
pub trait Port {
    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    fn read_some(&mut self, buf: &mut [u8], gap_us: u64) -> std::io::Result<usize>;
    fn drive(&mut self, _d: Direction) -> std::io::Result<()> {
        Ok(())
    }
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
    /// The cold line kept streaming for more than one ADU's worth of bytes without ever
    /// going silent: a stuck adapter or a broken wire, and the master refuses to join it.
    ColdLine,
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
            SerialError::ColdLine => {
                f.write_str("serial: the line never went silent (stuck adapter or broken wire)")
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
    ///
    /// Before writing, the line is drained: a cold RS-485 bus often holds a partial
    /// frame from an interrupted transaction, and those bytes belong to nobody — they
    /// are read out to the next silence gap (bounded: more than one ADU of garbage
    /// without silence is a stuck adapter, [`SerialError::ColdLine`]).
    pub fn transact(&mut self, request: &[u8], answer: &mut [u8]) -> Result<usize, SerialError> {
        // Only a well-formed request leaves the gate: same rule as everything else here.
        let op = rtu::parse(request).map_err(SerialError::MalformedRequest)?;
        let expected_unit = op.unit();
        drain_port(&mut self.port, self.timing)?;
        self.port
            .drive(Direction::Transmit)
            .map_err(SerialError::Port)?;
        let sent = self.port.write_all(request).map_err(SerialError::Port);
        self.port
            .drive(Direction::Receive)
            .map_err(SerialError::Port)?;
        sent?;

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

/// Читает вход до тишины, выбрасывая прочитанное. Граница: больше [`rtu::MAX_ADU`]
/// байт без единой тишины — не мусор, а застрявший передатчик; такому линию не доверяют.
fn drain_port<P: Port>(port: &mut P, timing: Timing) -> Result<(), SerialError> {
    let mut buf = [0u8; rtu::MAX_ADU];
    let mut drained = 0usize;
    loop {
        let n = port
            .read_some(&mut buf, timing.t35_us)
            .map_err(SerialError::Port)?;
        if n == 0 {
            return Ok(()); // тишина: линия чиста
        }
        drained += n;
        if drained > rtu::MAX_ADU {
            return Err(SerialError::ColdLine);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtu::Op;
    use std::cell::RefCell;

    /// Для счастливых путей: ошибка транзакции — падение теста с причиной в сообщении.
    fn tx(r: Result<usize, SerialError>) -> usize {
        assert!(r.is_ok(), "transact failed: {:?}", r.as_ref().err());
        r.unwrap_or(0)
    }

    /// Виртуальный порт с виртуальным секундомером: никаких sleep'ов.
    /// Два сценария: `pre` — мусор на холодной линии (доступен ДО записи),
    /// `resp` — ответ слейва (доступен ТОЛЬКО после записи: настоящий слейв
    /// не отвечает на запрос, которого не было). Направления DE/RE записываются.
    struct MockPort {
        pre: RefCell<Vec<(u64, u8)>>,
        resp: RefCell<Vec<(u64, u8)>>,
        answered: RefCell<bool>,
        now: RefCell<u64>,
        writes: RefCell<Vec<u8>>,
        dirs: RefCell<Vec<Direction>>,
    }

    impl MockPort {
        fn cold(script: &[(u64, u8)], resp: &[(u64, u8)]) -> MockPort {
            MockPort {
                pre: RefCell::new(script.to_vec()),
                resp: RefCell::new(resp.to_vec()),
                answered: RefCell::new(false),
                now: RefCell::new(0),
                writes: RefCell::new(Vec::new()),
                dirs: RefCell::new(Vec::new()),
            }
        }

        fn fresh(resp: &[(u64, u8)]) -> MockPort {
            Self::cold(&[], resp)
        }
    }

    impl Port for MockPort {
        fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            self.writes.borrow_mut().extend_from_slice(bytes);
            *self.answered.borrow_mut() = true;
            *self.now.borrow_mut() = 0; // время ответа отсчитывается от запроса
            Ok(())
        }

        fn drive(&mut self, d: Direction) -> std::io::Result<()> {
            self.dirs.borrow_mut().push(d);
            Ok(())
        }

        fn read_some(&mut self, buf: &mut [u8], gap_us: u64) -> std::io::Result<usize> {
            let mut now = *self.now.borrow();
            let source = if *self.answered.borrow() {
                &mut *self.resp.borrow_mut()
            } else {
                &mut *self.pre.borrow_mut()
            };
            if let Some(&(at, b)) = source.first() {
                if at <= now + gap_us {
                    source.remove(0);
                    now = at.max(now);
                    *self.now.borrow_mut() = now;
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

    /// Ответ слейва на FC3: unit, fc, count, значения, crc.
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

    /// Ответ, разложенный по прибытиям: первый байт через `start` мкс, дальше `step`.
    fn arrivals(resp: &[u8], start: u64, step: u64) -> Vec<(u64, u8)> {
        resp.iter()
            .enumerate()
            .map(|(i, b)| (start + (i as u64) * step, *b))
            .collect()
    }

    #[test]
    fn a_transaction_round_trips_over_a_scripted_line() {
        let req = fc3_request(1, 0, 2);
        let resp = fc3_response(1, &[0x1234, 0x0055]);
        let mut link = SerialLink::new(
            MockPort::fresh(&arrivals(&resp, 1000, 500)),
            Timing::for_baud(9600, 100),
        );
        let mut answer = [0u8; rtu::MAX_ADU];
        let n = tx(link.transact(&req, &mut answer));
        assert_eq!(n, resp.len());
        assert_eq!(&answer[..n], &resp[..]);
        // 2-проводная шина: передача запроса до, приём ответа после
        assert_eq!(
            *link.port.dirs.borrow(),
            vec![Direction::Transmit, Direction::Receive]
        );
    }

    #[test]
    fn inter_byte_gaps_do_not_split_the_frame() {
        let req = fc3_request(2, 10, 1);
        let resp = fc3_response(2, &[7]);
        // пауза между байтами 2000 мкс < T3.5(9600) ≈ 4010 мкс — кадр цел
        let mut link = SerialLink::new(
            MockPort::fresh(&arrivals(&resp, 500, 2000)),
            Timing::for_baud(9600, 100),
        );
        let mut answer = [0u8; rtu::MAX_ADU];
        assert_eq!(tx(link.transact(&req, &mut answer)), resp.len());
    }

    #[test]
    fn no_answer_is_a_timeout_not_a_hang() {
        let req = fc3_request(1, 0, 1);
        let mut link = SerialLink::new(MockPort::fresh(&[]), Timing::for_baud(9600, 5));
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
        let mut link = SerialLink::new(
            MockPort::fresh(&arrivals(&resp, 100, 100)),
            Timing::for_baud(9600, 100),
        );
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
        let mut link = SerialLink::new(MockPort::fresh(&[]), Timing::for_baud(9600, 5));
        let mut answer = [0u8; rtu::MAX_ADU];
        assert!(matches!(
            link.transact(&[0x01, 0x03, 0x00], &mut answer),
            Err(SerialError::MalformedRequest(_))
        ));
        // и на линию ничего не ушло
        assert!(link.port.writes.borrow().is_empty());
    }

    #[test]
    fn t35_follows_the_specification() {
        assert_eq!(Timing::for_baud(9600, 100).t35_us, 4_010);
        assert_eq!(Timing::for_baud(19200, 100).t35_us, 2_005);
        assert_eq!(Timing::for_baud(115200, 100).t35_us, 1_750);
    }

    #[test]
    fn cold_line_garbage_is_drained_to_silence() {
        // холодная шина держит хвост прерванной транзакции: дренаж вычитывает его
        // до тишины, запрос уходит, ответ разбирается нормально
        let req = fc3_request(1, 0, 1);
        let garbage = [0x01, 0x03, 0x02, 0x00, 0x0A]; // обрывок чужого кадра
        let resp = fc3_response(1, &[5]);
        let script: Vec<(u64, u8)> = garbage
            .iter()
            .enumerate()
            .map(|(i, b)| ((i as u64) * 100, *b))
            .chain(arrivals(&resp, 1000, 300))
            .collect();
        let mut link = SerialLink::new(MockPort::cold(&script, &[]), Timing::for_baud(9600, 100));
        // мусор в `pre`, ответ отдельного сценария не нужен: mock отдаёт pre до записи
        let mut answer = [0u8; rtu::MAX_ADU];
        // pre исчерпан дренаажом, resp пуст → таймаут; проверяем именно дренаж ниже
        assert!(matches!(
            link.transact(&req, &mut answer),
            Err(SerialError::TimedOut)
        ));
        // весь мусор вычитан и запрос ушёл на линию
        assert_eq!(link.port.writes.borrow().len(), req.len());
    }

    #[test]
    fn cold_line_that_never_goes_silent_is_refused() {
        // застрявший передатчик: байты текут непрерывно, тишины нет
        let req = fc3_request(1, 0, 1);
        let script: Vec<(u64, u8)> = (0..(rtu::MAX_ADU as u64 + 5))
            .map(|i| (i * 10, (i % 256) as u8))
            .collect();
        let mut link = SerialLink::new(MockPort::cold(&script, &[]), Timing::for_baud(9600, 100));
        let mut answer = [0u8; rtu::MAX_ADU];
        assert!(matches!(
            link.transact(&req, &mut answer),
            Err(SerialError::ColdLine)
        ));
    }

    #[test]
    fn a_normal_transaction_after_a_drained_cold_line_works() {
        // мусор кончился до тишины, затем слейв отвечает — полный happy-path
        let req = fc3_request(3, 0, 1);
        let garbage = [0x11, 0x03, 0x02];
        let resp = fc3_response(3, &[0x0F0F]);
        let script: Vec<(u64, u8)> = garbage
            .iter()
            .enumerate()
            .map(|(i, b)| ((i as u64) * 100, *b))
            .collect();
        let mut link = SerialLink::new(
            MockPort::cold(&script, &arrivals(&resp, 1000, 300)),
            Timing::for_baud(9600, 100),
        );
        let mut answer = [0u8; rtu::MAX_ADU];
        let n = tx(link.transact(&req, &mut answer));
        assert_eq!(n, resp.len());
        assert_eq!(&answer[..n], &resp[..]);
    }
}

/// Привязка к настоящему COM-порту: за фичей `serial`, чтобы дефолтная сборка
/// библиотеки оставалась без зависимостей. Адаптер тонкий по замыслу — единственная
/// его работа: перевести контракт «байт или тишина через gap» и «направление шины»
/// в таймауты и RTS (классический DE/RE) ОС.
#[cfg(feature = "serial")]
pub mod os {
    use super::{Direction, Port, SerialLink, Timing};
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

        // 2-проводная RS-485: направление — классический RTS-DE/RE адаптер.
        fn drive(&mut self, d: Direction) -> io::Result<()> {
            self.port
                .write_request_to_send(d == Direction::Transmit)
                .map_err(io::Error::other)
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
