//! RTU south side, end to end: the same policy judges a serial-line request, an allowed
//! write round-trips through the wire format, and attacker-chosen bytes never panic.

use redoubt::policy::{Policy, Role, Verdict};
use redoubt::rtu::{crc16, parse, Op, RtuError, MAX_ADU};

///Детерминированный xorshift вместо внешнего фаззера: тот же набор байтов на любой машине.
struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xFF) as u8
    }
}

#[test]
fn a_serial_line_request_is_judged_by_the_same_policy() {
    // Одна политика на оба транспорта: линия RS-485 не получает своего языка правил.
    let policy = Policy::parse(
        "allow fc in {3,4} addr 0..499 role reader\n\
         allow fc 6 addr 500..599 role operator\n\
         deny  fc 6 addr 0..99\n",
    )
    .unwrap_or_else(|_| unreachable_policy());

    let read = Op::Read {
        unit: 5,
        fc: 3,
        addr: 10,
        qty: 2,
    };
    let req = read.request(Role::Reader).unwrap_or_else(no_request);
    assert!(matches!(policy.evaluate(&req), Verdict::Allow { .. }));

    let write = Op::WriteSingle {
        unit: 5,
        fc: 6,
        addr: 50,
        value: 1,
    };
    let req = write.request(Role::Operator).unwrap_or_else(no_request);
    // deny перекрывает allow независимо от порядка строк
    assert!(matches!(policy.evaluate(&req), Verdict::Deny(_)));

    // исключение — ответ устройства, не намерение мастера: запроса нет
    let exc = Op::Exception {
        unit: 5,
        fc: 6,
        code: 2,
    };
    assert!(exc.request(Role::Operator).is_none());
}

#[test]
fn an_allowed_write_round_trips_through_the_wire() {
    let op = Op::WriteMultiple {
        unit: 9,
        addr: 40000,
        values: vec![10, 20, 30],
    };
    let mut buf = [0u8; MAX_ADU];
    let n = op.encode(&mut buf).unwrap_or(MAX_ADU);
    assert_eq!(n, 1 + 1 + 2 + 2 + 1 + 6 + 2);
    assert_eq!(parse(&buf[..n]), Ok(op));
    // CRC на проводе — младшим байтом вперёд, ровно как в спецификации
    assert_eq!(
        crc16(&buf[..n - 2]),
        u16::from_le_bytes([buf[n - 2], buf[n - 1]])
    );
}

#[test]
fn spec_vectors_decode_exactly() {
    // 01 03 00 00 00 01 84 0A — опрос одного регистра устройства 1
    let adu = [0x01, 0x03, 0x00, 0x00, 0x00, 0x01, 0x84, 0x0A];
    assert_eq!(
        parse(&adu),
        Ok(Op::Read {
            unit: 1,
            fc: 3,
            addr: 0,
            qty: 1
        })
    );
    // 11 03 006B 0003 7687 — пример из Modbus over serial line V1.02
    let adu = [0x11, 0x03, 0x00, 0x6B, 0x00, 0x03, 0x76, 0x87];
    assert_eq!(
        parse(&adu),
        Ok(Op::Read {
            unit: 0x11,
            fc: 3,
            addr: 0x6B,
            qty: 3
        })
    );
}

#[test]
fn attacker_chosen_bytes_never_panic_and_never_succeed_silently() {
    let mut rng = XorShift(0x0005_EED1_2026);
    for _ in 0..4000 {
        let len = (rng.next() % (MAX_ADU as u64 + 1)) as usize;
        let mut buf = [0u8; MAX_ADU + 8];
        for b in buf.iter_mut().take(len) {
            *b = rng.byte();
        }
        let adu = &buf[..len];
        // никакой вход не паникует; разбор — это либо ошибка, либо операция,
        // которая пере-кодируется байт в байт (свойство round-trip)
        match parse(adu) {
            Err(_) => {}
            Ok(op) => {
                let mut out = [0u8; MAX_ADU];
                let n = op.encode(&mut out).unwrap_or(MAX_ADU);
                assert_eq!(
                    parse(&out[..n]),
                    Ok(op.clone()),
                    "round-trip сломался на {:?}",
                    op
                );
            }
        }
    }
}

#[test]
fn every_refusal_reason_is_reachable_and_named() {
    let enc = |op: &Op| -> (Vec<u8>, usize) {
        let mut b = [0u8; MAX_ADU];
        let n = op.encode(&mut b).unwrap_or(MAX_ADU);
        (b.to_vec(), n)
    };

    let (b, n) = enc(&Op::Read {
        unit: 1,
        fc: 3,
        addr: 0,
        qty: 1,
    });
    assert_eq!(parse(&b[..3]), Err(RtuError::TooShort)); // короче unit+fc+crc
    assert_eq!(parse(&b[..n + 1]), Err(RtuError::TrailingBytes));
    assert_eq!(
        parse(&b[..n]),
        Ok(Op::Read {
            unit: 1,
            fc: 3,
            addr: 0,
            qty: 1
        })
    );

    let (b, n) = enc(&Op::WriteSingle {
        unit: 1,
        fc: 5,
        addr: 0,
        value: 0xFF00,
    });
    let mut tampered = b[..n].to_vec();
    tampered[4] = 0x12; // не 0x0000 и не 0xFF00
    let crc = crc16(&tampered[..n - 2]);
    tampered[n - 2] = (crc & 0xFF) as u8;
    tampered[n - 1] = (crc >> 8) as u8;
    assert_eq!(parse(&tampered), Err(RtuError::BadValue));

    let (b, n) = enc(&Op::Read {
        unit: 1,
        fc: 9,
        addr: 0,
        qty: 1,
    });
    assert_eq!(parse(&b[..n]), Err(RtuError::UnsupportedFc));
}

/// Заглушка только для тестов: request() выше разобран валидной операцией,
/// сюда управление не попадает. lib.rs запрещает unwrap — держим честно.
fn no_request() -> redoubt::policy::Request {
    redoubt::policy::Request {
        fc: 0,
        unit: 0,
        addr: 0,
        qty: 0,
        value: None,
        role: Role::Reader,
    }
}

/// Заглушка только для тестов: политика выше разобрана валидной строкой,
/// сюда управление не попадает. lib.rs запрещает unwrap — держим честно.
fn unreachable_policy() -> Policy {
    Policy::parse("deny fc in {0..255}\n").unwrap_or_else(|_| unreachable_policy())
}
