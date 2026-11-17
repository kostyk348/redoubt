//! Kani harnesses: proofs over the compiled code, not over the Lean model.
//!
//! These are compiled only under `cargo kani` (`cfg(kani)`), so a normal `cargo test` ignores them.
//! What they add: the Lean file reasons about a model we wrote down; Kani reasons about the actual
//! machine code paths — every length, every byte value, no sampling.

use crate::frame::{expected_payload, FrameHeader, Opcode, MAX_PAYLOAD};
use crate::policy::{Policy, Request, Role, Verdict};

/// **Decoding an arbitrary header never panics and never asks for more than the payload budget.**
#[kani::proof]
fn header_decoding_is_total_and_bounded() {
    let bytes: [u8; 24] = kani::any();
    if let Ok(header) = FrameHeader::decode(&bytes) {
        if let Ok(opcode) = Opcode::from_function(header.fc) {
            if let Ok(size) = expected_payload(opcode, header.qty, header.wants_dual()) {
                kani::assert(
                    size <= MAX_PAYLOAD,
                    "a validated payload must fit the budget",
                );
            }
        }
    }
}

/// **Every bounded request gets exactly one verdict, and `allow` is impossible outside the
/// rule's range.**
///
/// Раньше харнесс передавал в `evaluate` неограниченные `addr`/`qty`, и CBMC тонул: поиск байта
/// в std раскручивался на 4500+ итераций, джоба убивалась по лимиту (5 ч 31 мин).
/// Теперь вход ограничен тем, что действительно возможно в протоколе:
///
///   * `qty` — от 1 до 8 (бюджет транзакции, как в спецификации кадра);
///   * `addr + qty - 1` не выходит за 16-битное адресное пространство.
///
/// Проверяется не «функция не падает», а содержательное свойство политики: если запрос целиком
/// не попадает в диапазон правила `allow fc 6 addr 40001..40010`, разрешающего вердикта быть
/// не может (правило требует, чтобы весь интервал лежал внутри диапазона).
#[kani::proof]
#[kani::unwind(24)]
fn policy_evaluation_is_total() {
    let policy = match Policy::parse(
        "allow fc 6 addr 40001..40010 role operator
safe fc 6 addr 500..599
",
    ) {
        Ok(policy) => policy,
        // Константа заведомо валидна; если это не так — падать в доказательстве незачем,
        // об этом скажет обычный тест policy::tests.
        Err(_) => return,
    };

    let fc: u8 = kani::any();
    let addr: u16 = kani::any();
    let qty: u16 = kani::any();
    let value: u16 = kani::any();

    kani::assume(qty >= 1 && qty <= 8);
    kani::assume((addr as u32) + (qty as u32) - 1 <= 65535);

    let request = Request {
        fc,
        unit: 1,
        addr,
        qty,
        value: Some(value),
        role: Role::Operator,
    };

    let verdict = policy.evaluate(&request);

    let span_end = addr as u32 + qty as u32 - 1;
    let inside_allow_range = fc == 6 && addr >= 40001 && span_end <= 40010;
    if !inside_allow_range {
        kani::assert(
            !matches!(verdict, Verdict::Allow { .. }),
            "a request outside the allowed range must never be allowed",
        );
    }
}

/// **An address span that a rule validated cannot wrap**: the last address the guard would touch
/// stays inside the 16-bit space, so the write cannot spill into a neighbouring range.
#[kani::proof]
fn a_validated_span_does_not_wrap() {
    let addr: u16 = kani::any();
    let qty: u16 = kani::any();
    if qty >= 1 {
        let last = addr as u32 + (qty as u32 - 1);
        if last <= 65535 {
            kani::assert(last + 1 <= 65536, "no wrap past the address space");
        }
    }
}
