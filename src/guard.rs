//! The guard: the only place where a decision is made, and the only place that can say no.
//!
//! One request goes through seven gates, in this order, and a failure at any gate stops it:
//!
//! 1. **frame** — does it authenticate and parse as exactly one known operation?
//! 2. **session** — does the frame belong to the session that is open?
//! 3. **replay** — is this frame number fresh, given the window and the persisted boot counter?
//! 4. **policy** — deny-overrides, deny-by-default: is this function, address, unit, role allowed?
//! 5. **dual control** — for critical outputs, are there two valid signatures from two different keys?
//! 6. **audit** — can the decision be written down? If not, nothing happens.
//! 7. **apply** — writes are recorded with their previous values, so the batch can be revoked.
//!
//! The dead-man timer is the eighth gate and it runs on a clock, not on a request: if the supervisor
//! stops saying it is alive, the guard drives every output it knows a safe value for, and says so.
//!
//! Fail-closed is not a slogan here: gates 1–3 refuse, gate 4 refuses, gate 5 substitutes the safe
//! value instead of the request, gate 6 refuses when the log is unwritable, and the dead-man timer
//! runs on absence rather than presence.

use std::collections::HashMap;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::audit::AuditLog;
use crate::crypto::Session;
use crate::frame::{Frame, Opcode, FLAG_CRITICAL, FLAG_DUAL, MAX_FRAME};
use crate::policy::{Policy, Request, Role, Verdict};
use crate::replay::ReplayWindow;

/// A monotonic millisecond clock, injected so the dead-man timer can be tested without sleeping.
pub trait Clock {
    fn now_ms(&self) -> u64;
}

#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

/// The keys that make dual control real: two different secrets, held by two different people.
pub struct RoleKeys {
    pub operator: [u8; 32],
    pub supervisor: [u8; 32],
}

/// What the process memory looks like to the guard. Registers and coils share the map: a coil is a
/// register whose value is 0 or 1, and treating them as one kind of thing keeps the invariant simple.
#[derive(Debug, Clone, Default)]
pub struct PlcMemory {
    values: HashMap<(u8, u16), u16>,
}

impl PlcMemory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, unit: u8, addr: u16) -> u16 {
        self.values.get(&(unit, addr)).copied().unwrap_or(0)
    }

    pub fn set(&mut self, unit: u8, addr: u16, value: u16) {
        self.values.insert((unit, addr), value);
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request was authorised and applied; `batch` can be revoked.
    Allow { batch: u32, applied: usize },
    /// Nothing was touched.
    Deny(&'static str),
    /// The request was refused and the affected outputs were driven to their safe values.
    Safe(&'static str),
}

/// One applied batch, with the values it overwrote.
#[derive(Debug, Clone)]
struct Batch {
    id: u32,
    previous: Vec<(u8, u16, u16)>,
    current: Vec<(u8, u16, u16)>,
}

pub struct Guard {
    policy: Policy,
    audit: AuditLog,
    replay: ReplayWindow,
    plc: PlcMemory,
    session: Option<Session>,
    session_id: Option<u64>,
    role: Role,
    keys: RoleKeys,
    safe: HashMap<(u8, u16), u16>,
    batches: Vec<Batch>,
    next_batch: u32,
    heartbeat_timeout_ms: u64,
    /// `None` until somebody speaks: a guard that has never heard its supervisor must treat the
    /// very first tick as a dead-man event rather than assume everything is fine.
    last_beat_ms: Option<u64>,
}

impl Guard {
    pub fn new(policy: Policy, audit_key: [u8; 32], keys: RoleKeys, heartbeat_timeout_ms: u64) -> Self {
        Self {
            policy,
            audit: AuditLog::new(audit_key),
            replay: ReplayWindow::new(),
            plc: PlcMemory::new(),
            session: None,
            session_id: None,
            role: Role::Reader,
            keys,
            safe: HashMap::new(),
            batches: Vec::new(),
            next_batch: 1,
            heartbeat_timeout_ms,
            last_beat_ms: None,
        }
    }

    /// Start from a persisted floor: nothing at or below `highest_seq` is fresh after a restart.
    pub fn with_replay_floor(mut self, highest_seq: u64) -> Self {
        self.replay = ReplayWindow::from_highest(highest_seq);
        self
    }

    /// Provision the last-known-safe value of an output. These are what gate 5 and the dead-man
    /// timer write; they come from the engineering project, not from observation.
    pub fn provision_safe(&mut self, unit: u8, addr: u16, value: u16) {
        self.safe.insert((unit, addr), value);
    }

    pub fn attach(&mut self, session: Session, role: Role) {
        self.session_id = Some(session.session_id());
        self.session = Some(session);
        self.role = role;
    }

    pub fn plc(&self) -> &PlcMemory {
        &self.plc
    }

    pub fn audit_records(&self) -> usize {
        self.audit.records()
    }

    pub fn verify_audit(&self) -> Result<usize, crate::audit::AuditError> {
        self.audit.verify()
    }

    /// The heartbeat: called on every authenticated frame and by the supervisor's keep-alive.
    pub fn tick(&mut self, now_ms: u64) -> Decision {
        let alive = match self.last_beat_ms {
            Some(last) => now_ms.saturating_sub(last) <= self.heartbeat_timeout_ms,
            None => false,
        };
        if alive {
            return Decision::Allow { batch: 0, applied: 0 };
        }
        let affected = self.drive_all_safe();
        let _ = self.record(format!("dead-man: {affected} outputs driven safe"));
        Decision::Safe("the supervisor stopped breathing; outputs were driven to their safe values")
    }

    /// Take one frame and decide. `buffer` holds the ciphertext; on return it is destroyed.
    pub fn handle(&mut self, buffer: &mut [u8], length: usize, now_ms: u64) -> Decision {
        let Some(mut session) = self.session.take() else {
            return Decision::Deny("no established session: handshake first");
        };
        let frame = match Frame::open(buffer, length, &mut session) {
            Ok(frame) => frame,
            Err(error) => {
                self.session = Some(session);
                let _ = self.record(format!("refused: frame did not authenticate ({error})"));
                return Decision::Deny("the frame did not authenticate");
            }
        };
        // The session goes back before any other gate, so a refusal never leaves the guard deaf.
        let session_id = session.session_id();
        self.session = Some(session);
        if Some(frame.header.session_id) != self.session_id {
            let _ = self.record("refused: frame carries another session id".to_string());
            return Decision::Deny("the frame belongs to another session");
        }
        let _ = session_id;
        if let Err(error) = self.replay.check_and_update(frame.header.seq) {
            let _ = self.record(format!("refused: {error}"));
            return Decision::Deny("the frame is replayed or outside the window");
        }
        self.last_beat_ms = Some(now_ms);
        let opcode = match Opcode::from_function(frame.header.fc) {
            Ok(opcode) => opcode,
            Err(_) => {
                let _ = self.record(format!("refused: function {} is not one we speak", frame.header.fc));
                return Decision::Deny("unknown function code");
            }
        };
        let writes = opcode.writes();
        let value = if writes { read_u16(frame.payload(), 0) } else { None };
        let request = Request {
            fc: frame.header.fc,
            unit: frame.header.unit,
            addr: frame.header.addr,
            qty: frame.header.qty,
            value,
            role: self.role,
        };
        match self.policy.evaluate(&request) {
            Verdict::Deny(why) => {
                let _ = self.record(format!(
                    "denied: fc={} unit={} addr={} qty={} role={:?} — {why}",
                    request.fc, request.unit, request.addr, request.qty, request.role
                ));
                Decision::Deny(why)
            }
            Verdict::Safe(why) => {
                let affected = self.drive_safe(request.unit, request.addr, request.qty);
                let _ = self.record(format!("refused-safe: {affected} outputs driven safe — {why}"));
                Decision::Safe(why)
            }
            Verdict::Allow { dual } => {
                if dual && frame.header.flags & FLAG_DUAL == 0 {
                    let affected = self.drive_safe(request.unit, request.addr, request.qty);
                    let _ = self.record(format!(
                        "refused-safe: critical write without dual control, {affected} outputs driven safe"
                    ));
                    return Decision::Safe("dual control was required and not requested");
                }
                if dual && !self.dual_signatures_valid(&frame, value.unwrap_or(0)) {
                    let affected = self.drive_safe(request.unit, request.addr, request.qty);
                    let _ = self.record(format!(
                        "refused-safe: dual signatures did not verify, {affected} outputs driven safe"
                    ));
                    return Decision::Safe("dual control signatures did not verify");
                }
                if !writes {
                    let _ = self.record(format!(
                        "read: fc={} unit={} addr={} qty={}",
                        request.fc, request.unit, request.addr, request.qty
                    ));
                    return Decision::Allow { batch: 0, applied: 0 };
                }
                // Gate 6 before gate 7: if the decision cannot be recorded, it does not happen.
                if self
                    .record(format!(
                        "intent: fc={} unit={} addr={} qty={} value={:?} critical={}",
                        request.fc,
                        request.unit,
                        request.addr,
                        request.qty,
                        value,
                        frame.header.flags & FLAG_CRITICAL != 0
                    ))
                    .is_err()
                {
                    return Decision::Deny("the audit log is unavailable, so the write was refused");
                }
                let (batch, applied) = self.apply(&frame, opcode);
                let _ = self.record(format!("applied: batch {batch} touched {applied} outputs"));
                Decision::Allow { batch, applied }
            }
        }
    }

    /// Undo one batch: put back exactly the values it overwrote, and record that it happened.
    pub fn revoke(&mut self, batch: u32) -> Result<usize, &'static str> {
        let Some(found) = self.batches.iter().find(|b| b.id == batch) else {
            return Err("no such batch");
        };
        let previous = found.previous.clone();
        let restored = previous.len();
        for (unit, addr, value) in previous {
            self.plc.set(unit, addr, value);
        }
        if self.record(format!("revoked: batch {batch} restored {restored} outputs")).is_err() {
            return Err("the audit log is unavailable; the revocation was not recorded");
        }
        self.batches.retain(|b| b.id != batch);
        Ok(restored)
    }

    fn apply(&mut self, frame: &Frame, opcode: Opcode) -> (u32, usize) {
        let unit = frame.header.unit;
        let qty = usize::from(frame.header.qty);
        let mut previous = Vec::with_capacity(qty);
        let mut current = Vec::with_capacity(qty);
        for index in 0..qty {
            let addr = frame.header.addr.saturating_add(index as u16);
            let old = self.plc.get(unit, addr);
            let new = match opcode {
                Opcode::WriteMultiple => read_u16(frame.payload(), index).unwrap_or(old),
                _ => read_u16(frame.payload(), 0).unwrap_or(old),
            };
            previous.push((unit, addr, old));
            current.push((unit, addr, new));
            self.plc.set(unit, addr, new);
        }
        let id = self.next_batch;
        self.next_batch = self.next_batch.saturating_add(1);
        self.batches.push(Batch { id, previous, current });
        (id, qty)
    }

    /// Write safe values over a span, and remember what they replaced so even this is reversible.
    fn drive_safe(&mut self, unit: u8, addr: u16, qty: u16) -> usize {
        let mut previous = Vec::new();
        let mut current = Vec::new();
        for index in 0..qty {
            let at = addr.saturating_add(index);
            if let Some(value) = self.safe.get(&(unit, at)).copied() {
                let old = self.plc.get(unit, at);
                previous.push((unit, at, old));
                current.push((unit, at, value));
                self.plc.set(unit, at, value);
            }
        }
        if previous.is_empty() {
            return 0;
        }
        let count = previous.len();
        let id = self.next_batch;
        self.next_batch = self.next_batch.saturating_add(1);
        self.batches.push(Batch { id, previous, current });
        count
    }

    fn drive_all_safe(&mut self) -> usize {
        let targets: Vec<(u8, u16, u16)> = self.safe.iter().map(|((unit, addr), value)| (*unit, *addr, *value)).collect();
        let mut count = 0;
        for (unit, addr, value) in targets {
            self.plc.set(unit, addr, value);
            count += 1;
        }
        count
    }

    fn dual_signatures_valid(&self, frame: &Frame, value: u16) -> bool {
        let payload = frame.payload();
        if payload.len() != 66 {
            return false;
        }
        let header = frame.header.encode();
        let mut operator_sig = [0u8; 32];
        operator_sig.copy_from_slice(&payload[2..34]);
        let mut supervisor_sig = [0u8; 32];
        supervisor_sig.copy_from_slice(&payload[34..66]);
        verify_dual(&self.keys.operator, &header, value, &operator_sig)
            && verify_dual(&self.keys.supervisor, &header, value, &supervisor_sig)
    }

    fn record(&mut self, text: String) -> Result<usize, ()> {
        self.audit.append(&text).map_err(|_| ())
    }
}

/// The signature a person produces over one operation: bound to the whole header (session, frame
/// number, function, address, quantity) and to the value, so it cannot be lifted into another frame.
pub fn dual_signature(key: &[u8; 32], header: &[u8], value: u16) -> Option<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(b"REDOUBT/1 dual");
    mac.update(header);
    mac.update(&value.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    Some(out)
}

fn verify_dual(key: &[u8; 32], header: &[u8], value: u16, signature: &[u8; 32]) -> bool {
    match dual_signature(key, header, value) {
        Some(expected) => expected.ct_eq(signature).into(),
        None => false,
    }
}

fn read_u16(payload: &[u8], index: usize) -> Option<u16> {
    let at = index.checked_mul(2)?;
    let pair = payload.get(at..at + 2)?;
    Some(u16::from_be_bytes([pair[0], pair[1]]))
}

/// The largest frame the guard will ever look at; useful to size the receive buffer.
pub const RECEIVE_BUFFER: usize = MAX_FRAME;
