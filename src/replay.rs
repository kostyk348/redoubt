//! Replay protection that survives a power cut.
//!
//! A frame number alone is not enough. An attacker who can restart the guard — or the PLC, or the
//! whole cabinet — resets a counter kept in RAM to zero and then replays last week's "open the
//! valve" frame, which is new again. SNMPv3 solved this in 1998 with `engineBoots`: a counter that
//! is incremented *before* the protocol starts and persisted, so a restart raises the floor instead
//! of lowering it.
//!
//! Two pieces here:
//!
//! - [`ReplayWindow`] — the 64-frame sliding window from IPsec (RFC 4303), so a reordered but fresh
//!   frame is accepted and a repeated one is not.
//! - [`CounterStore`] — an append-only file of `(boots, previous record's MAC)`, each record carrying
//!   its own HMAC. A record that is edited fails its MAC; a record that is removed breaks the chain;
//!   a `boots` value lower than the last one is a rollback and is refused.
//!
//! What this cannot see: deleting **every** record. A fresh file is indistinguishable from a fresh
//! installation, so [`CounterStore::verify_against`] exists for the case where a supervisor keeps its
//! own copy of the highest `boots` it has ever seen — which is what "highest level" actually means:
//! two independent places must agree, and if they do not, the guard refuses to serve.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// This frame number was already accepted.
    Duplicate(u64),
    /// Older than the window; accepting it would mean accepting everything in between.
    TooOld(u64),
    /// Frame zero is reserved: it belongs to no session.
    Zero,
    /// The counter file does not form a valid chain.
    Tampered {
        line: usize,
        reason: String,
    },
    /// The counter went backwards relative to an anchor somebody else kept.
    Rollback {
        stored: u32,
        anchor: u32,
    },
    Io(String),
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayError::Duplicate(seq) => write!(f, "frame {seq} was already accepted"),
            ReplayError::TooOld(seq) => write!(f, "frame {seq} is outside the replay window"),
            ReplayError::Zero => write!(f, "frame number zero is reserved"),
            ReplayError::Tampered { line, reason } => {
                write!(f, "counter file line {line}: {reason}")
            }
            ReplayError::Rollback { stored, anchor } => {
                write!(
                    f,
                    "counter rolled back: file says {stored}, supervisor has seen {anchor}"
                )
            }
            ReplayError::Io(error) => write!(f, "{error}"),
        }
    }
}

/// The IPsec sliding window, 64 frames wide.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    highest: u64,
    seen: u64,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            highest: 0,
            seen: 0,
        }
    }

    /// After a restart, start from the persisted floor: nothing at or below it is fresh.
    pub fn from_highest(highest: u64) -> Self {
        Self {
            highest,
            seen: u64::MAX,
        }
    }

    pub fn highest(&self) -> u64 {
        self.highest
    }

    /// Accept a frame number once, in any order within the window.
    pub fn check_and_update(&mut self, seq: u64) -> Result<(), ReplayError> {
        if seq == 0 {
            return Err(ReplayError::Zero);
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            // Bit zero belongs to the new highest frame; the frames that were skipped land in the
            // bits above it as zeros, which is exactly what "not seen" means.
            self.seen = if shift >= 64 {
                1
            } else {
                (self.seen << shift) | 1
            };
            self.highest = seq;
            return Ok(());
        }
        let behind = self.highest - seq;
        if behind >= 64 {
            return Err(ReplayError::TooOld(seq));
        }
        let bit = 1u64 << behind;
        if self.seen & bit != 0 {
            return Err(ReplayError::Duplicate(seq));
        }
        self.seen |= bit;
        Ok(())
    }
}

/// The persisted `engineBoots` counter, hash-chained and HMACed.
pub struct CounterStore {
    path: PathBuf,
    key: [u8; 32],
    boots: u32,
    head: [u8; 32],
    records: usize,
}

impl CounterStore {
    /// Open (or create) the counter file and verify the whole chain before anyone trusts it.
    pub fn open(path: impl Into<PathBuf>, key: [u8; 32]) -> Result<Self, ReplayError> {
        let path = path.into();
        let mut store = Self {
            path,
            key,
            boots: 0,
            head: [0u8; 32],
            records: 0,
        };
        if !store.path.exists() {
            return Ok(store);
        }
        let file =
            std::fs::File::open(&store.path).map_err(|error| ReplayError::Io(error.to_string()))?;
        let mut previous = [0u8; 32];
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line_number = index + 1;
            let line = line.map_err(|error| ReplayError::Io(error.to_string()))?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split(' ');
            let boots_text = parts.next().ok_or_else(|| ReplayError::Tampered {
                line: line_number,
                reason: "no boots field".into(),
            })?;
            let head_text = parts.next().ok_or_else(|| ReplayError::Tampered {
                line: line_number,
                reason: "no chain field".into(),
            })?;
            let mac_text = parts.next().ok_or_else(|| ReplayError::Tampered {
                line: line_number,
                reason: "no MAC field".into(),
            })?;
            if parts.next().is_some() {
                return Err(ReplayError::Tampered {
                    line: line_number,
                    reason: "extra fields".into(),
                });
            }
            let boots: u32 = boots_text.parse().map_err(|_| ReplayError::Tampered {
                line: line_number,
                reason: "boots is not a number".into(),
            })?;
            let head = decode_hex(head_text).ok_or_else(|| ReplayError::Tampered {
                line: line_number,
                reason: "chain is not 32 hex bytes".into(),
            })?;
            let mac = decode_hex(mac_text).ok_or_else(|| ReplayError::Tampered {
                line: line_number,
                reason: "MAC is not 32 hex bytes".into(),
            })?;
            if head != previous {
                return Err(ReplayError::Tampered {
                    line: line_number,
                    reason: "chain does not link to the previous record".into(),
                });
            }
            let expected = store.mac(boots, &previous)?;
            if expected != mac {
                return Err(ReplayError::Tampered {
                    line: line_number,
                    reason: "MAC does not verify".into(),
                });
            }
            if boots < store.boots {
                return Err(ReplayError::Tampered {
                    line: line_number,
                    reason: "boots goes backwards".into(),
                });
            }
            store.boots = boots;
            store.head = mac;
            previous = mac;
            store.records += 1;
        }
        Ok(store)
    }

    pub fn boots(&self) -> u32 {
        self.boots
    }

    pub fn records(&self) -> usize {
        self.records
    }

    /// Increment and persist before the session starts. If this fails, the guard must not serve.
    pub fn bump(&mut self) -> Result<u32, ReplayError> {
        let next = self.boots.checked_add(1).ok_or(ReplayError::Rollback {
            stored: self.boots,
            anchor: u32::MAX,
        })?;
        let mac = self.mac(next, &self.head)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| ReplayError::Io(error.to_string()))?;
        let line = format!("{next} {} {}\n", encode_hex(&self.head), encode_hex(&mac));
        file.write_all(line.as_bytes())
            .map_err(|error| ReplayError::Io(error.to_string()))?;
        file.sync_all()
            .map_err(|error| ReplayError::Io(error.to_string()))?;
        self.boots = next;
        self.head = mac;
        self.records += 1;
        Ok(next)
    }

    /// Compare with a counter kept elsewhere (the supervisor's copy). Two places must agree; if the
    /// supervisor has seen a higher `boots`, this file has been replaced.
    pub fn verify_against(&self, anchor: u32) -> Result<(), ReplayError> {
        if self.boots < anchor {
            return Err(ReplayError::Rollback {
                stored: self.boots,
                anchor,
            });
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn mac(&self, boots: u32, previous: &[u8; 32]) -> Result<[u8; 32], ReplayError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|error| ReplayError::Io(error.to_string()))?;
        mac.update(b"REDOUBT/1 counter");
        mac.update(&boots.to_be_bytes());
        mac.update(previous);
        let mut out = [0u8; 32];
        out.copy_from_slice(&mac.finalize().into_bytes());
        Ok(out)
    }
}

/// What the chain does to itself: each record's chain field is the previous record's MAC, so a record
/// cannot be removed without breaking the link. Hash of the record is used for the audit log, not
/// here — the MAC already covers the content of the record that matters.
pub fn record_digest(boots: u32, previous: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"REDOUBT/1 digest");
    hasher.update(boots.to_be_bytes());
    hasher.update(previous);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn decode_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, chunk) in text.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).ok()?;
        out[index] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}
