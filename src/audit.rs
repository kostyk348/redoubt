//! The audit log: a chain that notices when somebody edits its middle.
//!
//! Each record's hash covers the previous hash and the record's own text, so changing record 7 of
//! 400 changes the hash of every record after it. Periodic checkpoints are signed with an HMAC key
//! the log itself does not store, which is what turns "the hashes look consistent" into "they are
//! the hashes this device produced": an attacker who rewrites the whole file also has to forge the
//! checkpoint, and that needs the key.
//!
//! Fail-closed rule, enforced by the guard: **if the audit entry cannot be written, the operation it
//! describes is not performed**. A control action nobody can prove afterwards is an action that did
//! not happen.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    /// The chain does not recompute: a record was edited, inserted or removed.
    ChainBroken { index: usize },
    /// The last checkpoint does not match the chain.
    CheckpointMismatch { index: usize },
    /// The log is empty and a checkpoint was expected.
    Empty,
    /// A checkpoint could not be signed.
    Key,
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::ChainBroken { index } => write!(f, "audit record {index} does not match the chain"),
            AuditError::CheckpointMismatch { index } => write!(f, "audit checkpoint at record {index} does not verify"),
            AuditError::Empty => write!(f, "the audit log is empty"),
            AuditError::Key => write!(f, "the audit key is unusable"),
        }
    }
}

#[derive(Debug, Clone)]
struct Record {
    text: String,
    hash: [u8; 32],
}

/// An append-only chain with signed checkpoints.
pub struct AuditLog {
    key: [u8; 32],
    records: Vec<Record>,
    checkpoints: Vec<(usize, [u8; 32])>,
    checkpoint_every: usize,
}

impl AuditLog {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, records: Vec::new(), checkpoints: Vec::new(), checkpoint_every: 8 }
    }

    pub fn with_checkpoint_every(mut self, every: usize) -> Self {
        self.checkpoint_every = every.max(1);
        self
    }

    /// Append one entry. Returns its index.
    pub fn append(&mut self, text: &str) -> Result<usize, AuditError> {
        let previous = self.head();
        let mut hasher = Sha256::new();
        hasher.update(b"OPLOT/1 audit");
        hasher.update(previous);
        hasher.update(text.as_bytes());
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        self.records.push(Record { text: text.to_string(), hash });
        let index = self.records.len() - 1;
        if (index + 1) % self.checkpoint_every == 0 {
            let signature = self.sign(index)?;
            self.checkpoints.push((index, signature));
        }
        Ok(index)
    }

    /// Recompute the whole chain and every checkpoint. This is what a supervisor runs before it
    /// believes anything the log says.
    pub fn verify(&self) -> Result<usize, AuditError> {
        let mut previous = [0u8; 32];
        for (index, record) in self.records.iter().enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(b"OPLOT/1 audit");
            hasher.update(previous);
            hasher.update(record.text.as_bytes());
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hasher.finalize());
            if hash != record.hash {
                return Err(AuditError::ChainBroken { index });
            }
            previous = hash;
        }
        for (index, signature) in &self.checkpoints {
            let expected = self.sign(*index)?;
            if expected != *signature {
                return Err(AuditError::CheckpointMismatch { index: *index });
            }
        }
        Ok(self.records.len())
    }

    pub fn head(&self) -> [u8; 32] {
        self.records.last().map(|record| record.hash).unwrap_or([0u8; 32])
    }

    pub fn records(&self) -> usize {
        self.records.len()
    }

    pub fn text(&self, index: usize) -> Option<&str> {
        self.records.get(index).map(|record| record.text.as_str())
    }

    /// Replace a record's text without touching its hash. Only meaningful in tests and in the drill
    /// that shows what tampering looks like from the verifier's side.
    pub fn replace_for_test(&mut self, index: usize, text: &str) -> bool {
        match self.records.get_mut(index) {
            Some(record) => {
                record.text = text.to_string();
                true
            }
            None => false,
        }
    }

    /// Drop the tail, as a truncation attack would.
    pub fn truncate_for_test(&mut self, keep: usize) {
        self.records.truncate(keep);
        self.checkpoints.retain(|(index, _)| *index < keep);
    }

    fn sign(&self, index: usize) -> Result<[u8; 32], AuditError> {
        let record = self.records.get(index).ok_or(AuditError::Empty)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).map_err(|_| AuditError::Key)?;
        mac.update(b"OPLOT/1 checkpoint");
        mac.update(&(index as u64).to_be_bytes());
        mac.update(&record.hash);
        let mut out = [0u8; 32];
        out.copy_from_slice(&mac.finalize().into_bytes());
        Ok(out)
    }
}
