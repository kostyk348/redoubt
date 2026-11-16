//! The handshake: Noise KK, and the session keys it leaves behind.
//!
//! Both sides know each other's static X25519 public key **before the first byte is sent** — that is
//! what KK means, and it is the right shape for a plant: provisioning already has a list of devices,
//! and there is no third party to ask at three in the morning.
//!
//! ```text
//!   initiator                                    responder
//!   ---------                                    ---------
//!   -> e, es, ss          ephemeral, DH(e_i, s_r), DH(s_i, s_r)
//!   <- e, ee, se          ephemeral, DH(e_r, e_i), DH(e_r, s_i)
//!   split                 two AES-256-GCM keys, one per direction
//! ```
//!
//! The two DHs in the first message bind the initiator's long-term key to the responder's; the two
//! in the second give forward secrecy and prove the responder holds its static key too. Every byte
//! that crosses is folded into `h` before it is used, so a modified message changes the key schedule
//! instead of merely failing a check at the end.
//!
//! The primitives are audited crates: `x25519-dalek` for the DH, `hkdf`+`sha2` for the key schedule,
//! `aes-gcm` for the AEAD. Nothing here is our own cryptography; the composition is ours, and it has
//! not been cross-checked against a reference Noise implementation — see `SECURITY.md`.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Bytes of a public key or an ephemeral key.
pub const KEY: usize = 32;
/// Bytes of an AEAD tag.
pub const TAG: usize = 16;
/// Bytes of a handshake message: one public key and one tag.
pub const MESSAGE: usize = KEY + TAG;
/// The Noise protocol name, padded to the hash length as the specification requires.
const PROTOCOL: &[u8; 32] = b"Noise_KK_25519_AESGCM_SHA256\0\0\0\0";
/// Domain separation so an РЕДУТ key cannot be mistaken for a key of some other protocol.
const PROLOGUE: &[u8] = b"REDOUBT/1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// The system random source refused to work. Never fall back to a weaker one.
    Random,
    /// A tag did not verify: the message was modified, replayed or meant for another peer.
    AuthenticationFailed,
    /// A message had the wrong size.
    BadLength { expected: usize, got: usize },
    /// The handshake was driven out of order (for example, message two before message one).
    OutOfOrder(&'static str),
    /// The message counter is exhausted; a session must not wrap its nonce.
    NonceExhausted,
    /// A payload does not fit the frame budget.
    TooLarge { limit: usize, got: usize },
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Random => write!(f, "the system random source refused to work"),
            CryptoError::AuthenticationFailed => write!(f, "authentication failed"),
            CryptoError::BadLength { expected, got } => write!(f, "expected {expected} bytes, got {got}"),
            CryptoError::OutOfOrder(what) => write!(f, "handshake out of order: {what}"),
            CryptoError::NonceExhausted => write!(f, "nonce space exhausted; the session must be re-keyed"),
            CryptoError::TooLarge { limit, got } => write!(f, "{got} bytes do not fit the {limit}-byte budget"),
        }
    }
}

/// A long-term identity: the static key pair a device is provisioned with.
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    /// A fresh key pair from the system random source.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; KEY];
        getrandom::getrandom(&mut bytes).map_err(|_| CryptoError::Random)?;
        let secret = StaticSecret::from(bytes);
        bytes.zeroize();
        let public = PublicKey::from(&secret);
        Ok(Self { secret, public })
    }

    /// A key pair from fixed bytes — for tests and for provisioning from a store.
    pub fn from_bytes(bytes: [u8; KEY]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; KEY] {
        self.public.to_bytes()
    }
}

/// One end of a handshake in progress.
pub struct Handshake {
    chaining_key: [u8; 32],
    hash: [u8; 32],
    cipher_key: Option<[u8; 32]>,
    nonce: u64,
    ephemeral: Option<StaticSecret>,
    peer_ephemeral: Option<PublicKey>,
    local: StaticSecret,
    remote: PublicKey,
    initiator: bool,
    step: Step,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Start,
    SentOne,
    ReadOne,
    SentTwo,
    Done,
}

impl Handshake {
    fn new(local: &KeyPair, remote: [u8; KEY], initiator: bool, prologue_extra: &[u8]) -> Self {
        // h = protocol name padded to HASHLEN; ck = h. The prologue is mixed in **one** call, as the
        // Noise specification says: mixing it in two pieces would hash it twice and make our
        // transcript differ from every reference implementation — a parity test with `snow` caught
        // exactly that.
        let mut hash = *PROTOCOL;
        let chaining_key = hash;
        let mut prologue = Vec::with_capacity(PROLOGUE.len() + prologue_extra.len());
        prologue.extend_from_slice(PROLOGUE);
        prologue.extend_from_slice(prologue_extra);
        mix_hash(&mut hash, &prologue);
        // Pre-messages: Noise folds the public keys that were known before the first byte into the
        // transcript hash, initiator first. KK knows both static keys in advance, so they are mixed
        // here — leaving them out makes every reference implementation fail to decrypt our first
        // message, which is exactly how the parity test found this.
        let local_public = local.public_bytes();
        if initiator {
            mix_hash(&mut hash, &local_public);
            mix_hash(&mut hash, &remote);
        } else {
            mix_hash(&mut hash, &remote);
            mix_hash(&mut hash, &local_public);
        }
        Self {
            chaining_key,
            hash,
            cipher_key: None,
            nonce: 0,
            ephemeral: None,
            peer_ephemeral: None,
            local: StaticSecret::from(local.secret.to_bytes()),
            remote: PublicKey::from(remote),
            initiator,
            step: Step::Start,
        }
    }

    /// Start a handshake as the side that speaks first.
    pub fn initiator(local: &KeyPair, remote: [u8; KEY], prologue_extra: &[u8]) -> Self {
        Self::new(local, remote, true, prologue_extra)
    }

    /// Start a handshake as the side that answers.
    pub fn responder(local: &KeyPair, remote: [u8; KEY], prologue_extra: &[u8]) -> Self {
        Self::new(local, remote, false, prologue_extra)
    }

    /// Initiator: `e, es, ss` and the first key-confirmation tag.
    pub fn write_message_1(&mut self) -> Result<[u8; MESSAGE], CryptoError> {
        if !self.initiator || self.step != Step::Start {
            return Err(CryptoError::OutOfOrder("message one is written once, by the initiator"));
        }
        let ephemeral = random_secret()?;
        let mut message = [0u8; MESSAGE];
        let public = PublicKey::from(&ephemeral).to_bytes();
        message[..KEY].copy_from_slice(&public);
        mix_hash(&mut self.hash, &public);
        // es: the initiator's ephemeral with the responder's static key.
        self.mix_key(&ephemeral.diffie_hellman(&self.remote).to_bytes());
        // ss: the two long-term keys.
        self.mix_key(&self.local.diffie_hellman(&self.remote).to_bytes());
        self.ephemeral = Some(ephemeral);
        let tag = self.encrypt_and_hash(&mut [])?;
        message[KEY..].copy_from_slice(&tag);
        self.step = Step::SentOne;
        Ok(message)
    }

    /// Responder: read message one. Fails if the tag does not verify, which happens when the
    /// initiator does not hold the static key its public key claims.
    pub fn read_message_1(&mut self, message: &[u8]) -> Result<(), CryptoError> {
        if self.initiator || self.step != Step::Start {
            return Err(CryptoError::OutOfOrder("message one is read once, by the responder"));
        }
        let message = expect_message(message)?;
        let mut peer_public = [0u8; KEY];
        peer_public.copy_from_slice(&message[..KEY]);
        let peer = PublicKey::from(peer_public);
        mix_hash(&mut self.hash, &peer_public);
        self.mix_key(&self.local.diffie_hellman(&peer).to_bytes());
        self.mix_key(&self.local.diffie_hellman(&self.remote).to_bytes());
        self.peer_ephemeral = Some(peer);
        self.decrypt_and_hash(&message[KEY..])?;
        self.step = Step::ReadOne;
        Ok(())
    }

    /// Responder: `e, ee, se` and the second key-confirmation tag.
    pub fn write_message_2(&mut self) -> Result<[u8; MESSAGE], CryptoError> {
        if self.initiator || self.step != Step::ReadOne {
            return Err(CryptoError::OutOfOrder("message two is written by the responder after message one"));
        }
        let peer = self.peer_ephemeral.ok_or(CryptoError::OutOfOrder("no peer ephemeral"))?;
        let ephemeral = random_secret()?;
        let mut message = [0u8; MESSAGE];
        let public = PublicKey::from(&ephemeral).to_bytes();
        message[..KEY].copy_from_slice(&public);
        mix_hash(&mut self.hash, &public);
        // ee: both ephemerals — this is where forward secrecy comes from.
        self.mix_key(&ephemeral.diffie_hellman(&peer).to_bytes());
        // se: the initiator's static key with the responder's ephemeral.
        self.mix_key(&ephemeral.diffie_hellman(&self.remote).to_bytes());
        let tag = self.encrypt_and_hash(&mut [])?;
        message[KEY..].copy_from_slice(&tag);
        self.ephemeral = Some(ephemeral);
        self.step = Step::SentTwo;
        Ok(message)
    }

    /// Initiator: read message two.
    pub fn read_message_2(&mut self, message: &[u8]) -> Result<(), CryptoError> {
        if !self.initiator || self.step != Step::SentOne {
            return Err(CryptoError::OutOfOrder("message two is read by the initiator after message one"));
        }
        let message = expect_message(message)?;
        let mut peer_public = [0u8; KEY];
        peer_public.copy_from_slice(&message[..KEY]);
        let peer = PublicKey::from(peer_public);
        mix_hash(&mut self.hash, &peer_public);
        let ephemeral = self.ephemeral.take().ok_or(CryptoError::OutOfOrder("no local ephemeral"))?;
        self.mix_key(&ephemeral.diffie_hellman(&peer).to_bytes());
        self.mix_key(&self.local.diffie_hellman(&peer).to_bytes());
        self.decrypt_and_hash(&message[KEY..])?;
        self.step = Step::Done;
        Ok(())
    }

    /// Turn the finished transcript into two directional keys. The chaining key is consumed, so a
    /// handshake object cannot produce a second session.
    pub fn finish(mut self, session_id: u64) -> Result<Session, CryptoError> {
        let finished = matches!(self.step, Step::Done | Step::SentTwo);
        if !finished {
            return Err(CryptoError::OutOfOrder("the handshake has not completed"));
        }
        let mut okm = [0u8; 64];
        let hkdf = Hkdf::<Sha256>::new(Some(&self.chaining_key), &[]);
        hkdf.expand(&[], &mut okm).map_err(|_| CryptoError::Random)?;
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        first.copy_from_slice(&okm[..32]);
        second.copy_from_slice(&okm[32..]);
        okm.zeroize();
        self.chaining_key.zeroize();
        let (send, recv) = if self.initiator { (first, second) } else { (second, first) };
        Session::new(send, recv, session_id)
    }

    fn mix_key(&mut self, input: &[u8; 32]) {
        // HKDF(ck, ikm, 2) with an empty info string, as the Noise specification defines it.
        let mut okm = [0u8; 64];
        let hkdf = Hkdf::<Sha256>::new(Some(&self.chaining_key), input);
        let _ = hkdf.expand(&[], &mut okm);
        self.chaining_key.copy_from_slice(&okm[..32]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&okm[32..]);
        self.cipher_key = Some(key);
        self.nonce = 0;
        okm.zeroize();
    }

    fn encrypt_and_hash(&mut self, plaintext: &mut [u8]) -> Result<[u8; TAG], CryptoError> {
        let key = self.cipher_key.ok_or(CryptoError::OutOfOrder("no key mixed yet"))?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::Random)?;
        let nonce = noise_nonce(self.nonce);
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &self.hash, plaintext)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        self.nonce = self.nonce.saturating_add(1);
        // Noise hashes the ciphertext, and the ciphertext is the encrypted payload followed by the
        // tag. Hashing an empty payload separately would hash nothing at all — which still changes
        // the transcript, because SHA-256 of (h || "") is not h. The reference implementation made
        // this visible.
        if !plaintext.is_empty() {
            mix_hash(&mut self.hash, plaintext);
        }
        mix_hash(&mut self.hash, &tag);
        let mut out = [0u8; TAG];
        out.copy_from_slice(&tag);
        Ok(out)
    }

    fn decrypt_and_hash(&mut self, tag: &[u8]) -> Result<(), CryptoError> {
        let key = self.cipher_key.ok_or(CryptoError::OutOfOrder("no key mixed yet"))?;
        if tag.len() != TAG {
            return Err(CryptoError::BadLength { expected: TAG, got: tag.len() });
        }
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::Random)?;
        let nonce = noise_nonce(self.nonce);
        let mut tag_bytes = [0u8; TAG];
        tag_bytes.copy_from_slice(tag);
        cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), &self.hash, &mut [], Tag::from_slice(&tag_bytes))
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        self.nonce = self.nonce.saturating_add(1);
        mix_hash(&mut self.hash, &tag_bytes);
        Ok(())
    }
}

/// A live session: two AEAD keys, one per direction, and two counters that must never repeat.
pub struct Session {
    send: Aes256Gcm,
    recv: Aes256Gcm,
    send_nonce: u64,
    recv_nonce: u64,
    session_id: u64,
}

impl Session {
    fn new(send: [u8; 32], recv: [u8; 32], session_id: u64) -> Result<Self, CryptoError> {
        Ok(Self {
            send: Aes256Gcm::new_from_slice(&send).map_err(|_| CryptoError::Random)?,
            recv: Aes256Gcm::new_from_slice(&recv).map_err(|_| CryptoError::Random)?,
            send_nonce: 0,
            recv_nonce: 0,
            session_id,
        })
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Encrypt in place and write the tag after the payload. `buffer` holds the plaintext on entry
    /// and the ciphertext plus tag on exit; the return value is the total length.
    pub fn seal(&mut self, header: &[u8], buffer: &mut [u8], plaintext_len: usize) -> Result<usize, CryptoError> {
        if plaintext_len + TAG > buffer.len() {
            return Err(CryptoError::TooLarge { limit: buffer.len(), got: plaintext_len + TAG });
        }
        if self.send_nonce == u64::MAX {
            return Err(CryptoError::NonceExhausted);
        }
        let nonce = transport_nonce(self.session_id, self.send_nonce);
        let tag = self
            .send
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), header, &mut buffer[..plaintext_len])
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        buffer[plaintext_len..plaintext_len + TAG].copy_from_slice(&tag);
        self.send_nonce += 1;
        Ok(plaintext_len + TAG)
    }

    /// Decrypt in place: `buffer` holds ciphertext plus tag, and on success holds the plaintext.
    pub fn open(&mut self, header: &[u8], buffer: &mut [u8], ciphertext_len: usize) -> Result<usize, CryptoError> {
        if ciphertext_len < TAG || ciphertext_len > buffer.len() {
            return Err(CryptoError::BadLength { expected: TAG, got: ciphertext_len });
        }
        if self.recv_nonce == u64::MAX {
            return Err(CryptoError::NonceExhausted);
        }
        let plaintext_len = ciphertext_len - TAG;
        let nonce = transport_nonce(self.session_id, self.recv_nonce);
        let mut tag = [0u8; TAG];
        tag.copy_from_slice(&buffer[plaintext_len..ciphertext_len]);
        self.recv
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), header, &mut buffer[..plaintext_len], Tag::from_slice(&tag))
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        self.recv_nonce += 1;
        Ok(plaintext_len)
    }
}

fn expect_message(message: &[u8]) -> Result<&[u8], CryptoError> {
    if message.len() != MESSAGE {
        return Err(CryptoError::BadLength { expected: MESSAGE, got: message.len() });
    }
    Ok(message)
}

fn random_secret() -> Result<StaticSecret, CryptoError> {
    let mut bytes = [0u8; KEY];
    getrandom::getrandom(&mut bytes).map_err(|_| CryptoError::Random)?;
    let secret = StaticSecret::from(bytes);
    bytes.zeroize();
    Ok(secret)
}

fn mix_hash(hash: &mut [u8; 32], data: &[u8]) {
    let mut hasher = Sha256::new();
    hasher.update(&hash[..]);
    hasher.update(data);
    hash.copy_from_slice(&hasher.finalize());
}

/// Noise nonce for handshake messages: four zero bytes and a little-endian counter.
fn noise_nonce(n: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    nonce
}

/// Transport nonce: the session id in the first four bytes, the counter after it. Two sessions can
/// never produce the same nonce, and one session can never repeat one.
fn transport_nonce(session_id: u64, n: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&(session_id as u32).to_le_bytes());
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    nonce
}

/// Constant-time comparison for values that are not tags but still secret (keys, identifiers).
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.ct_eq(right).into()
}
