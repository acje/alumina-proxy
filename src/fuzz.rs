//! The in-repo deterministic fuzz harness: one checked-in corpus plus a
//! generated-input campaign per parser target, driving the **real** parsers —
//! CONNECT request-head, `ClientHello`, DNS-wire, and log-record encoding —
//! instead of a scaffold (docs/alumina-proxy.md:388-391, alumina-sechd M3/L17).
//! Campaigns are test-augmented (`cargo test`); the harness is never called on
//! a production path, so it adds no post-boot allocation or runtime surface.

use crate::cache::Family;
use crate::client_hello::{ChInspector, Inspect};
use crate::config::Fqdn;
use crate::connect::{ConnectParser, Feed};
use crate::dns::{BailiwickZones, DNS_MSG_LIMIT, ResponseWorkspace, parse_response};

/// The fixed transaction id every DNS-wire input is anchored on: the corpus
/// message answers `(sub.example.org, A, tid 0x0ded)`.
const DNS_TID: u16 = 0x0ded;

/// A valid CONNECT request head for the allowlisted `sub.example.org:443`.
const CONNECT_CORPUS: &[&[u8]] = &[
    b"CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    b"CONNECT sub.example.org:443 HTTP/1.1\r\nHost: sub.example.org:443\r\n\r\n",
];

/// A valid TLS 1.3 `ClientHello` to `sub.example.org`: one 0x0301 record wrapping
/// a 0x0303 client-version hello offering 0x1301/0x1302 with a single SNI and a
/// supported-versions extension. Wire-format layout, byte by byte:
///
/// - `0x16 0x03 0x01 0x00 0x50` — record header, payload 80
/// - `0x01 0x00 0x00 0x4c` — handshake `ClientHello`, body 76
/// - `0x03 0x03` — client version TLS 1.2 wire value
/// - 32 bytes of `0x00` — random 32 bytes
/// - `0x00` — session id length
/// - `0x00 0x04 0x13 0x01 0x13 0x02` — cipher suites `TLS_AES_128/256_GCM`
/// - `0x01 0x00` — compression methods: 1 byte, null
/// - `0x00 0x1f` — extensions length 31
/// - `0x00 0x2b 0x00 0x03 0x02 0x03 0x04` — `supported_versions`: TLS 1.3
/// - `0x00 0x00 0x00 0x14` — `server_name` extension, data length 20
/// - `0x00 0x12 0x00 0x00 0x0f "sub.example.org"` — one `host_name` entry,
///   "sub.example.org"
const CLIENT_HELLO_CORPUS: &[&[u8]] = &[&[
    0x16, 0x03, 0x01, 0x00, 0x50, 0x01, 0x00, 0x00, 0x4c, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x13, 0x01,
    0x13, 0x02, 0x01, 0x00, 0x00, 0x1f, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00,
    0x14, 0x00, 0x12, 0x00, 0x00, 0x0f, b's', b'u', b'b', b'.', b'e', b'x', b'a', b'm', b'p', b'l',
    b'e', b'.', b'o', b'r', b'g',
]];

/// A valid DNS A-record response for `sub.example.org` answering the query
/// `(sub.example.org, A, tid 0x0ded)`: header (qr=1, rcode=0, qd=1, an=1), the
/// question, and one A record (93.184.216.34, ttl 120). Wire-format layout,
/// byte by byte:
///
/// - `0x0d 0xed` — tid 0x0ded
/// - `0x81 0x80` — qr=1, opcode=0, rcode=0
/// - `0x00 0x01` — qdcount 1
/// - `0x00 0x01` — ancount 1
/// - `0x00 0x00` — nscount 0
/// - `0x00 0x00` — arcount 0
/// - `0x03 "sub" 0x07 "example" 0x03 "org" 0x00` — question name
///   "sub.example.org"
/// - `0x00 0x01` — qtype A
/// - `0x00 0x01` — qclass IN
/// - `0xc0 0x0c` — answer name pointer -> question name at offset 12
/// - `0x00 0x01` — type A
/// - `0x00 0x01` — class IN
/// - `0x00 0x00 0x00 0x78` — ttl 120
/// - `0x00 0x04` — rdlength 4
/// - `0x5d 0xb8 0xd8 0x22` — 93.184.216.34
const DNS_CORPUS: &[&[u8]] = &[&[
    0x0d, 0xed, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, b's', b'u', b'b',
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'o', b'r', b'g', 0x00, 0x00, 0x01, 0x00,
    0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0x5d, 0xb8, 0xd8,
    0x22,
]];

/// Valid UTF-8 texts exercised through the fixed-slot log-record encoder's
/// escape path, including quote/backslash content and an empty value.
const LOG_CORPUS: &[&[u8]] = &[
    b"plain startup message",
    b"nested \"quotes\" and \\backslash",
    b"",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParserTarget {
    ConnectHeaders,
    ClientHello,
    DnsWire,
    LogRecord,
}

impl ParserTarget {
    pub const ALL: [ParserTarget; 4] = [
        ParserTarget::ConnectHeaders,
        ParserTarget::ClientHello,
        ParserTarget::DnsWire,
        ParserTarget::LogRecord,
    ];

    #[must_use]
    pub const fn owning_slice(self) -> u8 {
        match self {
            ParserTarget::ConnectHeaders => 3,
            ParserTarget::ClientHello => 4,
            ParserTarget::DnsWire => 2,
            ParserTarget::LogRecord => 6,
        }
    }

    /// Whether the target drives a real parser under the campaign rather than
    /// a scaffold. All four targets are wired to their real parser, so every
    /// target reports `driven` (alumina-sechd M3).
    #[must_use]
    pub const fn status(self) -> &'static str {
        "driven"
    }
}

/// The checked-in corpus inputs for a target: representative inputs that
/// complete the real parser, so every campaign reaches at least one deep parse
/// independent of the generated space (docs/alumina-proxy.md:388-391).
#[must_use]
pub const fn corpus(target: ParserTarget) -> &'static [&'static [u8]] {
    match target {
        ParserTarget::ConnectHeaders => CONNECT_CORPUS,
        ParserTarget::ClientHello => CLIENT_HELLO_CORPUS,
        ParserTarget::DnsWire => DNS_CORPUS,
        ParserTarget::LogRecord => LOG_CORPUS,
    }
}

/// The outcome of driving one input through a parser target: how the real
/// parser classified the input, plus `Panicked` for a campaign-crash signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriveOutcome {
    /// The input advanced the parser to a complete/valid verdict.
    Complete,
    /// The parser returned a refusal/error for the input.
    Rejected,
    /// An incremental parser accepted the bytes but needs more to conclude.
    NeedMore,
    /// The parser unwound while fed this input (campaign crash).
    Panicked,
}

/// The fixed query context the DNS-wire target anchors on: the allowlist entry
/// whose query the corpus message answers. Reconstructed per drive (test-only
/// allocation); the parse path itself remains allocation-free.
#[expect(
    clippy::expect_used,
    reason = "the fixed corpus FQDN literal is valid by construction"
)]
fn dns_context() -> Fqdn {
    Fqdn::parse("sub.example.org:443").expect("static dns corpus fqdn parses")
}

/// Drives one input through the target's real parser, without a panic guard.
/// The DNS target copies the input into a fixed buffer with the expected
/// transaction id forced at bytes 0..=1 — the parser reads it at the fixed
/// header offset, and without that the generated space would never pass the
/// tid check to reach record parsing. `LogRecord` drives the fixed-slot
/// encoder over the input as attacker-controlled text.
#[expect(
    clippy::expect_used,
    reason = "the DNS transaction-id low byte is masked to 0xff, always fitting u8"
)]
fn drive(target: ParserTarget, input: &[u8]) -> DriveOutcome {
    match target {
        ParserTarget::ConnectHeaders => {
            let mut parser = ConnectParser::new();
            match parser.feed(input) {
                Ok(Feed::Complete { .. }) => DriveOutcome::Complete,
                Ok(Feed::Incomplete) => DriveOutcome::NeedMore,
                Err(_) => DriveOutcome::Rejected,
            }
        }
        ParserTarget::ClientHello => {
            let mut inspector = ChInspector::new();
            match inspector.feed(input) {
                Ok(Inspect::Complete { .. }) => DriveOutcome::Complete,
                Ok(Inspect::NeedMore) => DriveOutcome::NeedMore,
                Err(_) => DriveOutcome::Rejected,
            }
        }
        ParserTarget::DnsWire => {
            let mut ws = ResponseWorkspace::default();
            let take = input.len().min(DNS_MSG_LIMIT);
            let mut wire = [0u8; DNS_MSG_LIMIT];
            wire[..take].copy_from_slice(&input[..take]);
            wire[0] = (DNS_TID >> 8) as u8;
            wire[1] = u8::try_from(DNS_TID & 0xff).expect("dns tid low byte");
            let fq = dns_context();
            match parse_response(
                &mut ws,
                &BailiwickZones::single(&fq),
                &fq,
                Family::A,
                DNS_TID,
                &wire[..take],
            ) {
                Ok(_) => DriveOutcome::Complete,
                Err(_) => DriveOutcome::Rejected,
            }
        }
        ParserTarget::LogRecord => {
            let text = std::str::from_utf8(input).unwrap_or("\u{FFFD}");
            match crate::log::fuzz_encode_text(text) {
                Some(_) => DriveOutcome::Complete,
                None => DriveOutcome::Rejected,
            }
        }
    }
}

/// Runs [`drive`] under a panic guard so a campaign can record a crashing
/// input's hash for exact reproduction (docs/alumina-proxy.md:388-391). A
/// `Panicked` verdict is the campaign's crash signal; the parsers must never
/// panic over the sampled space.
#[must_use]
pub fn drive_unwind(target: ParserTarget, input: &[u8]) -> DriveOutcome {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drive(target, input)))
        .unwrap_or(DriveOutcome::Panicked)
}

/// The result of one deterministic fuzz campaign over a target: the generated
/// and corpus input counts by verdict, the hash of the last generated input,
/// and whether any input panicked its parser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzRun {
    target: ParserTarget,
    corpus_driven: u64,
    corpus_complete: u64,
    corpus_rejected: u64,
    generated_inputs: u64,
    generated_complete: u64,
    generated_rejected: u64,
    generated_need_more: u64,
    last_input_hash: Option<InputHash>,
    panicked: bool,
}

impl FuzzRun {
    const fn new(target: ParserTarget) -> Self {
        FuzzRun {
            target,
            corpus_driven: 0,
            corpus_complete: 0,
            corpus_rejected: 0,
            generated_inputs: 0,
            generated_complete: 0,
            generated_rejected: 0,
            generated_need_more: 0,
            last_input_hash: None,
            panicked: false,
        }
    }

    /// Folds one input verdict into the campaign counters. `generated` selects
    /// the corpus or generated bucket; `hash` updates the last-input hash when
    /// the input was generated.
    const fn fold(&mut self, generated: bool, outcome: DriveOutcome, hash: Option<InputHash>) {
        if generated {
            self.generated_inputs += 1;
            if let Some(hash) = hash {
                self.last_input_hash = Some(hash);
            }
        } else {
            self.corpus_driven += 1;
        }
        match outcome {
            DriveOutcome::Complete => {
                if generated {
                    self.generated_complete += 1;
                } else {
                    self.corpus_complete += 1;
                }
            }
            DriveOutcome::Rejected => {
                if generated {
                    self.generated_rejected += 1;
                } else {
                    self.corpus_rejected += 1;
                }
            }
            DriveOutcome::NeedMore => {
                if generated {
                    self.generated_need_more += 1;
                }
            }
            DriveOutcome::Panicked => self.panicked = true,
        }
    }

    #[must_use]
    pub const fn target(&self) -> ParserTarget {
        self.target
    }

    /// The number of checked-in corpus inputs driven in this campaign.
    #[must_use]
    pub const fn corpus_driven(&self) -> u64 {
        self.corpus_driven
    }

    /// The number of checked-in corpus inputs that completed the real parser.
    #[must_use]
    pub const fn corpus_complete(&self) -> u64 {
        self.corpus_complete
    }

    /// The number of generated inputs driven in this campaign.
    #[must_use]
    pub const fn generated_inputs(&self) -> u64 {
        self.generated_inputs
    }

    #[must_use]
    pub const fn generated_complete(&self) -> u64 {
        self.generated_complete
    }

    #[must_use]
    pub const fn generated_rejected(&self) -> u64 {
        self.generated_rejected
    }

    #[must_use]
    pub const fn generated_need_more(&self) -> u64 {
        self.generated_need_more
    }

    /// The hash of the last generated input, for exact crash reproduction.
    #[must_use]
    pub const fn last_input_hash(&self) -> Option<InputHash> {
        self.last_input_hash
    }

    /// Whether any driven input panicked its parser (campaign crash).
    #[must_use]
    pub const fn panicked(&self) -> bool {
        self.panicked
    }
}

/// Runs one deterministic fuzz campaign over `target`: every checked-in corpus
/// input first, then `iterations` generated inputs of length `1..=max_len`
/// derived from `seed`, driven through the real parsers under a panic guard
/// (docs/alumina-proxy.md:388-391). A panic aborts the campaign with the
/// offending input's hash recorded so the input reproduces exactly. Never
/// called on a production path; campaigns execute under `cargo test`.
///
/// # Panics
///
/// Panics on the fixed `expect` only if a bounded fuzz length does not fit
/// `usize`, which cannot happen on supported platforms.
#[must_use]
#[expect(
    clippy::expect_used,
    reason = "fuzz length is reduced modulo the usize max_len bound, so it always fits usize"
)]
pub fn fuzz_target(target: ParserTarget, seed: Seed, iterations: u64, max_len: usize) -> FuzzRun {
    let mut rng = DeterministicGen::new(seed);
    let bound = max_len.max(1);
    let mut run = FuzzRun::new(target);
    for input in corpus(target) {
        run.fold(false, drive_unwind(target, input), None);
    }
    for _ in 0..iterations {
        let len = 1 + usize::try_from(rng.next_u64() % (bound as u64))
            .expect("bounded fuzz length fits usize");
        let input = rng.bytes(len);
        let hash = fnv1a64(input.iter().copied());
        run.fold(true, drive_unwind(target, &input), Some(hash));
        if run.panicked() {
            break;
        }
    }
    run
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seed([u8; 32]);

impl Seed {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Seed(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InputHash(u64);

impl InputHash {
    /// Lossless 64-bit FNV hex rendering (16 hex chars), for corpus and
    /// crash-input hashes that reproduce exactly across hosts.
    #[must_use]
    pub fn hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(16);
        for byte in self.0.to_le_bytes() {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}

fn fnv1a64_raw(data: impl Iterator<Item = u8>) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// The honest 64-bit FNV-1a input hash over a byte sequence.
pub fn fnv1a64(data: impl Iterator<Item = u8>) -> InputHash {
    InputHash(fnv1a64_raw(data))
}

/// A deterministic byte generator (splitmix64) that reproduces the same input
/// stream for the same seed, so a failing campaign regenerates its crashing
/// input exactly.
pub struct DeterministicGen {
    seed: Seed,
    state: u64,
}

impl DeterministicGen {
    #[must_use]
    pub fn new(seed: Seed) -> Self {
        let state = fnv1a64_raw(seed.as_bytes().iter().copied());
        DeterministicGen { seed, state }
    }

    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    #[must_use]
    pub const fn seed(&self) -> &Seed {
        &self.seed
    }

    /// The next `len` deterministic bytes derived from this generator's stream.
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64().to_be_bytes()[4]).collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterError {
    DuplicateTarget(ParserTarget),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpusRecord {
    target: ParserTarget,
    seed: Seed,
    corpus_checked_in: bool,
    generated_inputs: u64,
    last_input_hash: Option<InputHash>,
}

/// The campaign bookkeeping for a target: its corpus check-in flag, the
/// generated-input count the campaign folded in, and the last-input hash for
/// exact reproduction.
pub struct CorpusOwnership {
    records: Vec<CorpusRecord>,
}

impl CorpusOwnership {
    #[must_use]
    pub const fn new() -> Self {
        CorpusOwnership {
            records: Vec::new(),
        }
    }

    /// Registers `target` under `seed`, recording it in the ownership set.
    ///
    /// # Errors
    ///
    /// Returns `DuplicateTarget` when `target` is already registered.
    pub fn register(
        &mut self,
        target: ParserTarget,
        seed: Seed,
    ) -> Result<&mut CorpusRecord, RegisterError> {
        if self.records.iter().any(|record| record.target == target) {
            return Err(RegisterError::DuplicateTarget(target));
        }
        self.records.push(CorpusRecord {
            target,
            seed,
            corpus_checked_in: false,
            generated_inputs: 0,
            last_input_hash: None,
        });
        let index = self.records.len() - 1;
        Ok(&mut self.records[index])
    }

    #[must_use]
    pub fn records(&self) -> &[CorpusRecord] {
        &self.records
    }

    #[must_use]
    pub fn find(&self, target: ParserTarget) -> Option<&CorpusRecord> {
        self.records.iter().find(|record| record.target == target)
    }

    pub fn record_mut(&mut self, target: ParserTarget) -> Option<&mut CorpusRecord> {
        self.records
            .iter_mut()
            .find(|record| record.target == target)
    }

    #[must_use]
    pub fn contains(&self, target: ParserTarget) -> bool {
        self.records.iter().any(|record| record.target == target)
    }
}

impl Default for CorpusOwnership {
    fn default() -> Self {
        CorpusOwnership::new()
    }
}

impl CorpusRecord {
    #[must_use]
    pub const fn target(&self) -> ParserTarget {
        self.target
    }

    #[must_use]
    pub const fn seed(&self) -> &Seed {
        &self.seed
    }

    pub const fn set_corpus_checked_in(&mut self, value: bool) {
        self.corpus_checked_in = value;
    }

    #[must_use]
    pub const fn corpus_is_checked_in(&self) -> bool {
        self.corpus_checked_in
    }

    pub const fn add_generated(&mut self, inputs: u64) {
        self.generated_inputs = self.generated_inputs.saturating_add(inputs);
    }

    #[must_use]
    pub const fn generated_inputs(&self) -> u64 {
        self.generated_inputs
    }

    pub const fn set_last_input_hash(&mut self, hash: InputHash) {
        self.last_input_hash = Some(hash);
    }

    #[must_use]
    pub const fn last_input_hash(&self) -> Option<&InputHash> {
        self.last_input_hash.as_ref()
    }
}
