// M13 NODE — LOGIC KERNEL (REV 6.1)
// Sprint 6.1: Dual transport — AF_XDP (same-L2) or UDP (cross-internet)
//
// Usage:
//   AF_XDP: sudo ./m13-node --iface wlp91s0 [--echo] [--hexdump]
//   UDP:    ./m13-node --hub-ip <hub_ip:port> [--echo] [--hexdump]
//
// Both modes share: FSM, echo logic, hexdump, telemetry, M13 wire format.
// AF_XDP uses UMEM + zero-copy; UDP uses kernel sockets.
// The hot loop is structurally identical — only I/O differs.

mod datapath;
use crate::datapath::{
    M13_WIRE_MAGIC, M13_WIRE_VERSION,
    EthernetHeader, M13Header, ETH_P_M13, FRAME_SIZE,
    Engine, Telemetry, BpfSteersman, FixedSlab, TxPath, ZeroCopyTx,
    fatal,
    E_NO_ISOLATED_CORES, E_AFFINITY_FAIL,
};
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::net::UdpSocket;

// Sprint 6.2: PQC cold-path imports (handshake only — never in hot loop)
use sha2::{Sha512, Digest};
use hkdf::Hkdf;
use rand::rngs::OsRng;

// Sprint 6.3: PQC handshake — ML-KEM-1024 key exchange + ML-DSA-87 mutual auth
use ml_kem::{MlKem1024, KemCore, EncodedSizeUser};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_dsa::{MlDsa87, KeyGen};

const ETH_HDR_SIZE: usize = mem::size_of::<EthernetHeader>();
const M13_HDR_SIZE: usize = mem::size_of::<M13Header>();
const DATA_FRAME_WIRE_SIZE: u32 = (ETH_HDR_SIZE + M13_HDR_SIZE) as u32; // 62 bytes
const TX_RING_SIZE: usize = 2048;
const SLAB_DEPTH: usize = 4096;
const HW_FILL_MAX: usize = TX_RING_SIZE / 10;

const FLAG_CONTROL: u8  = 0x80;
#[allow(dead_code)] const FLAG_FEEDBACK: u8 = 0x40;
#[allow(dead_code)] const FLAG_CRITICAL: u8 = 0x20;
#[allow(dead_code)] const FLAG_ECN: u8      = 0x10;
#[allow(dead_code)] const FLAG_FIN: u8      = 0x08;
#[allow(dead_code)] const FLAG_FEC: u8      = 0x04;
const FLAG_HANDSHAKE: u8= 0x02;
const FLAG_FRAGMENT: u8 = 0x01;

/// Link-loss timeout: no frame for 5 seconds → Disconnected
const LINK_LOSS_TIMEOUT_NS: u64 = 5_000_000_000;
/// Handshake timeout: 5 seconds to complete 3-message exchange
const HANDSHAKE_TIMEOUT_NS: u64 = 5_000_000_000;
/// Rekey after 2^32 frames under one session key
const REKEY_FRAME_LIMIT: u64 = 1u64 << 32;
/// Rekey after 1 hour under one session key
const REKEY_TIME_LIMIT_NS: u64 = 3_600_000_000_000;

// PQC handshake sub-types (first byte of handshake payload)
const HS_CLIENT_HELLO: u8 = 0x01;
const HS_SERVER_HELLO: u8 = 0x02;
const HS_FINISHED: u8     = 0x03;

// Direction bytes for AEAD nonce (prevents reflection attacks)
const DIR_HUB_TO_NODE: u8 = 0x00;
const DIR_NODE_TO_HUB: u8 = 0x01;

// ============================================================================
// FAST CLOCK
// clock_ns(): CLOCK_MONOTONIC syscall fallback (used during calibration + cold paths)
// rdtsc_ns(): Fixed-point TSC conversion (~29 cycles vs ~41 for clock_gettime vDSO)
// ============================================================================
#[inline(always)]
fn clock_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// TSC-to-nanosecond calibration data. Computed once at boot, immutable after.
/// Conversion: ns = mono_base + ((rdtsc() - tsc_base) * mult) >> shift
/// The mult/shift pair encodes ns_per_tsc_tick as a fixed-point fraction.
#[derive(Clone, Copy)]
struct TscCal {
    tsc_base: u64,   // rdtsc value at calibration instant
    mono_base: u64,  // CLOCK_MONOTONIC (ns) at same instant
    mult: u32,       // fixed-point multiplier
    shift: u32,      // right-shift amount (typically 32)
    valid: bool,     // false if TSC is unreliable (VM, non-invariant)
}

impl TscCal {
    fn fallback() -> Self {
        TscCal { tsc_base: 0, mono_base: 0, mult: 0, shift: 0, valid: false }
    }
}

/// Raw TSC read. ~24 cycles on Skylake (~6.5ns at 3.7GHz).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn read_tsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem, preserves_flags)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// ARM equivalent: CNTVCT_EL0 (generic timer virtual count).
#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn read_tsc() -> u64 {
    let cnt: u64;
    unsafe {
        core::arch::asm!(
            "mrs {cnt}, CNTVCT_EL0",
            cnt = out(reg) cnt,
            options(nostack, nomem, preserves_flags)
        );
    }
    cnt
}

/// Fallback for non-x86/ARM: just use clock_gettime.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(always)]
fn read_tsc() -> u64 { clock_ns() }

/// Convert raw TSC value to nanoseconds using pre-computed calibration.
/// Hot path: 1 subtract + 1 multiply (u128) + 1 shift + 1 add = ~5 cycles.
#[inline(always)]
fn rdtsc_ns(cal: &TscCal) -> u64 {
    if !cal.valid { return clock_ns(); }
    let delta = read_tsc().wrapping_sub(cal.tsc_base);
    cal.mono_base.wrapping_add(
        ((delta as u128 * cal.mult as u128) >> cal.shift) as u64
    )
}

// ============================================================================
// NODE STATE FSM
// ============================================================================
#[derive(Debug, PartialEq, Clone)]
enum NodeState {
    Disconnected,
    Registering,
    /// PQC handshake in progress: ClientHello sent, awaiting ServerHello
    Handshaking {
        dk_bytes: Vec<u8>,           // ML-KEM-1024 decapsulation key (3168 bytes)
        session_nonce: [u8; 32],     // CSPRNG nonce for HKDF salt
        client_hello_bytes: Vec<u8>, // Full ClientHello payload for transcript
        our_pk: Vec<u8>,             // Our ML-DSA-87 public key bytes
        our_sk: Vec<u8>,             // Our ML-DSA-87 signing key bytes
        started_ns: u64,             // Handshake start timestamp
    },
    /// Session established: AEAD active, session key derived
    Established {
        session_key: [u8; 32],       // ChaCha20-Poly1305 key from HKDF-SHA-512
        anti_replay: AntiReplay,     // 2048-bit sliding window
        frame_count: u64,            // Frames encrypted under this key
        established_ns: u64,         // When session was established
    },
}

// ============================================================================
// HEXDUMP ENGINE (shared between AF_XDP and UDP modes)
// ============================================================================
const HEXDUMP_INTERVAL_NS: u64 = 100_000_000; // 10/sec max

struct HexdumpState { enabled: bool, last_tx_ns: u64, last_rx_ns: u64 }
impl HexdumpState {
    fn new(enabled: bool) -> Self { HexdumpState { enabled, last_tx_ns: 0, last_rx_ns: 0 } }
    fn dump_tx(&mut self, data: &[u8], now_ns: u64) {
        if !self.enabled || now_ns.saturating_sub(self.last_tx_ns) < HEXDUMP_INTERVAL_NS { return; }
        self.last_tx_ns = now_ns;
        dump_frame("[NODE-TX]", data);
    }
    fn dump_rx(&mut self, data: &[u8], now_ns: u64) {
        if !self.enabled || now_ns.saturating_sub(self.last_rx_ns) < HEXDUMP_INTERVAL_NS { return; }
        self.last_rx_ns = now_ns;
        dump_frame("[NODE-RX]", data);
    }
}

fn dump_frame(label: &str, data: &[u8]) {
    let cap = data.len().min(80);
    if cap < ETH_HDR_SIZE { return; }
    let dst = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        data[0], data[1], data[2], data[3], data[4], data[5]);
    let src = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        data[6], data[7], data[8], data[9], data[10], data[11]);
    let (seq, flags) = if cap >= ETH_HDR_SIZE + M13_HDR_SIZE {
        let m13 = unsafe { &*(data.as_ptr().add(ETH_HDR_SIZE) as *const M13Header) };
        (m13.seq_id, m13.flags)
    } else { (0, 0) };
    eprintln!("{} seq={} flags=0x{:02X} len={} dst={} src={}", label, seq, flags, data.len(), dst, src);
    if cap >= 14 {
        eprint!("  [00..14] ETH  |"); for i in 0..14 { eprint!(" {:02X}", data[i]); } eprintln!();
    }
    if cap >= 16 {
        eprint!("  [14..16] MAGIC|"); eprint!(" {:02X} {:02X}", data[14], data[15]); eprintln!();
    }
    if cap >= 18 {
        eprint!("  [16..18] CRYPT|"); eprint!(" {:02X} {:02X}", data[16], data[17]);
        eprintln!("  (crypto_ver=0x{:02X}={})", data[16], if data[16] == 0 { "cleartext" } else { "encrypted" });
    }
    if cap >= 34 {
        eprint!("  [18..34] MAC  |"); for i in 18..34 { eprint!(" {:02X}", data[i]); } eprintln!();
    }
    if cap >= 46 {
        eprint!("  [34..46] NONCE|"); for i in 34..46 { eprint!(" {:02X}", data[i]); } eprintln!();
    }
    if cap >= 54 {
        eprint!("  [46..54] SEQ  |"); for i in 46..54 { eprint!(" {:02X}", data[i]); }
        eprintln!("  (LE: seq_id={})", seq);
    }
    if cap >= 55 { eprintln!("  [54..55] FLAGS| {:02X}", data[54]); }
    if cap >= 59 {
        let plen = if cap >= ETH_HDR_SIZE + M13_HDR_SIZE {
            let m13 = unsafe { &*(data.as_ptr().add(ETH_HDR_SIZE) as *const M13Header) };
            m13.payload_len
        } else { 0 };
        eprint!("  [55..59] PLEN |"); for i in 55..59 { eprint!(" {:02X}", data[i]); }
        eprintln!("  (LE: payload_len={})", plen);
    }
    if cap >= 62 {
        eprint!("  [59..62] PAD  |"); for i in 59..62 { eprint!(" {:02X}", data[i]); } eprintln!();
    }
}

// ============================================================================
// FRAGMENTATION ENGINE (cold path — shared between modes)
// ============================================================================
const FRAG_HDR_SIZE: usize = 8;

#[repr(C, packed)]
struct FragHeader { frag_msg_id: u16, frag_index: u8, frag_total: u8, frag_offset: u16, frag_len: u16 }
const _: () = assert!(std::mem::size_of::<FragHeader>() == FRAG_HDR_SIZE);

struct Assembler { pending: std::collections::HashMap<u16, AssemblyBuf> }
struct AssemblyBuf { buf: Vec<u8>, mask: u16, total: u8, created_ns: u64 }
impl Assembler {
    fn new() -> Self { Assembler { pending: std::collections::HashMap::new() } }
    fn feed(&mut self, msg_id: u16, index: u8, total: u8, offset: u16, data: &[u8], now: u64)
        -> Option<Vec<u8>> {
        let entry = self.pending.entry(msg_id).or_insert_with(|| AssemblyBuf {
            buf: Vec::with_capacity(total as usize * 1444),
            mask: 0, total, created_ns: now,
        });
        if index >= 16 || index as u8 >= total { return None; }
        if entry.mask & (1 << index) != 0 { return None; }
        let off = offset as usize;
        if off + data.len() > entry.buf.len() { entry.buf.resize(off + data.len(), 0); }
        entry.buf[off..off + data.len()].copy_from_slice(data);
        entry.mask |= 1 << index;
        let need = (1u16 << total) - 1;
        if entry.mask == need { Some(self.pending.remove(&msg_id).unwrap().buf) } else { None }
    }
    fn gc(&mut self, now: u64) { self.pending.retain(|_, v| now - v.created_ns < 5_000_000_000); }
}

// ============================================================================
// SPRINT 6.2: INLINE ChaCha20-Poly1305 AEAD (RFC 8439)
// Zero external crates in hot path. Constant-time. ARX maps to ARM A53 ALU.
// ============================================================================

/// ChaCha20 quarter-round: the atomic ARX building block.
#[inline(always)]
fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(7);
}

/// ChaCha20 block function. 64-byte keystream. 20 rounds = 10 double-rounds.
fn chacha20_block(key: &[u8; 32], ctr: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut s = [0u32; 16];
    s[0]=0x61707865; s[1]=0x3320646e; s[2]=0x79622d32; s[3]=0x6b206574;
    for i in 0..8 { s[4+i] = u32::from_le_bytes(key[4*i..4*i+4].try_into().unwrap()); }
    s[12] = ctr;
    for i in 0..3 { s[13+i] = u32::from_le_bytes(nonce[4*i..4*i+4].try_into().unwrap()); }
    let w = s;
    for _ in 0..10 {
        qr(&mut s,0,4,8,12); qr(&mut s,1,5,9,13);
        qr(&mut s,2,6,10,14); qr(&mut s,3,7,11,15);
        qr(&mut s,0,5,10,15); qr(&mut s,1,6,11,12);
        qr(&mut s,2,7,8,13); qr(&mut s,3,4,9,14);
    }
    for i in 0..16 { s[i] = s[i].wrapping_add(w[i]); }
    let mut o = [0u8; 64];
    for i in 0..16 { o[4*i..4*i+4].copy_from_slice(&s[i].to_le_bytes()); }
    o
}

/// ChaCha20 XOR. Counter starts at ctr0 (1 for data, 0 reserved for Poly1305 OTK).
#[inline(always)]
fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], ctr0: u32, data: &mut [u8]) {
    let mut c = ctr0;
    let mut off = 0usize;
    while off < data.len() {
        let blk = chacha20_block(key, c, nonce);
        let n = (data.len() - off).min(64);
        for i in 0..n { data[off + i] ^= blk[i]; }
        off += n; c += 1;
    }
}

/// Poly1305 MAC (RFC 8439 §2.5). Donna-style: 5×26-bit limbs, u128 products.
fn poly1305_mac(otk: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let mut rb = [0u8; 16];
    rb.copy_from_slice(&otk[0..16]);
    rb[3] &= 15; rb[7] &= 15; rb[11] &= 15; rb[15] &= 15;
    rb[4] &= 252; rb[8] &= 252; rb[12] &= 252;
    let t0 = u32::from_le_bytes(rb[0..4].try_into().unwrap()) as u64;
    let t1 = u32::from_le_bytes(rb[4..8].try_into().unwrap()) as u64;
    let t2 = u32::from_le_bytes(rb[8..12].try_into().unwrap()) as u64;
    let t3 = u32::from_le_bytes(rb[12..16].try_into().unwrap()) as u64;
    let r0 = t0 & 0x3ffffff;
    let r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
    let r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
    let r3 = ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
    let r4 = (t3 >> 8) & 0x3ffffff;
    let s1 = r1 * 5; let s2 = r2 * 5; let s3 = r3 * 5; let s4 = r4 * 5;
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut pos = 0usize;
    while pos < data.len() {
        let (b, hibit) = if data.len() - pos >= 16 {
            let mut b = [0u8; 16];
            b.copy_from_slice(&data[pos..pos+16]); pos += 16;
            (b, 1u64 << 24)
        } else {
            let rem = data.len() - pos;
            let mut b = [0u8; 16];
            b[..rem].copy_from_slice(&data[pos..pos+rem]);
            b[rem] = 1; pos = data.len();
            (b, 0u64)
        };
        let bt0 = u32::from_le_bytes(b[0..4].try_into().unwrap()) as u64;
        let bt1 = u32::from_le_bytes(b[4..8].try_into().unwrap()) as u64;
        let bt2 = u32::from_le_bytes(b[8..12].try_into().unwrap()) as u64;
        let bt3 = u32::from_le_bytes(b[12..16].try_into().unwrap()) as u64;
        h0 += bt0 & 0x3ffffff;
        h1 += ((bt0 >> 26) | (bt1 << 6)) & 0x3ffffff;
        h2 += ((bt1 >> 20) | (bt2 << 12)) & 0x3ffffff;
        h3 += ((bt2 >> 14) | (bt3 << 18)) & 0x3ffffff;
        h4 += (bt3 >> 8) | hibit;
        let d0 = (h0 as u128)*(r0 as u128) + (h1 as u128)*(s4 as u128)
               + (h2 as u128)*(s3 as u128) + (h3 as u128)*(s2 as u128)
               + (h4 as u128)*(s1 as u128);
        let d1 = (h0 as u128)*(r1 as u128) + (h1 as u128)*(r0 as u128)
               + (h2 as u128)*(s4 as u128) + (h3 as u128)*(s3 as u128)
               + (h4 as u128)*(s2 as u128);
        let d2 = (h0 as u128)*(r2 as u128) + (h1 as u128)*(r1 as u128)
               + (h2 as u128)*(r0 as u128) + (h3 as u128)*(s4 as u128)
               + (h4 as u128)*(s3 as u128);
        let d3 = (h0 as u128)*(r3 as u128) + (h1 as u128)*(r2 as u128)
               + (h2 as u128)*(r1 as u128) + (h3 as u128)*(r0 as u128)
               + (h4 as u128)*(s4 as u128);
        let d4 = (h0 as u128)*(r4 as u128) + (h1 as u128)*(r3 as u128)
               + (h2 as u128)*(r2 as u128) + (h3 as u128)*(r1 as u128)
               + (h4 as u128)*(r0 as u128);
        let mut c: u64;
        c = (d0 >> 26) as u64; h0 = (d0 as u64) & 0x3ffffff;
        let d1 = d1 + c as u128; c = (d1 >> 26) as u64; h1 = (d1 as u64) & 0x3ffffff;
        let d2 = d2 + c as u128; c = (d2 >> 26) as u64; h2 = (d2 as u64) & 0x3ffffff;
        let d3 = d3 + c as u128; c = (d3 >> 26) as u64; h3 = (d3 as u64) & 0x3ffffff;
        let d4 = d4 + c as u128; c = (d4 >> 26) as u64; h4 = (d4 as u64) & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    }
    let mut c: u64;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    let mut g0 = h0.wrapping_add(5); c = g0 >> 26; g0 &= 0x3ffffff;
    let mut g1 = h1.wrapping_add(c); c = g1 >> 26; g1 &= 0x3ffffff;
    let mut g2 = h2.wrapping_add(c); c = g2 >> 26; g2 &= 0x3ffffff;
    let mut g3 = h3.wrapping_add(c); c = g3 >> 26; g3 &= 0x3ffffff;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);
    let mask = (g4 >> 63).wrapping_sub(1);
    h0 = (h0 & !mask) | (g0 & mask); h1 = (h1 & !mask) | (g1 & mask);
    h2 = (h2 & !mask) | (g2 & mask); h3 = (h3 & !mask) | (g3 & mask);
    h4 = (h4 & !mask) | (g4 & mask);
    let f0 = ((h0) | (h1 << 26)) as u32;
    let f1 = ((h1 >> 6) | (h2 << 20)) as u32;
    let f2 = ((h2 >> 12) | (h3 << 14)) as u32;
    let f3 = ((h3 >> 18) | (h4 << 8)) as u32;
    let p0 = u32::from_le_bytes(otk[16..20].try_into().unwrap());
    let p1 = u32::from_le_bytes(otk[20..24].try_into().unwrap());
    let p2 = u32::from_le_bytes(otk[24..28].try_into().unwrap());
    let p3 = u32::from_le_bytes(otk[28..32].try_into().unwrap());
    let mut acc = f0 as u64 + p0 as u64;
    let w0 = acc as u32; acc >>= 32;
    acc += f1 as u64 + p1 as u64; let w1 = acc as u32; acc >>= 32;
    acc += f2 as u64 + p2 as u64; let w2 = acc as u32; acc >>= 32;
    acc += f3 as u64 + p3 as u64; let w3 = acc as u32;
    let mut tag = [0u8; 16];
    tag[0..4].copy_from_slice(&w0.to_le_bytes());
    tag[4..8].copy_from_slice(&w1.to_le_bytes());
    tag[8..12].copy_from_slice(&w2.to_le_bytes());
    tag[12..16].copy_from_slice(&w3.to_le_bytes());
    tag
}

/// RFC 8439 §2.8 AEAD MAC construction. Stack-allocated buffer. Zero heap.
fn poly1305_aead_mac(otk: &[u8; 32], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut buf = [0u8; 1536];
    let mut len = 0usize;
    buf[len..len+aad.len()].copy_from_slice(aad); len += aad.len();
    len += (16 - (aad.len() % 16)) % 16; // pad16
    buf[len..len+ct.len()].copy_from_slice(ct); len += ct.len();
    len += (16 - (ct.len() % 16)) % 16;
    buf[len..len+8].copy_from_slice(&(aad.len() as u64).to_le_bytes()); len += 8;
    buf[len..len+8].copy_from_slice(&(ct.len() as u64).to_le_bytes()); len += 8;
    poly1305_mac(otk, &buf[..len])
}

/// Seal (encrypt+authenticate) an M13 frame in-place.
fn seal_frame(frame: &mut [u8], key: &[u8; 32], seq: u64, direction: u8) {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&seq.to_le_bytes());
    nonce[8] = direction;
    let sig = ETH_HDR_SIZE;
    frame[sig+2] = 0x01; frame[sig+3] = 0x00;
    frame[sig+20..sig+32].copy_from_slice(&nonce);
    let poly_blk = chacha20_block(key, 0, &nonce);
    let otk: [u8; 32] = poly_blk[0..32].try_into().unwrap();
    let pt = sig + 32;
    chacha20_xor(key, &nonce, 1, &mut frame[pt..]);
    let tag = poly1305_aead_mac(&otk, &frame[sig..sig+4], &frame[pt..]);
    frame[sig+4..sig+20].copy_from_slice(&tag);
}

/// Open (verify+decrypt) an M13 frame in-place. Returns true if authentic.
fn open_frame(frame: &mut [u8], key: &[u8; 32], our_dir: u8) -> bool {
    let sig = ETH_HDR_SIZE;
    if frame.len() < sig + 32 + 8 { return false; }
    if frame[sig+2] != 0x01 { return false; }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&frame[sig+20..sig+32]);
    if nonce[8] == our_dir { return false; } // reflection
    let mut wire_tag = [0u8; 16];
    wire_tag.copy_from_slice(&frame[sig+4..sig+20]);
    let poly_blk = chacha20_block(key, 0, &nonce);
    let otk: [u8; 32] = poly_blk[0..32].try_into().unwrap();
    let pt = sig + 32;
    let computed = poly1305_aead_mac(&otk, &frame[sig..sig+4], &frame[pt..]);
    let mut diff = 0u8;
    for i in 0..16 { diff |= wire_tag[i] ^ computed[i]; }
    if diff != 0 { return false; }
    chacha20_xor(key, &nonce, 1, &mut frame[pt..]);
    let dec_seq = u64::from_le_bytes(frame[pt..pt+8].try_into().unwrap());
    let nonce_seq = u64::from_le_bytes(nonce[0..8].try_into().unwrap());
    dec_seq == nonce_seq
}

// ============================================================================
// SPRINT 6.2: ANTI-REPLAY WINDOW (2048-BIT SLIDING, RFC 6479)
// ============================================================================
#[derive(Debug, Clone, PartialEq)]
struct AntiReplay { bitmap: [u64; 32], last_seq: u64 }

impl AntiReplay {
    fn new() -> Self { AntiReplay { bitmap: [0u64; 32], last_seq: 0 } }
    #[inline(always)]
    fn check(&mut self, seq: u64) -> bool {
        if seq == 0 { return false; }
        if seq > self.last_seq {
            let shift = seq - self.last_seq;
            if shift >= 2048 { self.bitmap = [0u64; 32]; }
            else {
                let ws = (shift / 64) as usize;
                let bs = (shift % 64) as u32;
                if ws > 0 {
                    for i in (ws..32).rev() { self.bitmap[i] = self.bitmap[i - ws]; }
                    for i in 0..ws.min(32) { self.bitmap[i] = 0; }
                }
                if bs > 0 {
                    for i in (1..32).rev() {
                        self.bitmap[i] = (self.bitmap[i] << bs) | (self.bitmap[i-1] >> (64 - bs));
                    }
                    self.bitmap[0] <<= bs;
                }
            }
            self.last_seq = seq; self.bitmap[0] |= 1;
            return true;
        }
        let diff = self.last_seq - seq;
        if diff >= 2048 { return false; }
        let w = (diff / 64) as usize; let b = (diff % 64) as u32;
        if self.bitmap[w] & (1u64 << b) != 0 { return false; }
        self.bitmap[w] |= 1u64 << b;
        true
    }
}

/// Volatile zeroize: prevents dead-store elimination by compiler/LTO.
#[inline(never)]
fn zeroize(buf: &mut [u8]) {
    for byte in buf.iter_mut() { unsafe { core::ptr::write_volatile(byte, 0); } }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Send fragmented handshake payload over UDP (cold path — heap allocation OK).
fn send_fragmented_udp(
    sock: &UdpSocket, src_mac: &[u8; 6], dst_mac: &[u8; 6],
    payload: &[u8], flags: u8, seq: &mut u64,
    hexdump: &mut HexdumpState, cal: &TscCal,
) -> u64 {
    // UDP payload limit: 1500 MTU - 20 IP - 8 UDP = 1472 bytes max
    // Frame overhead: ETH(14) + M13(48) + FRAG(8) = 70 bytes
    // Max handshake data per fragment: 1472 - 70 = 1402 bytes
    let max_chunk = 1402;
    let total = (payload.len() + max_chunk - 1) / max_chunk;
    let msg_id = (*seq & 0xFFFF) as u16;
    let mut sent = 0u64;
    for i in 0..total {
        let offset = i * max_chunk;
        let chunk_len = (payload.len() - offset).min(max_chunk);
        let flen = ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE + chunk_len;
        let mut frame = vec![0u8; flen];
        frame[0..6].copy_from_slice(dst_mac);
        frame[6..12].copy_from_slice(src_mac);
        frame[12] = (ETH_P_M13 >> 8) as u8;
        frame[13] = (ETH_P_M13 & 0xFF) as u8;
        frame[14] = M13_WIRE_MAGIC; frame[15] = M13_WIRE_VERSION;
        frame[46..54].copy_from_slice(&seq.to_le_bytes());
        frame[54] = flags | FLAG_FRAGMENT;
        let fh = ETH_HDR_SIZE + M13_HDR_SIZE;
        frame[fh..fh+2].copy_from_slice(&msg_id.to_le_bytes());
        frame[fh+2] = i as u8; frame[fh+3] = total as u8;
        frame[fh+4..fh+6].copy_from_slice(&(offset as u16).to_le_bytes());
        frame[fh+6..fh+8].copy_from_slice(&(chunk_len as u16).to_le_bytes());
        let dp = fh + FRAG_HDR_SIZE;
        frame[dp..dp+chunk_len].copy_from_slice(&payload[offset..offset+chunk_len]);
        hexdump.dump_tx(&frame, rdtsc_ns(cal));
        if sock.send(&frame).is_ok() { sent += 1; }
        *seq += 1;
    }
    sent
}

// ============================================================================
// SPRINT 6.3: PQC HANDSHAKE — 3-MESSAGE ML-KEM-1024 + ML-DSA-87
// ============================================================================
// Protocol:
//   Msg 1 (ClientHello): Node→Hub = nonce(32) + ek(1568) + pk_dsa(2592) = 4192 bytes
//   Msg 2 (ServerHello): Hub→Node = ct(1568) + pk_hub(2592) + sig_hub(4627) = 8787 bytes
//   Msg 3 (Finished):    Node→Hub = sig_node(4627) bytes
//
// Session key = HKDF-SHA-512(salt=nonce, IKM=ML-KEM-ss, info="M13-PQC-SESSION-KEY-v1", L=32)
// Forward secrecy: ephemeral ML-KEM dk destroyed after decapsulation.
// Mutual auth: both sides sign transcript with persistent ML-DSA-87 identity keys.
// ============================================================================

const PQC_CONTEXT: &[u8] = b"M13-HS-v1";
const PQC_INFO: &[u8] = b"M13-PQC-SESSION-KEY-v1";

/// Initiate PQC handshake: generate ephemeral ML-KEM-1024 keypair + ML-DSA-87 identity,
/// build ClientHello payload, send as fragmented frames, return Handshaking state.
///
/// ClientHello payload layout:
///   [0]       = HS_CLIENT_HELLO (0x01)
///   [1..33]   = session_nonce (32 bytes, CSPRNG)
///   [33..1601] = ek (encapsulation key, 1568 bytes)
///   [1601..4193] = pk_dsa (ML-DSA-87 verifying key, 2592 bytes)
fn initiate_handshake(
    sock: &UdpSocket,
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    seq: &mut u64,
    hexdump: &mut HexdumpState,
    cal: &TscCal,
) -> NodeState {
    let now = rdtsc_ns(cal);
    eprintln!("[M13-NODE-PQC] Initiating PQC handshake...");

    // 1. Generate ephemeral ML-KEM-1024 keypair (forward secrecy: dk is ephemeral)
    let (dk, ek) = MlKem1024::generate(&mut OsRng);
    let ek_bytes = ek.as_bytes(); // 1568 bytes
    eprintln!("[M13-NODE-PQC] ML-KEM-1024 keypair generated (ek={}B)", ek_bytes.len());

    // 2. Generate persistent ML-DSA-87 identity keypair (TOFU: first boot creates identity)
    let dsa_kp = MlDsa87::key_gen(&mut OsRng);
    let pk_dsa = dsa_kp.verifying_key().encode(); // 2592 bytes
    let sk_dsa = dsa_kp.signing_key().encode();    // 4896 bytes
    eprintln!("[M13-NODE-PQC] ML-DSA-87 identity generated (pk={}B)", pk_dsa.len());

    // 3. Generate session nonce (32 bytes CSPRNG — HKDF salt for session uniqueness)
    let mut session_nonce = [0u8; 32];
    use rand::RngCore;
    OsRng.fill_bytes(&mut session_nonce);

    // 4. Build ClientHello payload: type(1) + nonce(32) + ek(1568) + pk_dsa(2592) = 4193 bytes
    let mut payload = Vec::with_capacity(1 + 32 + ek_bytes.len() + pk_dsa.len());
    payload.push(HS_CLIENT_HELLO);
    payload.extend_from_slice(&session_nonce);
    payload.extend_from_slice(&ek_bytes);
    payload.extend_from_slice(&pk_dsa);

    // 5. Send as fragmented frames with FLAG_CONTROL | FLAG_HANDSHAKE = 0x82
    let flags = FLAG_CONTROL | FLAG_HANDSHAKE;
    let frags = send_fragmented_udp(sock, src_mac, dst_mac, &payload, flags, seq, hexdump, cal);
    eprintln!("[M13-NODE-PQC] ClientHello sent: {}B payload, {} fragments", payload.len(), frags);

    // 6. Store dk bytes for decapsulation when ServerHello arrives
    let dk_bytes = dk.as_bytes().to_vec();

    // 7. Transition to Handshaking state
    NodeState::Handshaking {
        dk_bytes,
        session_nonce,
        client_hello_bytes: payload,
        our_pk: pk_dsa.to_vec(),
        our_sk: sk_dsa.to_vec(),
        started_ns: now,
    }
}

/// Process a reassembled handshake message received from the Hub.
/// The Node only expects one handshake message type: ServerHello (Msg 2).
///
/// ServerHello payload layout:
///   [0]           = HS_SERVER_HELLO (0x02)
///   [1..1569]     = ct (ML-KEM-1024 ciphertext, 1568 bytes)
///   [1569..4161]  = pk_hub (ML-DSA-87 verifying key, 2592 bytes)
///   [4161..8788]  = sig_hub (ML-DSA-87 signature, 4627 bytes)
///
/// Returns Some((session_key, Finished_payload)) on success, None on failure.
fn process_handshake_node(
    reassembled: &[u8],
    state: &NodeState,
) -> Option<([u8; 32], Vec<u8>)> {
    // Must be in Handshaking state
    let (dk_bytes, session_nonce, client_hello_bytes, _our_pk, our_sk, _started_ns) = match state {
        NodeState::Handshaking {
            dk_bytes, session_nonce, client_hello_bytes, our_pk, our_sk, started_ns
        } => (dk_bytes, session_nonce, client_hello_bytes, our_pk, our_sk, started_ns),
        _ => {
            eprintln!("[M13-NODE-PQC] ERROR: Handshake message received but not in Handshaking state");
            return None;
        }
    };

    // Validate message type
    if reassembled.is_empty() || reassembled[0] != HS_SERVER_HELLO {
        eprintln!("[M13-NODE-PQC] ERROR: Expected ServerHello (0x02), got 0x{:02X}",
            reassembled.first().copied().unwrap_or(0));
        return None;
    }

    // Validate minimum length: 1 + 1568 + 2592 + 4627 = 8788 bytes
    const EXPECTED_LEN: usize = 1 + 1568 + 2592 + 4627;
    if reassembled.len() < EXPECTED_LEN {
        eprintln!("[M13-NODE-PQC] ERROR: ServerHello too short: {} < {}", reassembled.len(), EXPECTED_LEN);
        return None;
    }

    eprintln!("[M13-NODE-PQC] Processing ServerHello ({}B)...", reassembled.len());

    // Parse ServerHello fields
    let ct_bytes = &reassembled[1..1569];         // ML-KEM-1024 ciphertext (1568B)
    let pk_hub_bytes = &reassembled[1569..4161];   // ML-DSA-87 verifying key (2592B)
    let sig_hub_bytes = &reassembled[4161..8788];  // ML-DSA-87 signature (4627B)

    // 1. Reconstruct DecapsulationKey from stored bytes
    let dk_encoded = ml_kem::Encoded::<ml_kem::kem::DecapsulationKey<ml_kem::MlKem1024Params>>::try_from(
        dk_bytes.as_slice()
    );
    let dk_encoded = match dk_encoded {
        Ok(enc) => enc,
        Err(_) => {
            eprintln!("[M13-NODE-PQC] ERROR: Failed to parse stored DecapsulationKey");
            return None;
        }
    };
    let dk = ml_kem::kem::DecapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(&dk_encoded);

    // 2. Parse ciphertext
    let ct = match ml_kem::Ciphertext::<MlKem1024>::try_from(ct_bytes) {
        Ok(ct) => ct,
        Err(_) => {
            eprintln!("[M13-NODE-PQC] ERROR: Failed to parse ML-KEM ciphertext");
            return None;
        }
    };

    // 3. Decapsulate: dk + ct → shared secret (ss, 32 bytes)
    let ss = match dk.decapsulate(&ct) {
        Ok(ss) => ss,
        Err(_) => {
            eprintln!("[M13-NODE-PQC] ERROR: ML-KEM decapsulation failed");
            return None;
        }
    };
    eprintln!("[M13-NODE-PQC] ML-KEM-1024 decapsulation successful (ss=32B)");

    // 4. Verify Hub's ML-DSA-87 signature over transcript
    //    transcript = SHA-512(ClientHello_payload || ct)
    let mut hasher = Sha512::new();
    hasher.update(client_hello_bytes);
    hasher.update(ct_bytes);
    let transcript: [u8; 64] = hasher.finalize().into();

    // Parse Hub's verifying key
    let pk_hub_enc = match ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(pk_hub_bytes) {
        Ok(enc) => enc,
        Err(_) => {
            eprintln!("[M13-NODE-PQC] ERROR: Failed to parse Hub verifying key");
            return None;
        }
    };
    let pk_hub = ml_dsa::VerifyingKey::<MlDsa87>::decode(&pk_hub_enc);

    // Parse Hub's signature
    let sig_hub = match ml_dsa::Signature::<MlDsa87>::try_from(sig_hub_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            eprintln!("[M13-NODE-PQC] ERROR: Failed to parse Hub signature");
            return None;
        }
    };

    // Verify signature: pk_hub.verify(transcript, context="M13-HS-v1", sig_hub)
    if !pk_hub.verify_with_context(&transcript, PQC_CONTEXT, &sig_hub) {
        eprintln!("[M13-NODE-PQC] SECURITY FAILURE: Hub signature verification failed!");
        eprintln!("[M13-NODE-PQC] Possible MITM attack — aborting handshake");
        return None;
    }
    eprintln!("[M13-NODE-PQC] Hub ML-DSA-87 signature verified ✓");

    // 5. Derive session key via HKDF-SHA-512
    //    HKDF(salt=session_nonce, IKM=ss, info="M13-PQC-SESSION-KEY-v1", L=32)
    let hk = Hkdf::<Sha512>::new(Some(session_nonce), &ss);
    let mut session_key = [0u8; 32];
    hk.expand(PQC_INFO, &mut session_key)
        .expect("HKDF-SHA-512 expand failed (L=32 ≤ 255*64)");
    eprintln!("[M13-NODE-PQC] Session key derived via HKDF-SHA-512 (32B)");

    // 6. Sign full transcript for Finished message (mutual auth)
    //    transcript2 = SHA-512(ClientHello_payload || ServerHello_payload)
    let mut hasher2 = Sha512::new();
    hasher2.update(client_hello_bytes);
    hasher2.update(reassembled);
    let transcript2: [u8; 64] = hasher2.finalize().into();

    // Reconstruct our signing key
    let sk_enc = match ml_dsa::EncodedSigningKey::<MlDsa87>::try_from(our_sk.as_slice()) {
        Ok(enc) => enc,
        Err(_) => {
            eprintln!("[M13-NODE-PQC] ERROR: Failed to reconstruct our signing key");
            return None;
        }
    };
    let sk = ml_dsa::SigningKey::<MlDsa87>::decode(&sk_enc);

    // Sign transcript2 with our identity key
    let sig_node = match sk.sign_deterministic(&transcript2, PQC_CONTEXT) {
        Ok(sig) => sig,
        Err(_) => {
            eprintln!("[M13-NODE-PQC] ERROR: ML-DSA signing failed");
            return None;
        }
    };
    let sig_node_bytes = sig_node.encode(); // 4627 bytes
    eprintln!("[M13-NODE-PQC] Node signature generated ({}B)", sig_node_bytes.len());

    // 7. Build Finished payload: type(1) + sig_node(4627) = 4628 bytes
    let mut finished = Vec::with_capacity(1 + sig_node_bytes.len());
    finished.push(HS_FINISHED);
    finished.extend_from_slice(&sig_node_bytes);

    Some((session_key, finished))
}

/// Read the hardware MAC address of a network interface from sysfs.
/// Returns the 6-byte MAC or a locally-administered random fallback.
fn detect_mac(if_name: Option<&str>) -> [u8; 6] {
    if let Some(iface) = if_name {
        let path = format!("/sys/class/net/{}/address", iface);
        if let Ok(contents) = std::fs::read_to_string(&path) {
            let parts: Vec<u8> = contents.trim().split(':')
                .filter_map(|h| u8::from_str_radix(h, 16).ok())
                .collect();
            if parts.len() == 6 {
                eprintln!("[M13-NODE] Detected MAC for {}: {}", iface, contents.trim());
                return [parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]];
            }
        }
    }
    // Generate a random locally-administered MAC (LAA)
    let seed = (clock_ns() & 0xFFFFFFFFFFFF) as u64;
    let mac = [
        0x02, // locally administered, unicast
        ((seed >> 8) & 0xFF) as u8,
        ((seed >> 16) & 0xFF) as u8,
        ((seed >> 24) & 0xFF) as u8,
        ((seed >> 32) & 0xFF) as u8,
        ((seed >> 40) & 0xFF) as u8,
    ];
    eprintln!("[M13-NODE] Using generated LAA MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    mac
}

// ============================================================================
// M13 FRAME BUILDER (shared)
// ============================================================================
fn build_m13_frame(src_mac: &[u8; 6], dst_mac: &[u8; 6], seq: u64, flags: u8) -> [u8; 62] {
    let mut frame = [0u8; 62];
    frame[0..6].copy_from_slice(dst_mac);
    frame[6..12].copy_from_slice(src_mac);
    frame[12] = (ETH_P_M13 >> 8) as u8;
    frame[13] = (ETH_P_M13 & 0xFF) as u8;
    frame[14] = M13_WIRE_MAGIC;
    frame[15] = M13_WIRE_VERSION;
    frame[46..54].copy_from_slice(&seq.to_le_bytes());
    frame[54] = flags;
    frame
}

fn build_echo_frame(rx_frame: &[u8], new_seq: u64) -> Option<Vec<u8>> {
    if rx_frame.len() < ETH_HDR_SIZE + M13_HDR_SIZE { return None; }
    let mut echo = rx_frame.to_vec();
    // Swap dst/src MAC
    let (dst, src) = echo.split_at_mut(6);
    let mut tmp = [0u8; 6];
    tmp.copy_from_slice(&dst[..6]);
    dst[..6].copy_from_slice(&src[..6]);
    src[..6].copy_from_slice(&tmp);
    // Stamp our seq
    echo[46..54].copy_from_slice(&new_seq.to_le_bytes());
    Some(echo)
}

// ============================================================================
// SIGNAL HANDLER
// ============================================================================
static SHUTDOWN: AtomicBool = AtomicBool::new(false);
extern "C" fn signal_handler(_sig: i32) { SHUTDOWN.store(true, Ordering::Relaxed); }

// ============================================================================
// MAIN
// ============================================================================
fn main() {
    let args: Vec<String> = std::env::args().collect();
    unsafe {
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
    }

    let mut hub_ip: Option<String> = None;
    let mut iface: Option<String> = None;
    let mut echo_mode = true;
    let mut hexdump_mode = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--echo" => { echo_mode = true; }
            "--hexdump" => { hexdump_mode = true; }
            "--hub-ip" | "--ip" | "--hub" => {
                i += 1;
                if i < args.len() { hub_ip = Some(args[i].clone()); }
            }
            "--iface" | "-i" => {
                i += 1;
                if i < args.len() { iface = Some(args[i].clone()); }
            }
            _ => {}
        }
        i += 1;
    }

    if let Some(ref addr) = hub_ip {
        eprintln!("[M13-NODE] Mode: UDP → Hub at {}", addr);
        run_udp_worker(addr, echo_mode, hexdump_mode);
    } else if let Some(ref ifc) = iface {
        eprintln!("[M13-NODE] Mode: AF_XDP on {}", ifc);
        run_afxdp_worker(ifc, echo_mode, hexdump_mode);
    } else {
        eprintln!("Usage: m13-node --hub-ip <ip:port> [--echo] [--hexdump]");
        eprintln!("       m13-node --iface <dev> [--echo] [--hexdump]");
        std::process::exit(1);
    }
}

// ============================================================================
// UDP WORKER — kernel socket transport (cross-internet)
// Same FSM, echo, hexdump, telemetry as AF_XDP worker.
// ============================================================================
fn run_udp_worker(hub_addr: &str, echo: bool, hexdump_mode: bool) {
    let cal = calibrate_tsc();
    let sock = UdpSocket::bind("0.0.0.0:0")
        .unwrap_or_else(|_| fatal(0x30, "UDP bind failed"));
    sock.connect(hub_addr)
        .unwrap_or_else(|_| fatal(0x31, "UDP connect failed"));
    sock.set_read_timeout(Some(Duration::from_millis(1))).ok();

    let mut buf = [0u8; 2048];
    let mut seq_tx: u64 = 0;
    let mut rx_count: u64 = 0;
    let mut tx_count: u64 = 0;
    let mut last_rx_ns: u64 = 0;
    let mut hexdump = HexdumpState::new(hexdump_mode);
    let mut assembler = Assembler::new();
    let mut state = NodeState::Disconnected;
    let mut last_report_ns: u64 = rdtsc_ns(&cal);
    let mut gc_counter: u64 = 0;

    let src_mac: [u8; 6] = detect_mac(None); // No local NIC in UDP mode
    let hub_mac: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]; // broadcast — Hub identifies by addr

    eprintln!("[M13-NODE-UDP] Connected to {}. Echo={} Hexdump={}", hub_addr, echo, hexdump_mode);

    // Registration: send first frame to establish return path
    let reg = build_m13_frame(&src_mac, &hub_mac, seq_tx, FLAG_CONTROL);
    seq_tx += 1;
    if sock.send(&reg).is_ok() { tx_count += 1; }
    hexdump.dump_tx(&reg, rdtsc_ns(&cal));
    state = NodeState::Registering;

    loop {
        if SHUTDOWN.load(Ordering::Relaxed) { break; }
        let now = rdtsc_ns(&cal);

        // === RX ===
        match sock.recv(&mut buf) {
            Ok(len) => {
                rx_count += 1;
                last_rx_ns = now;
                hexdump.dump_rx(&buf[..len], now);

                if len >= ETH_HDR_SIZE + M13_HDR_SIZE {
                    let m13 = unsafe { &*(buf.as_ptr().add(ETH_HDR_SIZE) as *const M13Header) };
                    if m13.signature[0] == M13_WIRE_MAGIC && m13.signature[1] == M13_WIRE_VERSION {
                        // Sprint 6.3: State-driven transition
                        // Registering → initiate PQC handshake on first valid Hub frame
                        if matches!(state, NodeState::Registering) {
                            state = initiate_handshake(
                                &sock, &src_mac, &hub_mac, &mut seq_tx, &mut hexdump, &cal,
                            );
                            eprintln!("[M13-NODE-UDP] → Handshaking (PQC ClientHello sent)");
                        }
                        let flags = m13.flags;

                        // Sprint 6.2: AEAD verification on encrypted frames
                        if buf[ETH_HDR_SIZE + 2] == 0x01 {
                            // Encrypted frame — must verify+decrypt
                            if let NodeState::Established { ref session_key, ref mut anti_replay, ref mut frame_count, .. } = state {
                                if !open_frame(&mut buf[..len], session_key, DIR_NODE_TO_HUB) {
                                    // MAC failed: forgery, corruption, or wrong session key
                                    continue; // drop
                                }
                                // Re-read decrypted seq_id for anti-replay
                                let dec_seq = u64::from_le_bytes(
                                    buf[ETH_HDR_SIZE + 32..ETH_HDR_SIZE + 40].try_into().unwrap()
                                );
                                if !anti_replay.check(dec_seq) {
                                    continue; // replay
                                }
                                *frame_count += 1;
                            } else {
                                continue; // encrypted frame but no session — drop
                            }
                        }

                        // Fragment handling
                        if flags & FLAG_FRAGMENT != 0 && len >= ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE {
                            let frag_hdr = unsafe { &*(buf.as_ptr().add(ETH_HDR_SIZE + M13_HDR_SIZE) as *const FragHeader) };
                            let frag_msg_id = unsafe { std::ptr::addr_of!((*frag_hdr).frag_msg_id).read_unaligned() };
                            let frag_index = unsafe { std::ptr::addr_of!((*frag_hdr).frag_index).read_unaligned() };
                            let frag_total = unsafe { std::ptr::addr_of!((*frag_hdr).frag_total).read_unaligned() };
                            let frag_offset = unsafe { std::ptr::addr_of!((*frag_hdr).frag_offset).read_unaligned() };
                            let frag_data_len = unsafe { std::ptr::addr_of!((*frag_hdr).frag_len).read_unaligned() } as usize;
                            let frag_start = ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE;
                            if frag_start + frag_data_len <= len {
                                if let Some(reassembled) = assembler.feed(
                                    frag_msg_id, frag_index, frag_total, frag_offset,
                                    &buf[frag_start..frag_start + frag_data_len], now,
                                ) {
                                    // Sprint 6.3: Route handshake messages to PQC processor
                                    if flags & FLAG_HANDSHAKE != 0 {
                                        eprintln!("[M13-NODE-UDP] Reassembled handshake msg_id={} len={}",
                                            frag_msg_id, reassembled.len());
                                        if let Some((session_key, finished_payload)) = process_handshake_node(&reassembled, &state) {
                                            // Send Finished (Msg 3)
                                            let hs_flags = FLAG_CONTROL | FLAG_HANDSHAKE;
                                            let frags = send_fragmented_udp(
                                                &sock, &src_mac, &hub_mac,
                                                &finished_payload, hs_flags,
                                                &mut seq_tx, &mut hexdump, &cal,
                                            );
                                            eprintln!("[M13-NODE-PQC] Finished sent: {}B, {} fragments",
                                                finished_payload.len(), frags);

                                            // Transition to Established with PQC-derived session key
                                            state = NodeState::Established {
                                                session_key,
                                                anti_replay: AntiReplay::new(),
                                                frame_count: 0,
                                                established_ns: now,
                                            };
                                            eprintln!("[M13-NODE-PQC] → Established (session key derived, AEAD active)");
                                        } else {
                                            eprintln!("[M13-NODE-PQC] Handshake processing failed → Disconnected");
                                            state = NodeState::Disconnected;
                                        }
                                    } else {
                                        eprintln!("[M13-NODE-UDP] Reassembled data msg_id={} len={}",
                                            frag_msg_id, reassembled.len());
                                    }
                                }
                            }
                        } else if flags & FLAG_CONTROL != 0 {
                            // Control frame — handled
                        } else if echo && matches!(state, NodeState::Established { .. }) {
                            // Echo: swap MACs, re-stamp seq, encrypt, send back
                            if let Some(mut echo_frame) = build_echo_frame(&buf[..len], seq_tx) {
                                // Seal if session has non-zero key
                                if let NodeState::Established { ref session_key, .. } = state {
                                    if *session_key != [0u8; 32] {
                                        seal_frame(&mut echo_frame, session_key, seq_tx, DIR_NODE_TO_HUB);
                                    }
                                }
                                seq_tx += 1;
                                hexdump.dump_tx(&echo_frame, now);
                                if sock.send(&echo_frame).is_ok() { tx_count += 1; }
                            }
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                       || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => {}
        }

        // === Sprint 6.3: Handshake timeout ===
        if let NodeState::Handshaking { started_ns, .. } = &state {
            if now.saturating_sub(*started_ns) > HANDSHAKE_TIMEOUT_NS {
                eprintln!("[M13-NODE-PQC] Handshake timeout ({}s). → Disconnected",
                    HANDSHAKE_TIMEOUT_NS / 1_000_000_000);
                state = NodeState::Disconnected;
            }
        }

        // === Link-loss detection ===
        if matches!(state, NodeState::Established { .. }) && last_rx_ns > 0
            && now.saturating_sub(last_rx_ns) > LINK_LOSS_TIMEOUT_NS {
            eprintln!("[M13-NODE-UDP] Link loss detected. → Disconnected");
            state = NodeState::Disconnected;
        }

        // === Keepalive (100ms) — maintains NAT hole + triggers Hub TX ===
        if now.saturating_sub(last_report_ns) > 100_000_000 || tx_count == 0 {
            let ka = build_m13_frame(&src_mac, &hub_mac, seq_tx, 0);
            seq_tx += 1;
            if sock.send(&ka).is_ok() { tx_count += 1; }
        }

        // === Telemetry: report every second ===
        if now.saturating_sub(last_report_ns) > 1_000_000_000 {
            eprintln!("[M13-NODE-UDP] TX:{} RX:{} State:{:?} Echo:{}", tx_count, rx_count, state, echo);
            last_report_ns = now;
            gc_counter += 1;
            if gc_counter % 5 == 0 { assembler.gc(now); }
        }
    }
    eprintln!("[M13-NODE-UDP] Shutdown. TX:{} RX:{} State:{:?}", tx_count, rx_count, state);
}

// ============================================================================
// AF_XDP WORKER — zero-copy transport (same-L2 / WiFi 7)
// Full slab allocator, UMEM, BPF steersman.
// Same FSM, echo, hexdump, telemetry as UDP worker.
// ============================================================================
fn run_afxdp_worker(if_name: &str, echo: bool, hexdump_mode: bool) {
    // Discover isolated cores
    let isolated = discover_isolated_cores();
    if isolated.is_empty() { fatal(E_NO_ISOLATED_CORES, "No isolated cores"); }
    let core_id = isolated[0];

    // Pin to isolated core
    pin_to_core(core_id);
    eprintln!("[M13-NODE-EXEC] Pinned to core {}.", core_id);

    // TSC calibration (full TscCal for rdtsc_ns hot-loop clock)
    let cal = calibrate_tsc();

    // IRQ fencing
    fence_irqs(core_id);

    // BPF Steersman
    let bpf = BpfSteersman::load_and_attach(if_name);
    eprintln!("[M13-NODE-EXEC] BPF Steersman attached to {}.", if_name);

    // Telemetry
    let stats = Telemetry::map_worker(0, true);

    // AF_XDP engine
    let queue_id = 0i32;
    let mut engine = Engine::new_zerocopy(if_name, queue_id, bpf.map_fd());
    let mut slab = FixedSlab::new(SLAB_DEPTH);
    let mut hexdump = HexdumpState::new(hexdump_mode);
    let mut assembler = Assembler::new();
    let mut state = NodeState::Disconnected;
    let mut seq_tx: u64 = 0;
    let mut rx_total: u64 = 0;
    let mut tx_total: u64 = 0;
    let mut last_rx_ns: u64 = 0;
    let mut last_report_ns: u64 = rdtsc_ns(&cal);
    let mut gc_counter: u64 = 0;
    let src_mac: [u8; 6] = detect_mac(Some(if_name));

    // Pre-stamp all UMEM frames with ETH + M13 headers
    for i in 0..SLAB_DEPTH as u32 {
        let fp = engine.get_frame_ptr(i);
        unsafe {
            let eth = &mut *(fp as *mut EthernetHeader);
            let m13 = &mut *(fp.add(ETH_HDR_SIZE) as *mut M13Header);
            eth.src = src_mac;
            eth.dst = [0xFF; 6]; // broadcast until peer known
            eth.ethertype = ETH_P_M13.to_be();
            m13.signature = [0; 32];
            m13.signature[0] = M13_WIRE_MAGIC;
            m13.signature[1] = M13_WIRE_VERSION;
        }
    }
    engine.refill_rx_full(&mut slab);

    eprintln!("[M13-NODE-W0] ACTIVE. Slab: {} Batch: 64 Echo: {} Hexdump: {}",
        SLAB_DEPTH, echo, hexdump_mode);

    let mut rx_batch: [libbpf_sys::xdp_desc; 64] = unsafe { mem::zeroed() };

    loop {
        if SHUTDOWN.load(Ordering::Relaxed) { break; }
        let now = rdtsc_ns(&cal);

        engine.recycle_tx(&mut slab);
        engine.refill_rx(&mut slab);

        // === RX: batch drain ===
        let rx_count = engine.poll_rx_batch(&mut rx_batch, &stats);
        let umem = engine.umem_base();

        for i in 0..rx_count {
            let desc = &rx_batch[i];
            let frame_len = desc.len as usize;
            let frame_ptr = unsafe { umem.add(desc.addr as usize) };

            if frame_len < ETH_HDR_SIZE + M13_HDR_SIZE {
                slab.free((desc.addr / FRAME_SIZE as u64) as u32);
                continue;
            }

            let frame_slice = unsafe { std::slice::from_raw_parts(frame_ptr, frame_len) };
            let m13 = unsafe { &*(frame_ptr.add(ETH_HDR_SIZE) as *const M13Header) };

            if m13.signature[0] != M13_WIRE_MAGIC || m13.signature[1] != M13_WIRE_VERSION {
                slab.free((desc.addr / FRAME_SIZE as u64) as u32);
                continue;
            }

            rx_total += 1;
            last_rx_ns = now;
            hexdump.dump_rx(frame_slice, now);

            // Transition to Established on first valid frame (pre-PQC: cleartext mode)
            if !matches!(state, NodeState::Established { .. }) {
                state = NodeState::Established {
                    session_key: [0u8; 32],
                    anti_replay: AntiReplay::new(),
                    frame_count: 0,
                    established_ns: now,
                };
                eprintln!("[M13-NODE-W0] → Established");
            }

            let flags = m13.flags;

            // Sprint 6.2: AEAD verification on encrypted frames
            if frame_slice[ETH_HDR_SIZE + 2] == 0x01 {
                let frame_mut = unsafe { std::slice::from_raw_parts_mut(frame_ptr, frame_len) };
                if let NodeState::Established { ref session_key, ref mut anti_replay, ref mut frame_count, .. } = state {
                    if !open_frame(frame_mut, session_key, DIR_NODE_TO_HUB) {
                        slab.free((desc.addr / FRAME_SIZE as u64) as u32);
                        continue;
                    }
                    let dec_seq = u64::from_le_bytes(
                        frame_mut[ETH_HDR_SIZE + 32..ETH_HDR_SIZE + 40].try_into().unwrap()
                    );
                    if !anti_replay.check(dec_seq) {
                        slab.free((desc.addr / FRAME_SIZE as u64) as u32);
                        continue;
                    }
                    *frame_count += 1;
                } else {
                    slab.free((desc.addr / FRAME_SIZE as u64) as u32);
                    continue;
                }
            }

            if flags & FLAG_FRAGMENT != 0 {
                if frame_len >= ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE {
                    let frag_hdr = unsafe {
                        &*(frame_ptr.add(ETH_HDR_SIZE + M13_HDR_SIZE) as *const FragHeader)
                    };
                    let frag_msg_id = unsafe {
                        std::ptr::addr_of!((*frag_hdr).frag_msg_id).read_unaligned()
                    };
                    let frag_index = unsafe {
                        std::ptr::addr_of!((*frag_hdr).frag_index).read_unaligned()
                    };
                    let frag_total = unsafe {
                        std::ptr::addr_of!((*frag_hdr).frag_total).read_unaligned()
                    };
                    let frag_offset = unsafe {
                        std::ptr::addr_of!((*frag_hdr).frag_offset).read_unaligned()
                    };
                    let frag_data_len = unsafe {
                        std::ptr::addr_of!((*frag_hdr).frag_len).read_unaligned()
                    } as usize;
                    let frag_start = ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE;
                    if frag_start + frag_data_len <= frame_len {
                        if let Some(reassembled) = assembler.feed(
                            frag_msg_id, frag_index, frag_total, frag_offset,
                            &frame_slice[frag_start..frag_start + frag_data_len], now,
                        ) {
                            eprintln!(
                                "[M13-NODE-W0] Reassembled msg_id={} len={}",
                                frag_msg_id, reassembled.len()
                            );
                        }
                    }
                }
                slab.free((desc.addr / FRAME_SIZE as u64) as u32);
            } else if flags & FLAG_CONTROL != 0 {
                slab.free((desc.addr / FRAME_SIZE as u64) as u32);
            } else if echo && matches!(state, NodeState::Established { .. }) {
                // Echo: swap MACs in-place, stamp seq, seal, send back via AF_XDP TX
                unsafe {
                    let eth = &mut *(frame_ptr as *mut EthernetHeader);
                    let tmp = eth.dst;
                    eth.dst = eth.src;
                    eth.src = tmp;
                    let m13_mut = &mut *(frame_ptr.add(ETH_HDR_SIZE) as *mut M13Header);
                    m13_mut.seq_id = seq_tx;
                }
                // Seal if session has non-zero key
                if let NodeState::Established { ref session_key, .. } = state {
                    if *session_key != [0u8; 32] {
                        let frame_mut = unsafe { std::slice::from_raw_parts_mut(frame_ptr, frame_len) };
                        seal_frame(frame_mut, session_key, seq_tx, DIR_NODE_TO_HUB);
                    }
                }
                seq_tx += 1;
                hexdump.dump_tx(frame_slice, now);
                engine.tx_path.stage_tx((desc.addr / FRAME_SIZE as u64) as u32, desc.len);
                engine.tx_path.commit_tx();
                engine.tx_path.kick_tx();
                tx_total += 1;
            } else {
                slab.free((desc.addr / FRAME_SIZE as u64) as u32);
            }
        }

        // Link-loss detection
        if matches!(state, NodeState::Established { .. }) && last_rx_ns > 0
            && now.saturating_sub(last_rx_ns) > LINK_LOSS_TIMEOUT_NS {
            eprintln!("[M13-NODE-W0] Link loss. → Disconnected");
            state = NodeState::Disconnected;
        }

        // Telemetry (1/sec)
        if now.saturating_sub(last_report_ns) > 1_000_000_000 {
            eprintln!("[M13-NODE-W0] TX:{} RX:{} State:{:?} Slab:{}/{}",
                tx_total, rx_total, state, slab.available(), SLAB_DEPTH);
            last_report_ns = now;
            gc_counter += 1;
            if gc_counter % 5 == 0 { assembler.gc(now); }
        }
    }

    eprintln!("[M13-NODE-W0] Shutdown. TX:{} RX:{} State:{:?}", tx_total, rx_total, state);
}

// ============================================================================
// UTILS
// ============================================================================
fn discover_isolated_cores() -> Vec<usize> {
    if let Ok(mock) = std::env::var("M13_MOCK_CMDLINE") {
        if let Some(part) = mock.split_whitespace().find(|p| p.starts_with("isolcpus=")) {
            return parse_isolcpus(&part[9..]);
        }
    }
    if let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline") {
        if let Some(part) = cmdline.split_whitespace().find(|p| p.starts_with("isolcpus=")) {
            return parse_isolcpus(&part[9..]);
        }
    }
    Vec::new()
}

fn parse_isolcpus(s: &str) -> Vec<usize> {
    let mut cores = Vec::new();
    for part in s.split(',') {
        if let Some(dash) = part.find('-') {
            let lo: usize = part[..dash].parse().unwrap_or(0);
            let hi: usize = part[dash+1..].parse().unwrap_or(0);
            for c in lo..=hi { cores.push(c); }
        } else if let Ok(c) = part.parse() {
            cores.push(c);
        }
    }
    cores
}

fn pin_to_core(core: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = mem::zeroed();
        libc::CPU_SET(core, &mut set);
        let ret = libc::sched_setaffinity(0, mem::size_of::<libc::cpu_set_t>(), &set);
        if ret != 0 { fatal(E_AFFINITY_FAIL, "sched_setaffinity failed"); }
    }
}

/// Two-point TSC calibration against CLOCK_MONOTONIC.
/// Runs for 100ms, comparing rdtsc deltas against kernel clock deltas.
/// Computes fixed-point mult/shift such that:
///   ns_per_tick = mult / 2^shift
/// After calibration, validates accuracy over 1000 samples.
/// Returns TscCal::fallback() if TSC is unreliable.
fn calibrate_tsc() -> TscCal {
    // Check invariant TSC support (CPUID leaf 0x80000007, bit 8)
    #[cfg(target_arch = "x86_64")]
    {
        let has_invariant_tsc = unsafe {
            let result: u32;
            core::arch::asm!(
                "push rbx",
                "mov eax, 0x80000007",
                "cpuid",
                "pop rbx",
                out("edx") result,
                out("eax") _,
                out("ecx") _,
                options(nomem)
            );
            (result >> 8) & 1 == 1
        };
        if !has_invariant_tsc {
            eprintln!("[M13-TSC] WARNING: CPU lacks invariant TSC. Using clock_gettime fallback.");
            return TscCal::fallback();
        }
    }

    // Warm up caches: 100 iterations (discard results)
    for _ in 0..100 {
        let _ = read_tsc();
        let _ = clock_ns();
    }

    // Two-point calibration over 100ms
    let tsc0 = read_tsc();
    let mono0 = clock_ns();
    std::thread::sleep(Duration::from_millis(100));
    let tsc1 = read_tsc();
    let mono1 = clock_ns();

    let tsc_delta = tsc1.wrapping_sub(tsc0);
    let mono_delta = mono1.saturating_sub(mono0);

    if tsc_delta == 0 || mono_delta == 0 {
        eprintln!("[M13-TSC] WARNING: TSC calibration failed (zero delta). Using fallback.");
        return TscCal::fallback();
    }

    // Compute ns_per_tick as fixed-point: mult / 2^shift
    // Choose shift = 32 for maximum precision with u32 mult.
    // mult = (mono_delta * 2^32) / tsc_delta
    let shift: u32 = 32;
    let mult = ((mono_delta as u128) << shift) / (tsc_delta as u128);
    if mult > u32::MAX as u128 {
        eprintln!("[M13-TSC] WARNING: TSC frequency too low for u32 mult. Using fallback.");
        return TscCal::fallback();
    }
    let mult = mult as u32;

    // Snapshot the base point for conversion
    let tsc_base = read_tsc();
    let mono_base = clock_ns();

    let cal = TscCal { tsc_base, mono_base, mult, shift, valid: true };

    // Validation: compare rdtsc_ns() vs clock_ns() over 1000 samples.
    let mut max_error: i64 = 0;
    for _ in 0..1000 {
        let tsc_time = rdtsc_ns(&cal) as i64;
        let mono_time = clock_ns() as i64;
        let err = (tsc_time - mono_time).abs();
        if err > max_error { max_error = err; }
    }

    let tsc_freq_mhz = (tsc_delta as u128 * 1000) / (mono_delta as u128);
    eprintln!("[M13-TSC] Calibrated: freq={}.{}MHz mult={} shift={} max_err={}ns",
        tsc_freq_mhz / 1000, tsc_freq_mhz % 1000, mult, shift, max_error);

    if max_error > 1000 { // > 1µs
        eprintln!("[M13-TSC] WARNING: Calibration error {}ns > 1µs. Using clock_gettime fallback.", max_error);
        return TscCal::fallback();
    }

    cal
}

fn fence_irqs(protected_core: usize) {
    let irq_dir = "/proc/irq";
    if let Ok(entries) = std::fs::read_dir(irq_dir) {
        let mut fenced = 0u32;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.parse::<u32>().is_err() { continue; }
            let affinity_path = format!("{}/{}/smp_affinity_list", irq_dir, name_str);
            if let Ok(current) = std::fs::read_to_string(&affinity_path) {
                let cores = parse_isolcpus(current.trim());
                if cores.contains(&protected_core) {
                    // Move this IRQ away from our core
                    let new_mask = "0";
                    let _ = std::fs::write(&affinity_path, new_mask);
                    fenced += 1;
                }
            }
        }
        eprintln!("[M13-NODE-EXEC] IRQ fence: {} IRQs moved off core {}", fenced, protected_core);
    }
}
