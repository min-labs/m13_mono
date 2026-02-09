// M13 HUB - LOGIC KERNEL (REV 6.1)
// Sprint 6.1: Fragmentation Engine + Hexdump (bilateral with Node)
// Sprint 5.1: The Executive (Thread Pinning, Multi-Core)
// Sprint 5.2: Typestate FSM (Compile-Time Protocol State)
// Sprint 5.3: The Graph Pipeline (I/O Vector Batching)
// Sprint 5.4: The Latency Floor (Adaptive Batching)
// Sprint 5.5: Software Prefetching (D-Cache Warming)
// Sprint 5.6: The Interrupt Fence (IRQ Affinity)
// Sprint 5.7: The Isochronous Scheduler (Hierarchical DWRR)
// Sprint 5.8: The Feedback Channel (ACK Frame)
// Sprint 5.9: BBRv3 Congestion Control (Model-Based Rate Pacing)
// Sprint 5.10: Deterministic Jitter Buffer (RFC 3550 EWMA, Adaptive D_buf)
// Sprint 5.11: Diagnostic Error Codes (Structured Exit, Zero-Alloc Fatal)
//   - Windowed max filter for BtlBw (Kathleen Nichols algorithm, 10-round window)
//   - Expiring min for RTprop (10-second window, triggers ProbeRTT)
//   - Full BBRv3 state machine: Startup → Drain → ProbeBW (Down/Cruise/Refill/Up) → ProbeRTT
//   - Token bucket pacing at batch level (no per-packet busy-wait, preserves batching)
//   - cwnd = BDP × cwnd_gain (caps inflight, replaces static HW_FILL_MAX when active)
//   - All gains from Google's BBRv3: Startup 2.77x, Drain 0.36x, ProbeUp 1.25x, ProbeDown 0.9x
//   - Fixed-point arithmetic (integer rationals, no f64)
//   - Feedback-first pipeline: control frames processed BEFORE generation for zero-cycle latency
mod datapath;
use crate::datapath::{M13_WIRE_MAGIC, M13_WIRE_VERSION, 
    FixedSlab, Engine, Telemetry, EthernetHeader, M13Header, FeedbackFrame,
    ETH_P_M13, ZeroCopyTx, TxPath, BpfSteersman, MAX_WORKERS, FRAME_SIZE, UMEM_SIZE,
    // Structured exits — single source of truth for error codes
    fatal,
    E_NO_ISOLATED_CORES, E_AFFINITY_FAIL, E_PMU_LOCK_FAIL, E_AFFINITY_VERIFY,
};
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use std::fs::{OpenOptions, File};
use std::io::{Write, Read, Seek, SeekFrom, BufReader, BufRead};
use std::cmp::min;
use std::time::Duration;
use std::marker::PhantomData;
use std::collections::HashMap;

// Sprint 6.2: PQC cold-path imports (handshake only — never in hot loop)
use sha2::{Sha512, Digest};
use hkdf::Hkdf;
use rand::rngs::OsRng;

// Sprint 6.3: PQC handshake — ML-KEM-1024 key exchange + ML-DSA-87 mutual auth
use ml_kem::{MlKem1024, KemCore, EncodedSizeUser};
use ml_kem::kem::Encapsulate;
use ml_dsa::{MlDsa87, KeyGen};

const SLAB_DEPTH: usize = 8192;
const BATCH_SIZE: usize = 16;
const GRAPH_BATCH: usize = 256;
const FLAG_CONTROL: u8  = 0x80;
const FLAG_FEEDBACK: u8 = 0x40;
const FLAG_CRITICAL: u8 = 0x20;
const FLAG_ECN: u8      = 0x10;  // Receiver signals congestion (Sprint 5.19)
const FLAG_FIN: u8      = 0x08;  // Graceful close signal (Sprint 5.21)
#[allow(dead_code)] const FLAG_FEC: u8      = 0x04;  // RLNC coded frame (Sprint 6.7)
const FLAG_HANDSHAKE: u8= 0x02;  // Handshake control (Sprint 6.3)
const FLAG_FRAGMENT: u8 = 0x01;  // Fragmented message (Sprint 6.1)

// Sprint 6.2: PQC handshake sub-types
const HS_CLIENT_HELLO: u8 = 0x01;
const HS_SERVER_HELLO: u8 = 0x02;
const HS_FINISHED: u8     = 0x03;
// Direction bytes for AEAD nonce (prevents reflection attacks)
const DIR_HUB_TO_NODE: u8 = 0x00;
const DIR_NODE_TO_HUB: u8 = 0x01;
// Rekey thresholds
const REKEY_FRAME_LIMIT: u64 = 1u64 << 32;
const REKEY_TIME_LIMIT_NS: u64 = 3_600_000_000_000;
const HANDSHAKE_TIMEOUT_NS: u64 = 5_000_000_000;
const ETH_HDR_SIZE: usize = mem::size_of::<EthernetHeader>();
const M13_HDR_SIZE: usize = mem::size_of::<M13Header>();
const DATA_FRAME_WIRE_SIZE: u64 = (ETH_HDR_SIZE + M13_HDR_SIZE) as u64; // 62 bytes
const FEEDBACK_FRAME_LEN: u32 = (ETH_HDR_SIZE + M13_HDR_SIZE + mem::size_of::<FeedbackFrame>()) as u32;
const DEADLINE_NS: u64 = 50_000;
const PREFETCH_DIST: usize = 4;
const TX_RING_SIZE: usize = 2048;
const HW_FILL_MAX: usize = TX_RING_SIZE / 10;

const FEEDBACK_INTERVAL_PKTS: u32 = 32;
const FEEDBACK_RTT_DEFAULT_NS: u64 = 10_000_000; // 10ms until first RTprop sample

const SEQ_WINDOW: usize = 131_072; // 2^17
const SEQ_WINDOW_MASK: usize = SEQ_WINDOW - 1;
const _: () = assert!(SEQ_WINDOW & (SEQ_WINDOW - 1) == 0);

#[inline(always)]
fn clock_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

// ============================================================================
// SPRINT 5.17: TSC FAST CLOCK
// Replaces clock_gettime(MONOTONIC) in the hot loop with raw rdtsc.
// Calibrated at boot against CLOCK_MONOTONIC. Fixed-point multiply+shift
// conversion — identical method to Linux kernel (arch/x86/kernel/tsc.c).
// ============================================================================

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
    /// Fallback calibration — rdtsc_ns() will call clock_ns() instead.
    fn fallback() -> Self {
        TscCal { tsc_base: 0, mono_base: 0, mult: 0, shift: 0, valid: false }
    }
}

/// Raw TSC read. ~24 cycles on Skylake (~6.5ns at 3.7GHz).
/// No serialization (lfence/rdtscp) — not needed for "what time is it?" queries.
/// OoO reordering error is ±2ns, irrelevant for 50µs deadlines.
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
/// Constant-rate, monotonic, unprivileged. Same calibration math applies.
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
/// Total with rdtsc: ~29 cycles = ~7.8ns at 3.7GHz.
/// Compare: clock_gettime vDSO = ~41 cycles = ~11-25ns.
#[inline(always)]
fn rdtsc_ns(cal: &TscCal) -> u64 {
    if !cal.valid { return clock_ns(); }
    let delta = read_tsc().wrapping_sub(cal.tsc_base);
    cal.mono_base.wrapping_add(
        ((delta as u128 * cal.mult as u128) >> cal.shift) as u64
    )
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
    // If any sample deviates by > 1µs, the calibration is bad.
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

#[inline(always)]
unsafe fn prefetch_read_l1(addr: *const u8) {
    #[cfg(target_arch = "x86_64")]
    { core::arch::x86_64::_mm_prefetch(addr as *const i8, core::arch::x86_64::_MM_HINT_T0); }
    #[cfg(target_arch = "aarch64")]
    { core::arch::asm!("prfm pldl1keep, [{addr}]", addr = in(reg) addr, options(nostack, preserves_flags)); }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { let _ = addr; }
}

// ============================================================================
// SPRINT 5.7: ISOCHRONOUS SCHEDULER (5.9: cwnd + pacing-aware)
// ============================================================================
#[derive(Copy, Clone)]
struct TxDesc { addr: u64, len: u32 }

struct Scheduler {
    critical: [TxDesc; 256],
    critical_len: usize,
    bulk: [TxDesc; 288],
    bulk_len: usize,
}

impl Scheduler {
    fn new() -> Self {
        Scheduler {
            critical: [TxDesc { addr: 0, len: 0 }; 256], critical_len: 0,
            bulk: [TxDesc { addr: 0, len: 0 }; 288], bulk_len: 0,
        }
    }
    /// Budget respects BBR cwnd (replaces hardcoded HW_FILL_MAX when BBR active).
    #[inline(always)]
    fn budget(&self, tx_avail: usize, cwnd: usize) -> usize {
        let inflight = TX_RING_SIZE.saturating_sub(tx_avail);
        let cap = cwnd.min(HW_FILL_MAX);
        cap.saturating_sub(inflight).min(tx_avail)
    }
    #[inline(always)]
    fn enqueue_critical(&mut self, addr: u64, len: u32) {
        if self.critical_len < self.critical.len() {
            self.critical[self.critical_len] = TxDesc { addr, len };
            self.critical_len += 1;
        }
    }
    #[inline(always)]
    fn enqueue_bulk(&mut self, addr: u64, len: u32) {
        if self.bulk_len < self.bulk.len() {
            self.bulk[self.bulk_len] = TxDesc { addr, len };
            self.bulk_len += 1;
        }
    }
    /// Schedule: critical bypasses pacing (strict priority), bulk capped by bulk_limit.
    fn schedule(&mut self, tx_path: &mut impl TxPath, stats: &Telemetry,
                bulk_limit: usize) -> usize {
        let avail = tx_path.available_slots() as usize;
        let hw_budget = {
            let inflight = TX_RING_SIZE.saturating_sub(avail);
            HW_FILL_MAX.saturating_sub(inflight).min(avail)
        };
        let mut submitted = 0usize;
        // Phase 1: Critical (feedback frames) — bypass pacing, HW-limited only
        let crit = self.critical_len.min(hw_budget);
        for i in 0..crit {
            tx_path.stage_tx_addr(self.critical[i].addr, self.critical[i].len);
            submitted += 1;
        }
        // Phase 2: Bulk (data frames) — pacing-limited AND HW-limited (FIFO order)
        let bulk_hw = hw_budget.saturating_sub(submitted);
        let bulk = self.bulk_len.min(bulk_hw).min(bulk_limit);
        for i in 0..bulk {
            tx_path.stage_tx_addr(self.bulk[i].addr, self.bulk[i].len);
            submitted += 1;
        }
        if submitted > 0 {
            tx_path.commit_tx();
            tx_path.kick_tx();
            stats.tx_count.value.fetch_add(submitted as u64, Ordering::Relaxed);
        }
        self.critical_len = 0;
        self.bulk_len = 0;
        submitted
    }
}

// ============================================================================
// SPRINT 5.9: WINDOWED MIN/MAX FILTER (Kathleen Nichols / Van Jacobson)
// Port of linux/lib/win_minmax.c to Rust with u64 time+value.
// O(1) space (3 samples), O(1) per update. Tracks best, 2nd, 3rd best.
// ============================================================================
#[derive(Copy, Clone)]
struct MinMaxSample { t: u64, v: u64 }

#[derive(Clone)]
struct WindowedFilter { s: [MinMaxSample; 3] }

impl WindowedFilter {
    fn new() -> Self { WindowedFilter { s: [MinMaxSample { t: 0, v: 0 }; 3] } }
    #[inline(always)] fn get(&self) -> u64 { self.s[0].v }

    fn reset(&mut self, t: u64, v: u64) {
        let val = MinMaxSample { t, v };
        self.s = [val; 3];
    }

    /// Windowed running maximum. `win` = window length in same units as `t`.
    fn running_max(&mut self, win: u64, t: u64, v: u64) -> u64 {
        let val = MinMaxSample { t, v };
        if v >= self.s[0].v || t.wrapping_sub(self.s[2].t) > win {
            self.reset(t, v); return v;
        }
        if v >= self.s[1].v { self.s[2] = val; self.s[1] = val; }
        else if v >= self.s[2].v { self.s[2] = val; }
        self.subwin_update(win, &val)
    }

    fn subwin_update(&mut self, win: u64, val: &MinMaxSample) -> u64 {
        let dt = val.t.wrapping_sub(self.s[0].t);
        if dt > win {
            self.s[0] = self.s[1]; self.s[1] = self.s[2]; self.s[2] = *val;
            if val.t.wrapping_sub(self.s[0].t) > win {
                self.s[0] = self.s[1]; self.s[1] = self.s[2]; self.s[2] = *val;
            }
        } else if self.s[1].t == self.s[0].t && dt > win / 4 {
            self.s[2] = *val; self.s[1] = *val;
        } else if self.s[2].t == self.s[1].t && dt > win / 2 {
            self.s[2] = *val;
        }
        self.s[0].v
    }
}

// ============================================================================
// SPRINT 5.9: TOKEN BUCKET PACER
// Accumulates nanosecond credit. When credit >= ns_per_packet, a token is
// available. Batch-level pacing: no per-packet busy-wait, preserves graph batching
// batching. When ns_per_packet == 0: unlimited (pre-measurement / Startup).
// Safety floor: BBR_MIN_PACING_RATE_PPS prevents zero-rate lockup.
// ============================================================================
const BBR_MIN_PACING_RATE_PPS: u64 = 100; // Floor: ~50Kbps

struct TokenBucket {
    ns_per_packet: u64,  // inter-packet gap in ns (0 = no pacing)
    credit_ns: u64,      // accumulated credit
    max_burst: u64,      // maximum tokens in bucket
}

impl TokenBucket {
    fn new(max_burst: u64) -> Self {
        TokenBucket { ns_per_packet: 0, credit_ns: 0, max_burst }
    }
    #[inline(always)]
    fn refill(&mut self, elapsed_ns: u64) {
        if self.ns_per_packet == 0 { self.credit_ns = self.max_burst; return; }
        self.credit_ns = (self.credit_ns + elapsed_ns).min(self.max_burst * self.ns_per_packet);
    }
    #[inline(always)]
    fn available(&self) -> usize {
        if self.ns_per_packet == 0 { return self.max_burst as usize; }
        (self.credit_ns / self.ns_per_packet) as usize
    }
    #[inline(always)]
    fn consume(&mut self, count: usize) {
        if self.ns_per_packet > 0 {
            self.credit_ns = self.credit_ns.saturating_sub(count as u64 * self.ns_per_packet);
        }
    }
    fn set_rate_pps(&mut self, pps: u64) {
        let effective = if pps == 0 { 0 } else { pps.max(BBR_MIN_PACING_RATE_PPS) };
        self.ns_per_packet = if effective > 0 { 1_000_000_000 / effective } else { 0 };
    }
}

// ============================================================================
// SPRINT 5.10: DETERMINISTIC JITTER BUFFER
// RFC 3550 EWMA jitter estimator + fixed-size circular buffer.
// TC_CRITICAL frames: stochastic arrival → deterministic playout.
// D_buf adaptive: k * J(ewma) + ε_proc, clamped [1ms, 100ms].
// ============================================================================
const JBUF_CAPACITY: usize = 64;       // 64 entries @ 100Hz = 640ms capacity
const JBUF_K: u64 = 4;                 // Safety factor: P(|X-μ|>4σ) < 0.0063%
const JBUF_MIN_DEPTH_NS: u64 = 1_000_000;     // Floor: 1ms
const JBUF_MAX_DEPTH_NS: u64 = 100_000_000;   // Ceiling: 100ms
const JBUF_DEFAULT_DEPTH_NS: u64 = 50_000_000; // Conservative initial: 50ms
const JBUF_EWMA_GAIN_SHIFT: u32 = 4;  // 1/16 = right shift by 4 (RFC 3550)

#[repr(C)]
#[derive(Copy, Clone)]
struct JitterEntry {
    addr: u64,       // UMEM frame address (slab slot stays allocated)
    len: u32,        // frame length in bytes
    release_ns: u64, // CLOCK_MONOTONIC time to release
}

/// RFC 3550 §6.4.1 interarrival jitter estimator.
/// J(i) = J(i-1) + (|D(i)| - J(i-1)) >> 4
/// D(i) = (R_i - R_{i-1}) - (S_i - S_{i-1})  [one-way delay variation]
struct JitterEstimator {
    last_rx_ns: u64,       // arrival time of previous TC_CRITICAL frame
    last_seq: u64,         // sequence number of previous frame
    jitter_ns: u64,        // current EWMA jitter estimate (ns)
    seq_interval_ns: u64,  // expected inter-packet interval (ns), 0 = unknown
}

impl JitterEstimator {
    fn new() -> Self {
        JitterEstimator { last_rx_ns: 0, last_seq: 0, jitter_ns: 0, seq_interval_ns: 0 }
    }
    /// Update jitter estimate with a new TC_CRITICAL frame arrival.
    /// rx_ns: CLOCK_MONOTONIC arrival time. seq: M13Header.seq_id.
    #[inline(always)]
    fn update(&mut self, rx_ns: u64, seq: u64) {
        if self.last_rx_ns == 0 {
            // First frame: seed the estimator, no jitter sample yet
            self.last_rx_ns = rx_ns;
            self.last_seq = seq;
            return;
        }
        // Receiver inter-arrival: R_i - R_{i-1}
        let rx_delta = rx_ns.saturating_sub(self.last_rx_ns);
        // Sender inter-departure: (S_i - S_{i-1}) approximated from seq deltas
        // If seq_interval_ns > 0, use it. Otherwise use rx_delta as baseline (no send clock).
        let seq_delta = seq.saturating_sub(self.last_seq);
        let send_delta = if self.seq_interval_ns > 0 && seq_delta > 0 {
            seq_delta * self.seq_interval_ns
        } else {
            rx_delta // No send clock → D=0, jitter stays unchanged
        };
        // D(i) = one-way delay variation
        let d = if rx_delta > send_delta {
            rx_delta - send_delta
        } else {
            send_delta - rx_delta
        };
        // RFC 3550 EWMA: J(i) = J(i-1) + (|D(i)| - J(i-1)) / 16
        if d > self.jitter_ns {
            self.jitter_ns += (d - self.jitter_ns) >> JBUF_EWMA_GAIN_SHIFT;
        } else {
            self.jitter_ns -= (self.jitter_ns - d) >> JBUF_EWMA_GAIN_SHIFT;
        }
        self.last_rx_ns = rx_ns;
        self.last_seq = seq;
    }
    #[inline(always)]
    fn get(&self) -> u64 { self.jitter_ns }
}

/// Fixed-size circular jitter buffer. Zero heap allocation.
/// Holds TC_CRITICAL frames until their deterministic release time.
#[repr(align(128))]
struct JitterBuffer {
    entries: [JitterEntry; JBUF_CAPACITY],
    head: usize,        // next slot to READ (oldest)
    tail: usize,        // next slot to WRITE (newest)
    depth_ns: u64,      // current D_buf in nanoseconds
    epsilon_ns: u64,    // worst-case processing time (measured at boot)
    estimator: JitterEstimator,
    total_releases: u64,
    total_drops: u64,
}

impl JitterBuffer {
    fn new(epsilon_ns: u64) -> Self {
        JitterBuffer {
            entries: [JitterEntry { addr: 0, len: 0, release_ns: 0 }; JBUF_CAPACITY],
            head: 0, tail: 0,
            depth_ns: JBUF_DEFAULT_DEPTH_NS,
            epsilon_ns,
            estimator: JitterEstimator::new(),
            total_releases: 0, total_drops: 0,
        }
    }

    /// Update jitter estimate and recalculate D_buf
    #[inline(always)]
    fn update_jitter(&mut self, rx_ns: u64, seq: u64) {
        self.estimator.update(rx_ns, seq);
        let j = self.estimator.get();
        if j > 0 {
            let raw = JBUF_K * j + self.epsilon_ns;
            self.depth_ns = raw.max(JBUF_MIN_DEPTH_NS).min(JBUF_MAX_DEPTH_NS);
        }
    }

    /// Insert a TC_CRITICAL frame. Slab slot stays allocated (NOT freed).
    /// Returns Some(dropped_addr) if overflow forced drop of oldest frame.
    /// Caller MUST free the returned slab slot to prevent UMEM leak.
    #[inline(always)]
    fn insert(&mut self, addr: u64, len: u32, rx_ns: u64) -> Option<u64> {
        let release_ns = rx_ns + self.depth_ns;
        let mut dropped_addr = None;
        // Overflow: if buffer is full, drop oldest (buffer undersized for this link)
        if self.tail - self.head >= JBUF_CAPACITY {
            let old_slot = self.head & (JBUF_CAPACITY - 1);
            dropped_addr = Some(self.entries[old_slot].addr);
            self.head += 1;
            self.total_drops += 1;
        }
        let slot = self.tail & (JBUF_CAPACITY - 1);
        self.entries[slot] = JitterEntry { addr, len, release_ns };
        self.tail += 1;
        dropped_addr
    }

    /// Drain due frames to scheduler as TC_CRITICAL. Returns (released, late_dropped).
    #[inline(always)]
    fn drain(&mut self, now_ns: u64, scheduler: &mut Scheduler) -> (usize, usize) {
        let mut released = 0usize;
        while self.head < self.tail {
            let slot = self.head & (JBUF_CAPACITY - 1);
            let e = &self.entries[slot];
            if now_ns >= e.release_ns {
                scheduler.enqueue_critical(e.addr, e.len);
                self.head += 1;
                released += 1;
                self.total_releases += 1;
            } else {
                // Not yet time. Entries are time-ordered (monotonic insertion).
                break;
            }
        }
        (released, 0)
    }

    #[allow(dead_code)] fn len(&self) -> usize { self.tail - self.head }
}

/// Measure worst-case hot-loop iteration time. Run 10K rdtsc_ns() pairs.
/// Uses rdtsc (the actual hot-path clock) so epsilon reflects real overhead.
fn measure_epsilon_proc(cal: &TscCal) -> u64 {
    let mut max_delta = 0u64;
    for _ in 0..10_000 {
        let t0 = rdtsc_ns(cal);
        // Simulate minimal work: one clock read (what a minimal loop iteration does)
        let t1 = rdtsc_ns(cal);
        let delta = t1.saturating_sub(t0);
        if delta > max_delta { max_delta = delta; }
    }
    // Add 2x safety margin for real classify+schedule overhead
    max_delta * 2
}

// ============================================================================
// SPRINT 5.9: BBRv3 STATE MACHINE
// Google BBRv3 gains (fixed-point numerator/denominator, no f64):
// ============================================================================
const BBR_STARTUP_PACING_NUM: u32 = 277;  const BBR_STARTUP_PACING_DEN: u32 = 100; // 2.77
const BBR_STARTUP_CWND_NUM: u32 = 2;      const BBR_STARTUP_CWND_DEN: u32 = 1;     // 2.0
const BBR_DRAIN_PACING_NUM: u32 = 100;    const BBR_DRAIN_PACING_DEN: u32 = 277;   // 0.361
const BBR_UP_PACING_NUM: u32 = 5;         const BBR_UP_PACING_DEN: u32 = 4;        // 1.25
const BBR_UP_CWND_NUM: u32 = 9;           const BBR_UP_CWND_DEN: u32 = 4;          // 2.25
const BBR_DOWN_PACING_NUM: u32 = 9;       const BBR_DOWN_PACING_DEN: u32 = 10;     // 0.9
const BBR_UNITY_NUM: u32 = 1;             const BBR_UNITY_DEN: u32 = 1;            // 1.0
const BBR_CWND_2X_NUM: u32 = 2;           const BBR_CWND_2X_DEN: u32 = 1;          // 2.0

const BBR_PROBE_RTT_CWND: u32 = 4;
const BBR_PROBE_RTT_DURATION_NS: u64 = 200_000_000;       // 200ms
const BBR_RTPROP_FILTER_LEN_NS: u64 = 10_000_000_000;     // 10 seconds
const BBR_BTLBW_FILTER_LEN: u64 = 10;                     // 10 rounds
const BBR_FULL_BW_GROWTH: u64 = 125;                       // 25% = must reach 125% of prior
const BBR_FULL_BW_COUNT: u32 = 3;                          // 3 rounds without 25% growth
const BBR_PROBE_CRUISE_MIN_NS: u64 = 2_000_000_000;       // 2 seconds
const BBR_CALIBRATION_THRESHOLD: u32 = 4;                  // 4 full ProbeBW cycles = calibrated
const BBR_CALIBRATION_DURATION_NS: u64 = 30_000_000_000;   // 30 seconds boot calibration

#[derive(Clone, Copy, PartialEq, Debug)]
enum BbrPhase { Startup, Drain, ProbeBW, ProbeRTT }

#[derive(Clone, Copy, PartialEq, Debug)]
enum ProbeBwPhase { Down, Cruise, Refill, Up }

struct BbrState {
    // Measurement
    btlbw_filter: WindowedFilter,
    rtprop_ns: u64,
    rtprop_stamp_ns: u64,
    // State machine
    phase: BbrPhase,
    probe_bw_phase: ProbeBwPhase,
    has_measurements: bool,
    // Active gains (fixed-point)
    pacing_num: u32, pacing_den: u32,
    cwnd_num: u32, cwnd_den: u32,
    // Derived
    pacing_rate_pps: u64,
    cwnd: u32,
    // Round tracking
    round_count: u64,
    next_round_seq: u64,
    round_start: bool,
    delivered: u64,
    // Startup
    full_bw: u64,
    full_bw_count: u32,
    // ProbeRTT
    probe_rtt_done_ns: u64,
    probe_rtt_round_done: bool,
    // ProbeBW
    probe_cruise_start_ns: u64,
    probe_up_rounds: u32,
    prior_probe_bw: u64,
    // Calibration
    calibrated: bool,
    calibration_cycles: u32,
    // Feedback bookkeeping
    last_feedback_time_ns: u64,
    feedback_count: u64,
    // Loss detection
    loss_in_round: u32,
    // ECN tracking (Sprint 5.19): receiver-driven congestion signal
    ecn_in_round: u32,              // ECN-marked feedbacks in current round
    ecn_consecutive_rounds: u32,    // consecutive rounds with ECN (for cwnd reduction)
    // Probe safety (Sprint 5.20): BBRv3-compliant drain verification + inflight cap
    est_inflight: u64,              // estimated packets in flight = send_seq - highest_ack
    down_rounds: u32,               // rounds spent in ProbeBW:Down (safety upper bound)
}

impl BbrState {
    fn new() -> Self {
        BbrState {
            btlbw_filter: WindowedFilter::new(),
            rtprop_ns: u64::MAX, rtprop_stamp_ns: 0,
            phase: BbrPhase::Startup,
            probe_bw_phase: ProbeBwPhase::Cruise,
            has_measurements: false,
            pacing_num: BBR_STARTUP_PACING_NUM, pacing_den: BBR_STARTUP_PACING_DEN,
            cwnd_num: BBR_STARTUP_CWND_NUM, cwnd_den: BBR_STARTUP_CWND_DEN,
            pacing_rate_pps: 0, cwnd: HW_FILL_MAX as u32,
            round_count: 0, next_round_seq: 0, round_start: false, delivered: 0,
            full_bw: 0, full_bw_count: 0,
            probe_rtt_done_ns: 0, probe_rtt_round_done: false,
            probe_cruise_start_ns: 0, probe_up_rounds: 0, prior_probe_bw: 0,
            calibrated: false, calibration_cycles: 0,
            last_feedback_time_ns: 0, feedback_count: 0,
            loss_in_round: 0,
            ecn_in_round: 0,
            ecn_consecutive_rounds: 0,
            est_inflight: 0,
            down_rounds: 0,
        }
    }

    fn bdp_packets(&self) -> u32 {
        let bw = self.btlbw_filter.get();
        if bw == 0 || self.rtprop_ns == u64::MAX { return HW_FILL_MAX as u32; }
        let frame_bits = DATA_FRAME_WIRE_SIZE as u128 * 8; // 496
        ((bw as u128 * self.rtprop_ns as u128) / (frame_bits * 1_000_000_000u128)).max(4) as u32
    }

    fn rtprop_expired(&self, now_ns: u64) -> bool {
        self.rtprop_stamp_ns > 0 && now_ns.saturating_sub(self.rtprop_stamp_ns) > BBR_RTPROP_FILTER_LEN_NS
    }

    fn effective_cwnd(&self) -> usize {
        if !self.has_measurements { return HW_FILL_MAX; }
        let base = (self.cwnd as usize).min(HW_FILL_MAX);
        // Sprint 5.20: BBRv3 probe safety — cap inflight to 2×BDP during ProbeBW:Up.
        // Prevents probe flooding on shallow buffers (e.g., JBUF_CAPACITY=64).
        // Spec ref: draft-ietf-ccwg-bbr-04 §5.3.3.4 — inflight_longterm caps probing.
        if self.phase == BbrPhase::ProbeBW
            && self.probe_bw_phase == ProbeBwPhase::Up
        {
            let bdp = self.bdp_packets() as usize;
            let cap = (bdp.saturating_mul(2)).max(4);
            return base.min(cap);
        }
        base
    }

    fn phase_as_u32(&self) -> u32 {
        match self.phase {
            BbrPhase::Startup => 0, BbrPhase::Drain => 1,
            BbrPhase::ProbeBW => 2, BbrPhase::ProbeRTT => 3,
        }
    }

    // ---- GAINS ----
    fn sync_gains(&mut self) {
        match self.phase {
            BbrPhase::Startup => {
                self.pacing_num = BBR_STARTUP_PACING_NUM; self.pacing_den = BBR_STARTUP_PACING_DEN;
                self.cwnd_num = BBR_STARTUP_CWND_NUM;     self.cwnd_den = BBR_STARTUP_CWND_DEN;
            }
            BbrPhase::Drain => {
                self.pacing_num = BBR_DRAIN_PACING_NUM; self.pacing_den = BBR_DRAIN_PACING_DEN;
                self.cwnd_num = BBR_CWND_2X_NUM;        self.cwnd_den = BBR_CWND_2X_DEN;
            }
            BbrPhase::ProbeBW => match self.probe_bw_phase {
                ProbeBwPhase::Up => {
                    self.pacing_num = BBR_UP_PACING_NUM; self.pacing_den = BBR_UP_PACING_DEN;
                    self.cwnd_num = BBR_UP_CWND_NUM;     self.cwnd_den = BBR_UP_CWND_DEN;
                }
                ProbeBwPhase::Down => {
                    self.pacing_num = BBR_DOWN_PACING_NUM; self.pacing_den = BBR_DOWN_PACING_DEN;
                    self.cwnd_num = BBR_CWND_2X_NUM;       self.cwnd_den = BBR_CWND_2X_DEN;
                }
                ProbeBwPhase::Cruise | ProbeBwPhase::Refill => {
                    self.pacing_num = BBR_UNITY_NUM; self.pacing_den = BBR_UNITY_DEN;
                    self.cwnd_num = BBR_CWND_2X_NUM; self.cwnd_den = BBR_CWND_2X_DEN;
                }
            }
            BbrPhase::ProbeRTT => {
                self.pacing_num = BBR_UNITY_NUM; self.pacing_den = BBR_UNITY_DEN;
                self.cwnd_num = BBR_UNITY_NUM;   self.cwnd_den = BBR_UNITY_DEN;
            }
        }
    }

    // ---- DERIVED RATES ----
    fn recompute_pacing(&mut self, bucket: &mut TokenBucket) {
        let bw = self.btlbw_filter.get();
        if bw == 0 { self.pacing_rate_pps = 0; bucket.set_rate_pps(0); return; }
        let frame_bits = DATA_FRAME_WIRE_SIZE as u128 * 8; // 496
        self.pacing_rate_pps = ((bw as u128 * self.pacing_num as u128)
            / (self.pacing_den as u128 * frame_bits)) as u64;
        bucket.set_rate_pps(self.pacing_rate_pps);
    }

    fn recompute_cwnd(&mut self) {
        if self.phase == BbrPhase::ProbeRTT { self.cwnd = BBR_PROBE_RTT_CWND; return; }
        let bdp = self.bdp_packets();
        self.cwnd = ((bdp as u64 * self.cwnd_num as u64 / self.cwnd_den as u64) as u32)
            .max(4).min(HW_FILL_MAX as u32);
    }

    // ---- ROUND TRACKING ----
    fn advance_round(&mut self, highest_ack_seq: u64, current_send_seq: u64) {
        self.round_start = false;
        if highest_ack_seq >= self.next_round_seq {
            self.round_count += 1;
            self.next_round_seq = current_send_seq;
            self.round_start = true;
        }
    }

    // ---- RTprop (expiring min, 10-second window) ----
    fn update_rtprop(&mut self, rtt_ns: u64, now_ns: u64) {
        if now_ns.saturating_sub(self.rtprop_stamp_ns) > BBR_RTPROP_FILTER_LEN_NS {
            self.rtprop_ns = rtt_ns;
            self.rtprop_stamp_ns = now_ns;
        } else if rtt_ns <= self.rtprop_ns {
            self.rtprop_ns = rtt_ns;
            self.rtprop_stamp_ns = now_ns;
        }
    }

    // ---- PHASE TRANSITIONS ----
    fn update_phase(&mut self, now_ns: u64) {
        match self.phase {
            BbrPhase::Startup => {
                if self.round_start {
                    let bw = self.btlbw_filter.get();
                    if self.full_bw > 0 && bw * 100 < self.full_bw * BBR_FULL_BW_GROWTH {
                        self.full_bw_count += 1;
                    } else {
                        self.full_bw = bw;
                        self.full_bw_count = 0;
                    }
                    if self.full_bw_count >= BBR_FULL_BW_COUNT {
                        self.phase = BbrPhase::Drain;
                    }
                }
            }
            BbrPhase::Drain => {
                // Exit Drain after 1 round (queue should have drained at 0.36x rate)
                if self.round_start {
                    self.phase = BbrPhase::ProbeBW;
                    self.probe_bw_phase = ProbeBwPhase::Down;
                }
            }
            BbrPhase::ProbeBW => self.update_probe_bw(now_ns),
            BbrPhase::ProbeRTT => {
                if self.probe_rtt_done_ns == 0 {
                    self.probe_rtt_done_ns = now_ns + BBR_PROBE_RTT_DURATION_NS;
                    self.probe_rtt_round_done = false;
                }
                if self.round_start { self.probe_rtt_round_done = true; }
                if now_ns >= self.probe_rtt_done_ns && self.probe_rtt_round_done {
                    self.rtprop_stamp_ns = now_ns;
                    self.phase = BbrPhase::ProbeBW;
                    self.probe_bw_phase = ProbeBwPhase::Cruise;
                    self.probe_cruise_start_ns = now_ns;
                    self.probe_rtt_done_ns = 0;
                }
            }
        }
        // ProbeRTT entry from any non-ProbeRTT phase
        if self.phase != BbrPhase::ProbeRTT && self.rtprop_expired(now_ns) {
            self.phase = BbrPhase::ProbeRTT;
            self.probe_rtt_done_ns = 0;
        }
    }

    fn update_probe_bw(&mut self, now_ns: u64) {
        match self.probe_bw_phase {
            ProbeBwPhase::Up => {
                if self.round_start {
                    self.probe_up_rounds += 1;
                    let bw = self.btlbw_filter.get();
                    let no_growth = self.prior_probe_bw > 0
                        && bw * 100 < self.prior_probe_bw * BBR_FULL_BW_GROWTH;
                    if no_growth || self.probe_up_rounds >= 3 {
                        self.probe_bw_phase = ProbeBwPhase::Down;
                        self.down_rounds = 0; // Reset drain round counter
                        self.calibration_cycles += 1;
                        if self.calibration_cycles >= BBR_CALIBRATION_THRESHOLD {
                            self.calibrated = true;
                        }
                    }
                }
            }
            ProbeBwPhase::Down => {
                // Sprint 5.20: Drain verification per BBRv3 spec §5.3.3.1.
                // Transition Down→Cruise ONLY when inflight ≤ BDP (drain complete).
                // Safety: max 8 rounds in Down to prevent livelock if BDP is wrong.
                if self.round_start {
                    self.down_rounds += 1;
                    let bdp = self.bdp_packets() as u64;
                    let drained = self.est_inflight <= bdp || bdp == 0;
                    if drained || self.down_rounds >= 8 {
                        self.probe_bw_phase = ProbeBwPhase::Cruise;
                        self.probe_cruise_start_ns = now_ns;
                        self.down_rounds = 0;
                    }
                }
            }
            ProbeBwPhase::Cruise => {
                if now_ns.saturating_sub(self.probe_cruise_start_ns) >= BBR_PROBE_CRUISE_MIN_NS {
                    self.probe_bw_phase = ProbeBwPhase::Refill;
                }
            }
            ProbeBwPhase::Refill => {
                if self.round_start {
                    self.probe_bw_phase = ProbeBwPhase::Up;
                    self.probe_up_rounds = 0;
                    self.prior_probe_bw = self.btlbw_filter.get();
                }
            }
        }
    }

    // ---- TOP-LEVEL FEEDBACK HANDLER ----
    fn on_feedback(
        &mut self, fb: &FeedbackFrame, send_times: &[u64],
        now_ns: u64, current_send_seq: u64, bucket: &mut TokenBucket,
        ecn: bool,
    ) {
        self.delivered += fb.delivered as u64;

        // 1. BtlBw sample (delivery rate via windowed max filter)
        if self.last_feedback_time_ns > 0 && fb.delivered > 0 {
            let interval = fb.delivered_time_ns.saturating_sub(self.last_feedback_time_ns);
            if interval > 0 {
                let bits = (fb.delivered as u64) * DATA_FRAME_WIRE_SIZE * 8;
                let rate = ((bits as u128) * 1_000_000_000u128 / interval as u128) as u64;
                self.btlbw_filter.running_max(BBR_BTLBW_FILTER_LEN, self.round_count, rate);
            }
        }

        // 2. RTprop sample (sender-clock RTT, expiring min filter)
        let seq_idx = fb.highest_seq as usize & SEQ_WINDOW_MASK;
        let st = send_times[seq_idx];
        if st > 0 && now_ns > st {
            let rtt_sample = now_ns - st;
            // Sanity bound: reject RTT samples > 30s. At 1Mpps, the 131072-entry
            // seq window wraps in 131ms. Without this guard, stale timestamps from
            // a prior epoch produce multi-second "RTT" values that poison RTprop.
            if rtt_sample < 30_000_000_000 {
                self.update_rtprop(rtt_sample, now_ns);
            }
        }

        // 3. Round tracking (sequence-based)
        self.advance_round(fb.highest_seq, current_send_seq);

        // 3b. Inflight estimation (Sprint 5.20): packets sent but not yet acknowledged.
        // Used by drain verification to decide when ProbeBW:Down->Cruise is safe.
        // Approximate: doesn't subtract lost packets, but sufficient for drain check.
        self.est_inflight = current_send_seq.saturating_sub(fb.highest_seq);

        // 4. Phase transitions
        self.update_phase(now_ns);

        // 5. Sync gains + recompute rates
        self.sync_gains();
        self.recompute_pacing(bucket);
        self.recompute_cwnd();

        // 6. Loss detection — ground-truth from RxBitmap sequence gap tracking.
        // fb.loss_count = exact number of sequence gaps detected since last feedback.
        // Replaces the delivery-rate heuristic (circular reasoning, 50% threshold).
        // 3 consecutive rounds with loss → persistent loss → future FEC trigger.
        if fb.loss_count > 0 {
            self.loss_in_round += 1;
        } else if self.round_start {
            // Only reset at round boundaries — sporadic zero-loss feedback
            // between loss events should not immediately clear the counter.
            self.loss_in_round = 0;
        }
        // Sprint 5.22: if self.loss_in_round >= 3 { increase RLNC coded rate }

        // 7. ECN response — receiver-driven congestion signal (Sprint 5.19)
        // ECN is softer than loss: receiver marks at 75% jbuf occupancy or on any gap.
        // Immediate: reduce pacing to drain gain (0.9x) on ANY ECN feedback.
        // Sustained: if ECN persists for >= 2 consecutive rounds, reduce cwnd to 3/4.
        // Hysteresis: clear ECN state after 4 rounds of no-ECN to prevent oscillation.
        if ecn {
            self.ecn_in_round += 1;
            // Immediate response: force drain-level pacing (0.9x = 9/10)
            if self.phase == BbrPhase::ProbeBW && self.pacing_num > 9 * self.pacing_den / 10 {
                self.pacing_num = 9;
                self.pacing_den = 10;
                self.recompute_pacing(bucket);
            }
        }
        if self.round_start {
            if self.ecn_in_round > 0 {
                self.ecn_consecutive_rounds += 1;
                // Persistent ECN (>= 2 rounds): reduce cwnd to 3/4.
                // Gentler than TCP's 1/2 because ECN fires earlier than loss.
                if self.ecn_consecutive_rounds >= 2 {
                    self.cwnd = (self.cwnd * 3 / 4).max(4);
                }
            } else {
                // No ECN for this round. Decrement toward 0 with 4-round hysteresis.
                self.ecn_consecutive_rounds = self.ecn_consecutive_rounds.saturating_sub(1);
            }
            self.ecn_in_round = 0;
        }

        self.has_measurements = true;
        self.last_feedback_time_ns = fb.delivered_time_ns;
        self.feedback_count += 1;
    }

    fn phase_label(&self) -> &'static str {
        match self.phase {
            BbrPhase::Startup => "STARTUP",
            BbrPhase::Drain => "DRAIN",
            BbrPhase::ProbeBW => match self.probe_bw_phase {
                ProbeBwPhase::Up => "PBW:UP", ProbeBwPhase::Down => "PBW:DN",
                ProbeBwPhase::Cruise => "PBW:CR", ProbeBwPhase::Refill => "PBW:RF",
            },
            BbrPhase::ProbeRTT => "P_RTT",
        }
    }
}

// ============================================================================
// RECEIVER STATE — tracks delivered packets for feedback generation
// ============================================================================
// ============================================================================
// SPRINT 5.18: RX BITMAP — 1024-BIT SLIDING WINDOW LOSS DETECTOR
// Tracks which seq_ids have been received. Zeros = gaps = losses.
// O(1) mark via bitmask. O(words) advance via popcount.
// Stack-allocated: 128 bytes = 2 cache lines.
// ============================================================================

/// 1024-bit sliding window bitmap for sequence gap detection.
/// bit N = 1 means seq_id (base_seq + N) has been received.
/// When the window advances, evicted zero-bits are counted as losses.
struct RxBitmap {
    bits: [u64; 16],       // 1024 bits = 16 x u64
    base_seq: u64,         // seq_id corresponding to bit 0
    loss_accum: u32,       // losses accumulated since last feedback
    highest_marked: u64,   // highest seq_id marked in the bitmap
}

impl RxBitmap {
    fn new() -> Self {
        RxBitmap { bits: [0u64; 16], base_seq: 0, loss_accum: 0, highest_marked: 0 }
    }

    /// Mark a seq_id as received. Advances the window if seq exceeds capacity.
    /// O(1) for in-window marks. O(words_shifted) for window advance.
    #[inline(always)]
    fn mark(&mut self, seq: u64) {
        // Ignore packets before our window (too old — already evicted)
        if seq < self.base_seq { return; }

        let offset = seq - self.base_seq;

        // If seq exceeds window, advance. Count gaps in evicted words.
        if offset >= 1024 {
            self.advance_to(seq);
        }

        let offset = (seq - self.base_seq) as usize;
        if offset < 1024 {
            let word = offset >> 6;   // offset / 64
            let bit = offset & 63;    // offset % 64
            self.bits[word] |= 1u64 << bit;
        }

        if seq > self.highest_marked {
            self.highest_marked = seq;
        }
    }

    /// Advance window so that `seq` fits within [base_seq, base_seq+1023].
    /// Evicted words have their zero-bits counted as losses.
    fn advance_to(&mut self, seq: u64) {
        // How many words to shift out
        let target_base = seq.saturating_sub(1023);
        if target_base <= self.base_seq { return; }

        let bit_shift = target_base - self.base_seq;
        let word_shift = (bit_shift / 64) as usize;

        if word_shift >= 16 {
            // Entire window evicted — count all unmarked bits as losses
            for w in 0..16 {
                // Only count losses for sequence ranges we've actually entered
                // (bits that were zero because we hadn't reached them yet aren't losses)
                let word_base = self.base_seq + (w as u64 * 64);
                if word_base < self.highest_marked {
                    let relevant_bits = if word_base + 64 <= self.highest_marked {
                        64
                    } else {
                        (self.highest_marked - word_base) as u32
                    };
                    let received = self.bits[w].count_ones().min(relevant_bits);
                    self.loss_accum += relevant_bits - received;
                }
            }
            self.bits = [0u64; 16];
        } else {
            // Partial shift: count gaps in evicted words, shift array
            for w in 0..word_shift {
                if w < 16 {
                    let word_base = self.base_seq + (w as u64 * 64);
                    if word_base < self.highest_marked {
                        let relevant_bits = if word_base + 64 <= self.highest_marked {
                            64
                        } else {
                            (self.highest_marked - word_base) as u32
                        };
                        let received = self.bits[w].count_ones().min(relevant_bits);
                        self.loss_accum += relevant_bits - received;
                    }
                }
            }
            // Shift remaining words left
            let remain = 16 - word_shift;
            for i in 0..remain {
                self.bits[i] = self.bits[i + word_shift];
            }
            for i in remain..16 {
                self.bits[i] = 0;
            }
        }
        self.base_seq = target_base;
    }

    /// Return (loss_count, nack_bitmap) and reset accumulator.
    /// nack_bitmap: 64 bits relative to highest_marked-63.
    /// Bit i = 1 means received, bit i = 0 means lost.
    fn drain_losses(&mut self) -> (u32, u64) {
        let losses = self.loss_accum;
        self.loss_accum = 0;

        // Build NACK bitmap: the 64 bits around highest_marked
        let nack = if self.highest_marked >= self.base_seq + 63 {
            let nack_base = self.highest_marked - 63;
            if nack_base >= self.base_seq {
                let offset = (nack_base - self.base_seq) as usize;
                // Extract 64 contiguous bits starting at 'offset'
                let word_idx = offset >> 6;
                let bit_idx = offset & 63;
                if bit_idx == 0 && word_idx < 16 {
                    self.bits[word_idx]
                } else if word_idx + 1 < 16 {
                    // Cross-word extraction
                    let lo = self.bits[word_idx] >> bit_idx;
                    let hi = self.bits[word_idx + 1] << (64 - bit_idx);
                    lo | hi
                } else if word_idx < 16 {
                    self.bits[word_idx] >> bit_idx
                } else {
                    u64::MAX // all received (out of range)
                }
            } else {
                u64::MAX // all within range received
            }
        } else {
            u64::MAX // not enough data yet
        };

        (losses, nack)
    }
}

struct ReceiverState {
    highest_seq: u64, delivered: u32,
    last_feedback_ns: u64, last_rx_batch_ns: u64,
}
impl ReceiverState {
    fn new() -> Self { ReceiverState { highest_seq: 0, delivered: 0, last_feedback_ns: 0, last_rx_batch_ns: 0 } }
    #[inline(always)]
    fn needs_feedback(&self, now_ns: u64, rtt_estimate_ns: u64) -> bool {
        if self.delivered >= FEEDBACK_INTERVAL_PKTS { return true; }
        if self.delivered > 0 && self.last_feedback_ns > 0
            && now_ns.saturating_sub(self.last_feedback_ns) >= rtt_estimate_ns { return true; }
        false
    }
}

// ============================================================================
// SPRINT 6.1: FRAGMENTATION ENGINE (cold path — handshake only)
// ============================================================================

/// Fragment sub-header. 8 bytes, prepended to payload when FLAG_FRAGMENT set.
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct FragHeader {
    frag_msg_id: u16,   // Message ID (links fragments of same message)
    frag_index: u8,     // Fragment index (0-based)
    frag_total: u8,     // Total fragments in message
    frag_offset: u16,   // Byte offset into original message
    frag_len: u16,      // Bytes in this fragment
}
const FRAG_HDR_SIZE: usize = 8;
const _FRAG_SZ: () = assert!(std::mem::size_of::<FragHeader>() == FRAG_HDR_SIZE);

/// Maximum fragment payload = 1452 (max M13 payload) - 8 (frag header) = 1444
#[allow(dead_code)] const MAX_FRAG_PAYLOAD: usize = 1444;

#[allow(dead_code)]
struct Fragment { msg_id: u16, index: u8, total: u8, offset: u16, data: Vec<u8> }

#[allow(dead_code)]
fn fragment_message(payload: &[u8], max_frag_size: usize, msg_id: u16) -> Vec<Fragment> {
    let actual_max = max_frag_size.min(MAX_FRAG_PAYLOAD);
    if payload.is_empty() { return Vec::new(); }
    let frag_count = (payload.len() + actual_max - 1) / actual_max;
    assert!(frag_count <= 16, "Too many fragments (max 16)");
    let total = frag_count as u8;
    let mut frags = Vec::with_capacity(frag_count);
    let mut offset = 0usize;
    for i in 0..frag_count {
        let end = (offset + actual_max).min(payload.len());
        frags.push(Fragment {
            msg_id, index: i as u8, total, offset: offset as u16,
            data: payload[offset..end].to_vec(),
        });
        offset = end;
    }
    frags
}

struct AssemblyBuffer {
    fragments: [Option<Vec<u8>>; 16], received_mask: u16,
    total: u8, first_rx_ns: u64,
}
impl AssemblyBuffer {
    fn new(total: u8, now_ns: u64) -> Self {
        AssemblyBuffer { fragments: Default::default(), received_mask: 0, total, first_rx_ns: now_ns }
    }
    fn insert(&mut self, index: u8, _offset: u16, data: &[u8]) -> bool {
        if index >= 16 || index >= self.total { return false; }
        let bit = 1u16 << index;
        if self.received_mask & bit != 0 { return self.is_complete(); }
        self.fragments[index as usize] = Some(data.to_vec());
        self.received_mask |= bit;
        self.is_complete()
    }
    fn is_complete(&self) -> bool {
        let expected = (1u16 << self.total) - 1;
        self.received_mask & expected == expected
    }
    fn reassemble(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for i in 0..self.total as usize {
            if let Some(ref data) = self.fragments[i] { result.extend_from_slice(data); }
        }
        result
    }
}

struct Assembler { pending: HashMap<u16, AssemblyBuffer>, }
impl Assembler {
    fn new() -> Self { Assembler { pending: HashMap::new() } }
    fn feed(&mut self, msg_id: u16, index: u8, total: u8, offset: u16,
            data: &[u8], now_ns: u64) -> Option<Vec<u8>> {
        let buf = self.pending.entry(msg_id).or_insert_with(|| AssemblyBuffer::new(total, now_ns));
        if buf.insert(index, offset, data) {
            let result = buf.reassemble();
            self.pending.remove(&msg_id);
            Some(result)
        } else { None }
    }
    fn gc(&mut self, now_ns: u64) {
        self.pending.retain(|_, buf| now_ns.saturating_sub(buf.first_rx_ns) < 5_000_000_000);
    }
}

// ============================================================================
// SPRINT 6.2: INLINE ChaCha20-Poly1305 AEAD (RFC 8439)
// Zero external crates in hot path. Constant-time. ARX maps to ARM A53 ALU.
// ============================================================================

#[inline(always)]
fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(7);
}

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

fn poly1305_aead_mac(otk: &[u8; 32], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut buf = [0u8; 1536];
    let mut len = 0usize;
    buf[len..len+aad.len()].copy_from_slice(aad); len += aad.len();
    len += (16 - (aad.len() % 16)) % 16;
    buf[len..len+ct.len()].copy_from_slice(ct); len += ct.len();
    len += (16 - (ct.len() % 16)) % 16;
    buf[len..len+8].copy_from_slice(&(aad.len() as u64).to_le_bytes()); len += 8;
    buf[len..len+8].copy_from_slice(&(ct.len() as u64).to_le_bytes()); len += 8;
    poly1305_mac(otk, &buf[..len])
}

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

fn open_frame(frame: &mut [u8], key: &[u8; 32], our_dir: u8) -> bool {
    let sig = ETH_HDR_SIZE;
    if frame.len() < sig + 32 + 8 { return false; }
    if frame[sig+2] != 0x01 { return false; }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&frame[sig+20..sig+32]);
    if nonce[8] == our_dir { return false; }
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

#[inline(never)]
fn zeroize(buf: &mut [u8]) {
    for byte in buf.iter_mut() { unsafe { core::ptr::write_volatile(byte, 0); } }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// ============================================================================
// SPRINT 6.3: PQC HANDSHAKE — HUB RESPONDER
// ============================================================================
// Hub receives:
//   Msg 1 (ClientHello): nonce(32) + ek(1568) + pk_node(2592) = 4192 bytes
//   Msg 3 (Finished):    sig_node(4627) bytes
// Hub sends:
//   Msg 2 (ServerHello): ct(1568) + pk_hub(2592) + sig_hub(4627) = 8787 bytes
//
// Session key = HKDF-SHA-512(salt=nonce, IKM=ML-KEM-ss, info="M13-PQC-SESSION-KEY-v1", L=32)
// ============================================================================

const PQC_CONTEXT: &[u8] = b"M13-HS-v1";
const PQC_INFO: &[u8] = b"M13-PQC-SESSION-KEY-v1";

/// Hub-side handshake state: stored between ClientHello and Finished processing.
struct HubHandshakeState {
    /// Node's ML-DSA-87 verifying key bytes (for Finished verification)
    node_pk_bytes: Vec<u8>,
    /// ML-KEM shared secret (32 bytes, derived from encapsulation)
    shared_secret: [u8; 32],
    /// Session nonce from ClientHello (32 bytes, HKDF salt)
    session_nonce: [u8; 32],
    /// Full ClientHello payload bytes (for transcript computation)
    client_hello_bytes: Vec<u8>,
    /// Full ServerHello payload bytes (for transcript computation)
    server_hello_bytes: Vec<u8>,
    /// Handshake start timestamp (for timeout)
    started_ns: u64,
}

/// Send fragmented handshake payload over UDP (Hub cold-path mirror of Node's helper).
fn send_fragmented_udp_hub(
    sock: &std::net::UdpSocket,
    addr: &std::net::SocketAddr,
    src_mac: &[u8; 6],
    payload: &[u8],
    flags: u8,
    seq: &mut u64,
    hexdump: &mut HexdumpState,
    cal: &TscCal,
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
        // dst = broadcast (Node identifies by addr), src = hub MAC
        frame[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
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
        hexdump.dump_tx(frame.as_ptr(), flen, rdtsc_ns(cal));
        if sock.send_to(&frame, addr).is_ok() { sent += 1; }
        *seq += 1;
    }
    sent
}

/// Process a ClientHello (Msg 1) from a Node.
/// Encapsulates shared secret, signs transcript, sends ServerHello (Msg 2).
/// Returns HubHandshakeState for use when Finished arrives.
///
/// ClientHello layout: type(1) + nonce(32) + ek(1568) + pk_node(2592) = 4193 bytes
/// ServerHello layout: type(1) + ct(1568) + pk_hub(2592) + sig_hub(4627) = 8788 bytes
fn process_client_hello_hub(
    reassembled: &[u8],
    sock: &std::net::UdpSocket,
    addr: &std::net::SocketAddr,
    src_mac: &[u8; 6],
    seq: &mut u64,
    hexdump: &mut HexdumpState,
    cal: &TscCal,
    now: u64,
) -> Option<HubHandshakeState> {
    // Validate: type(1) + nonce(32) + ek(1568) + pk_node(2592) = 4193
    const EXPECTED_LEN: usize = 1 + 32 + 1568 + 2592;
    if reassembled.len() < EXPECTED_LEN {
        eprintln!("[M13-HUB-PQC] ERROR: ClientHello too short: {} < {}", reassembled.len(), EXPECTED_LEN);
        return None;
    }
    if reassembled[0] != HS_CLIENT_HELLO {
        eprintln!("[M13-HUB-PQC] ERROR: Expected ClientHello (0x01), got 0x{:02X}", reassembled[0]);
        return None;
    }

    eprintln!("[M13-HUB-PQC] Processing ClientHello ({}B)...", reassembled.len());

    // Parse fields
    let mut session_nonce = [0u8; 32];
    session_nonce.copy_from_slice(&reassembled[1..33]);
    let ek_bytes = &reassembled[33..1601];        // ML-KEM-1024 encapsulation key (1568B)
    let pk_node_bytes = &reassembled[1601..4193];  // ML-DSA-87 verifying key (2592B)

    // 1. Reconstruct EncapsulationKey from bytes
    let ek_enc = match ml_kem::Encoded::<ml_kem::kem::EncapsulationKey<ml_kem::MlKem1024Params>>::try_from(
        ek_bytes
    ) {
        Ok(enc) => enc,
        Err(_) => {
            eprintln!("[M13-HUB-PQC] ERROR: Failed to parse EncapsulationKey");
            return None;
        }
    };
    let ek = ml_kem::kem::EncapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(&ek_enc);

    // 2. Encapsulate: ek + OsRng → (ct, ss)
    let (ct, ss) = match ek.encapsulate(&mut OsRng) {
        Ok((ct, ss)) => (ct, ss),
        Err(_) => {
            eprintln!("[M13-HUB-PQC] ERROR: ML-KEM encapsulation failed");
            return None;
        }
    };
    let ct_bytes_arr = ct;
    eprintln!("[M13-HUB-PQC] ML-KEM-1024 encapsulation successful (ct={}B, ss=32B)", ct_bytes_arr.len());

    // 3. Generate Hub's ML-DSA-87 identity keypair (TOFU)
    let dsa_kp = MlDsa87::key_gen(&mut OsRng);
    let pk_hub = dsa_kp.verifying_key().encode(); // 2592 bytes
    eprintln!("[M13-HUB-PQC] ML-DSA-87 identity generated (pk={}B)", pk_hub.len());

    // 4. Compute transcript = SHA-512(ClientHello_payload || ct)
    let mut hasher = Sha512::new();
    hasher.update(reassembled);
    hasher.update(ct_bytes_arr.as_slice());
    let transcript: [u8; 64] = hasher.finalize().into();

    // 5. Sign transcript with Hub's signing key
    let sig_hub = match dsa_kp.signing_key().sign_deterministic(&transcript, PQC_CONTEXT) {
        Ok(sig) => sig,
        Err(_) => {
            eprintln!("[M13-HUB-PQC] ERROR: ML-DSA signing failed");
            return None;
        }
    };
    let sig_hub_bytes = sig_hub.encode(); // 4627 bytes
    eprintln!("[M13-HUB-PQC] Hub signature generated ({}B)", sig_hub_bytes.len());

    // 6. Build ServerHello payload: type(1) + ct(1568) + pk_hub(2592) + sig_hub(4627) = 8788
    let mut server_hello = Vec::with_capacity(1 + ct_bytes_arr.len() + pk_hub.len() + sig_hub_bytes.len());
    server_hello.push(HS_SERVER_HELLO);
    server_hello.extend_from_slice(ct_bytes_arr.as_slice());
    server_hello.extend_from_slice(&pk_hub);
    server_hello.extend_from_slice(&sig_hub_bytes);

    // 7. Send ServerHello as fragmented frames
    let hs_flags = FLAG_CONTROL | FLAG_HANDSHAKE;
    let frags = send_fragmented_udp_hub(sock, addr, src_mac, &server_hello, hs_flags, seq, hexdump, cal);
    eprintln!("[M13-HUB-PQC] ServerHello sent: {}B payload, {} fragments", server_hello.len(), frags);

    // 8. Store intermediate state for Finished processing
    let mut ss_arr = [0u8; 32];
    ss_arr.copy_from_slice(&ss);
    Some(HubHandshakeState {
        node_pk_bytes: pk_node_bytes.to_vec(),
        shared_secret: ss_arr,
        session_nonce,
        client_hello_bytes: reassembled.to_vec(),
        server_hello_bytes: server_hello,
        started_ns: now,
    })
}

/// Process a Finished message (Msg 3) from a Node.
/// Verifies Node's ML-DSA-87 signature, derives session key via HKDF-SHA-512.
/// Returns session_key on success.
///
/// Finished layout: type(1) + sig_node(4627) = 4628 bytes
fn process_finished_hub(
    reassembled: &[u8],
    hs_state: &HubHandshakeState,
) -> Option<[u8; 32]> {
    // Validate length: type(1) + sig(4627) = 4628
    const EXPECTED_LEN: usize = 1 + 4627;
    if reassembled.len() < EXPECTED_LEN {
        eprintln!("[M13-HUB-PQC] ERROR: Finished too short: {} < {}", reassembled.len(), EXPECTED_LEN);
        return None;
    }
    if reassembled[0] != HS_FINISHED {
        eprintln!("[M13-HUB-PQC] ERROR: Expected Finished (0x03), got 0x{:02X}", reassembled[0]);
        return None;
    }

    eprintln!("[M13-HUB-PQC] Processing Finished ({}B)...", reassembled.len());

    let sig_node_bytes = &reassembled[1..4628];

    // 1. Compute transcript2 = SHA-512(ClientHello_payload || ServerHello_payload)
    let mut hasher = Sha512::new();
    hasher.update(&hs_state.client_hello_bytes);
    hasher.update(&hs_state.server_hello_bytes);
    let transcript2: [u8; 64] = hasher.finalize().into();

    // 2. Parse Node's verifying key
    let pk_node_enc = match ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(
        hs_state.node_pk_bytes.as_slice()
    ) {
        Ok(enc) => enc,
        Err(_) => {
            eprintln!("[M13-HUB-PQC] ERROR: Failed to parse Node verifying key");
            return None;
        }
    };
    let pk_node = ml_dsa::VerifyingKey::<MlDsa87>::decode(&pk_node_enc);

    // 3. Parse Node's signature
    let sig_node = match ml_dsa::Signature::<MlDsa87>::try_from(sig_node_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            eprintln!("[M13-HUB-PQC] ERROR: Failed to parse Node signature");
            return None;
        }
    };

    // 4. Verify signature
    if !pk_node.verify_with_context(&transcript2, PQC_CONTEXT, &sig_node) {
        eprintln!("[M13-HUB-PQC] SECURITY FAILURE: Node signature verification failed!");
        eprintln!("[M13-HUB-PQC] Possible MITM attack — aborting handshake");
        return None;
    }
    eprintln!("[M13-HUB-PQC] Node ML-DSA-87 signature verified ✓");

    // 5. Derive session key via HKDF-SHA-512
    let hk = Hkdf::<Sha512>::new(Some(&hs_state.session_nonce), &hs_state.shared_secret);
    let mut session_key = [0u8; 32];
    hk.expand(PQC_INFO, &mut session_key)
        .expect("HKDF-SHA-512 expand failed (L=32 ≤ 255*64)");
    eprintln!("[M13-HUB-PQC] Session key derived via HKDF-SHA-512 (32B)");

    Some(session_key)
}

// ============================================================================
// SPRINT 6.1: HEXDUMP ENGINE (all 4 capture points, rate-limited)
// ============================================================================
const HEXDUMP_INTERVAL_NS: u64 = 100_000_000; // 100ms = 10/sec max

struct HexdumpState { enabled: bool, last_tx_ns: u64, last_rx_ns: u64 }
impl HexdumpState {
    fn new(enabled: bool) -> Self { HexdumpState { enabled, last_tx_ns: 0, last_rx_ns: 0 } }
    fn dump_tx(&mut self, frame: *const u8, len: usize, now_ns: u64) {
        if !self.enabled { return; }
        if now_ns.saturating_sub(self.last_tx_ns) < HEXDUMP_INTERVAL_NS { return; }
        self.last_tx_ns = now_ns;
        dump_frame("[HUB-TX]", frame, len);
    }
    fn dump_rx(&mut self, frame: *const u8, len: usize, now_ns: u64) {
        if !self.enabled { return; }
        if now_ns.saturating_sub(self.last_rx_ns) < HEXDUMP_INTERVAL_NS { return; }
        self.last_rx_ns = now_ns;
        dump_frame("[HUB-RX]", frame, len);
    }
}

fn dump_frame(label: &str, frame: *const u8, len: usize) {
    let cap = len.min(80);
    let data = unsafe { std::slice::from_raw_parts(frame, cap) };
    let (seq, flags) = if cap >= ETH_HDR_SIZE + M13_HDR_SIZE {
        let m13 = unsafe { &*(frame.add(ETH_HDR_SIZE) as *const M13Header) };
        (m13.seq_id, m13.flags)
    } else { (0, 0) };
    let dst = if cap >= 6 { format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        data[0], data[1], data[2], data[3], data[4], data[5]) } else { "?".into() };
    let src = if cap >= 12 { format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        data[6], data[7], data[8], data[9], data[10], data[11]) } else { "?".into() };
    eprintln!("{} seq={} flags=0x{:02X} len={} dst={} src={}", label, seq, flags, len, dst, src);
    if cap >= 14 {
        eprint!("  [00..14] ETH  |"); for i in 0..14 { eprint!(" {:02X}", data[i]); } eprintln!();
    }
    if cap >= 16 { eprint!("  [14..16] MAGIC|"); eprint!(" {:02X} {:02X}", data[14], data[15]); eprintln!(); }
    if cap >= 18 {
        eprint!("  [16..18] CRYPT|"); eprint!(" {:02X} {:02X}", data[16], data[17]);
        eprintln!("  (crypto_ver=0x{:02X}={})", data[16], if data[16] == 0 { "cleartext" } else { "encrypted" });
    }
    if cap >= 34 { eprint!("  [18..34] MAC  |"); for i in 18..34 { eprint!(" {:02X}", data[i]); } eprintln!(); }
    if cap >= 46 { eprint!("  [34..46] NONCE|"); for i in 34..46 { eprint!(" {:02X}", data[i]); } eprintln!(); }
    if cap >= 54 {
        eprint!("  [46..54] SEQ  |"); for i in 46..54 { eprint!(" {:02X}", data[i]); }
        eprintln!("  (LE: seq_id={})", seq);
    }
    if cap >= 55 { eprintln!("  [54..55] FLAGS| {:02X}", data[54]); }
    if cap >= 59 {
        let plen = if cap >= ETH_HDR_SIZE + M13_HDR_SIZE {
            let m13 = unsafe { &*(frame.add(ETH_HDR_SIZE) as *const M13Header) }; m13.payload_len
        } else { 0 };
        eprint!("  [55..59] PLEN |"); for i in 55..59 { eprint!(" {:02X}", data[i]); }
        eprintln!("  (LE: payload_len={})", plen);
    }
    if cap >= 62 { eprint!("  [59..62] PAD  |"); for i in 59..62 { eprint!(" {:02X}", data[i]); } eprintln!(); }
}

/// Process-wide shutdown flag. Set by SIGTERM/SIGINT handler.
/// Checked at the top of every worker loop iteration.
/// Ordering::Relaxed is correct — monotonic flag (once true, never false).
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn signal_handler(_sig: i32) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

/// Read the hardware MAC address of a network interface from sysfs.
/// Returns the 6-byte MAC or a locally-administered fallback if sysfs is unavailable.
fn detect_mac(if_name: &str) -> [u8; 6] {
    let path = format!("/sys/class/net/{}/address", if_name);
    if let Ok(contents) = std::fs::read_to_string(&path) {
        let parts: Vec<u8> = contents.trim().split(':')
            .filter_map(|h| u8::from_str_radix(h, 16).ok())
            .collect();
        if parts.len() == 6 {
            eprintln!("[M13-EXEC] Detected MAC for {}: {}", if_name, contents.trim());
            return [parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]];
        }
    }
    eprintln!("[M13-EXEC] WARNING: Could not read MAC from sysfs ({}), using LAA fallback", path);
    [0x02, 0x00, 0x00, 0x00, 0x00, 0x01] // locally administered fallback
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    unsafe {
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
    }
    if args.iter().any(|a| a == "--monitor") {
        run_monitor();
        return;
    }
    let mut if_name = "veth0".to_string();
    let mut single_queue: Option<i32> = None;
    let mut hexdump_mode = false;
    let mut listen_port: Option<u16> = Some(443); // Default: UDP/443 (blends with QUIC)
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--monitor" => { run_monitor(); return; }
            "--hexdump" => { hexdump_mode = true; }
            "--port" | "--listen" => {
                i += 1;
                if i < args.len() {
                    listen_port = Some(match args[i].parse() {
                        Ok(p) => p,
                        Err(_) => fatal(E_AFFINITY_FAIL, "Invalid port number"),
                    });
                }
            }
            "--single-queue" => {
                i += 1;
                if i < args.len() {
                    single_queue = Some(match args[i].parse() {
                        Ok(v) => v,
                        Err(_) => fatal(E_AFFINITY_FAIL, "Invalid queue ID argument"),
                    });
                }
            }
            "-i" | "--iface" => {
                i += 1;
                if i < args.len() { if_name = args[i].clone(); }
            }
            other => {
                if !other.starts_with("--") { if_name = other.to_string(); }
            }
        }
        i += 1;
    }
    if hexdump_mode {
        std::env::set_var("M13_HEXDUMP", "1");
    }
    // Hub always listens. Port passed via env to workers.
    if let Some(port) = listen_port {
        std::env::set_var("M13_LISTEN_PORT", port.to_string());
    }
    run_executive(&if_name, single_queue);
}

// ============================================================================
// TYPESTATE FSM — Compile-time protocol state. No BBR pollution.
// ============================================================================
pub struct Listening;
pub struct Established;
#[repr(C)]
pub struct Peer<S> { mac: [u8; 6], seq_tx: u64, _state: PhantomData<S> }
impl Peer<Listening> {
    pub fn new() -> Self { Self { mac: [0u8; 6], seq_tx: 0, _state: PhantomData } }
    pub fn accept_registration(self, peer_mac: [u8; 6]) -> Peer<Established> {
        Peer { mac: peer_mac, seq_tx: 0, _state: PhantomData }
    }
}
impl Peer<Established> {
    #[inline(always)] pub fn next_seq(&mut self) -> u64 { let s = self.seq_tx; self.seq_tx = s.wrapping_add(1); s }
    #[inline(always)] pub fn mac(&self) -> &[u8; 6] { &self.mac }
}

#[inline(always)]
fn produce_data_frame(peer: &mut Peer<Established>, frame_ptr: *mut u8,
                      seq_send_times: &mut [u64], batch_ts_ns: u64) {
    let seq = peer.next_seq();
    unsafe { let m13 = &mut *(frame_ptr.add(ETH_HDR_SIZE) as *mut M13Header); m13.seq_id = seq; }
    seq_send_times[seq as usize & SEQ_WINDOW_MASK] = batch_ts_ns;
}

#[inline(always)]
fn produce_feedback_frame(
    frame_ptr: *mut u8, dst_mac: &[u8; 6], src_mac: &[u8; 6],
    rx_state: &mut ReceiverState, rx_bitmap: &mut RxBitmap, now_ns: u64,
    jbuf_len: usize,
) {
    // Drain loss accumulator and NACK bitmap from RxBitmap
    let (loss_count, nack_bitmap) = rx_bitmap.drain_losses();
    // ECN decision: mark if jitter buffer > 75% or any loss detected.
    // This gives the sender advance warning of congestion before overflow.
    let congested = jbuf_len > JBUF_CAPACITY * 3 / 4 || loss_count > 0;
    unsafe {
        let eth = &mut *(frame_ptr as *mut EthernetHeader);
        eth.dst = *dst_mac; eth.src = *src_mac; eth.ethertype = ETH_P_M13.to_be();
        let m13 = &mut *(frame_ptr.add(ETH_HDR_SIZE) as *mut M13Header);
        m13.signature = [0; 32];
        m13.signature[0] = M13_WIRE_MAGIC;
        m13.signature[1] = M13_WIRE_VERSION;
        m13.seq_id = 0;
        m13.flags = FLAG_CONTROL | FLAG_FEEDBACK | if congested { FLAG_ECN } else { 0 };
        m13.payload_len = mem::size_of::<FeedbackFrame>() as u32;
        m13.padding = [0; 3];
        let fb = &mut *(frame_ptr.add(ETH_HDR_SIZE + M13_HDR_SIZE) as *mut FeedbackFrame);
        fb.highest_seq = rx_state.highest_seq;
        fb.rx_timestamp_ns = rx_state.last_rx_batch_ns;
        fb.delivered = rx_state.delivered;
        fb.delivered_time_ns = now_ns;
        fb.loss_count = loss_count;
        fb.nack_bitmap = nack_bitmap;
    }
    rx_state.delivered = 0;
    rx_state.last_feedback_ns = now_ns;
}

/// Construct a FIN control frame (Sprint 5.21): ETH(14) + M13(48) = 62 bytes.
/// `fin_ack`: false = FIN, true = FIN-ACK (adds FLAG_FEEDBACK, includes seq).
#[inline(always)]
fn produce_fin_frame(
    frame_ptr: *mut u8, dst_mac: &[u8; 6], src_mac: &[u8; 6],
    final_seq: u64, fin_ack: bool,
) {
    unsafe {
        let eth = &mut *(frame_ptr as *mut EthernetHeader);
        eth.dst = *dst_mac; eth.src = *src_mac; eth.ethertype = ETH_P_M13.to_be();
        let m13 = &mut *(frame_ptr.add(ETH_HDR_SIZE) as *mut M13Header);
        m13.signature = [0; 32];
        m13.signature[0] = M13_WIRE_MAGIC;
        m13.signature[1] = M13_WIRE_VERSION;
        m13.seq_id = final_seq;
        m13.flags = FLAG_CONTROL | FLAG_FIN | if fin_ack { FLAG_FEEDBACK } else { 0 };
        m13.payload_len = 0;
        m13.padding = [0; 3];
    }
}

/// Send `count` redundant FIN or FIN-ACK frames via the critical scheduler path.
/// Returns number of frames actually enqueued (may be < count if slab exhausted).
#[inline(never)]
fn send_fin_burst(
    slab: &mut FixedSlab, engine: &Engine<ZeroCopyTx>,
    scheduler: &mut Scheduler, dst_mac: &[u8; 6], src_mac: &[u8; 6],
    final_seq: u64, fin_ack: bool, count: usize,
) -> usize {
    let mut sent = 0;
    for _ in 0..count {
        if let Some(idx) = slab.alloc() {
            let frame_ptr = unsafe { engine.umem_base().add((idx as usize) * FRAME_SIZE as usize) };
            produce_fin_frame(frame_ptr, dst_mac, src_mac, final_seq, fin_ack);
            scheduler.enqueue_critical((idx as u64) * FRAME_SIZE as u64, DATA_FRAME_WIRE_SIZE as u32);
            sent += 1;
        }
    }
    sent
}

// ============================================================================
// THE EXECUTIVE (Boot Calibration Sequence)
// ============================================================================
const CALIBRATION_PHASES: [&str; 5] = [
    "Discovering link capacity",
    "Measuring propagation delay",
    "Calibrating optimal rate",
    "Confirming path characteristics",
    "Link calibrated",
];

fn run_executive(if_name: &str, single_queue: Option<i32>) {
    // Register signal handlers before spawning workers.
    // signal() is async-signal-safe. Handler sets AtomicBool — one CPU instruction.
    unsafe {
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
    }

    // === AUTO-CLEANUP: kill stale hub, detach XDP, allocate hugepages ===
    eprintln!("[M13-EXEC] Pre-flight cleanup...");
    // Kill any previous m13-hub (SIGKILL, exclude ourselves)
    let my_pid = std::process::id();
    if let Ok(output) = std::process::Command::new("pgrep").arg("m13-hub").output() {
        if output.status.success() {
            let pids = String::from_utf8_lossy(&output.stdout);
            for pid_str in pids.lines() {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    if pid != my_pid {
                        unsafe { libc::kill(pid as i32, 9); }
                    }
                }
            }
        }
    }
    // Detach any stale XDP programs from the interface
    let _ = std::process::Command::new("ip").args(&["link", "set", if_name, "xdp", "off"]).output();
    let _ = std::process::Command::new("ip").args(&["link", "set", if_name, "xdpgeneric", "off"]).output();
    // Allocate hugepages: workers × UMEM_SIZE / 2MB per hugepage
    let hp_worker_count = match single_queue { Some(_) => 1, None => 3 }; // max workers
    let hugepages_needed = (hp_worker_count * UMEM_SIZE) / (2 * 1024 * 1024);
    let _ = std::fs::write("/proc/sys/vm/nr_hugepages", format!("{}\n", hugepages_needed));
    if let Ok(hp) = std::fs::read_to_string("/proc/sys/vm/nr_hugepages") {
        eprintln!("[M13-EXEC] Hugepages: {} allocated", hp.trim());
    }
    eprintln!("[M13-EXEC] Pre-flight cleanup complete.");

    // Sprint 5.17: TSC calibration. Must happen before workers spawn.
    // Workers receive a copy of the calibration data (immutable, per-worker).
    let tsc_cal = calibrate_tsc();

    lock_pmu();
    fence_interrupts();
    let isolated_cores = discover_isolated_cores();
    if isolated_cores.is_empty() {
        fatal(E_NO_ISOLATED_CORES, "No isolated cores. Boot with isolcpus=... or set M13_MOCK_CMDLINE");
    }
    let worker_count = match single_queue { Some(_) => 1, None => isolated_cores.len().min(MAX_WORKERS) };
    eprintln!("[M13-EXEC] Discovered {} isolated core(s): {:?}. Spawning {} worker(s).",
        isolated_cores.len(), &isolated_cores[..worker_count], worker_count);
    let steersman = BpfSteersman::load_and_attach(if_name);
    let map_fd = steersman.map_fd();
    eprintln!("[M13-EXEC] BPF Steersman attached to {}. map_fd={}", if_name, map_fd);
    let mut handles = Vec::with_capacity(worker_count);
    for worker_idx in 0..worker_count {
        let core_id = isolated_cores[worker_idx];
        let queue_id = match single_queue { Some(q) => q, None => worker_idx as i32 };
        let iface = if_name.to_string();
        let cal = tsc_cal; // Copy for this worker (TscCal is Copy)
        let handle = std::thread::Builder::new()
            .name(format!("m13-w{}", worker_idx)).stack_size(2 * 1024 * 1024)
            .spawn(move || { worker_entry(worker_idx, core_id, queue_id, &iface, map_fd, cal); })
            .unwrap_or_else(|_| fatal(E_AFFINITY_FAIL, "Thread spawn failed"));
        handles.push(handle);
    }

    // Boot calibration sequence: BBR converges while executive monitors
    // Workers are already running and BBR is converging in background.
    // Executive thread monitors telemetry and shows progress animation.
    // This thread is NOT on an isolated core — sleep is fine here.
    let cal_secs = (BBR_CALIBRATION_DURATION_NS / 1_000_000_000) as u32;
    // Wait for worker 0 telemetry to exist (avoids race with thread spawn)
    let w0 = loop {
        if let Some(t) = Telemetry::try_map_worker(0) { break t; }
        std::thread::sleep(Duration::from_millis(100));
    };
    eprintln!("[M13-EXEC] BBRv3 Calibration: {}s sequence starting...", cal_secs);
    for tick in 0..cal_secs {
        std::thread::sleep(Duration::from_secs(1));
        if SHUTDOWN.load(Ordering::Relaxed) {
            eprintln!("\n[M13-EXEC] Shutdown requested during calibration.");
            break;
        }
        let cal = w0.bbr_calibrated.value.load(Ordering::Relaxed);
        let phase = w0.bbr_phase.value.load(Ordering::Relaxed);
        let bw = w0.bbr_btlbw_kbps.value.load(Ordering::Relaxed);
        let rtt = w0.bbr_rtprop_us.value.load(Ordering::Relaxed);
        let progress = ((tick + 1) as f32 / cal_secs as f32 * 10.0) as usize;
        let filled = "\u{2593}".repeat(progress.min(10));
        let empty = "\u{2591}".repeat(10usize.saturating_sub(progress));
        let phase_idx = (tick as usize * CALIBRATION_PHASES.len() / cal_secs as usize)
            .min(CALIBRATION_PHASES.len() - 1);
        let phase_label = match phase { 0 => "STARTUP", 1 => "DRAIN", 2 => "PBW", 3 => "P_RTT", _ => "?" };
        eprint!("\r[M13-CAL] [{}{}] {}... BBR:{} BW:{}kbps RTT:{}us   ",
            filled, empty, CALIBRATION_PHASES[phase_idx], phase_label, bw, rtt);
        if cal == 1 {
            eprintln!("\n[M13-EXEC] \u{2713} BBR CALIBRATED. BtlBw={}kbps RTprop={}us. Golden ratio found.", bw, rtt);
            break;
        }
    }
    if w0.bbr_calibrated.value.load(Ordering::Relaxed) == 0 {
        let bw = w0.bbr_btlbw_kbps.value.load(Ordering::Relaxed);
        if bw > 0 {
            eprintln!("\n[M13-EXEC] Calibration partial. BtlBw={}kbps. Proceeding with best estimate.", bw);
        } else {
            eprintln!("\n[M13-EXEC] No link feedback detected. Operating in Startup mode (full rate).");
        }
    }
    eprintln!("[M13-EXEC] Engine operational. Workers running.");

    for h in handles { let _ = h.join(); }
    drop(steersman);
    eprintln!("[M13-EXEC] All workers stopped. XDP detached. Clean exit.");
}

// ============================================================================
// INTERRUPT FENCE — pin NIC IRQs away from isolated cores
// ============================================================================
fn fence_interrupts() {
    if std::env::var("M13_MOCK_CMDLINE").is_ok() { return; }
    let _ = std::fs::write("/proc/irq/default_smp_affinity", "1\n");
    if let Ok(output) = std::process::Command::new("pgrep").arg("irqbalance").output() {
        if output.status.success() {
            eprintln!("[M13-EXEC] WARNING: irqbalance is running. It will fight the IRQ fence.");
            eprintln!("[M13-EXEC] WARNING: Run 'systemctl stop irqbalance' for optimal performance.");
        }
    }
    let irq_dir = match std::fs::read_dir("/proc/irq") {
        Ok(d) => d, Err(_) => { eprintln!("[M13-EXEC] WARNING: Cannot read /proc/irq, skipping IRQ fence"); return; }
    };
    let (mut pinned, mut skipped) = (0u32, 0u32);
    for entry in irq_dir {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        let name = entry.file_name();
        let name_str = match name.to_str() { Some(s) => s, None => continue };
        if !name_str.bytes().next().map_or(false, |b| b.is_ascii_digit()) { continue; }
        let affinity_path = format!("/proc/irq/{}/smp_affinity_list", name_str);
        match std::fs::write(&affinity_path, "0\n") {
            Ok(_) => {
                if let Ok(rb) = std::fs::read_to_string(&affinity_path) {
                    if rb.trim() == "0" { pinned += 1; }
                    else { eprintln!("[M13-EXEC] IRQ {} readback: '{}'", name_str, rb.trim()); }
                }
            }
            Err(_) => { skipped += 1; }
        }
    }
    eprintln!("[M13-EXEC] Interrupt Fence: {} IRQs pinned to core 0, {} immovable", pinned, skipped);
}

// ============================================================================
// WORKER ENTRY — Feedback-first BBRv3 paced pipeline
// Stage order: Classify → Feedback Processing → Feedback Generation →
//              Token Refill → Enqueue+Generate (paced) → Schedule
// ============================================================================
fn worker_entry(worker_idx: usize, core_id: usize, queue_id: i32, if_name: &str, bpf_map_fd: i32, cal: TscCal) {
    pin_to_core(core_id);
    verify_affinity(core_id);
    let stats = Telemetry::map_worker(worker_idx, true);
    stats.pid.value.store(unsafe { libc::syscall(libc::SYS_gettid) } as u32, Ordering::Relaxed);
    let pending_peer = Peer::<Listening>::new();
    let mut peer = pending_peer.accept_registration([0xFF; 6]);
    let mut engine = Engine::<ZeroCopyTx>::new_zerocopy(if_name, queue_id, bpf_map_fd);
    let mut slab = FixedSlab::new(SLAB_DEPTH);
    let mut scheduler = Scheduler::new();
    let mut bbr = BbrState::new();
    let mut rx_state = ReceiverState::new();
    let mut rx_bitmap = RxBitmap::new();
    let mut seq_send_times: Box<[u64]> = vec![0u64; SEQ_WINDOW].into_boxed_slice();
    let mut bucket = TokenBucket::new(BATCH_SIZE as u64);
    let mut last_pacing_ns: u64 = rdtsc_ns(&cal);
    // Sprint 6.1: Hexdump + Fragmentation
    let hexdump_enabled = std::env::var("M13_HEXDUMP").is_ok();
    let mut hexdump = HexdumpState::new(hexdump_enabled);
    let mut assembler = Assembler::new();
    let mut gc_counter: u64 = 0;
    let iface_mac = detect_mac(if_name);
    let src_mac = iface_mac;

    // Sprint 6.2: Per-session PQC security state
    let mut session_key: [u8; 32] = [0u8; 32]; // Placeholder until PQC handshake
    let mut anti_replay = AntiReplay::new();
    let mut pqc_frame_count: u64 = 0;

    // Sprint 6.3: Hub-side handshake state
    let mut hub_hs_state: Option<HubHandshakeState> = None;
    let mut udp_seq_tx: u64 = 0;

    // Sprint 6.1: UDP transport (alongside AF_XDP). --listen <port>
    let udp_sock: Option<std::net::UdpSocket> = std::env::var("M13_LISTEN_PORT").ok()
        .and_then(|p| p.parse::<u16>().ok())
        .and_then(|port| {
            // Only worker 0 opens the UDP socket
            if worker_idx == 0 {
                match std::net::UdpSocket::bind(format!("0.0.0.0:{}", port)) {
                    Ok(s) => {
                        s.set_nonblocking(true).ok();
                        eprintln!("[M13-W{}] UDP listener on port {}", worker_idx, port);
                        Some(s)
                    }
                    Err(e) => { eprintln!("[M13-W{}] UDP bind failed: {}", worker_idx, e); None }
                }
            } else { None }
        });
    let mut udp_peer: Option<std::net::SocketAddr> = None;
    let mut udp_buf = [0u8; 2048];
    let mut udp_rx_count: u64 = 0;
    let mut udp_tx_count: u64 = 0;
    let mut udp_last_tx_ns: u64 = 0;

    for i in 0..SLAB_DEPTH {
        let fp = engine.get_frame_ptr(i as u32);
        unsafe {
            let eth = &mut *(fp as *mut EthernetHeader);
            let m13 = &mut *(fp.add(ETH_HDR_SIZE) as *mut M13Header);
            eth.dst = *peer.mac(); eth.src = src_mac;
            eth.ethertype = ETH_P_M13.to_be();
            m13.signature = [0; 32];
            m13.signature[0] = M13_WIRE_MAGIC;
            m13.signature[1] = M13_WIRE_VERSION;
            m13.seq_id = 0; m13.flags = 0;
            m13.payload_len = 0; m13.padding = [0; 3];
        }
    }
    engine.refill_rx_full(&mut slab);
    let umem = engine.umem_base();

    // Measure ε_proc (processing jitter floor) and create jitter buffer
    let epsilon_ns = measure_epsilon_proc(&cal);
    let mut jbuf = JitterBuffer::new(epsilon_ns);
    eprintln!("[M13-W{}] ACTIVE. Pipeline: Graph({}) Deadline: {}us Prefetch: {} HW_Fill: {}/{} \
              SeqWin: {} Feedback: every {} pkts BBR: {} MinPace: {} pps \
              JBuf: {}entries D_buf={}us ε={}us",
        worker_idx, GRAPH_BATCH, DEADLINE_NS / 1000, PREFETCH_DIST, HW_FILL_MAX, TX_RING_SIZE,
        SEQ_WINDOW, FEEDBACK_INTERVAL_PKTS, bbr.phase_label(), BBR_MIN_PACING_RATE_PPS,
        JBUF_CAPACITY, jbuf.depth_ns / 1000, epsilon_ns / 1000);

    let mut rx_batch: [libbpf_sys::xdp_desc; GRAPH_BATCH] = unsafe { mem::zeroed() };
    let mut data_indices = [0u16; GRAPH_BATCH];
    let mut ctrl_indices = [0u16; GRAPH_BATCH];
    let mut crit_indices = [0u16; GRAPH_BATCH];

    // Sprint 5.21: Graceful close state
    let mut closing = false;
    let mut fin_deadline_ns: u64 = 0;

    loop {
        // Sprint 5.21: Graceful close protocol.
        // On SHUTDOWN: send 3x FIN, then keep looping (RX only) until FIN-ACK or deadline.
        if SHUTDOWN.load(Ordering::Relaxed) && !closing {
            closing = true;
            let rtprop = if bbr.rtprop_ns < u64::MAX { bbr.rtprop_ns } else { 10_000_000 };
            // Deadline: max(5*RTprop, 10ms), capped at 100ms.
            // Lower bound 10ms: even on LAN, FIN-ACK may queue behind other frames.
            // Upper bound 100ms: bounded shutdown time, don't hang on dead peers.
            fin_deadline_ns = rdtsc_ns(&cal) + (rtprop.saturating_mul(5).max(10_000_000).min(100_000_000));
            let sent = send_fin_burst(&mut slab, &engine, &mut scheduler,
                peer.mac(), &src_mac, peer.seq_tx, false, 3);
            eprintln!("[M13-W{}] FIN sent ({}x). Awaiting FIN-ACK, deadline={}ms.",
                worker_idx, sent, (fin_deadline_ns.saturating_sub(rdtsc_ns(&cal))) / 1_000_000);
        }
        if closing && rdtsc_ns(&cal) >= fin_deadline_ns {
            eprintln!("[M13-W{}] FIN deadline expired. Force-closing.", worker_idx);
            break;
        }
        let now = rdtsc_ns(&cal);
        stats.cycles.value.fetch_add(1, Ordering::Relaxed);
        engine.recycle_tx(&mut slab);
        engine.refill_rx(&mut slab);

        // === STAGE -1: UDP RX (if listening) ===
        if let Some(ref sock) = udp_sock {
            loop {
                match sock.recv_from(&mut udp_buf) {
                    Ok((len, addr)) => {
                        if udp_peer.is_none() {
                            eprintln!("[M13-W{}] UDP node connected: {}", worker_idx, addr);
                        }
                        udp_peer = Some(addr);
                        udp_rx_count += 1;
                        hexdump.dump_rx(udp_buf.as_ptr(), len, now);
                        stats.rx_count.value.fetch_add(1, Ordering::Relaxed);

                        // Sprint 6.3: Parse UDP frames for handshake fragments
                        if len >= ETH_HDR_SIZE + M13_HDR_SIZE {
                            let m13 = unsafe { &*(udp_buf.as_ptr().add(ETH_HDR_SIZE) as *const M13Header) };
                            if m13.signature[0] == M13_WIRE_MAGIC && m13.signature[1] == M13_WIRE_VERSION {
                                let flags = m13.flags;
                                if flags & FLAG_FRAGMENT != 0 {
                                    eprintln!("[M13-W{}] UDP FRAG RX: len={} flags=0x{:02X}", worker_idx, len, flags);
                                    if len >= ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE {
                                        let frag_hdr = unsafe { &*(udp_buf.as_ptr().add(ETH_HDR_SIZE + M13_HDR_SIZE) as *const FragHeader) };
                                        let frag_msg_id = unsafe { std::ptr::addr_of!((*frag_hdr).frag_msg_id).read_unaligned() };
                                        let frag_index = unsafe { std::ptr::addr_of!((*frag_hdr).frag_index).read_unaligned() };
                                        let frag_total = unsafe { std::ptr::addr_of!((*frag_hdr).frag_total).read_unaligned() };
                                        let frag_offset = unsafe { std::ptr::addr_of!((*frag_hdr).frag_offset).read_unaligned() };
                                        let frag_data_len = unsafe { std::ptr::addr_of!((*frag_hdr).frag_len).read_unaligned() } as usize;
                                        let frag_start = ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE;
                                        eprintln!("[M13-W{}] FRAG DETAIL: msg_id={} idx={}/{} offset={} data_len={} frag_start={}",
                                            worker_idx, frag_msg_id, frag_index, frag_total, frag_offset, frag_data_len, frag_start);
                                        if frag_start + frag_data_len <= len {
                                            if let Some(reassembled) = assembler.feed(
                                                frag_msg_id, frag_index, frag_total,
                                                frag_offset, &udp_buf[frag_start..frag_start + frag_data_len], now,
                                            ) {
                                                // Route handshake messages
                                                if flags & FLAG_HANDSHAKE != 0 && !reassembled.is_empty() {
                                                    let msg_type = reassembled[0];
                                                    eprintln!("[M13-W{}] UDP reassembled handshake msg_id={} type=0x{:02X} len={}",
                                                        worker_idx, frag_msg_id, msg_type, reassembled.len());
                                                    match msg_type {
                                                        HS_CLIENT_HELLO => {
                                                            if let Some(hs) = process_client_hello_hub(
                                                                &reassembled, sock, &addr, &src_mac,
                                                                &mut udp_seq_tx, &mut hexdump, &cal, now,
                                                            ) {
                                                                hub_hs_state = Some(hs);
                                                                eprintln!("[M13-HUB-PQC] ClientHello processed, ServerHello sent. Awaiting Finished.");
                                                            } else {
                                                                eprintln!("[M13-HUB-PQC] ClientHello processing failed.");
                                                            }
                                                        }
                                                        HS_FINISHED => {
                                                            if let Some(ref hs) = hub_hs_state {
                                                                if let Some(key) = process_finished_hub(&reassembled, hs) {
                                                                    session_key = key;
                                                                    anti_replay = AntiReplay::new();
                                                                    pqc_frame_count = 0;
                                                                    hub_hs_state = None;
                                                                    eprintln!("[M13-HUB-PQC] \u{2192} Session established (AEAD active)");
                                                                } else {
                                                                    eprintln!("[M13-HUB-PQC] Finished processing failed.");
                                                                    hub_hs_state = None;
                                                                }
                                                            } else {
                                                                eprintln!("[M13-HUB-PQC] Finished received but no handshake in progress.");
                                                            }
                                                        }
                                                        _ => {
                                                            eprintln!("[M13-HUB-PQC] Unknown handshake type: 0x{:02X}", msg_type);
                                                        }
                                                    }
                                                } else {
                                                    eprintln!("[M13-W{}] UDP reassembled data msg_id={} len={}",
                                                        worker_idx, frag_msg_id, reassembled.len());
                                                }
                                            }
                                        } else {
                                            eprintln!("[M13-W{}] FRAG DATA OVERRUN: frag_start+data_len={} > len={}", worker_idx, frag_start + frag_data_len, len);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        // === STAGE 0: ADAPTIVE BATCH DRAIN ===
        let mut rx_count = engine.poll_rx_batch(&mut rx_batch, &stats);
        if rx_count > 0 && rx_count < GRAPH_BATCH {
            loop {
                engine.recycle_tx(&mut slab); engine.refill_rx(&mut slab);
                let n = engine.poll_rx_batch(&mut rx_batch[rx_count..], &stats);
                rx_count += n;
                if rx_count >= GRAPH_BATCH || rdtsc_ns(&cal) - now >= DEADLINE_NS { break; }
            }
        }

        // === STAGE 0.5: JITTER BUFFER DRAIN ===
        // Release TC_CRITICAL frames whose release time has arrived.
        // Must happen BEFORE classification so buffered frames from previous
        // cycles get scheduled THIS cycle.
        {
            let (rel, _) = jbuf.drain(now, &mut scheduler);
            if rel > 0 {
                // Bridge jitter buffer telemetry (4 Relaxed stores)
                stats.jbuf_depth_us.value.store(jbuf.depth_ns / 1000, Ordering::Relaxed);
                stats.jbuf_jitter_us.value.store(jbuf.estimator.get() / 1000, Ordering::Relaxed);
                stats.jbuf_releases.value.store(jbuf.total_releases, Ordering::Relaxed);
                stats.jbuf_drops.value.store(jbuf.total_drops, Ordering::Relaxed);
            }
        }

        // === STAGE 1: CLASSIFY (3-way split: data / feedback / critical) ===
        // Data (TC_BULK) | Feedback → BBR | TC_CRITICAL → Jitter Buffer
        let rx_batch_ns = if rx_count > 0 { now } else { 0 };
        let (mut data_count, mut ctrl_count, mut crit_count) = (0usize, 0usize, 0usize);
        for i in 0..rx_count {
            if i + PREFETCH_DIST < rx_count {
                unsafe { prefetch_read_l1(umem.add(rx_batch[i + PREFETCH_DIST].addr as usize + ETH_HDR_SIZE)); }
            }
            // Sprint 6.1: Hexdump RX capture point
            hexdump.dump_rx(unsafe { umem.add(rx_batch[i].addr as usize) }, rx_batch[i].len as usize, now);

            let m13 = unsafe { &*(umem.add(rx_batch[i].addr as usize + ETH_HDR_SIZE) as *const M13Header) };
            // Wire protocol validation: reject frames with wrong magic/version.
            // Defense-in-depth behind BPF EtherType filter.
            if m13.signature[0] != M13_WIRE_MAGIC || m13.signature[1] != M13_WIRE_VERSION {
                slab.free((rx_batch[i].addr / FRAME_SIZE as u64) as u32);
                continue;
            }

            // Sprint 6.2: AEAD verification on encrypted frames
            if m13.signature[2] == 0x01 {
                let frame_ptr = unsafe { umem.add(rx_batch[i].addr as usize) };
                let frame_len = rx_batch[i].len as usize;
                let frame_mut = unsafe { std::slice::from_raw_parts_mut(frame_ptr, frame_len) };
                if !open_frame(frame_mut, &session_key, DIR_HUB_TO_NODE) {
                    // MAC failed or direction mismatch: forgery/corruption/reflection
                    stats.auth_fail.value.fetch_add(1, Ordering::Relaxed);
                    slab.free((rx_batch[i].addr / FRAME_SIZE as u64) as u32);
                    continue;
                }
                // Re-read decrypted seq_id for anti-replay
                let dec_seq = u64::from_le_bytes(
                    frame_mut[ETH_HDR_SIZE + 32..ETH_HDR_SIZE + 40].try_into().unwrap()
                );
                if !anti_replay.check(dec_seq) {
                    stats.replay_drops.value.fetch_add(1, Ordering::Relaxed);
                    slab.free((rx_batch[i].addr / FRAME_SIZE as u64) as u32);
                    continue;
                }
                pqc_frame_count += 1;
                stats.decrypt_ok.value.fetch_add(1, Ordering::Relaxed);
            }

            // Sprint 6.1: Fragment reassembly on cold path
            if m13.flags & FLAG_FRAGMENT != 0 {
                let frame_ptr = unsafe { umem.add(rx_batch[i].addr as usize) };
                let frame_len = rx_batch[i].len as usize;
                if frame_len >= ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE {
                    let frag_hdr = unsafe { &*(frame_ptr.add(ETH_HDR_SIZE + M13_HDR_SIZE) as *const FragHeader) };
                    let frag_data_start = ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE;
                    let frag_msg_id = unsafe { std::ptr::addr_of!((*frag_hdr).frag_msg_id).read_unaligned() };
                    let frag_index = unsafe { std::ptr::addr_of!((*frag_hdr).frag_index).read_unaligned() };
                    let frag_total = unsafe { std::ptr::addr_of!((*frag_hdr).frag_total).read_unaligned() };
                    let frag_offset = unsafe { std::ptr::addr_of!((*frag_hdr).frag_offset).read_unaligned() };
                    let frag_data_len = unsafe { std::ptr::addr_of!((*frag_hdr).frag_len).read_unaligned() } as usize;
                    if frag_data_start + frag_data_len <= frame_len {
                        let frag_data = unsafe { std::slice::from_raw_parts(frame_ptr.add(frag_data_start), frag_data_len) };
                        if let Some(reassembled) = assembler.feed(
                            frag_msg_id, frag_index, frag_total,
                            frag_offset, frag_data, now,
                        ) {
                            // Sprint 6.3: Route handshake messages to PQC processor
                            if m13.flags & FLAG_HANDSHAKE != 0 && !reassembled.is_empty() {
                                let msg_type = reassembled[0];
                                eprintln!("[M13-W{}] AF_XDP reassembled handshake type=0x{:02X} len={}",
                                    worker_idx, msg_type, reassembled.len());
                                if let Some(ref sock) = udp_sock {
                                    if let Some(ref peer) = udp_peer {
                                        match msg_type {
                                            HS_CLIENT_HELLO => {
                                                if let Some(hs) = process_client_hello_hub(
                                                    &reassembled, sock, peer, &src_mac,
                                                    &mut udp_seq_tx, &mut hexdump, &cal, now,
                                                ) {
                                                    hub_hs_state = Some(hs);
                                                    eprintln!("[M13-HUB-PQC] ClientHello processed (AF_XDP), ServerHello sent.");
                                                }
                                            }
                                            HS_FINISHED => {
                                                if let Some(ref hs) = hub_hs_state {
                                                    if let Some(key) = process_finished_hub(&reassembled, hs) {
                                                        session_key = key;
                                                        anti_replay = AntiReplay::new();
                                                        pqc_frame_count = 0;
                                                        hub_hs_state = None;
                                                        eprintln!("[M13-HUB-PQC] \u{2192} Session established (AF_XDP, AEAD active)");
                                                    } else {
                                                        hub_hs_state = None;
                                                    }
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            } else {
                                eprintln!("[M13-W{}] Reassembled msg_id={} total_len={}",
                                    worker_idx, frag_msg_id, reassembled.len());
                            }
                        }
                    }
                }
                slab.free((rx_batch[i].addr / FRAME_SIZE as u64) as u32);
                continue;
            }
            if m13.flags & FLAG_FEEDBACK != 0 {
                // Feedback frame → BBR processing (slab freed after processing)
                ctrl_indices[ctrl_count] = i as u16; ctrl_count += 1;
            } else if m13.flags & FLAG_CRITICAL != 0 {
                // TC_CRITICAL → jitter buffer (slab NOT freed — held until drain)
                crit_indices[crit_count] = i as u16; crit_count += 1;
            } else if m13.flags & FLAG_CONTROL != 0 {
                // Sprint 5.21: Check for FIN/FIN-ACK
                if m13.flags & FLAG_FIN != 0 {
                    if closing {
                        // FIN-ACK received (or peer also sending FIN) — close complete
                        eprintln!("[M13-W{}] FIN-ACK received. Graceful close complete.", worker_idx);
                        slab.free((rx_batch[i].addr / FRAME_SIZE as u64) as u32);
                        // Mark for immediate exit after this RX batch
                        fin_deadline_ns = 0;
                        continue;
                    } else {
                        // Inbound FIN from peer — we are the responder.
                        // Send 3x FIN-ACK and initiate our own shutdown.
                        eprintln!("[M13-W{}] FIN received from peer. Sending FIN-ACK.", worker_idx);
                        send_fin_burst(&mut slab, &engine, &mut scheduler,
                            peer.mac(), &src_mac, peer.seq_tx, true, 3);
                        slab.free((rx_batch[i].addr / FRAME_SIZE as u64) as u32);
                        SHUTDOWN.store(true, Ordering::Relaxed);
                        continue;
                    }
                }
                // Generic control: no handler, free immediately
                slab.free((rx_batch[i].addr / FRAME_SIZE as u64) as u32);
            } else {
                // Data (TC_BULK): bypass jitter buffer entirely
                data_indices[data_count] = i as u16; data_count += 1;
                rx_state.highest_seq = m13.seq_id;
                rx_state.delivered += 1;
                rx_state.last_rx_batch_ns = rx_batch_ns;
                rx_bitmap.mark(m13.seq_id);
            }
        }

        // === STAGE 2: FEEDBACK PROCESSING — BBR ===
        let ctrl_now_ns = if ctrl_count > 0 { now } else { 0 };
        for i in 0..ctrl_count {
            let d = &rx_batch[ctrl_indices[i] as usize];
            let frame = unsafe { umem.add(d.addr as usize) as *const u8 };
            let flags = unsafe { (*(frame.add(ETH_HDR_SIZE) as *const M13Header)).flags };
            if flags & FLAG_FEEDBACK != 0 && d.len >= FEEDBACK_FRAME_LEN {
                let fb = unsafe { &*(frame.add(ETH_HDR_SIZE + M13_HDR_SIZE) as *const FeedbackFrame) };
                let ecn = flags & FLAG_ECN != 0;
                bbr.on_feedback(fb, &seq_send_times, ctrl_now_ns, peer.seq_tx, &mut bucket, ecn);
                stats.bbr_phase.value.store(bbr.phase_as_u32(), Ordering::Relaxed);
                stats.bbr_calibrated.value.store(bbr.calibrated as u32, Ordering::Relaxed);
                stats.bbr_btlbw_kbps.value.store(bbr.btlbw_filter.get() / 1000, Ordering::Relaxed);
                let rtprop_us = if bbr.rtprop_ns < u64::MAX { bbr.rtprop_ns / 1000 } else { 0 };
                stats.bbr_rtprop_us.value.store(rtprop_us, Ordering::Relaxed);
            }
            slab.free((d.addr / FRAME_SIZE as u64) as u32);
        }

        // === STAGE 2.5: TC_CRITICAL → JITTER BUFFER INSERT ===
        for i in 0..crit_count {
            let d = &rx_batch[crit_indices[i] as usize];
            let m13 = unsafe { &*(umem.add(d.addr as usize + ETH_HDR_SIZE) as *const M13Header) };
            // Update RFC 3550 EWMA jitter + adaptive D_buf
            jbuf.update_jitter(rx_batch_ns, m13.seq_id);
            // Insert into jitter buffer (slab NOT freed — frame held in UMEM)
            // If overflow drops oldest, free its slab slot to prevent UMEM leak
            if let Some(dropped_addr) = jbuf.insert(d.addr, d.len, rx_batch_ns) {
                slab.free((dropped_addr / FRAME_SIZE as u64) as u32);
            }
        }

        // === STAGE 3: FEEDBACK GENERATION ===
        let rtt_est = if bbr.rtprop_ns < u64::MAX { bbr.rtprop_ns } else { FEEDBACK_RTT_DEFAULT_NS };
        if rx_state.needs_feedback(rx_batch_ns, rtt_est) {
            if let Some(idx) = slab.alloc() {
                let frame_ptr = unsafe { umem.add((idx as usize) * FRAME_SIZE as usize) };
                produce_feedback_frame(frame_ptr, peer.mac(), &src_mac, &mut rx_state, &mut rx_bitmap, rx_batch_ns, jbuf.tail - jbuf.head);
                scheduler.enqueue_critical((idx as u64) * FRAME_SIZE as u64, FEEDBACK_FRAME_LEN);
            }
        }

        // === STAGE 4: TOKEN BUCKET REFILL ===
        let elapsed_pacing = now.saturating_sub(last_pacing_ns);
        last_pacing_ns = now;
        bucket.refill(elapsed_pacing);
        let pacing_tokens = bucket.available();

        // === STAGE 5: ENQUEUE DATA (cwnd-aware + pacing-aware) ===
        // Sprint 5.21: When closing, don't send new data — only process RX + FIN.
        if !closing {
            let effective_cwnd = bbr.effective_cwnd();
            let tx_budget = scheduler.budget(engine.tx_path.available_slots() as usize, effective_cwnd);
            let forward_count = data_count.min(tx_budget);
            for i in 0..forward_count {
                let d = &rx_batch[data_indices[i] as usize];
                scheduler.enqueue_bulk(d.addr, d.len);
            }
            for i in forward_count..data_count {
                slab.free((rx_batch[data_indices[i] as usize].addr / FRAME_SIZE as u64) as u32);
                stats.drops.value.fetch_add(1, Ordering::Relaxed);
            }

            // Generate new data frames → TC_BULK (pacing-limited)
            let gen_budget = tx_budget.saturating_sub(forward_count);
            let slab_avail = slab.available();
            let gen_target = min(BATCH_SIZE, min(gen_budget, min(slab_avail, pacing_tokens)));
            let batch_ts_ns = if gen_target > 0 { now } else { 0 };
            for _ in 0..gen_target {
                if let Some(idx) = slab.alloc() {
                    let frame_addr = (idx as u64) * (FRAME_SIZE as u64);
                    let frame_ptr = unsafe { umem.add(frame_addr as usize) };
                    produce_data_frame(&mut peer, frame_ptr, &mut seq_send_times, batch_ts_ns);
                    // Sprint 6.1: Hexdump TX capture point
                    hexdump.dump_tx(frame_ptr, 62, now);
                    scheduler.enqueue_bulk(frame_addr, 62);
                }
            }
        } else {
            // Closing: free all received data frames (no forwarding)
            for i in 0..data_count {
                slab.free((rx_batch[data_indices[i] as usize].addr / FRAME_SIZE as u64) as u32);
            }
        }

        // === STAGE 6: SCHEDULE (critical bypasses pacing, bulk paced) ===
        let submitted = scheduler.schedule(&mut engine.tx_path, &stats, pacing_tokens);
        bucket.consume(submitted);

        // === STAGE 7: UDP TX (if peer connected) ===
        // Independent pacing: BBRv3 controls AF_XDP rate; UDP uses its own
        // rate derived from BBR's btlbw estimate (or 1000pps baseline).
        if let (Some(ref sock), Some(ref addr)) = (&udp_sock, &udp_peer) {
            let udp_pace_ns = if bbr.btlbw_filter.get() > 0 {
                // Derive from BBR bandwidth: bytes/sec → frames/sec → ns/frame
                let bw_bps = bbr.btlbw_filter.get();
                let fps = (bw_bps / (62 * 8)).max(100); // frames per second
                1_000_000_000u64 / fps
            } else {
                1_000_000 // 1ms = 1000 pps baseline during STARTUP
            };
            if now.saturating_sub(udp_last_tx_ns) >= udp_pace_ns {
                let mut frame = [0u8; 62];
                frame[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
                frame[6..12].copy_from_slice(&src_mac);
                frame[12] = (ETH_P_M13 >> 8) as u8;
                frame[13] = (ETH_P_M13 & 0xFF) as u8;
                frame[14] = M13_WIRE_MAGIC;
                frame[15] = M13_WIRE_VERSION;
                let udp_seq = peer.next_seq();
                frame[46..54].copy_from_slice(&udp_seq.to_le_bytes());
                // Sprint 6.2: Seal if session has non-zero key
                if session_key != [0u8; 32] {
                    seal_frame(&mut frame, &session_key, udp_seq, DIR_HUB_TO_NODE);
                }
                hexdump.dump_tx(frame.as_ptr(), 62, now);
                if sock.send_to(&frame, addr).is_ok() {
                    udp_tx_count += 1;
                    stats.tx_count.value.fetch_add(1, Ordering::Relaxed);
                }
                udp_last_tx_ns = now;
            }
        }

        // Sprint 6.1: Periodic assembler GC
        gc_counter += 1;
        if gc_counter % 10000 == 0 { assembler.gc(now); }
    }

    // === GRACEFUL SHUTDOWN CLEANUP ===
    // Drain jitter buffer: free all held UMEM frames back to slab
    while jbuf.head < jbuf.tail {
        let slot = jbuf.head & (JBUF_CAPACITY - 1);
        slab.free((jbuf.entries[slot].addr / FRAME_SIZE as u64) as u32);
        jbuf.head += 1;
    }
    eprintln!("[M13-W{}] Shutdown complete. Slab: {}/{} free. UDP TX:{} RX:{}",
        worker_idx, slab.available(), SLAB_DEPTH, udp_tx_count, udp_rx_count);
}

// ============================================================================
// UTILS (unchanged)
// ============================================================================
fn discover_isolated_cores() -> Vec<usize> {
    if let Ok(mock) = std::env::var("M13_MOCK_CMDLINE") {
        if let Some(part) = mock.split_whitespace().find(|p| p.starts_with("isolcpus=")) {
            return parse_cpu_list(part.strip_prefix("isolcpus=").unwrap_or(""));
        }
        return Vec::new();
    }
    match std::fs::read_to_string("/sys/devices/system/cpu/isolated") {
        Ok(s) => parse_cpu_list(s.trim()), Err(_) => Vec::new(),
    }
}
fn parse_cpu_list(list: &str) -> Vec<usize> {
    let mut cores = Vec::new();
    if list.is_empty() { return cores; }
    for part in list.split(',') {
        if part.contains('-') {
            let r: Vec<&str> = part.split('-').collect();
            if r.len() == 2 {
                let s: usize = match r[0].parse() {
                    Ok(v) => v,
                    Err(_) => fatal(E_NO_ISOLATED_CORES, "Invalid CPU range in isolcpus"),
                };
                let e: usize = match r[1].parse() {
                    Ok(v) => v,
                    Err(_) => fatal(E_NO_ISOLATED_CORES, "Invalid CPU range in isolcpus"),
                };
                for i in s..=e { cores.push(i); }
            }
        } else if let Ok(id) = part.parse::<usize>() { cores.push(id); }
    }
    cores.sort(); cores.dedup(); cores
}
fn pin_to_core(core_id: usize) {
    unsafe {
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core_id, &mut cpuset);
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &cpuset) != 0 {
            fatal(E_AFFINITY_FAIL, "sched_setaffinity failed");
        }
    }
}
fn verify_affinity(expected_core: usize) {
    if std::env::var("M13_MOCK_CMDLINE").is_ok() { return; }
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    let path = format!("/proc/self/task/{}/status", tid);
    let file = match File::open(&path) {
        Ok(f) => f, Err(_) => match File::open("/proc/self/status") {
            Ok(f) => f, Err(_) => fatal(E_AFFINITY_VERIFY, "Cannot open status file"),
        }
    };
    for line in BufReader::new(file).lines() {
        if let Ok(l) = line {
            if l.starts_with("Cpus_allowed_list:") {
                let mask = l.split_whitespace().last().unwrap_or("");
                if mask != expected_core.to_string() {
                    fatal(E_AFFINITY_VERIFY, "Core affinity mismatch");
                }
                return;
            }
        }
    }
    fatal(E_AFFINITY_VERIFY, "Could not verify affinity");
}
fn lock_pmu() {
    if std::env::var("M13_MOCK_CMDLINE").is_ok() { return; }
    let mut file = match OpenOptions::new().read(true).write(true).open("/dev/cpu_dma_latency") {
        Ok(f) => f, Err(_) => fatal(E_PMU_LOCK_FAIL, "Cannot open PMU"),
    };
    if file.write_all(&0i32.to_ne_bytes()).is_err() { fatal(E_PMU_LOCK_FAIL, "PMU write failed"); }
    if file.seek(SeekFrom::Start(0)).is_err() { fatal(E_PMU_LOCK_FAIL, "PMU seek failed"); }
    let mut buf = [0u8; 4];
    if file.read_exact(&mut buf).is_err() || i32::from_ne_bytes(buf) != 0 {
        fatal(E_PMU_LOCK_FAIL, "PMU lock rejected");
    }
    eprintln!("[M13-EXEC] PMU Locked: max_latency=0us (C0 only)");
    mem::forget(file);
}

// ============================================================================
// MONITOR
// ============================================================================
fn run_monitor() {
    eprintln!("[M13-MONITOR] Scanning for active workers...");
    let mut workers = Vec::new();
    for i in 0..MAX_WORKERS {
        if let Some(t) = Telemetry::try_map_worker(i) { workers.push(t); } else { break; }
    }
    if workers.is_empty() {
        eprintln!("[M13-MONITOR] No workers found. Waiting...");
        while workers.is_empty() {
            if let Some(t) = Telemetry::try_map_worker(0) { workers.push(t); break; }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    eprintln!("[M13-MONITOR] Attached to {} worker(s).", workers.len());
    eprintln!("---------------------------------------------------------------------");
    let mut last_tx = vec![0u64; workers.len()];
    let mut tids = vec![0u32; workers.len()];
    loop {
        let (mut ttx, mut trx, mut _td, mut tpps) = (0u64, 0u64, 0u64, 0u64);
        let mut cs = String::new();
        for (i, w) in workers.iter().enumerate() {
            let tx = w.tx_count.value.load(Ordering::Relaxed);
            let rx = w.rx_count.value.load(Ordering::Relaxed);
            let d = w.drops.value.load(Ordering::Relaxed);
            let pps = tx - last_tx[i]; last_tx[i] = tx;
            ttx += tx; trx += rx; _td += d; tpps += pps;
            if tids[i] == 0 { tids[i] = w.pid.value.load(Ordering::Relaxed); }
            if tids[i] != 0 {
                let (v, n) = read_ctxt_switches(tids[i]);
                if i > 0 { cs.push('|'); }
                cs.push_str(&format!("W{}:{}/{}", i, v, n));
            }
        }
        // BBR state from worker 0
        let bbr_phase = match workers[0].bbr_phase.value.load(Ordering::Relaxed) {
            0 => "START", 1 => "DRAIN", 2 => "PBW", 3 => "P_RTT", _ => "?"
        };
        let bbr_cal = if workers[0].bbr_calibrated.value.load(Ordering::Relaxed) == 1 { "\u{2713}" } else { "..." };
        let bbr_bw = workers[0].bbr_btlbw_kbps.value.load(Ordering::Relaxed);
        let _bbr_rtt = workers[0].bbr_rtprop_us.value.load(Ordering::Relaxed);
        // Jitter buffer state from worker 0
        let jb_depth = workers[0].jbuf_depth_us.value.load(Ordering::Relaxed);
        let jb_jitter = workers[0].jbuf_jitter_us.value.load(Ordering::Relaxed);
        let jb_rel = workers[0].jbuf_releases.value.load(Ordering::Relaxed);
        let jb_drop = workers[0].jbuf_drops.value.load(Ordering::Relaxed);
        eprint!("\r[TELEM] TX:{:<12} RX:{:<12} PPS:{:<10} BBR:{}[{}] BW:{}k JB:{}us/{}us R:{} D:{} CTX:[{}]   ",
            ttx, trx, tpps, bbr_phase, bbr_cal, bbr_bw, jb_depth, jb_jitter, jb_rel, jb_drop, cs);
        std::thread::sleep(Duration::from_secs(1));
    }
}
fn read_ctxt_switches(tid: u32) -> (u64, u64) {
    let path = format!("/proc/{}/status", tid);
    if let Ok(file) = File::open(&path) {
        let (mut v, mut n) = (0u64, 0u64);
        for line in BufReader::new(file).lines() {
            if let Ok(l) = line {
                if l.starts_with("voluntary_ctxt_switches:") {
                    // Intentional unwrap_or(0): monitor graceful degradation
                    v = l.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
                } else if l.starts_with("nonvoluntary_ctxt_switches:") {
                    // Intentional unwrap_or(0): monitor graceful degradation
                    n = l.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
                }
            }
        }
        (v, n)
    } else { (0, 0) }
}
