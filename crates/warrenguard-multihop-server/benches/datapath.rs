//! Per-packet cost of the exit's multi-hop datapath, outside the crypto.
//!
//! Both the `/v1` and `/v2` pumps run the same gate chain on every uplink
//! packet (anti-spoof, flow memo, MSS clamp) and the same adaptation on every
//! downlink packet (budget check, frag-needed reflection). These are the only
//! parts of the datapath a refactor can regress without a test noticing, since
//! their cost is invisible until it is multiplied by line-rate packet counts.
//!
//! `daita_sink` is the one to watch when comparing pump generations: a
//! connection that negotiated no cover must pay a null check per packet, not a
//! mutex acquisition plus a clock read.

use std::net::Ipv4Addr;
use std::time::Duration;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use warrenguard_daita::DaitaPool;
use warrenguard_daita::daita::DaitaEvent;
use warrenguard_daita::daita::DaitaState;
use warrenguard_multihop::MULTIHOP_FRAME_MAX_OVERHEAD;
use warrenguard_multihop_server::internals::{
    DaitaSink, FlowNoter, SpoofGate, adapt_inner_for_budget, canonical_flow_key, inner_budget,
};

const ASSIGNED: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 7);
const PEER: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

/// A TCP packet of `len` bytes from `src`, so both the anti-spoof gate and the
/// 5-tuple flow hash see a well-formed header.
fn tcp_packet(src: Ipv4Addr, src_port: u16, len: usize) -> Vec<u8> {
    let total = len.max(24);
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&u16::try_from(total).unwrap_or(u16::MAX).to_be_bytes());
    p[9] = 6;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&PEER.octets());
    p[20..22].copy_from_slice(&src_port.to_be_bytes());
    p[22..24].copy_from_slice(&443u16.to_be_bytes());
    p
}

fn spoof_gate(c: &mut Criterion) {
    let mut g = c.benchmark_group("spoof_gate");
    let ours = tcp_packet(ASSIGNED, 4242, 1400);
    let forged = tcp_packet(Ipv4Addr::new(10, 66, 0, 8), 4242, 1400);
    g.bench_function("admits", |b| {
        let mut gate = SpoofGate::new(ASSIGNED, None, "bench");
        b.iter(|| black_box(gate.admits(black_box(&ours))));
    });
    // The rejection path also runs the rate-limited counter, so it must stay
    // as cheap as the accept path: a spoofing flood is exactly when the exit
    // can least afford per-packet work.
    g.bench_function("rejects", |b| {
        let mut gate = SpoofGate::new(ASSIGNED, None, "bench");
        b.iter(|| black_box(gate.admits(black_box(&forged))));
    });
    g.finish();
}

fn flow_noter(c: &mut Criterion) {
    let pkt = tcp_packet(ASSIGNED, 4242, 1400);

    let mut g = c.benchmark_group("flow_noter");
    // The steady state: a flow already announced, so the memo must answer
    // without the caller ever reaching for the router lock.
    g.bench_function("memoized_hit", |b| {
        let mut noter = FlowNoter::new();
        noter.is_first_of_flow(&pkt);
        b.iter(|| black_box(noter.is_first_of_flow(black_box(&pkt))));
    });
    g.bench_function("flow_key_only", |b| {
        b.iter(|| black_box(canonical_flow_key(black_box(&pkt))));
    });
    g.finish();
}

fn downlink_adaptation(c: &mut Criterion) {
    let mut g = c.benchmark_group("downlink_adaptation");
    let budget = inner_budget(Some(1452), MULTIHOP_FRAME_MAX_OVERHEAD);
    let fits = tcp_packet(PEER, 443, 1200);
    let oversized = tcp_packet(PEER, 443, 1400);
    g.bench_function("fits_budget", |b| {
        b.iter_batched_ref(
            || fits.clone(),
            |p| black_box(adapt_inner_for_budget(p, budget)),
            BatchSize::SmallInput,
        );
    });
    g.bench_function("reflects_frag_needed", |b| {
        b.iter_batched_ref(
            || oversized.clone(),
            |p| black_box(adapt_inner_for_budget(p, budget)),
            BatchSize::SmallInput,
        );
    });
    g.finish();
}

fn daita_sink(c: &mut Criterion) {
    let mut g = c.benchmark_group("daita_sink");
    // The cost a connection WITHOUT cover pays per packet. This is the common
    // case on a DAITA-armed exit (only clients that negotiate get machines),
    // so it must be a null check.
    g.bench_function("off", |b| {
        let sink = DaitaSink::off();
        b.iter(|| black_box(&sink).fire(black_box(&[DaitaEvent::TunnelRecv])));
    });
    let cfg = DaitaPool::default_pool()
        .pick_named_os("tamaraw")
        .expect("curated pool carries tamaraw");
    g.bench_function("armed", |b| {
        let sink = DaitaSink::armed(
            DaitaState::from_config(&cfg, std::time::Instant::now()).expect("state builds"),
        );
        b.iter(|| black_box(&sink).fire(black_box(&[DaitaEvent::TunnelRecv])));
    });
    g.finish();
}

/// The full per-packet chain an uplink packet runs between the HPKE open and
/// the TUN write. Read this one as the headline number: it is what a refactor
/// of the pump actually changes.
fn uplink_gate_chain(c: &mut Criterion) {
    let pkt = tcp_packet(ASSIGNED, 4242, 1400);
    c.bench_function("uplink_gate_chain", |b| {
        let sink = DaitaSink::off();
        let mut gate = SpoofGate::new(ASSIGNED, None, "bench");
        let mut noter = FlowNoter::new();
        b.iter(|| {
            sink.fire(&[DaitaEvent::TunnelRecv]);
            if gate.admits(black_box(&pkt)) {
                black_box(noter.is_first_of_flow(black_box(&pkt)));
            }
        });
    });
}

criterion_group! {
    name = datapath;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(3));
    targets = spoof_gate, flow_noter, downlink_adaptation, daita_sink, uplink_gate_chain
}
criterion_main!(datapath);
