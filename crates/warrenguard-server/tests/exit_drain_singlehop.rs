//! Exit drain on the single-hop datapath: the admission gate and the
//! in-band `ExitDraining` emitter (see `warrenguard-server::exit::drain`).
//!
//! Real components end to end: a real [`ExitListener`] accept loop with a
//! `FakeTun` and a real [`ClientTunnel`], talking QUIC on localhost. The
//! drain watch sender plays the deployer's control-plane.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;
use warrenguard_multihop::{WarrenControlMessage, try_decode_control};
use warrenguard_server::{ExitBindOpts, ExitDrainSignal, ExitListener};
use warrenguard_transport::ClientTunnel;
use warrenguard_transport_core::FakeTun;
use warrenguard_transport_core::constants::WARREN_EXIT_DRAINING;
use warrenguard_transport_core::error::TunnelError;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn test_client(seed: u8) -> ClientTunnel {
    let node_key = warrenguard_identity::derive_node_key(&[seed; 32]);
    ClientTunnel::with_signing_key(&node_key)
}

/// Bind a drain-wired exit and run the PRODUCTION accept loop
/// (`accept_forever_with_tun`, the same loop the exit binary serves with).
/// Returns the exit address and the drain sender (the control-plane seam).
async fn spawn_drained_capable_exit(
    initial: Option<ExitDrainSignal>,
) -> (
    warrenguard_wire::WarrenExitAddr,
    watch::Sender<Option<ExitDrainSignal>>,
    tokio::task::JoinHandle<()>,
) {
    let (drain_tx, drain_rx) = watch::channel(initial);
    let opts = ExitBindOpts {
        drain_rx: Some(drain_rx),
        ..ExitBindOpts::default()
    };
    let exit = ExitListener::bind_with_opts("127.0.0.1:0".parse().expect("addr"), opts)
        .await
        .expect("exit binds on localhost");
    let addr = exit.bound_addr();
    let accept = tokio::spawn(async move {
        let _ = exit.accept_forever_with_tun(FakeTun::new()).await;
    });
    (addr, drain_tx, accept)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drained_exit_refuses_a_new_handshake_with_the_draining_close_code() {
    let signal = ExitDrainSignal {
        deadline_unix_secs: unix_now_secs() + 120,
        reason_code: 0,
    };
    let (addr, _drain_tx, accept) = spawn_drained_capable_exit(Some(signal)).await;

    let client = test_client(0x11);
    let res = tokio::time::timeout(TEST_TIMEOUT, client.connect(addr))
        .await
        .expect("connect attempt must not hang");

    let Err(err) = res else {
        panic!("a DRAINED exit must refuse a new authenticated handshake (fail-fast reconnect)");
    };
    assert!(
        matches!(err, TunnelError::ExitDrainingRefused),
        "the refusal must surface as ExitDrainingRefused (mapped from the \
         WARREN_EXIT_DRAINING close code), got: {err}"
    );

    accept.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_drained_exit_with_a_drain_watch_accepts_a_new_handshake() {
    // Same wiring, but the watch holds None (not draining): the gate must
    // be a no-op and the handshake must complete with a tunnel IP.
    let (addr, _drain_tx, accept) = spawn_drained_capable_exit(None).await;

    let client = test_client(0x22);
    let session = tokio::time::timeout(TEST_TIMEOUT, client.connect(addr))
        .await
        .expect("connect attempt must not hang")
        .expect("a NON-drained exit must admit the client (zero regression on the normal path)");
    assert_eq!(
        session.assigned_ipv4().octets()[0],
        10,
        "admitted client must receive a pool tunnel IP"
    );

    accept.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn singlehop_connection_receives_drain_advisory_then_hard_close_at_deadline() {
    // Connect FIRST (not draining), then drain: the established session
    // must receive the in-band ExitDraining control datagram (the soft
    // signal a client migrates off) and, once the deadline passes, the
    // hard close carrying WARREN_EXIT_DRAINING.
    let (addr, drain_tx, accept) = spawn_drained_capable_exit(None).await;

    let client = test_client(0x33);
    let session = tokio::time::timeout(TEST_TIMEOUT, client.connect(addr))
        .await
        .expect("connect attempt must not hang")
        .expect("handshake succeeds before the drain");

    const REASON: u8 = 7;
    let deadline = unix_now_secs() + 3;
    drain_tx
        .send(Some(ExitDrainSignal {
            deadline_unix_secs: deadline,
            reason_code: REASON,
        }))
        .expect("drain watch has a live receiver (the serve loop)");

    let mut got_advisory = false;
    let mut got_close = false;
    let overall = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < overall && !(got_advisory && got_close) {
        let remaining = overall.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, session.read_datagram()).await {
            Ok(Ok(datagram)) => {
                // The single-hop downlink carries the SAME frozen 0xC0
                // control encoding the multi-hop client decoder consumes.
                if let Ok(Some(WarrenControlMessage::ExitDraining {
                    deadline_unix_secs,
                    reason_code,
                })) = try_decode_control(&datagram)
                {
                    assert_eq!(
                        deadline_unix_secs, deadline,
                        "advisory must carry the exact drain deadline"
                    );
                    assert_eq!(
                        reason_code, REASON,
                        "advisory must carry the exact reason code"
                    );
                    got_advisory = true;
                }
            }
            Ok(Err(_)) => {
                got_close = true;
                break;
            }
            Err(_) => break, // overall window elapsed
        }
    }

    assert!(
        got_advisory,
        "a drained single-hop exit MUST emit the in-band ExitDraining advisory \
         so single-hop clients learn about the drain before the hard close"
    );
    assert!(
        got_close,
        "the still-attached single-hop connection MUST be hard-closed at the drain deadline"
    );
    match session.clone_conn().close_reason() {
        Some(quinn::ConnectionError::ApplicationClosed(close)) => {
            assert_eq!(
                close.error_code, WARREN_EXIT_DRAINING,
                "the deadline hard-close must carry the WARREN_EXIT_DRAINING code"
            );
        }
        other => panic!("expected an application close with WARREN_EXIT_DRAINING, got {other:?}"),
    }

    accept.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn undrain_before_deadline_keeps_the_connection_open() {
    // Cancelled maintenance: drain then withdraw before the deadline. The
    // connection must survive well past the (withdrawn) deadline.
    let (addr, drain_tx, accept) = spawn_drained_capable_exit(None).await;

    let client = test_client(0x44);
    let session = tokio::time::timeout(TEST_TIMEOUT, client.connect(addr))
        .await
        .expect("connect attempt must not hang")
        .expect("handshake succeeds before the drain");

    let deadline = unix_now_secs() + 2;
    drain_tx
        .send(Some(ExitDrainSignal {
            deadline_unix_secs: deadline,
            reason_code: 0,
        }))
        .expect("drain watch live");
    // Wait for the first advisory so the emitter is armed on this drain
    // before we withdraw it.
    let advisory_seen = tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            let dg = session.read_datagram().await.expect("conn still open");
            if matches!(
                try_decode_control(&dg),
                Ok(Some(WarrenControlMessage::ExitDraining { .. }))
            ) {
                return;
            }
        }
    })
    .await;
    assert!(advisory_seen.is_ok(), "advisory must arrive before undrain");

    drain_tx.send(None).expect("undrain publish");

    // Past the withdrawn deadline the connection must still be alive:
    // read_datagram must time out (no close), not error.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        session.clone_conn().close_reason().is_none(),
        "an undrained exit must NOT hard-close at the withdrawn deadline"
    );

    accept.abort();
}
