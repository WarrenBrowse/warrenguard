//! `NftablesBackend` tests with a mock executor.
//!
//! Verifies the correct sequence of nft calls (setup → add element
//! on allocate → delete element on release) and the allocator-side
//! rollback when the executor fails, without actually running `nft`.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use warrenguard_natpmp_server::nftables::{
    HairpinSnat, NftExecutor, NftablesBackend, PortFailGuard,
};
use warrenguard_natpmp_server::{PortForwardingBackend, Proto};

/// Recorder: captures each script submitted to `nft -f -`. Allows
/// asserting on order and content without real I/O.
struct Recorder {
    scripts: Mutex<Vec<String>>,
    fail_next: Mutex<bool>,
}

impl Recorder {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            scripts: Mutex::new(Vec::new()),
            fail_next: Mutex::new(false),
        })
    }

    fn scripts(&self) -> Vec<String> {
        self.scripts.lock().clone()
    }

    fn arm_failure(&self) {
        *self.fail_next.lock() = true;
    }
}

impl NftExecutor for Recorder {
    fn run_script(
        &self,
        script: &str,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send {
        let recorded = script.to_string();
        let fail = std::mem::replace(&mut *self.fail_next.lock(), false);
        self.scripts.lock().push(recorded);
        async move {
            if fail {
                Err("simulated nft failure".to_string())
            } else {
                Ok(())
            }
        }
    }
}

const ALICE: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 42);
const BOB: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 99);

/// Replay the recorded nft scripts into the resulting map element set
/// `(map_name, external_port)`, the way the kernel would apply each
/// `add element` / `delete element`. Lets a test assert "no ghost
/// element remains" rather than only checking that a delete was
/// emitted. Setup lines (`add table`/`map`/`chain`/`rule`) are ignored
/// because their second token is not `element`.
fn element_set(scripts: &[String]) -> std::collections::BTreeSet<(String, u16)> {
    let mut set = std::collections::BTreeSet::new();
    for script in scripts {
        for line in script.lines() {
            let toks: Vec<&str> = line.split_whitespace().collect();
            if toks.len() < 7 || toks[1] != "element" || toks[2] != "inet" {
                continue;
            }
            let map = toks[4].to_string();
            let port_tok = toks[6].trim_matches(|c: char| !c.is_ascii_digit());
            let Ok(port) = port_tok.parse::<u16>() else {
                continue;
            };
            match toks[0] {
                "add" => {
                    set.insert((map, port));
                }
                "delete" => {
                    set.remove(&(map, port));
                }
                _ => {}
            }
        }
    }
    set
}

#[tokio::test]
async fn backend_setup_runs_setup_script_on_construction() {
    let recorder = Recorder::new();
    let _backend = NftablesBackend::new(Arc::clone(&recorder))
        .await
        .expect("setup ok");
    let scripts = recorder.scripts();
    assert_eq!(
        scripts.len(),
        1,
        "exactly one setup script expected, got {}",
        scripts.len()
    );
    assert!(
        scripts[0].contains("delete table inet warren"),
        "first script must be the setup with reset (add → delete → add), got:\n{}",
        scripts[0]
    );
    assert!(
        scripts[0].contains("add chain inet warren prerouting_natpmp"),
        "first script must create the chain, got:\n{}",
        scripts[0]
    );
}

#[tokio::test]
async fn backend_with_guard_installs_the_portfail_guard_in_setup() {
    // When the exit opts into the Port Fail defense-in-depth guard, the
    // backend must install the connected-real-IP set + forward drop chain as
    // part of the same atomic setup (so the table reset cannot leave it half
    // created).
    let recorder = Recorder::new();
    let _backend = NftablesBackend::with_pfwd_ip_and_guard(
        Arc::clone(&recorder),
        None,
        Some(PortFailGuard::new("10.66.0.0/16")),
    )
    .await
    .expect("setup ok");
    let scripts = recorder.scripts();
    assert_eq!(scripts.len(), 1, "setup must stay a single atomic script");
    assert!(
        scripts[0].contains("add set inet warren warren_client_real_ips { type ipv4_addr ; }"),
        "guard set must be created in setup, got:\n{}",
        scripts[0]
    );
    assert!(
        scripts[0].contains("ip saddr @warren_client_real_ips ip daddr 10.66.0.0/16 drop"),
        "guard drop rule must be installed in setup, got:\n{}",
        scripts[0]
    );
}

#[tokio::test]
async fn backend_sync_portfail_guard_ips_flushes_and_adds() {
    let recorder = Recorder::new();
    let backend = NftablesBackend::with_pfwd_ip_and_guard(
        Arc::clone(&recorder),
        None,
        Some(PortFailGuard::new("10.66.0.0/16")),
    )
    .await
    .expect("setup ok");
    backend
        .sync_portfail_guard_ips(&[Ipv4Addr::new(203, 0, 113, 9)])
        .await
        .expect("sync ok");
    let scripts = recorder.scripts();
    let last = scripts.last().expect("a sync script was recorded");
    assert!(
        last.contains("flush set inet warren warren_client_real_ips")
            && last.contains("add element inet warren warren_client_real_ips { 203.0.113.9 }"),
        "sync must flush then add the connected IPs, got:\n{last}"
    );
}

#[tokio::test]
async fn backend_without_guard_syncs_nothing() {
    // A backend with the guard disabled must never touch nft on a sync call:
    // no set exists, so issuing a flush/add would error. It is a silent no-op.
    let recorder = Recorder::new();
    let backend = NftablesBackend::new(Arc::clone(&recorder))
        .await
        .expect("setup ok");
    let before = recorder.scripts().len();
    backend
        .sync_portfail_guard_ips(&[Ipv4Addr::new(203, 0, 113, 9)])
        .await
        .expect("no-op sync is Ok");
    assert_eq!(
        recorder.scripts().len(),
        before,
        "sync without a configured guard must run no nft script"
    );
}

#[tokio::test]
async fn backend_with_options_installs_the_hairpin_snat_in_setup() {
    // The optional hairpin SNAT (off by default) is installed atomically with
    // the table setup and scoped to pool-internal hairpinned sources.
    let recorder = Recorder::new();
    let _backend = NftablesBackend::with_options(
        Arc::clone(&recorder),
        None,
        None,
        Some(HairpinSnat::new("10.66.0.0/16", "warren0")),
    )
    .await
    .expect("setup ok");
    let scripts = recorder.scripts();
    assert_eq!(scripts.len(), 1, "setup must stay a single atomic script");
    assert!(
        scripts[0].contains(
            "add rule inet warren warren_hairpin_snat ip saddr 10.66.0.0/16 oifname \"warren0\" masquerade"
        ),
        "hairpin masquerade must be installed and pool-scoped, got:\n{}",
        scripts[0]
    );
}

#[tokio::test]
async fn backend_allocate_emits_add_element_script() {
    // The DNAT must map `external_port → client_ip:internal_port`
    // (not client_ip:external_port). Pass an explicit internal_port
    // (8080) to validate the client-side port is preserved in the
    // DNAT rule.
    let recorder = Recorder::new();
    let backend = NftablesBackend::new(Arc::clone(&recorder))
        .await
        .expect("setup");
    let internal_port = 8080;
    let alloc = backend
        .allocate(
            ALICE,
            Proto::Tcp,
            internal_port,
            0,
            Duration::from_secs(600),
        )
        .await
        .expect("alloc");

    let scripts = recorder.scripts();
    assert_eq!(scripts.len(), 2, "setup + add element expected");
    let add_script = &scripts[1];
    let expected = format!(
        "add element inet warren natpmp_tcp_dnat {{ {ext} : 10.66.0.42 . {internal_port} }}",
        ext = alloc.external_port
    );
    assert_eq!(
        add_script.trim(),
        expected,
        "exact add element script expected, got:\n{add_script}"
    );
    assert_eq!(alloc.internal_port, internal_port);
}

#[tokio::test]
async fn backend_honors_suggested_external_port_when_free() {
    // Bug fix: the backend must forward the client's suggested
    // external port to the allocator instead of hardcoding 0. A free,
    // in-range suggestion is granted verbatim, and the DNAT rule maps
    // that exact external port.
    let recorder = Recorder::new();
    let backend = NftablesBackend::new(Arc::clone(&recorder))
        .await
        .expect("setup");
    let suggested = 50_000;
    let internal_port = 8080;
    let alloc = backend
        .allocate(
            ALICE,
            Proto::Tcp,
            internal_port,
            suggested,
            Duration::from_secs(600),
        )
        .await
        .expect("alloc");
    assert_eq!(
        alloc.external_port, suggested,
        "a free, in-range suggested port must be honoured verbatim"
    );
    let add_script = &recorder.scripts()[1];
    assert_eq!(
        add_script.trim(),
        format!(
            "add element inet warren natpmp_tcp_dnat {{ {suggested} : 10.66.0.42 . {internal_port} }}"
        )
    );
}

#[tokio::test]
async fn backend_dnats_to_external_port_when_internal_port_is_zero() {
    // Bug fix: a client that does not bind a specific local port sends
    // internal_port == 0. DNAT-ing to port 0 is a black hole, so the
    // backend must target the allocated external port instead
    // (public E → client:E).
    let recorder = Recorder::new();
    let backend = NftablesBackend::new(Arc::clone(&recorder))
        .await
        .expect("setup");
    let suggested = 51_000;
    let alloc = backend
        .allocate(ALICE, Proto::Udp, 0, suggested, Duration::from_secs(600))
        .await
        .expect("alloc");
    assert_eq!(alloc.external_port, suggested);
    assert_eq!(
        alloc.internal_port, 0,
        "the stored internal_port stays 0 so the RFC 6886 refresh key is unchanged"
    );
    let add_script = &recorder.scripts()[1];
    assert_eq!(
        add_script.trim(),
        format!(
            "add element inet warren natpmp_udp_dnat {{ {suggested} : 10.66.0.42 . {suggested} }}"
        ),
        "the DNAT target port must be the external port, never 0"
    );
}

#[tokio::test]
async fn backend_release_emits_delete_element_script() {
    let recorder = Recorder::new();
    let backend = NftablesBackend::new(Arc::clone(&recorder))
        .await
        .expect("setup");
    let alloc = backend
        .allocate(ALICE, Proto::Udp, 0, 0, Duration::from_secs(600))
        .await
        .expect("alloc");
    backend.release(&alloc).await.expect("release");

    let scripts = recorder.scripts();
    assert_eq!(scripts.len(), 3, "setup + add + delete expected");
    let del_script = &scripts[2];
    let expected = format!(
        "delete element inet warren natpmp_udp_dnat {{ {ext} }}",
        ext = alloc.external_port
    );
    assert_eq!(
        del_script.trim(),
        expected,
        "exact delete element script expected, got:\n{del_script}"
    );
}

#[tokio::test]
async fn refresh_to_a_new_port_deletes_the_old_dnat_element() {
    // Regression for the allocator<->nftables desync. A client that
    // refreshes its mapping with a CHANGED suggested external port used
    // to leave the OLD port's DNAT element behind (ghost). Observed
    // live: one client accumulated three UDP DNAT elements under a
    // quota of one, and then got QuotaExceeded on a fresh request. The
    // backend must now emit `delete element` for the surrendered port.
    let recorder = Recorder::new();
    let backend = NftablesBackend::new(Arc::clone(&recorder))
        .await
        .expect("setup");

    let first = backend
        .allocate(ALICE, Proto::Tcp, 8080, 50_111, Duration::from_secs(600))
        .await
        .expect("first map");
    assert_eq!(first.external_port, 50_111);

    let refreshed = backend
        .allocate(ALICE, Proto::Tcp, 8080, 50_222, Duration::from_secs(600))
        .await
        .expect("refresh to a new port");
    assert_eq!(refreshed.external_port, 50_222);

    let scripts = recorder.scripts();
    assert!(
        scripts
            .iter()
            .any(|s| s.trim() == "delete element inet warren natpmp_tcp_dnat { 50111 }"),
        "the old port's DNAT element must be deleted on a port-change refresh, got:\n{scripts:#?}"
    );
    assert_eq!(
        element_set(&scripts),
        std::collections::BTreeSet::from([("natpmp_tcp_dnat".to_string(), 50_222u16)]),
        "exactly the new port must remain mapped after the refresh - no ghost"
    );
}

#[tokio::test]
async fn expired_mapping_is_torn_down_at_the_backend_on_next_allocate() {
    // The expiry leg of the desync: a mapping that lapses without an
    // explicit delete is swept lazily on the next allocate. The backend
    // must delete its DNAT element instead of leaving it forwarding to a
    // gone client. Driven through the injectable-now `allocate_at` seam
    // because the RFC lifetime floor is 60s.
    let recorder = Recorder::new();
    let backend = NftablesBackend::new(Arc::clone(&recorder))
        .await
        .expect("setup");
    let t0 = std::time::Instant::now();

    let alice = backend
        .allocate_at(ALICE, Proto::Tcp, 8080, 50_111, Duration::from_secs(60), t0)
        .await
        .expect("alice maps");
    assert_eq!(alice.external_port, 50_111);

    let bob = backend
        .allocate_at(
            BOB,
            Proto::Tcp,
            9090,
            50_222,
            Duration::from_secs(60),
            t0 + Duration::from_secs(120),
        )
        .await
        .expect("bob maps after alice expired");
    assert_eq!(bob.external_port, 50_222);

    let scripts = recorder.scripts();
    assert!(
        scripts
            .iter()
            .any(|s| s.trim() == "delete element inet warren natpmp_tcp_dnat { 50111 }"),
        "alice's expired DNAT element must be deleted on the next allocate, got:\n{scripts:#?}"
    );
    let set = element_set(&scripts);
    assert!(
        !set.contains(&("natpmp_tcp_dnat".to_string(), 50_111u16)),
        "the expired port must not survive in the kernel map (ghost), got {set:?}"
    );
    assert!(
        set.contains(&("natpmp_tcp_dnat".to_string(), 50_222u16)),
        "bob's live mapping must be present, got {set:?}"
    );
}

#[tokio::test]
async fn backend_rolls_back_alloc_when_nft_fails() {
    // If `nft add element` fails (e.g. missing nat kernel module,
    // permission denied, etc.), the allocation must be undone on the
    // Allocator side so we do not leak a phantom server-side mapping
    // (which would respond with a port that nothing routes to).
    let recorder = Recorder::new();
    let backend = NftablesBackend::new(Arc::clone(&recorder))
        .await
        .expect("setup");
    recorder.arm_failure();

    let res = backend
        .allocate(ALICE, Proto::Tcp, 0, 0, Duration::from_secs(600))
        .await;
    assert!(
        res.is_err(),
        "allocate must propagate the backend error, got {res:?}"
    );

    // No leak in the allocator: active_count must stay at 0.
    assert_eq!(
        backend.allocator().active_count(),
        0,
        "rollback: no mapping must remain active after a failed add element"
    );
}

#[tokio::test]
async fn restore_reinjects_kernel_elements_for_saved_mappings() {
    let recorder = Recorder::new();
    let backend = NftablesBackend::new(Arc::clone(&recorder))
        .await
        .expect("setup");
    let alloc = backend
        .allocate(
            Ipv4Addr::new(10, 66, 0, 42),
            Proto::Tcp,
            8080,
            50000,
            Duration::from_secs(600),
        )
        .await
        .expect("alloc");

    // Fresh backend = process restart (its setup script wiped the table).
    let recorder2 = Recorder::new();
    let backend2 = NftablesBackend::new(Arc::clone(&recorder2))
        .await
        .expect("setup 2");
    let reinstated = backend2.restore(vec![alloc]).await;
    assert_eq!(reinstated.len(), 1);
    assert_eq!(backend2.allocator().active_count(), 1);
    let scripts = recorder2.scripts();
    assert!(
        scripts
            .iter()
            .any(|s| s.contains("50000") && s.contains("add element")),
        "restore must re-add the DNAT element, got {scripts:?}"
    );
}

#[tokio::test]
async fn restore_drops_entry_when_kernel_reinject_fails() {
    let recorder = Recorder::new();
    let backend = NftablesBackend::new(Arc::clone(&recorder))
        .await
        .expect("setup");
    let alloc = backend
        .allocate(
            Ipv4Addr::new(10, 66, 0, 42),
            Proto::Udp,
            1000,
            50001,
            Duration::from_secs(600),
        )
        .await
        .expect("alloc");

    let recorder2 = Recorder::new();
    let backend2 = NftablesBackend::new(Arc::clone(&recorder2))
        .await
        .expect("setup 2");
    recorder2.arm_failure();
    let reinstated = backend2.restore(vec![alloc]).await;
    assert!(
        reinstated.is_empty(),
        "an entry whose kernel rule failed must not be reported as restored"
    );
    assert_eq!(
        backend2.allocator().active_count(),
        0,
        "no phantom allocator entry without a kernel rule"
    );
}
