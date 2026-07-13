//! Tests of nftables script rendering (pure, no I/O).
//!
//! These validate the *exact syntax* sent to `nft -f -` on the Linux
//! exit. Any accidental mutation (whitespace, keyword order,
//! table/chain/map names) breaks these tests, preventing a silent
//! fault from only surfacing at VPS deployment time.

use std::net::Ipv4Addr;

use warrenguard_natpmp_server::Proto;
use warrenguard_natpmp_server::nftables::{
    render_add_element, render_delete_element, render_hairpin_snat_setup,
    render_portfail_guard_setup, render_setup_script, render_sync_client_ips,
};

// ---------------------------------------------------------------------------
// render_setup_script: table + chain + maps + rules
// ---------------------------------------------------------------------------

#[test]
fn setup_script_resets_table_idempotently_on_each_boot() {
    // On boot we must clean up any prior daemon state (previous
    // crash, nft shut down badly, ...). Idempotent pattern
    // compatible with nft 1.0.6 (Debian 12), which does not support
    // `destroy table`:
    //   add table       (no-op if it exists, creates if absent)
    //   delete table    (necessarily exists after the add)
    //   add table       (recreates empty)
    // The `destroy` keyword was not enabled in the Debian build of
    // nftables 1.0.6, so we avoid it.
    let script = render_setup_script("warren", "prerouting_natpmp", None);
    let add_idx = script
        .find("add table inet warren")
        .expect("must contain add table");
    let delete_idx = script
        .find("delete table inet warren")
        .expect("must contain delete table");
    let second_add_idx = script[add_idx + 1..]
        .find("add table inet warren")
        .expect("must contain a second add table after the delete")
        + add_idx
        + 1;
    assert!(
        add_idx < delete_idx && delete_idx < second_add_idx,
        "expected order: add → delete → add, got positions {add_idx}/{delete_idx}/{second_add_idx} in:\n{script}"
    );
    // Anti-regression: no `destroy` (incompatible Debian 12 nft 1.0.6).
    assert!(
        !script.contains("destroy table"),
        "must not use `destroy table` (incompat nft Debian 12), got:\n{script}"
    );
}

#[test]
fn setup_script_creates_table_in_inet_family() {
    let script = render_setup_script("warren", "prerouting_natpmp", None);
    assert!(
        script.contains("add table inet warren"),
        "expected inet (dual-stack) table, got:\n{script}"
    );
}

#[test]
fn setup_script_creates_dnat_chain() {
    let script = render_setup_script("warren", "prerouting_natpmp", None);
    // Chain must hook prerouting + priority dstnat (= -100, the
    // standard DNAT priority). Symbolic `dstnat` syntax is supported
    // since nftables 0.9.6.
    assert!(
        script.contains("add chain inet warren prerouting_natpmp"),
        "missing chain, got:\n{script}"
    );
    assert!(
        script.contains("type nat hook prerouting priority dstnat"),
        "chain must be type nat, hook prerouting, priority dstnat, got:\n{script}"
    );
}

#[test]
fn setup_script_creates_tcp_and_udp_maps() {
    let script = render_setup_script("warren", "prerouting_natpmp", None);
    // Map key = external port, value = (internal IP, internal port).
    assert!(
        script.contains("add map inet warren natpmp_tcp_dnat"),
        "missing TCP map, got:\n{script}"
    );
    assert!(
        script.contains("add map inet warren natpmp_udp_dnat"),
        "missing UDP map, got:\n{script}"
    );
    // Map type: critical for the per-map DNAT syntax.
    assert!(
        script.contains("type inet_service : ipv4_addr . inet_service"),
        "incorrect map type (must be port→IP.port), got:\n{script}"
    );
}

#[test]
fn setup_script_creates_dnat_rules_for_both_protocols() {
    let script = render_setup_script("warren", "prerouting_natpmp", None);
    // TCP rule: meta l4proto tcp + map-based DNAT. Compatible with
    // Debian 12 nft 1.0.6 (cf. render_setup_script doc-comment).
    assert!(
        script.contains(
            "add rule inet warren prerouting_natpmp meta l4proto tcp dnat ip to tcp dport map @natpmp_tcp_dnat"
        ),
        "missing or syntactically incorrect TCP DNAT rule, got:\n{script}"
    );
    assert!(
        script.contains(
            "add rule inet warren prerouting_natpmp meta l4proto udp dnat ip to udp dport map @natpmp_udp_dnat"
        ),
        "missing or syntactically incorrect UDP DNAT rule, got:\n{script}"
    );
}

#[test]
fn setup_script_scopes_dnat_to_forwarded_port_ip_when_given() {
    // Port Fail parade (Perfect Privacy 2015): forwarded ports must live
    // on a dedicated egress IP, NOT the QUIC ingress endpoint. With a
    // pfwd IP, each DNAT rule gains an `ip daddr <PFWD_IP>` match so it
    // only fires for packets destined to that address. A co-tenant
    // probing the port then transits the tunnel instead of leaking its
    // real off-tunnel IP (which the ingress route-split bypass would).
    let pfwd = Ipv4Addr::new(203, 0, 113, 7);
    let script = render_setup_script("warren", "prerouting_natpmp", Some(pfwd));
    assert!(
        script.contains(
            "add rule inet warren prerouting_natpmp ip daddr 203.0.113.7 meta l4proto tcp dnat ip to tcp dport map @natpmp_tcp_dnat"
        ),
        "TCP DNAT rule must be scoped to the forwarded-port IP, got:\n{script}"
    );
    assert!(
        script.contains(
            "add rule inet warren prerouting_natpmp ip daddr 203.0.113.7 meta l4proto udp dnat ip to udp dport map @natpmp_udp_dnat"
        ),
        "UDP DNAT rule must be scoped to the forwarded-port IP, got:\n{script}"
    );
}

#[test]
fn setup_script_without_scope_matches_any_destination() {
    // Single-IP dev fallback: no `ip daddr` match, DNAT on any
    // destination (the legacy behaviour). Explicit so a future change
    // cannot silently start scoping dev nodes and black-hole their ports.
    let script = render_setup_script("warren", "prerouting_natpmp", None);
    assert!(
        !script.contains("ip daddr"),
        "unscoped setup must not emit an ip daddr match, got:\n{script}"
    );
}

#[test]
fn setup_script_uses_custom_table_and_chain_names() {
    // Sanity: names are not hardcoded. An operator wanting to
    // colocate several warren-* on the same host (e.g. dev + prod)
    // can change the prefix.
    let script = render_setup_script("warren_dev", "myroute", None);
    assert!(
        script.contains("delete table inet warren_dev"),
        "custom table must appear in the reset, got:\n{script}"
    );
    assert!(
        script.contains("add chain inet warren_dev myroute"),
        "custom chain must appear, got:\n{script}"
    );
}

// ---------------------------------------------------------------------------
// render_portfail_guard_setup: connected-subscriber real-IP leak guard
// (defense in depth for old clients whose route-split is not yet fixed)
// ---------------------------------------------------------------------------

#[test]
fn portfail_guard_creates_a_client_real_ip_set() {
    // The guard drops packets whose SOURCE is the real (outer, 5-tuple) IP of
    // a currently-connected subscriber. Those IPs are held in a dynamic set,
    // synced by the exit as sessions come and go.
    let script = render_portfail_guard_setup(
        "warren",
        "warren_portfail_guard",
        "warren_client_real_ips",
        "10.66.0.0/16",
    );
    assert!(
        script.contains("add set inet warren warren_client_real_ips { type ipv4_addr ; }"),
        "guard must declare the connected-subscriber real-IP set, got:\n{script}"
    );
}

#[test]
fn portfail_guard_hook_runs_before_the_forward_accept() {
    // Placed on the forward hook at a priority below the default filter (0)
    // so it evaluates the already-DNATed packet (daddr rewritten to the
    // owner's inner pool IP) and drops it before the main forward chain would
    // accept the flow onto the TUN.
    let script = render_portfail_guard_setup(
        "warren",
        "warren_portfail_guard",
        "warren_client_real_ips",
        "10.66.0.0/16",
    );
    assert!(
        script.contains("add chain inet warren warren_portfail_guard { type filter hook forward priority -10 ; policy accept ; }"),
        "guard chain must hook forward before the filter default, got:\n{script}"
    );
}

#[test]
fn portfail_guard_drops_only_connected_real_ip_sources_to_a_forwarded_port() {
    // The DROP is narrow: source is a connected subscriber's real IP AND the
    // destination is a forwarded port (post-DNAT daddr is in the inner pool,
    // because only forwarded-port packets are DNATed into the pool). This is
    // NOT a tunneled-vs-untunneled filter: a public Internet peer is never in
    // the set, so its probe to the forwarded port passes untouched.
    let script = render_portfail_guard_setup(
        "warren",
        "warren_portfail_guard",
        "warren_client_real_ips",
        "10.66.0.0/16",
    );
    assert!(
        script.contains(
            "add rule inet warren warren_portfail_guard ip saddr @warren_client_real_ips ip daddr 10.66.0.0/16 drop"
        ),
        "the drop must be scoped to (connected real IP -> forwarded port), got:\n{script}"
    );
}

#[test]
fn portfail_guard_has_no_unconditional_or_tunnel_wide_drop() {
    // Anti-regression: the guard must never blanket-drop. Every drop line is
    // conditioned on the connected-real-IP set, so port forwarding stays
    // unrestricted for public peers and the exit never filters "tunneled vs
    // not". A stray `drop` without `@warren_client_real_ips` would break both.
    let script = render_portfail_guard_setup(
        "warren",
        "warren_portfail_guard",
        "warren_client_real_ips",
        "10.66.0.0/16",
    );
    for line in script.lines().filter(|l| l.contains("drop")) {
        assert!(
            line.contains("@warren_client_real_ips"),
            "a drop line is not scoped to the connected-real-IP set: {line}"
        );
    }
}

// ---------------------------------------------------------------------------
// render_sync_client_ips: atomically replace the set membership
// ---------------------------------------------------------------------------

#[test]
fn sync_client_ips_flushes_then_adds_each_ip() {
    // One atomic `nft -f -` script: flush the set, then re-add the current
    // connected-subscriber real IPs. Flush-first makes the update a full
    // replace, so a disconnected client's IP stops being dropped at once.
    let ips = [
        Ipv4Addr::new(198, 51, 100, 7),
        Ipv4Addr::new(203, 0, 113, 9),
    ];
    let script = render_sync_client_ips("warren", "warren_client_real_ips", &ips);
    let flush_idx = script
        .find("flush set inet warren warren_client_real_ips")
        .expect("must flush the set first");
    let first_add = script
        .find("add element inet warren warren_client_real_ips { 198.51.100.7 }")
        .expect("must add the first IP");
    let second_add = script
        .find("add element inet warren warren_client_real_ips { 203.0.113.9 }")
        .expect("must add the second IP");
    assert!(
        flush_idx < first_add && first_add < second_add,
        "expected flush before adds, got positions {flush_idx}/{first_add}/{second_add} in:\n{script}"
    );
}

#[test]
fn sync_client_ips_empty_only_flushes() {
    // No connected subscribers => an empty set => the guard drops nothing
    // (fail-open when there is nothing to protect). The sync must still emit
    // the flush so a previously-populated set is cleared.
    let script = render_sync_client_ips("warren", "warren_client_real_ips", &[]);
    assert_eq!(
        script.trim(),
        "flush set inet warren warren_client_real_ips",
        "empty sync must be exactly the flush, got:\n{script}"
    );
}

// ---------------------------------------------------------------------------
// render_hairpin_snat_setup: optional same-exit-peer inner-IP masking
// (off by default; 10.66.x is ephemeral, so the gain is marginal)
// ---------------------------------------------------------------------------

#[test]
fn hairpin_snat_creates_a_postrouting_srcnat_chain() {
    let script =
        render_hairpin_snat_setup("warren", "warren_hairpin_snat", "10.66.0.0/16", "warren0");
    assert!(
        script.contains(
            "add chain inet warren warren_hairpin_snat { type nat hook postrouting priority srcnat ; policy accept ; }"
        ),
        "hairpin SNAT must hook postrouting/srcnat, got:\n{script}"
    );
}

#[test]
fn hairpin_snat_masquerades_only_pool_internal_sources_back_into_the_tun() {
    // The DNAT of a forwarded port sends a same-exit peer's packet BACK out the
    // tun to the owner, keeping the peer's inner 10.66.x source. Masquerading
    // it to the tun gateway hides that inner IP from the owner. It is scoped to
    // `ip saddr <pool> oifname "<tun>"`, so it fires ONLY for hairpinned
    // pool-internal sources.
    let script =
        render_hairpin_snat_setup("warren", "warren_hairpin_snat", "10.66.0.0/16", "warren0");
    assert!(
        script.contains(
            "add rule inet warren warren_hairpin_snat ip saddr 10.66.0.0/16 oifname \"warren0\" masquerade"
        ),
        "hairpin masquerade must be scoped to pool sources going out the tun, got:\n{script}"
    );
}

#[test]
fn hairpin_snat_never_masquerades_a_public_peer() {
    // Feature-preserving invariant: a public Internet peer (NOT in the pool)
    // reaching a forwarded port keeps its real source IP, because every
    // masquerade line is scoped to `ip saddr <pool>`. A stray masquerade
    // without the pool scope would silently rewrite public peers.
    let script =
        render_hairpin_snat_setup("warren", "warren_hairpin_snat", "10.66.0.0/16", "warren0");
    for line in script.lines().filter(|l| l.contains("masquerade")) {
        assert!(
            line.contains("ip saddr 10.66.0.0/16"),
            "a masquerade line is not scoped to pool-internal sources: {line}"
        );
    }
}

// ---------------------------------------------------------------------------
// render_add_element: insert a mapping into the map
// ---------------------------------------------------------------------------

#[test]
fn add_element_tcp_uses_tcp_map() {
    let s = render_add_element(
        "warren",
        Proto::Tcp,
        49180,
        Ipv4Addr::new(10, 66, 0, 7),
        49180,
    );
    assert_eq!(
        s, "add element inet warren natpmp_tcp_dnat { 49180 : 10.66.0.7 . 49180 }",
        "exact syntax expected (whitespace included), got:\n{s}"
    );
}

#[test]
fn add_element_udp_uses_udp_map() {
    let s = render_add_element(
        "warren",
        Proto::Udp,
        49200,
        Ipv4Addr::new(10, 66, 5, 42),
        49200,
    );
    assert_eq!(
        s, "add element inet warren natpmp_udp_dnat { 49200 : 10.66.5.42 . 49200 }",
        "exact UDP syntax expected, got:\n{s}"
    );
}

#[test]
fn add_element_distinct_internal_external_ports() {
    // Non-trivial case: if the allocator ever maps an external port
    // distinct from the internal port (e.g. external collision on
    // the suggested port), the syntax must reflect it.
    let s = render_add_element(
        "warren",
        Proto::Tcp,
        50001,
        Ipv4Addr::new(10, 66, 0, 7),
        49180,
    );
    assert_eq!(
        s, "add element inet warren natpmp_tcp_dnat { 50001 : 10.66.0.7 . 49180 }",
        "external != internal port must be encoded correctly, got:\n{s}"
    );
}

// ---------------------------------------------------------------------------
// render_delete_element: remove by external port
// ---------------------------------------------------------------------------

#[test]
fn delete_element_tcp() {
    let s = render_delete_element("warren", Proto::Tcp, 49180);
    assert_eq!(
        s, "delete element inet warren natpmp_tcp_dnat { 49180 }",
        "TCP delete: exact syntax expected, got:\n{s}"
    );
}

#[test]
fn delete_element_udp() {
    let s = render_delete_element("warren", Proto::Udp, 49200);
    assert_eq!(
        s, "delete element inet warren natpmp_udp_dnat { 49200 }",
        "UDP delete: exact syntax expected, got:\n{s}"
    );
}
