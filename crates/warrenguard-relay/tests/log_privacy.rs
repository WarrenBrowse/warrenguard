//! The relay's per-leg path probe writes below `info`: on a relay node the
//! client-variant line would be one activity timeline per relayed session,
//! and paired with the exit's own lines it ties the two legs together.

#[test]
fn the_relay_spawns_only_the_server_path_probe() {
    let entries = std::fs::read_dir("src").expect("read src/");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            !src.contains("spawn_path_probe("),
            "{} spawns the client path probe; a relay must use spawn_server_path_probe",
            path.display()
        );
    }
}
