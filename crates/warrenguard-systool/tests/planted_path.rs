//! A process that embeds the engine inherits its `PATH` from whoever launched
//! it. A tool planted ahead of the system directories in that `PATH` must never
//! run, neither when the engine starts the tool itself nor when a tool it
//! started runs another one by name.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use warrenguard_systool::SystemTool;

/// Set in the re-executed child: the marker file its planted tools append to.
const CHILD_MARKER: &str = "WARRENGUARD_SYSTOOL_PLANTED_MARKER";

const TEST_NAME: &str = "a_tool_planted_ahead_in_the_callers_path_never_runs";

/// Arguments that make a real tool print something and exit at once. With
/// none, `netstat` and `route` resolve every address they list through DNS,
/// which stalls on a host whose resolver is down.
fn quiet_args(tool: SystemTool) -> &'static [&'static str] {
    match tool {
        SystemTool::Netstat | SystemTool::Route => &["-n"],
        _ => &[],
    }
}

/// Runs every tool this host has, directly and by name through the shell, the
/// way the engine's call sites do. The tools get no input, so the real ones
/// print a usage or a listing and exit.
fn run_every_tool() {
    for tool in SystemTool::ALL {
        let Ok(mut command) = tool.command() else {
            continue;
        };
        let _ = command
            .args(quiet_args(tool))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if tool == SystemTool::PowerShell {
            continue;
        }
        if let Ok(mut shell) = SystemTool::Sh.command() {
            let script = std::iter::once(tool.name())
                .chain(quiet_args(tool).iter().copied())
                .collect::<Vec<_>>()
                .join(" ");
            let _ = shell
                .args(["-c", &script])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// Fills `dir` with one executable per tool that records its own name in
/// `marker` when it runs.
fn plant_tools(dir: &Path, marker: &Path) {
    for tool in SystemTool::ALL {
        let script = dir.join(tool.name());
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\necho {} >> '{}'\n",
                tool.name(),
                marker.display()
            ),
        )
        .expect("write planted tool");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("make planted tool executable");
    }
}

fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wg-systool-planted-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("bin")).expect("create scratch dir");
    dir
}

#[test]
fn a_tool_planted_ahead_in_the_callers_path_never_runs() {
    if std::env::var_os(CHILD_MARKER).is_some() {
        run_every_tool();
        return;
    }

    let dir = scratch_dir();
    let planted = dir.join("bin");
    let marker = dir.join("ran");
    plant_tools(&planted, &marker);
    let callers_path = format!(
        "{}:{}",
        planted.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    // The child is this same test, re-executed with the planted directory at
    // the head of its PATH, which is the only way to give a process a hostile
    // PATH without mutating the environment of the test harness itself.
    #[allow(
        clippy::disallowed_methods,
        reason = "re-executes the test binary itself, not a system tool"
    )]
    let status = std::process::Command::new(std::env::current_exe().expect("test binary path"))
        .args([TEST_NAME, "--exact", "--test-threads=1"])
        .env("PATH", callers_path)
        .env(CHILD_MARKER, &marker)
        .stdout(Stdio::null())
        .status()
        .expect("re-execute the test binary");
    let ran = std::fs::read_to_string(&marker).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(status.success(), "the child run failed: {status}");
    assert!(
        ran.is_empty(),
        "tools planted in the caller's PATH ran: {:?}",
        ran.lines().collect::<Vec<_>>()
    );
}
