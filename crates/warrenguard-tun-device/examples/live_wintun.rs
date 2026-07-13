//! Windows Wintun device smoke-test harness. EXPERIMENTAL.
//!
//! Cannot run from the dev sandbox: needs a Windows host, Administrator, and the
//! `wintun.dll` runtime on PATH (or next to the exe). It opens a Wintun adapter,
//! confirms the device is live, attempts one non-blocking read, and tears down.
//! This validates the Windows device open + ring I/O in isolation; a full
//! tunnel additionally needs routing, killswitch and a driver loop on top,
//! which a deployer wires up separately (see the crate docs).
//!
//! Run on Windows as Administrator:
//!   cargo run -p warrenguard-tun-device --example live_wintun --features experimental-tun

#[cfg(all(target_os = "windows", feature = "experimental-tun"))]
fn main() -> std::io::Result<()> {
    use warrenguard_tun_device::RawTunDevice;

    println!("opening Wintun adapter 'warren0' (needs Administrator + wintun.dll)...");
    let mut device = warrenguard_tun_device::device::open_tun("warren0")?;
    println!("adapter open. attempting one non-blocking read...");

    let mut buf = vec![0u8; 1500 + 4];
    match device.read_frame(&mut buf) {
        Ok(n) => println!("read {n} bytes from the device"),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            println!("no packet pending (expected on a quiet device): ring I/O works");
        }
        Err(e) => return Err(e),
    }
    println!("Wintun device smoke test OK; tearing down.");
    Ok(()) // dropping `device` ends the session + closes the adapter + frees the DLL
}

#[cfg(not(all(target_os = "windows", feature = "experimental-tun")))]
fn main() {
    eprintln!(
        "live_wintun runs on Windows with --features experimental-tun \
         (as Administrator, with wintun.dll on PATH)."
    );
}
