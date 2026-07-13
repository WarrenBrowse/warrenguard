//! Multi-hop TUN <-> tunnel pump: thin re-export of the engine pump
//! (`warrenguard_pump::pump_multi_hop_bidirectional`), so the call site can
//! match on the typed [`warrenguard_pump::MultiHopPumpError`] instead of an
//! opaque `anyhow::Error` while the loop itself lives once in the engine.

use std::sync::Arc;

use warrenguard_daita::daita::DaitaState;
use warrenguard_pump::{MultiHopPumpError, WarrenPumpHandle};
use warrenguard_transport_core::PacketDevice;

/// Pumps a [`PacketDevice`] (TUN) against any [`WarrenPumpHandle`].
///
/// # Errors
///
/// [`MultiHopPumpError`] on the first direction failure (TUN I/O or the
/// tunnel handle).
pub async fn pump_multi_hop_bidirectional<P, T>(
    pump: Arc<P>,
    tun: T,
) -> Result<(), MultiHopPumpError<P::Error>>
where
    P: WarrenPumpHandle + Send + Sync + 'static,
    T: PacketDevice + Clone + Send + Sync + 'static,
{
    warrenguard_pump::pump_multi_hop_bidirectional(pump, tun).await
}

/// DAITA-aware variant of [`pump_multi_hop_bidirectional`].
///
/// # Errors
///
/// [`MultiHopPumpError`] on the first direction failure (TUN I/O or the
/// tunnel handle).
pub async fn pump_multi_hop_bidirectional_with_daita<P, T>(
    pump: Arc<P>,
    tun: T,
    state: DaitaState,
) -> Result<(), MultiHopPumpError<P::Error>>
where
    P: WarrenPumpHandle + Send + Sync + 'static,
    T: PacketDevice + Clone + Send + Sync + 'static,
{
    warrenguard_pump::pump_multi_hop_bidirectional_with_daita(pump, tun, state).await
}
