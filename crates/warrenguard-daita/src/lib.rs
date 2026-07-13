//! DAITA (Defense Against AI-guided Traffic Analysis) for the WarrenGuard
//! tunnel: the maybenot-driven padding/blocking framework shared by the client
//! and the server, plus the server-side machine pool. The defense is inert
//! unless negotiated for a session.

pub mod daita;
pub mod daita_pool;

pub use daita::{
    DAITA_PLACEHOLDER_SLEEP, DaitaAction, DaitaConfig, DaitaConfigExt, DaitaError, DaitaEvent,
    DaitaFramework, DaitaMetrics, DaitaState, DaitaTimer, MachineId,
};
pub use daita_pool::DaitaPool;
