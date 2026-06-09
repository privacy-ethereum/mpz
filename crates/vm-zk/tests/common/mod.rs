//! Shared test utilities.

use std::sync::Once;

use tracing_subscriber::{EnvFilter, fmt};

static INIT_TRACING: Once = Once::new();

/// Install a `tracing-subscriber` once per test process. Filter
/// defaults to `mpz_vm_zk=info` and is overridable via `RUST_LOG`.
/// Output goes to stderr; cargo test captures it unless `--nocapture`
/// is passed.
pub fn init_tracing() {
    INIT_TRACING.call_once(|| {
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("mpz_vm_zk=info"));
        let _ = fmt()
            .with_env_filter(filter)
            .with_test_writer()
            .with_target(true)
            .try_init();
    });
}
