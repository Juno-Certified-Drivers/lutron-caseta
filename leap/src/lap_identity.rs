//! The client identity every Caséta bridge is provisioned to recognize on its pairing port.
//!
//! This is not a secret — it is published as part of Lutron's own open LEAP client library
//! (`pylutron_caseta`, the one Home Assistant uses), because pairing is a chicken-and-egg
//! problem: a client needs *some* certificate the bridge already trusts before it can be
//! issued a real one. Every third-party integration presents this same identity for exactly
//! that one exchange; it grants nothing beyond "let me submit a CSR," and the per-installation
//! certificate the bridge signs in response is what actually authorizes anything afterward.
//!
//! Source: <https://github.com/gurumitts/pylutron-caseta/blob/dev/src/pylutron_caseta/assets.py>
//! Kept as standalone `.pem` files (rather than inline strings) so `core/examples/leap_probe.rs`
//! can `include_str!` the same files without depending on this crate.

pub const LAP_CERT_PEM: &str = include_str!("lap_cert.pem");
pub const LAP_KEY_PEM: &str = include_str!("lap_key.pem");
