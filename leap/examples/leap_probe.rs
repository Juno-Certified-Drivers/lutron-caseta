//! Standalone probe for a Caséta bridge's LEAP API — no server, no UI, no `Runtime`. It reuses
//! exactly the TLS code `core` uses for real (`junod::io::Http` and its `leap://`/`leaps://`
//! handling), so this proves whether the wire-format assumptions baked into
//! this driver match what a real bridge actually says. Every response
//! prints as raw JSON — a mismatch shows up here, not as a silent failure deep in the driver.
//!
//! ```bash
//! cargo run --example leap_probe -- pair [<bridge-ip>]       # press the bridge's button first
//! cargo run --example leap_probe -- list                     # after pairing
//! cargo run --example leap_probe -- set <zone-href> <level>  # after pairing
//! ```
//!
//! Pairing writes the issued certificate to a state file (`$LEAP_PROBE_STATE`, or a temp file
//! by default) so `list`/`set` do not need the button pressed again.

use junod::driver::host::HttpRequest;
use junod::io::Http;
use serde_json::{Value, json};

fn state_file() -> std::path::PathBuf {
    std::env::var("LEAP_PROBE_STATE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("juno-leap-probe.json"))
}

fn save(state: &Value) {
    let path = state_file();
    std::fs::write(&path, serde_json::to_string_pretty(state).unwrap()).expect("write pairing state");
    println!("saved pairing to {}", path.display());
}

fn load() -> Option<(String, String, String)> {
    let state: Value = serde_json::from_str(&std::fs::read_to_string(state_file()).ok()?).ok()?;
    Some((
        state.get("address")?.as_str()?.to_string(),
        state.get("cert_pem")?.as_str()?.to_string(),
        state.get("key_pem")?.as_str()?.to_string(),
    ))
}

fn discover_address() -> Option<String> {
    println!("scanning mDNS for _lutron._tcp (3s)...");
    let found = junod::mdns::scan(&["_lutron._tcp".to_string()], std::time::Duration::from_secs(3));
    let first = found.first().cloned()?;
    println!("found {} at {}", first.name, first.address);
    Some(first.address)
}

/// The per-installation keypair and CSR — what the bridge is asked to sign. Distinct from the
/// fixed `LAP_CERT_PEM`/`LAP_KEY_PEM` identity below, which is what gets the connection in the
/// door in the first place.
fn generate_csr() -> (String, String) {
    let key_pair = rcgen::KeyPair::generate().expect("generate keypair");
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, "juno-probe");
    let csr = params.serialize_request(&key_pair).expect("build csr");
    (key_pair.serialize_pem(), csr.pem().expect("csr pem"))
}

// Lutron's own published pairing identity — every third-party LEAP client presents this same
// certificate to get in the door before it has one of its own. Not a secret; see
// src/lap_identity.rs for where this came from.
const LAP_CERT_PEM: &str = include_str!("../src/lap_cert.pem");
const LAP_KEY_PEM: &str = include_str!("../src/lap_key.pem");

fn show(label: &str, req: &HttpRequest) {
    println!("--> {label}\n{}", req.body.as_deref().unwrap_or(""));
}

fn pair(addr: &str) {
    let (key_pem, csr_pem) = generate_csr();

    let body = json!({
        "Header": {
            "RequestType": "Execute",
            "Url": "/pair",
            "ClientTag": "get-cert",
        },
        "Body": {
            "CommandType": "CSR",
            "Parameters": {
                "CSR": csr_pem,
                "DisplayName": "Juno probe",
                "DeviceUID": "000000000000",
                "Role": "Admin",
            },
        },
    });
    let req = HttpRequest::new("POST", format!("leaps://{addr}:8083/pair"))
        .header("x-client-cert", LAP_CERT_PEM)
        .header("x-client-key", LAP_KEY_PEM)
        .json(body.to_string());
    show("POST /pair", &req);
    println!(
        "connecting and waiting up to 30s for the bridge to confirm a button press — press \
         and release the button on the bridge NOW..."
    );

    match Http::request(&req) {
        Ok(resp) => {
            println!("<-- status {}\n{}", resp.status, resp.body);
            let parsed: Value = serde_json::from_str(resp.body.trim()).unwrap_or(Value::Null);
            let cert = parsed.pointer("/Body/SigningResult/Certificate").and_then(Value::as_str);
            let ca = parsed.pointer("/Body/SigningResult/RootCertificate").and_then(Value::as_str);
            match (cert, ca) {
                (Some(cert), Some(ca)) => {
                    save(&json!({ "address": addr, "cert_pem": cert, "key_pem": key_pem, "ca_pem": ca }));
                    println!("paired.");
                }
                _ => println!(
                    "no certificate in that reply — see the raw JSON above. The field names \
                     the driver expects are Body.SigningResult.Certificate / .RootCertificate."
                ),
            }
        }
        Err(e) => println!("request failed: {e}"),
    }
}

fn list() {
    let Some((addr, cert, key)) = load() else {
        println!("no saved pairing — run `pair` first");
        return;
    };
    let body = json!({ "CommuniqueType": "ReadRequest", "Header": { "Url": "/device" } });
    let req = HttpRequest::new("POST", format!("leaps://{addr}:8081/device"))
        .header("x-client-cert", cert)
        .header("x-client-key", key)
        .json(body.to_string());
    show("ReadRequest /device", &req);
    match Http::request(&req) {
        Ok(resp) => println!("<-- status {}\n{}", resp.status, resp.body),
        Err(e) => println!("request failed: {e}"),
    }
}

fn set_level(zone: &str, level: u8) {
    let Some((addr, cert, key)) = load() else {
        println!("no saved pairing — run `pair` first");
        return;
    };
    let body = json!({
        "CommuniqueType": "CreateRequest",
        "Header": { "Url": format!("{zone}/commandprocessor") },
        "Body": {
            "Command": {
                "CommandType": "GoToDimmedLevel",
                "DimmedLevelParameters": { "Level": level, "FadeTime": "00:00:01" },
            },
        },
    });
    let req = HttpRequest::new("POST", format!("leaps://{addr}:8081{zone}/commandprocessor"))
        .header("x-client-cert", cert)
        .header("x-client-key", key)
        .json(body.to_string());
    show("GoToDimmedLevel", &req);
    match Http::request(&req) {
        Ok(resp) => println!("<-- status {}\n{}", resp.status, resp.body),
        Err(e) => println!("request failed: {e}"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("pair") => {
            let addr = args
                .get(2)
                .cloned()
                .or_else(discover_address)
                .expect("no bridge address given, and none found over mDNS");
            pair(&addr);
        }
        Some("list") => list(),
        Some("set") => {
            let zone = args.get(2).expect("usage: set <zone-href> <level>");
            let level: u8 = args
                .get(3)
                .expect("usage: set <zone-href> <level>")
                .parse()
                .expect("level must be 0-100");
            set_level(zone, level);
        }
        _ => println!("usage: leap_probe pair [<ip>] | list | set <zone-href> <level>"),
    }
}
