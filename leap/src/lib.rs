//! Lutron Caséta over LEAP — the bridge's TLS API port, as opposed to the PRO-only plaintext
//! integration port `lutron.caseta.dimmer` speaks.
//!
//! Two manifests share this one module: `lutron.caseta.leap_bridge` (the parent — pairing
//! lives here) and `lutron.caseta.leap_dimmer` (a zone behind it). A dimmer is never set up on
//! its own; it is found by browsing an already-paired bridge, the same way a Hue bulb is found
//! by browsing a Hue bridge.
//!
//! LEAP itself is not HTTP. It is one JSON object per line over a TLS socket:
//!
//! - Port 8083, pairing: connect presenting Lutron's own published pairing identity (see
//!   [`lap_identity`] — every third-party LEAP client uses this same one; it exists so a
//!   client can talk to the bridge *before* it has an identity of its own), wait for the
//!   bridge to push confirmation that its button was physically pressed, then submit a CSR
//!   and get back a certificate signed for this installation specifically.
//! - Port 8081, mutual TLS with that certificate: everything else. A `ReadRequest` for
//!   `/device` lists what is paired; a `SubscribeRequest` on a zone's `/status` is how a wall
//!   dimmer press reaches us without polling.
//!
//! Core has no idea any of this is going on. Pairing rides `SetupStep::Fetch` against a
//! `leaps://` pseudo-URL core's `Http::request` knows how to speak (waiting for the
//! button-press push is core's job too — see its `request_leap`); the live connection rides
//! the same `control: 0` Tx/rx path the integration-port driver uses, just wrapped in TLS
//! because the manifest says so.

mod lap_identity;

use driver_sdk::*;
use std::collections::BTreeMap;

const BRIDGE_ID: &str = "lutron.caseta.leap_bridge";
const DIMMER_ID: &str = "lutron.caseta.leap_dimmer";

/// `control: 0` is the driver's own network transport — core owns the socket.
const NET: LocalId = 0;

#[derive(Default)]
pub struct CasetaLeap;

// ---------------------------------------------------------------------------------------
// Setup flow — pairing a bridge, then listing what is behind it.
// ---------------------------------------------------------------------------------------

fn field(state: &Value, key: &str) -> String {
    state.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Merge a few keys into a state object, keeping everything else. State is opaque to core —
/// it round-trips through the installer's browser between steps, so it has to be plain JSON.
fn with_fields(state: &Value, updates: &[(&str, &str)]) -> Value {
    let mut m = state.as_object().cloned().unwrap_or_default();
    for (k, v) in updates {
        m.insert((*k).to_string(), json!(v));
    }
    Value::Object(m)
}

fn instruct(title: &str, body: &str) -> SetupStep {
    SetupStep::Instruct {
        title: title.into(),
        body: body.into(),
        continue_label: "Continue".into(),
    }
}

fn generate_csr() -> Result<(String, String), String> {
    let key_pair = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "juno");
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| e.to_string())?;
    Ok((key_pair.serialize_pem(), csr.pem().map_err(|e| e.to_string())?))
}

/// What core's mDNS scan found before this flow's first call, if anything — `(name, address)`.
fn mdns_candidates(state: &Value) -> Vec<(String, String)> {
    state
        .get("mdns_candidates")
        .and_then(Value::as_array)
        .map(|v| {
            v.iter()
                .filter_map(|c| {
                    let name = c.get("name").and_then(Value::as_str)?.to_string();
                    let address = c.get("address").and_then(Value::as_str)?.to_string();
                    Some((name, address))
                })
                .collect()
        })
        .unwrap_or_default()
}

impl CasetaLeap {
    fn ask_address(state: &Value, input: &Args) -> (SetupStep, Value) {
        let typed = input
            .get("Bridge address")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let found = mdns_candidates(state);

        // Exactly one bridge answered mDNS and nobody typed something else — that is the
        // bridge, no need to make anyone confirm an IP address they never had to know.
        if typed.is_empty() && found.len() == 1 {
            return Self::begin_pairing(state, &found[0].1);
        }
        if !typed.is_empty() {
            return Self::begin_pairing(state, &typed);
        }

        let body = if found.is_empty() {
            "Enter the bridge's IP address. You'll be asked to press the button on the \
             bridge next."
                .to_string()
        } else {
            format!(
                "Found {} on the network — pick the right one, or type an address. \
                 You'll be asked to press the button on the bridge next.",
                found.iter().map(|(n, a)| format!("{n} ({a})")).collect::<Vec<_>>().join(", ")
            )
        };
        (
            SetupStep::Form {
                title: "Pair a Caséta Smart Bridge".into(),
                body,
                fields: vec![Field {
                    name: "Bridge address".into(),
                    label: "Bridge IP address".into(),
                    kind: "string".into(),
                    help: "e.g. 192.168.1.50".into(),
                    default: found.first().map(|(_, a)| json!(a)),
                    options: Vec::new(),
                    required: true,
                }],
            },
            state.clone(),
        )
    }

    fn begin_pairing(state: &Value, addr: &str) -> (SetupStep, Value) {
        match generate_csr() {
            Ok((key_pem, csr_pem)) => (
                instruct(
                    "Ready to pair",
                    "When you continue, this connects to the bridge and waits up to 30 \
                     seconds for it to confirm its button was pressed — so press and release \
                     the small button on top of the Caséta Smart Bridge right as you continue, \
                     not before.",
                ),
                with_fields(
                    state,
                    &[
                        ("stage", "ready_to_pair"),
                        ("address", addr),
                        ("key_pem", &key_pem),
                        ("csr_pem", &csr_pem),
                    ],
                ),
            ),
            Err(e) => (
                SetupStep::Failed {
                    reason: format!("could not generate a pairing key: {e}"),
                },
                Value::Null,
            ),
        }
    }

    /// Sent over `leaps://`, presenting Lutron's published pairing identity as this
    /// connection's own client certificate — see [`lap_identity`]. Core's `request_leap`
    /// handles waiting for the button-press confirmation before this is written; the driver
    /// just has to frame the request the way a real bridge expects it, matching
    /// `pylutron-caseta` field-for-field since that is the proven-working shape.
    fn send_pair_request(state: &Value) -> (SetupStep, Value) {
        let address = field(state, "address");
        let csr = field(state, "csr_pem");
        let body = json!({
            "Header": {
                "RequestType": "Execute",
                "Url": "/pair",
                "ClientTag": "get-cert",
            },
            "Body": {
                "CommandType": "CSR",
                "Parameters": {
                    "CSR": csr,
                    "DisplayName": "Juno",
                    "DeviceUID": "000000000000",
                    "Role": "Admin",
                },
            },
        });
        let request = HttpRequest::new("POST", format!("leaps://{address}:8083/pair"))
            .header("x-client-cert", lap_identity::LAP_CERT_PEM)
            .header("x-client-key", lap_identity::LAP_KEY_PEM)
            .json(body.to_string());
        (
            SetupStep::Fetch { request, note: "pair".into() },
            with_fields(state, &[("stage", "pairing")]),
        )
    }

    fn handle_pair_response(state: &Value, input: &Args) -> (SetupStep, Value) {
        if let Some(err) = input.get("error").and_then(Value::as_str) {
            return (
                instruct(
                    "Not paired yet",
                    &format!(
                        "{err} — press the button on the bridge right when you continue \
                         (the bridge only recognizes a press while a client is connected and \
                         waiting), then continue."
                    ),
                ),
                with_fields(state, &[("stage", "ready_to_pair")]),
            );
        }
        let response = input.get("response").cloned().unwrap_or(Value::Null);
        let cert = response
            .pointer("/Body/SigningResult/Certificate")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let ca = response
            .pointer("/Body/SigningResult/RootCertificate")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if cert.is_empty() || ca.is_empty() {
            return (
                SetupStep::Failed {
                    reason: format!("the bridge answered but sent no certificate: {response}"),
                },
                Value::Null,
            );
        }
        Self::request_device_list(&with_fields(
            state,
            &[("stage", "listing"), ("cert_pem", &cert), ("ca_pem", &ca)],
        ))
    }

    fn request_device_list(state: &Value) -> (SetupStep, Value) {
        let address = {
            let v = field(state, "Address");
            if v.is_empty() { field(state, "address") } else { v }
        };
        let cert = {
            let v = field(state, "Client certificate");
            if v.is_empty() { field(state, "cert_pem") } else { v }
        };
        let key = {
            let v = field(state, "Client key");
            if v.is_empty() { field(state, "key_pem") } else { v }
        };
        let body = json!({ "CommuniqueType": "ReadRequest", "Header": { "Url": "/device" } });
        let request = HttpRequest::new("POST", format!("leaps://{address}:8081/device"))
            .header("x-client-cert", cert)
            .header("x-client-key", key)
            .json(body.to_string());
        (SetupStep::Fetch { request, note: "list".into() }, state.clone())
    }

    /// Turn a `/device` reply into candidates. Only dimmable outputs are offered — a Pico
    /// remote or an occupancy sensor found on the same bridge is real Caséta hardware this
    /// driver does not model yet, so it is silently skipped rather than offered and failing.
    fn handle_device_list(state: &Value, input: &Args, include_bridge: bool) -> (SetupStep, Value) {
        let response = input.get("response").cloned().unwrap_or(Value::Null);
        let devices = response
            .pointer("/Body/Devices")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut out = Vec::new();
        if include_bridge {
            let mut props = BTreeMap::new();
            props.insert("Address".into(), json!(field(state, "address")));
            props.insert("Client certificate".into(), json!(field(state, "cert_pem")));
            props.insert("Client key".into(), json!(field(state, "key_pem")));
            props.insert("CA certificate".into(), json!(field(state, "ca_pem")));
            out.push(Candidate {
                label: format!("Caséta Smart Bridge ({})", field(state, "address")),
                kind: "bridge".into(),
                driver_id: BRIDGE_ID.into(),
                properties: props,
                verified: "paired".into(),
            });
        }

        // ponytail: dimmers only, matching the integration-port driver's scope. Switches,
        // keypads, and Pico remotes are real LEAP device types too — add a DeviceType arm
        // here plus a manifest for each when one is needed.
        const DIMMABLE: &[&str] = &["WallDimmer", "PlugInDimmer", "InLineDimmer", "Dimmed"];
        for d in &devices {
            let kind = d.get("DeviceType").and_then(Value::as_str).unwrap_or("");
            if !DIMMABLE.contains(&kind) {
                continue;
            }
            let Some(zone) = d.pointer("/LocalZones/0/href").and_then(Value::as_str) else {
                continue; // no zone means nothing to command
            };
            let name = d
                .get("Name")
                .and_then(Value::as_str)
                .unwrap_or("Caséta Dimmer")
                .to_string();
            let mut props = BTreeMap::new();
            props.insert("Zone".into(), json!(zone));
            out.push(Candidate {
                label: name,
                kind: "light".into(),
                driver_id: DIMMER_ID.into(),
                properties: props,
                verified: "found on bridge".into(),
            });
        }

        (SetupStep::Done { devices: out }, Value::Null)
    }
}

impl DriverModule for CasetaLeap {
    fn discover(&self, driver_id: &str, state: &Value, input: &Args) -> (SetupStep, Value) {
        if driver_id != BRIDGE_ID {
            // Dimmers are found by browsing their bridge, never set up on their own.
            return (SetupStep::Done { devices: Vec::new() }, Value::Null);
        }

        // Browsing a bridge that is paired already: core seeded `state` with its properties
        // directly, so there is nothing to pair — go straight to listing.
        if state.get("browse").and_then(Value::as_bool) == Some(true) {
            if input.get("response").is_some() || input.get("error").is_some() {
                return Self::handle_device_list(state, input, false);
            }
            return Self::request_device_list(state);
        }

        match field(state, "stage").as_str() {
            "ready_to_pair" => Self::send_pair_request(state),
            "pairing" => Self::handle_pair_response(state, input),
            "listing" => Self::handle_device_list(state, input, true),
            _ => Self::ask_address(state, input),
        }
    }

    fn on_command(&self, inst: &mut Instance, _proxy: LocalId, cmd: &str, args: &Args) -> Vec<HostCall> {
        // The bridge proxy takes no commands (see its manifest) — anything reaching here is
        // for the dimmer's light proxy.
        Self::on_dimmer_command(inst, cmd, args)
    }

    fn on_event(&self, inst: &mut Instance, _control: LocalId, note: &str, args: &Args) -> Vec<HostCall> {
        Self::on_dimmer_event(inst, note, args)
    }

    fn on_bind(&self, inst: &mut Instance) -> Vec<HostCall> {
        let mut a = Args::new();
        a.insert("online".into(), json!(true));
        let mut out = vec![HostCall::notify(1, "online_changed", a)];

        // Only a dimmer has a zone to subscribe to; a bridge instance binding has nothing
        // further to do here — pairing already happened in its setup flow.
        if let Some(z) = zone(inst) {
            out.push(tx(&subscribe(&z)));
        }
        out
    }
}

// ---------------------------------------------------------------------------------------
// The live connection — one zone's on/off/dim, and the status push that keeps it in sync.
// ---------------------------------------------------------------------------------------

fn zone(inst: &Instance) -> Option<String> {
    inst.property("Zone")
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn fade_time(seconds: u64) -> String {
    format!("{:02}:{:02}:{:02}", seconds / 3600, (seconds % 3600) / 60, seconds % 60)
}

fn tx(msg: &Value) -> HostCall {
    let mut line = msg.to_string();
    line.push('\n');
    HostCall::Tx { control: NET, data: line.into_bytes() }
}

fn go_to_level(zone: &str, level: u8, fade_secs: u64) -> Value {
    json!({
        "CommuniqueType": "CreateRequest",
        "Header": { "Url": format!("{zone}/commandprocessor") },
        "Body": {
            "Command": {
                "CommandType": "GoToDimmedLevel",
                "DimmedLevelParameters": { "Level": level, "FadeTime": fade_time(fade_secs) },
            },
        },
    })
}

fn subscribe(zone: &str) -> Value {
    json!({ "CommuniqueType": "SubscribeRequest", "Header": { "Url": format!("{zone}/status") } })
}

fn report(level: u8) -> HostCall {
    let mut args = Args::new();
    args.insert("level".into(), json!(level));
    HostCall::notify(1, "level_changed", args)
}

impl CasetaLeap {
    fn on_dimmer_command(inst: &mut Instance, cmd: &str, args: &Args) -> Vec<HostCall> {
        let Some(z) = zone(inst) else {
            return vec![HostCall::warn(
                "caseta-leap: this device has no Zone — adopt it through the bridge's setup flow",
            )];
        };

        let default_fade = inst.property("Default fade").as_u64().unwrap_or(1);
        let secs = args
            .get("ramp_ms")
            .and_then(Value::as_u64)
            .map(|ms| ms / 1000)
            .unwrap_or(default_fade);
        let last = inst.scratch.get("level").and_then(Value::as_u64).unwrap_or(100) as u8;

        // LEAP has real open-ended raise/lower/stop commands (`CommandType: "Raise"` etc.);
        // ponytail: this fakes a held button with a long fade to the extreme instead, the way
        // the Hue driver does, since it needs no separate stop-tracking state. Swap in the
        // native commands if a held keypad button needs to feel less like a slow fade.
        let (level, fade) = match cmd {
            "on" => (if last == 0 { 100 } else { last }, secs),
            "off" => (0, secs),
            "toggle" => {
                let on = inst.scratch.get("on").and_then(Value::as_bool).unwrap_or(false);
                (if on { 0 } else if last == 0 { 100 } else { last }, secs)
            }
            "set_level" => (args.get("level").and_then(Value::as_u64).unwrap_or(0) as u8, secs),
            "ramp_start" => {
                let up = args.get("direction").and_then(Value::as_str) == Some("up");
                (if up { 100 } else { 1 }, 4)
            }
            "ramp_stop" => (last, 0),
            other => return vec![HostCall::warn(format!("caseta-leap: unhandled `{other}`"))],
        };

        if level > 0 {
            inst.scratch.insert("level".into(), json!(level));
        }
        inst.scratch.insert("on".into(), json!(level > 0));

        vec![tx(&go_to_level(&z, level, fade)), report(level)]
    }

    fn on_dimmer_event(inst: &mut Instance, note: &str, args: &Args) -> Vec<HostCall> {
        if note != "rx" {
            return Vec::new();
        }
        let Some(text) = args.get("data").and_then(Value::as_str) else {
            return Vec::new();
        };
        let Some(mine) = zone(inst) else {
            return Vec::new();
        };

        let mut out = Vec::new();
        for line in text.split('\n').map(str::trim).filter(|l| !l.is_empty()) {
            let Ok(msg) = serde_json::from_str::<Value>(line) else { continue };
            let Some(status) = msg.pointer("/Body/ZoneStatus") else { continue };
            let href = status.pointer("/Zone/href").and_then(Value::as_str).unwrap_or("");
            if href != mine {
                continue;
            }
            let Some(level) = status.get("Level").and_then(Value::as_u64) else { continue };
            let level = level.clamp(0, 100) as u8;

            if inst.scratch.get("level").and_then(Value::as_u64) == Some(level as u64) {
                continue; // already knew; do not manufacture a state change
            }
            if level > 0 {
                inst.scratch.insert("level".into(), json!(level));
            }
            inst.scratch.insert("on".into(), json!(level > 0));
            out.push(report(level));
        }
        out
    }
}

export_driver!(CasetaLeap);
