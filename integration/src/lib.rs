//! Lutron Caséta dimmers over the Smart Bridge PRO's integration port.
//!
//! The protocol is line-oriented ASCII on TCP 23:
//!
//! ```text
//!   #OUTPUT,<id>,1,<level>,<fade>    set level, fade as SS or MM:SS
//!   #OUTPUT,<id>,2                   start raising
//!   #OUTPUT,<id>,3                   start lowering
//!   #OUTPUT,<id>,4                   stop
//!   ?OUTPUT,<id>,1                   query
//!   ~OUTPUT,<id>,1,<level>           unsolicited report — the bridge tells us about wall
//!                                    dimmer presses, which is how manual changes stay in sync
//! ```
//!
//! Note this needs the **PRO** bridge. The standard Caséta bridge has no integration port at
//! all, which is the single most common reason one of these installs does not work.

use juno_driver_sdk::*;
use serde_json::Value;

#[derive(Default)]
pub struct CasetaDimmer;

/// `control: 0` is the driver's own network transport — core owns the socket.
const NET: LocalId = 0;

fn fade(seconds: u64) -> String {
    if seconds >= 60 {
        format!("{}:{:02}", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}")
    }
}

impl CasetaDimmer {
    fn integration_id(inst: &Instance) -> Option<i64> {
        match inst.property("Integration id") {
            Value::Number(n) => n.as_i64(),
            Value::String(s) => s.parse().ok(),
            _ => None,
        }
    }

    fn send(inst: &Instance, tail: &str) -> Option<HostCall> {
        let id = Self::integration_id(inst)?;
        Some(HostCall::Tx {
            control: NET,
            data: format!("#OUTPUT,{id},{tail}\r\n").into_bytes(),
        })
    }

    fn report(level: u8) -> HostCall {
        let mut args = Args::new();
        args.insert("level".into(), json!(level));
        HostCall::notify(1, "level_changed", args)
    }
}

impl DriverModule for CasetaDimmer {
    fn on_command(
        &self,
        inst: &mut Instance,
        _proxy: LocalId,
        cmd: &str,
        args: &Args,
    ) -> Vec<HostCall> {
        let default_fade = inst
            .property("Default fade")
            .as_u64()
            .unwrap_or(1);
        let secs = args
            .get("ramp_ms")
            .and_then(Value::as_u64)
            .map(|ms| ms / 1000)
            .unwrap_or(default_fade);

        let last = inst
            .scratch
            .get("level")
            .and_then(Value::as_u64)
            .unwrap_or(100) as u8;

        let (tail, level) = match cmd {
            "on" => {
                let restore = if last == 0 { 100 } else { last };
                (format!("1,{restore},{}", fade(secs)), Some(restore))
            }
            "off" => (format!("1,0,{}", fade(secs)), Some(0)),
            "toggle" => {
                let on = inst
                    .scratch
                    .get("on")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let next = if on { 0 } else if last == 0 { 100 } else { last };
                (format!("1,{next},{}", fade(secs)), Some(next))
            }
            "set_level" => {
                let l = args.get("level").and_then(Value::as_u64).unwrap_or(0) as u8;
                (format!("1,{l},{}", fade(secs)), Some(l))
            }
            // The bridge has real open-ended ramping, so a held keypad button maps exactly.
            "ramp_start" => {
                let up = args.get("direction").and_then(Value::as_str) == Some("up");
                ((if up { "2" } else { "3" }).to_string(), None)
            }
            "ramp_stop" => ("4".to_string(), None),
            other => return vec![HostCall::warn(format!("caseta: unhandled `{other}`"))],
        };

        let Some(tx) = Self::send(inst, &tail) else {
            return vec![HostCall::warn(
                "caseta: set the Integration id on this device first",
            )];
        };

        let mut out = vec![tx];
        if let Some(l) = level {
            if l > 0 {
                inst.scratch.insert("level".into(), json!(l));
            }
            inst.scratch.insert("on".into(), json!(l > 0));
            out.push(Self::report(l));
        } else {
            // A ramp's end level is unknown until the bridge reports it, so ask.
            if let Some(q) = Self::integration_id(inst).map(|id| HostCall::Tx {
                control: NET,
                data: format!("?OUTPUT,{id},1\r\n").into_bytes(),
            }) {
                out.push(q);
            }
        }
        out
    }

    /// Bytes back from the bridge. `~OUTPUT` lines are how a wall dimmer press reaches us —
    /// without handling these, the UI would go stale the moment anyone touched a switch.
    fn on_event(
        &self,
        inst: &mut Instance,
        _control: LocalId,
        note: &str,
        args: &Args,
    ) -> Vec<HostCall> {
        if note != "rx" {
            return Vec::new();
        }
        let Some(text) = args.get("data").and_then(Value::as_str) else {
            return Vec::new();
        };
        let Some(mine) = Self::integration_id(inst) else {
            return Vec::new();
        };

        let mut out = Vec::new();
        for line in text.split(['\r', '\n']).filter(|l| !l.is_empty()) {
            let parts: Vec<&str> = line.trim_start_matches('~').split(',').collect();
            // ~OUTPUT,<id>,1,<level>
            if parts.len() < 4 || parts[0] != "OUTPUT" || parts[2] != "1" {
                continue;
            }
            if parts[1].parse::<i64>() != Ok(mine) {
                continue;
            }
            let Ok(level) = parts[3].trim().parse::<f64>() else {
                continue;
            };
            let level = level.round().clamp(0.0, 100.0) as u8;

            if inst.scratch.get("level").and_then(Value::as_u64) == Some(level as u64) {
                continue; // already knew; do not manufacture a state change
            }
            if level > 0 {
                inst.scratch.insert("level".into(), json!(level));
            }
            inst.scratch.insert("on".into(), json!(level > 0));
            out.push(Self::report(level));
        }
        out
    }

    fn on_bind(&self, inst: &mut Instance) -> Vec<HostCall> {
        let mut out = Vec::new();
        let mut a = Args::new();
        a.insert("online".into(), json!(true));
        out.push(HostCall::notify(1, "online_changed", a));
        // Ask where the dimmer actually is rather than assuming it is off.
        if let Some(id) = Self::integration_id(inst) {
            out.push(HostCall::Tx {
                control: NET,
                data: format!("?OUTPUT,{id},1\r\n").into_bytes(),
            });
        }
        out
    }
}


export_driver!(CasetaDimmer);
