//! instruments over the tunnel: process list, launch, signals and screenshots.

use crate::dtx::{Aux, Dtx};
use crate::nskeyed::NS;
use crate::tunnel::Tunnel;
use crate::util::{Result, bail};
use serde_json::{Value as J, json};
use std::sync::Arc;

pub const DTSERVICEHUB: &str = "com.apple.instruments.dtservicehub";
const DEVICEINFO: &str = "com.apple.instruments.server.services.deviceinfo";
const PROCESSCONTROL: &str = "com.apple.instruments.server.services.processcontrol";
const SCREENSHOT: &str = "com.apple.instruments.server.services.screenshot";

pub fn connect(t: &Tunnel) -> Result<Arc<Dtx>> {
    Dtx::new(t.connect_service(DTSERVICEHUB)?)
}

/// Running processes the way `devicectl device info processes` lists them.
pub fn process_list(d: &Dtx) -> Result<Vec<J>> {
    let ch = d.request_channel(DEVICEINFO, false)?;
    let reply = d.call(ch, "runningProcesses", vec![])?;
    crate::debug!("runningProcesses reply", "bytes" => reply.payload.len());
    let Some(NS::Array(list)) = reply.payload_object() else {
        return bail("runningProcesses: unexpected reply");
    };
    Ok(list
        .iter()
        .map(|p| {
            let mut e =
                json!({"processIdentifier": p.get("pid").and_then(|v| v.as_u64()).unwrap_or(0)});
            if let Some(path) = p.get("realAppName").and_then(|v| v.as_str()) {
                e["executable"] = crate::util::file_url(path).into();
            }
            e
        })
        .collect())
}

pub fn launch(
    d: &Dtx,
    bundle: &str,
    args: &[String],
    env: &[(String, String)],
    kill_existing: bool,
) -> Result<u64> {
    let ch = d.request_channel(PROCESSCONTROL, false)?;
    let mut envd = vec![(NS::str("NSUnbufferedIO"), NS::str("YES"))];
    envd.extend(env.iter().map(|(k, v)| (NS::str(k), NS::str(v))));
    let opts = NS::dict(vec![
        ("StartSuspendedKey", NS::UInt(0)),
        ("KillExisting", NS::UInt(kill_existing as u64)),
    ]);
    // processcontrol answers a busy launchd with error code 2; retry a few times.
    for attempt in 1..=4u64 {
        let reply = d.call(
            ch,
            "launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:options:",
            vec![
                Aux::archived(&NS::str("/private/")),
                Aux::archived(&NS::str(bundle)),
                Aux::archived(&NS::Dict(envd.clone())),
                Aux::archived(&NS::Array(args.iter().map(|a| NS::str(a)).collect())),
                Aux::archived(&opts),
            ],
        );
        match reply {
            Ok(m) => match m.payload_object() {
                Some(NS::UInt(pid)) => return Ok(pid),
                Some(NS::Int(pid)) if pid > 0 => return Ok(pid as u64),
                other => return bail(format!("unexpected launch reply: {other:?}")),
            },
            Err(e)
                if attempt < 4
                    && e.0.contains("\"code\":2,")
                    && e.0.contains("deviceprocesscontrolservice") =>
            {
                std::thread::sleep(std::time::Duration::from_millis(500 * attempt));
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

/// A PNG of the screen.
pub fn screenshot(d: &Dtx) -> Result<Vec<u8>> {
    let ch = d.request_channel(SCREENSHOT, false)?;
    match d.call(ch, "takeScreenshot", vec![])?.payload_object() {
        Some(NS::Data(png)) => Ok(png),
        other => bail(format!("takeScreenshot: unexpected reply {other:?}")),
    }
}

/// SIGKILL, or any other signal through `sendSignal:toPid:`.
pub fn signal(d: &Dtx, pid: u64, sig: u64) -> Result<()> {
    let ch = d.request_channel(PROCESSCONTROL, false)?;
    if sig == 9 {
        d.call(ch, "killPid:", vec![Aux::archived(&NS::UInt(pid))])?;
    } else {
        d.call(
            ch,
            "sendSignal:toPid:",
            vec![Aux::archived(&NS::UInt(sig)), Aux::archived(&NS::UInt(pid))],
        )?;
    }
    Ok(())
}
