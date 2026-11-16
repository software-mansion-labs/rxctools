//! instruments over the tunnel: app launch and screenshots.

use crate::dtx::{Aux, Dtx};
use crate::nskeyed::NS;
use crate::tunnel::Tunnel;
use crate::util::{Result, bail};
use std::sync::Arc;

pub const DTSERVICEHUB: &str = "com.apple.instruments.dtservicehub";
const PROCESSCONTROL: &str = "com.apple.instruments.server.services.processcontrol";
const SCREENSHOT: &str = "com.apple.instruments.server.services.screenshot";

pub fn connect(t: &Tunnel) -> Result<Arc<Dtx>> {
    Dtx::new(t.connect_service(DTSERVICEHUB)?)
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
