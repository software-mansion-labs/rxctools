//! test-without-building for iOS 17+: testmanagerd sessions, the runner launched through CoreDevice
//! appservice, and the IDE side of the XCTest protocol, which hands the runner its configuration and
//! acks its callbacks.

use crate::dtx::{self, Aux, Dtx, Msg};
use crate::nskeyed::{self, NS};
use crate::tunnel::Tunnel;
use crate::util::{Error, Result, bail};
use crate::xpc::{self, X, XpcConn, xdict};
use plist::Value;
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};

const TESTMANAGERD: &str = "com.apple.dt.testmanagerd.remote";
const APPSERVICE: &str = "com.apple.coredevice.appservice";
const OPENSTDIO: &str = "com.apple.coredevice.openstdiosocket";
const DAEMON_CHANNEL: &str =
    "dtxproxy:XCTestManager_IDEInterface:XCTestManager_DaemonConnectionInterface";
const DRIVER_CHANNEL: &str = "dtxproxy:XCTestDriverInterface:XCTestManager_IDEInterface";

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SchemeData {
    pub test_host_bundle_identifier: String,
    pub test_bundle_path: String,
    pub skip_test_identifiers: Option<Vec<String>>,
    pub only_test_identifiers: Option<Vec<String>>,
    pub is_ui_test_bundle: bool,
    pub command_line_arguments: Vec<String>,
    pub environment_variables: BTreeMap<String, String>,
    pub testing_environment_variables: BTreeMap<String, String>,
    pub ui_target_app_environment_variables: Option<BTreeMap<String, String>>,
    pub ui_target_app_path: String,
}

#[derive(Debug, PartialEq)]
pub struct TestConfiguration {
    pub name: String,
    pub targets: Vec<SchemeData>,
}

fn strings(v: Option<&Value>) -> Option<Vec<String>> {
    v.and_then(|v| v.as_array()).map(|a| {
        a.iter()
            .filter_map(|s| s.as_string().map(|s| s.to_string()))
            .collect()
    })
}

fn env(v: Option<&Value>) -> Option<BTreeMap<String, String>> {
    v.and_then(|v| v.as_dictionary()).map(|d| {
        d.iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    v.as_string().map(|s| s.to_string()).unwrap_or_default(),
                )
            })
            .collect()
    })
}

fn scheme(d: &plist::Dictionary) -> SchemeData {
    let s = |k: &str| {
        d.get(k)
            .and_then(|v| v.as_string())
            .unwrap_or("")
            .to_string()
    };
    SchemeData {
        test_host_bundle_identifier: s("TestHostBundleIdentifier"),
        test_bundle_path: s("TestBundlePath"),
        skip_test_identifiers: strings(d.get("SkipTestIdentifiers")),
        only_test_identifiers: strings(d.get("OnlyTestIdentifiers")),
        is_ui_test_bundle: d
            .get("IsUITestBundle")
            .and_then(|v| v.as_boolean())
            .unwrap_or(false),
        command_line_arguments: strings(d.get("CommandLineArguments")).unwrap_or_default(),
        environment_variables: env(d.get("EnvironmentVariables")).unwrap_or_default(),
        testing_environment_variables: env(d.get("TestingEnvironmentVariables"))
            .unwrap_or_default(),
        ui_target_app_environment_variables: env(d.get("UITargetAppEnvironmentVariables")),
        ui_target_app_path: s("UITargetAppPath"),
    }
}

pub fn parse_xctestrun(bytes: &[u8]) -> Result<Vec<TestConfiguration>> {
    let root: plist::Dictionary = plist::from_bytes(bytes)
        .map_err(|e| Error::msg(format!("failed to parse format version: {e}")))?;
    let version = root
        .get("__xctestrun_metadata__")
        .and_then(|m| m.as_dictionary())
        .and_then(|m| m.get("FormatVersion"))
        .and_then(|v| v.as_unsigned_integer())
        .unwrap_or(0);
    match version {
        1 => Ok(root
            .iter()
            .filter(|(k, _)| *k != "__xctestrun_metadata__")
            .filter_map(|(_, v)| v.as_dictionary())
            .take(1)
            .map(|d| TestConfiguration {
                name: String::new(),
                targets: vec![scheme(d)],
            })
            .collect()),
        2 => {
            let confs: Vec<TestConfiguration> = root
                .get("TestConfigurations")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|c| c.as_dictionary())
                        .map(|c| TestConfiguration {
                            name: c
                                .get("Name")
                                .and_then(|v| v.as_string())
                                .unwrap_or("")
                                .to_string(),
                            targets: c
                                .get("TestTargets")
                                .and_then(|v| v.as_array())
                                .map(|t| {
                                    t.iter()
                                        .filter_map(|x| x.as_dictionary())
                                        .map(scheme)
                                        .collect()
                                })
                                .unwrap_or_default(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            if confs.is_empty() {
                return bail(
                    "The .xctestrun file you provided does not contain any test configurations. Please check your test setup and ensure it includes at least one test configuration.",
                );
            }
            Ok(confs)
        }
        v => bail(format!(
            "the provided .xctestrun format version {v} is not supported"
        )),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TestConfig {
    pub test_runner_bundle_id: String,
    pub xctest_config_name: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub tests_to_run: Option<Vec<String>>,
    pub tests_to_skip: Option<Vec<String>>,
    pub xctest: bool,
    /// UITargetAppPath's app name, resolved to a bundle id against the installed apps.
    pub target_app_name: Option<String>,
}

impl SchemeData {
    pub fn build_test_config(&self) -> TestConfig {
        let mut env = BTreeMap::new();
        let mut target = None;
        if self.is_ui_test_bundle {
            env.extend(self.environment_variables.clone());
            env.extend(self.testing_environment_variables.clone());
            env.extend(
                self.ui_target_app_environment_variables
                    .clone()
                    .unwrap_or_default(),
            );
            if !self.ui_target_app_path.is_empty() {
                let base = self.ui_target_app_path.rsplit('/').next().unwrap_or("");
                target = Some(base.trim_end_matches(".app").to_string());
            }
        }
        TestConfig {
            test_runner_bundle_id: self.test_host_bundle_identifier.clone(),
            xctest_config_name: self
                .test_bundle_path
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_string(),
            args: self.command_line_arguments.clone(),
            env,
            tests_to_run: self.only_test_identifiers.clone(),
            tests_to_skip: self.skip_test_identifiers.clone(),
            xctest: !self.is_ui_test_bundle,
            target_app_name: target,
        }
    }
}

fn capabilities(entries: &[(&str, NS)]) -> NS {
    NS::obj(
        "XCTCapabilities",
        vec![(
            "capabilities-dictionary",
            NS::Dict(
                entries
                    .iter()
                    .map(|(k, v)| (NS::str(k), v.clone()))
                    .collect(),
            ),
        )],
    )
}

fn test_identifier_set(tests: &[String]) -> NS {
    // `Class/method` -> XCTTestIdentifier components; a module prefix is dropped
    let ids = tests
        .iter()
        .map(|t| {
            let t = t
                .split_once('.')
                .map(|(_, r)| r)
                .filter(|_| !t.starts_with('/'))
                .unwrap_or(t);
            let comps: Vec<NS> = t
                .split('/')
                .filter(|c| !c.is_empty())
                .map(NS::str)
                .collect();
            let options = if comps.len() > 1 { 3 } else { 2 };
            NS::obj(
                "XCTTestIdentifier",
                vec![("c", NS::Array(comps)), ("o", NS::UInt(options))],
            )
        })
        .collect();
    NS::obj(
        "XCTTestIdentifierSet",
        vec![("identifiers", NS::Array(ids))],
    )
}

pub struct Apps {
    pub runner_path: String,
    pub target: Option<(String, String)>, // bundle id, path
}

pub fn xctest_configuration(
    cfg: &TestConfig,
    session: [u8; 16],
    apps: &Apps,
    report_activities: bool,
) -> NS {
    let mut f: Vec<(&str, NS)> = vec![
        (
            "aggregateStatisticsBeforeCrash",
            NS::dict(vec![("XCSuiteRecordsKey", NS::dict(vec![]))]),
        ),
        (
            "automationFrameworkPath",
            NS::str("/System/Developer/Library/PrivateFrameworks/XCTAutomationSupport.framework"),
        ),
        ("baselineFileRelativePath", NS::Null),
        ("baselineFileURL", NS::Null),
        ("defaultTestExecutionTimeAllowance", NS::Null),
        ("disablePerformanceMetrics", NS::Bool(false)),
        ("emitOSLogs", NS::Bool(false)),
        ("gatherLocalizableStringsData", NS::Bool(false)),
        ("initializeForUITesting", NS::Bool(!cfg.xctest)),
        ("maximumTestExecutionTimeAllowance", NS::Null),
        ("randomExecutionOrderingSeed", NS::Null),
        ("reportActivities", NS::Bool(report_activities)),
        ("reportResultsToIDE", NS::Bool(true)),
        ("sessionIdentifier", NS::Uuid(session)),
        ("systemAttachmentLifetime", NS::Int(2)),
        ("testApplicationUserOverrides", NS::Null),
        ("testBundleRelativePath", NS::Null),
        (
            "testBundleURL",
            NS::Url {
                base: None,
                relative: format!(
                    "file://{}/PlugIns/{}",
                    apps.runner_path, cfg.xctest_config_name
                ),
            },
        ),
        ("testExecutionOrdering", NS::Int(0)),
        ("testsDrivenByIDE", NS::Bool(false)),
        ("testsMustRunOnMainThread", NS::Bool(true)),
        ("testTimeoutsEnabled", NS::Bool(false)),
        ("treatMissingBaselinesAsFailures", NS::Bool(false)),
        ("userAttachmentLifetime", NS::Int(0)),
        ("preferredScreenCaptureFormat", NS::Int(2)),
        (
            "IDECapabilities",
            capabilities(
                &[
                    "expected failure test capability",
                    "test case run configurations",
                    "test timeout capability",
                    "test iterations",
                    "request diagnostics for specific devices",
                    "delayed attachment transfer",
                    "skipped test capability",
                    "daemon container sandbox extension",
                    "ubiquitous test identifiers",
                    "XCTIssue capability",
                ]
                .map(|k| (k, NS::Bool(true))),
            ),
        ),
    ];
    if let Some((bundle, path)) = &apps.target {
        f.push((
            "productModuleName",
            NS::str(cfg.xctest_config_name.trim_end_matches(".xctest")),
        ));
        f.push(("targetApplicationBundleID", NS::str(bundle)));
        f.push(("targetApplicationPath", NS::str(path)));
    }
    if let Some(t) = &cfg.tests_to_run {
        f.push((
            "testsToRun",
            NS::Set(t.iter().map(|s| NS::str(s)).collect()),
        ));
        f.push(("testIdentifiersToRun", test_identifier_set(t)));
    }
    if let Some(t) = &cfg.tests_to_skip {
        f.push((
            "testsToSkip",
            NS::Set(t.iter().map(|s| NS::str(s)).collect()),
        ));
        f.push(("testIdentifiersToSkip", test_identifier_set(t)));
    }
    NS::obj("XCTestConfiguration", f)
}

/// Runner and target app paths from the installation proxy shim inside the tunnel.
fn resolve_apps(t: &Tunnel, cfg: &TestConfig) -> Result<Apps> {
    let mut s = t.connect_shim("com.apple.mobile.installation_proxy.shim.remote")?;
    let mut req = crate::services::browse_request("User", true);
    let attrs: Vec<Value> = ["CFBundleIdentifier", "CFBundleName", "Path"]
        .iter()
        .map(|s| Value::from(*s))
        .collect();
    req.get_mut("ClientOptions")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("ReturnAttributes".into(), attrs.into());
    let apps = crate::services::browse(&mut s, &req)?;
    let get = |a: &plist::Dictionary, k: &str| {
        a.get(k)
            .and_then(|v| v.as_string())
            .unwrap_or("")
            .to_string()
    };
    let runner = apps
        .iter()
        .find(|a| get(a, "CFBundleIdentifier") == cfg.test_runner_bundle_id)
        .ok_or_else(|| {
            Error::msg(format!(
                "the test runner {} is not installed",
                cfg.test_runner_bundle_id
            ))
        })?;
    let target = cfg.target_app_name.as_ref().and_then(|name| {
        apps.iter()
            .find(|a| &get(a, "CFBundleName") == name)
            .map(|a| (get(a, "CFBundleIdentifier"), get(a, "Path")))
    });
    Ok(Apps {
        runner_path: get(runner, "Path"),
        target,
    })
}

pub struct Launch<'a> {
    pub args: &'a [String],
    pub env: &'a BTreeMap<String, String>,
    pub platform_opts: &'a plist::Dictionary,
    pub stdio: Option<[u8; 16]>,
    pub terminate_existing: bool,
    /// Handed to the app on launch, as `devicectl device process launch --payload-url` does.
    pub payload_url: Option<&'a str>,
}

/// CoreDevice appservice: launch an app with arguments, environment and stdio, returns the pid.
pub fn launch_app(t: &Tunnel, bundle: &str, l: &Launch) -> Result<i64> {
    let mut c = XpcConn::connect(t.connect_service(APPSERVICE)?)?;
    let mut platform_opts = vec![];
    plist::to_writer_binary(&mut platform_opts, l.platform_opts)?;
    let stdio_ids = match l.stdio {
        Some(u) => xdict(vec![
            ("standardInput", X::Uuid(u)),
            ("standardOutput", X::Uuid(u)),
            ("standardError", X::Uuid(u)),
        ]),
        None => xdict(vec![]),
    };
    let mut options = vec![
        (
            "arguments",
            X::Array(l.args.iter().map(|a| X::Str(a.clone())).collect()),
        ),
        (
            "environmentVariables",
            X::Dict(
                l.env
                    .iter()
                    .map(|(k, v)| (k.clone(), X::Str(v.clone())))
                    .collect(),
            ),
        ),
        ("platformSpecificOptions", X::Data(platform_opts)),
        ("standardIOUsesPseudoterminals", true.into()),
        ("startStopped", false.into()),
        ("terminateExisting", l.terminate_existing.into()),
        ("user", xdict(vec![("active", true.into())])),
        ("workingDirectory", X::Null),
    ];
    if let Some(url) = l.payload_url {
        options.push(("payloadURL", xdict(vec![("relative", url.into())])));
    }
    let input = xdict(vec![
        (
            "applicationSpecifier",
            xdict(vec![(
                "bundleIdentifier",
                xdict(vec![("_0", bundle.into())]),
            )]),
        ),
        ("options", xdict(options)),
        ("standardIOIdentifiers", stdio_ids),
    ]);
    let device_id = uuid::Uuid::new_v4().to_string().to_uppercase();
    c.send(
        xpc::coredevice_request(
            &device_id,
            "com.apple.coredevice.feature.launchapplication",
            input,
        ),
        xpc::HEARTBEAT_REQUEST,
    )?;
    let m = c.recv_body(xpc::SERVER_CLIENT)?;
    if let Some(e) = m.get("CoreDevice.error") {
        return bail(format!("launch {bundle} failed: {e:?}"));
    }
    m.get("CoreDevice.output")
        .and_then(|o| o.get("processToken"))
        .and_then(|p| p.get("processIdentifier"))
        .and_then(|p| p.as_i64())
        .ok_or_else(|| {
            Error::msg(format!(
                "pidFromResponse: could not get pid from response {m:?}"
            ))
        })
}

pub fn run(
    t: &Tunnel,
    xctestrun: &[u8],
    report_activities: bool,
    mut log: impl std::io::Write + Send + 'static,
) -> Result<()> {
    let confs = parse_xctestrun(xctestrun)?;
    let targets: Vec<&SchemeData> = confs.iter().flat_map(|c| &c.targets).collect();
    // shortcut: one target per run; loop over them when xctestruns with several need rxc
    let [target] = targets.as_slice() else {
        return bail(format!(
            "rxc runs one test target, the xctestrun has {}",
            targets.len()
        ));
    };
    let cfg = target.build_test_config();
    crate::info!("running xctest", "runner" => cfg.test_runner_bundle_id, "bundle" => cfg.xctest_config_name);

    // Everything that only needs the tunnel happens at once.
    let session = *uuid::Uuid::new_v4().as_bytes();
    let session_str = uuid::Uuid::from_bytes(session).to_string().to_uppercase();
    let (apps_tx, apps_rx) = mpsc::channel();
    {
        let (t2, cfg2) = (t.clone(), cfg.clone());
        std::thread::spawn(move || {
            let _ = apps_tx.send(resolve_apps(&t2, &cfg2));
        });
    }
    let (stdio_tx, stdio_rx) = mpsc::channel();
    {
        let t2 = t.clone();
        std::thread::spawn(move || {
            let r = (|| -> Result<(std::net::TcpStream, [u8; 16])> {
                let mut s = t2.connect_service(OPENSTDIO)?;
                let mut u = [0u8; 16];
                s.read_exact(&mut u)?;
                Ok((s, u))
            })();
            let _ = stdio_tx.send(r);
        });
    }
    let conn1 = Dtx::new(t.connect_service(TESTMANAGERD)?)?;
    let conn2 = Dtx::new(t.connect_service(TESTMANAGERD)?)?;

    let config_reply: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let driver_channel = Arc::new(AtomicI32::new(0));
    let failures = Arc::new(AtomicUsize::new(0));
    let (done_tx, done_rx) = mpsc::channel::<String>();
    {
        let (config_reply, driver_channel, done_tx, failures) = (
            config_reply.clone(),
            driver_channel.clone(),
            done_tx.clone(),
            failures.clone(),
        );
        conn1.set_handler(Box::new(move |_d, m: &Msg| {
            if m.msg_type == u32::MAX {
                let _ = done_tx.send(
                    "lost connection to testmanagerd. the test-runner may have been killed".into(),
                );
                return None;
            }
            let sel = m.selector().unwrap_or_default();
            match sel.as_str() {
                "_requestChannelWithCode:identifier:" => {
                    if let (Some(Aux::U32(code)), Some(Some(NS::Str(id)))) =
                        (m.aux.first(), m.args().get(1))
                        && id == DRIVER_CHANNEL
                    {
                        driver_channel.store(-(*code as i32), Ordering::SeqCst);
                    }
                    None
                }
                "_XCT_testRunnerReadyWithCapabilities:" => {
                    let payload = config_reply.lock().unwrap().clone().unwrap_or_default();
                    crate::debug!("received testRunnerReadyWithCapabilities");
                    Some(dtx::encode(&Msg {
                        identifier: m.identifier,
                        conversation_index: m.conversation_index + 1,
                        channel: m.channel,
                        msg_type: dtx::RESPONSE_WITH_RETURN_VALUE,
                        payload,
                        ..Default::default()
                    }))
                }
                "_XCT_didFinishExecutingTestPlan" => {
                    let _ = done_tx.send(String::new());
                    None
                }
                "_XCT_logDebugMessage:" | "_XCT_logMessage:" => {
                    if let Some(Some(NS::Str(s))) = m.args().first() {
                        crate::debug!("runner", "log" => s.trim_end());
                    }
                    None
                }
                s => {
                    if test_failed(s, m) {
                        failures.fetch_add(1, Ordering::SeqCst);
                    }
                    if !s.is_empty() {
                        crate::debug!("method received", "method" => s);
                    }
                    None
                }
            }
        }));
    }
    {
        let done_tx = done_tx.clone();
        conn2.set_handler(Box::new(move |_d, m: &Msg| {
            if m.msg_type == u32::MAX {
                let _ = done_tx.send(
                    "lost connection to testmanagerd. the test-runner may have been killed".into(),
                );
            }
            None
        }));
    }

    let ch1 = conn1.request_channel(DAEMON_CHANNEL, false)?;
    let ch2 = conn2.request_channel(DAEMON_CHANNEL, false)?;
    let local_caps = capabilities(
        &[
            "XCTIssue capability",
            "daemon container sandbox extension",
            "delayed attachment transfer",
            "expected failure test capability",
            "request diagnostics for specific devices",
            "skipped test capability",
            "test case run configurations",
            "test iterations",
            "test timeout capability",
            "ubiquitous test identifiers",
        ]
        .map(|k| (k, NS::UInt(1))),
    );
    let r = conn1.call(
        ch1,
        "_IDE_initiateSessionWithIdentifier:capabilities:",
        vec![
            Aux::archived(&NS::Uuid(session)),
            Aux::archived(&local_caps),
        ],
    )?;
    crate::debug!("got capabilities", "receivedCaps" => r.payload_object().map(|p| p.to_json()));
    // the control session does not depend on the runner, so ask for it while the runner starts
    let control = std::thread::spawn({
        let conn2 = conn2.clone();
        move || {
            conn2.call(
                ch2,
                "_IDE_initiateControlSessionWithCapabilities:",
                vec![Aux::archived(&capabilities(&[]))],
            )
        }
    });

    let apps = apps_rx
        .recv()
        .map_err(|_| Error::msg("app lookup thread died"))??;
    *config_reply.lock().unwrap() = Some(nskeyed::archive_bin(&xctest_configuration(
        &cfg,
        session,
        &apps,
        report_activities,
    )));
    let (stdio_sock, stdio_id) = stdio_rx
        .recv()
        .map_err(|_| Error::msg("stdio thread died"))??;

    let mut libraries = "/Developer/usr/lib/libMainThreadChecker.dylib".to_string();
    if cfg.xctest {
        libraries += ":/System/Developer/usr/lib/libXCTestBundleInject.dylib";
    }
    let mut env: BTreeMap<String, String> = [
        ("CA_ASSERT_MAIN_THREAD_TRANSACTIONS", "0"),
        ("CA_DEBUG_TRANSACTIONS", "0"),
        ("DYLD_INSERT_LIBRARIES", libraries.as_str()),
        (
            "DYLD_FRAMEWORK_PATH",
            "/System/Developer/Library/Frameworks",
        ),
        ("DYLD_LIBRARY_PATH", "/System/Developer/usr/lib"),
        ("MTC_CRASH_ON_REPORT", "1"),
        ("NSUnbufferedIO", "YES"),
        ("OS_ACTIVITY_DT_MODE", "YES"),
        ("SQLITE_ENABLE_THREAD_ASSERTIONS", "1"),
        ("XCTestConfigurationFilePath", ""),
        ("XCTestManagerVariant", "DDI"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    env.insert(
        "XCTestBundlePath".into(),
        format!("{}/PlugIns/{}", apps.runner_path, cfg.xctest_config_name),
    );
    env.insert("XCTestSessionIdentifier".into(), session_str);
    env.extend(cfg.env.clone());
    let opts: plist::Dictionary = if cfg.xctest {
        plist::Dictionary::new()
    } else {
        [
            ("ActivateSuspended", 1u64),
            ("StartSuspendedKey", 0),
            ("__ActivateSuspended", 1),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), Value::from(*v)))
        .collect()
    };
    let l = Launch {
        args: &cfg.args,
        env: &env,
        platform_opts: &opts,
        stdio: Some(stdio_id),
        terminate_existing: true,
        payload_url: None,
    };
    let pid = launch_app(t, &cfg.test_runner_bundle_id, &l)?;
    crate::info!("runner started", "pid" => pid);
    {
        let mut s = stdio_sock;
        std::thread::spawn(move || {
            let mut b = [0u8; 16384];
            while let Ok(n) = s.read(&mut b) {
                if n == 0 || log.write_all(&b[..n]).is_err() {
                    break;
                }
                let _ = log.flush();
            }
        });
    }

    let caps = control
        .join()
        .map_err(|_| Error::msg("control session thread panicked"))??;
    crate::debug!("got capabilities", "caps" => caps.payload_object().map(|p| p.to_json()));
    let auth = conn2.call(
        ch2,
        "_IDE_authorizeTestSessionWithProcessID:",
        vec![Aux::archived(&NS::UInt(pid as u64))],
    )?;
    crate::debug!("authorized", "pid" => pid, "authorized" => auth.payload_object().and_then(|p| p.as_bool()));

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while driver_channel.load(Ordering::SeqCst) == 0 {
        if std::time::Instant::now() > deadline || conn1.closed.load(Ordering::SeqCst) {
            return bail("the test runner never opened its channel to the IDE");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    conn1.invoke(
        driver_channel.load(Ordering::SeqCst),
        "_IDE_startExecutingTestPlanWithProtocolVersion:",
        vec![Aux::archived(&NS::UInt(36))],
        false,
    )?;

    let reason = done_rx.recv().unwrap_or_default();
    if !reason.is_empty() {
        crate::util::log(
            "ERROR",
            "test run ended",
            &[("err", serde_json::json!(reason))],
        );
    }
    // take the runner down with the session
    let _ = kill_process(t, pid);
    let failed = failures.load(Ordering::SeqCst);
    if !reason.is_empty() {
        bail(reason)
    } else if failed > 0 {
        bail(format!("** TEST FAILED **: {failed} test case(s) failed"))
    } else {
        Ok(())
    }
}

/// A test case finished with a failing status; "expected failure" and "skipped" do not count.
fn test_failed(selector: &str, m: &Msg) -> bool {
    selector.starts_with("_XCT_testCase")
        && m.args()
            .iter()
            .any(|a| matches!(a, Some(NS::Str(s)) if s == "failure" || s == "failed"))
}

fn kill_process(t: &Tunnel, pid: i64) -> Result<()> {
    let mut c = XpcConn::connect(t.connect_service(APPSERVICE)?)?;
    let device_id = uuid::Uuid::new_v4().to_string().to_uppercase();
    let input = xdict(vec![
        ("process", xdict(vec![("processIdentifier", X::I64(pid))])),
        ("signal", X::I64(9)),
    ]);
    c.send(
        xpc::coredevice_request(
            &device_id,
            "com.apple.coredevice.feature.sendsignaltoprocess",
            input,
        ),
        xpc::HEARTBEAT_REQUEST,
    )?;
    c.recv_body(xpc::SERVER_CLIENT)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(n: &str) -> Vec<u8> {
        std::fs::read(format!("tests/fixtures/xctestrun/{n}")).unwrap()
    }

    fn m(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn std_env() -> BTreeMap<String, String> {
        m(&[("OS_ACTIVITY_DT_MODE", "YES"), ("TERM", "dumb")])
    }

    fn inject_env() -> BTreeMap<String, String> {
        m(&[
            (
                "DYLD_INSERT_LIBRARIES",
                "__TESTHOST__/Frameworks/libXCTestBundleInject.dylib",
            ),
            ("XCInjectBundleInto", "unused"),
        ])
    }

    fn login_tests() -> Option<Vec<String>> {
        Some(vec![
            "LoginTests/testLogin".into(),
            "LoginTests/testLogout".into(),
        ])
    }

    /// The UI test target both fixture formats describe.
    fn ui_target() -> SchemeData {
        SchemeData {
            test_host_bundle_identifier: "com.example.RunnerUITests.xctrunner".into(),
            test_bundle_path: "__TESTHOST__/PlugIns/RunnerUITests.xctest".into(),
            environment_variables: std_env(),
            testing_environment_variables: inject_env(),
            command_line_arguments: vec!["-verbose".into()],
            only_test_identifiers: login_tests(),
            skip_test_identifiers: Some(vec!["LoginTests/testSlow".into()]),
            is_ui_test_bundle: true,
            ui_target_app_environment_variables: Some(m(&[("EXAMPLE_MODE", "ui")])),
            ui_target_app_path: "__TESTROOT__/Debug-iphoneos/Example.app".into(),
        }
    }

    #[test]
    fn parsing_v1() {
        let c = parse_xctestrun(&fixture("format_version_1.xctestrun")).unwrap();
        assert_eq!(
            c,
            vec![TestConfiguration {
                name: String::new(),
                targets: vec![ui_target()],
            }]
        );
    }

    #[test]
    fn build_test_config_ui() {
        let mut env = std_env();
        env.extend(inject_env());
        env.insert("EXAMPLE_MODE".into(), "ui".into());
        assert_eq!(
            ui_target().build_test_config(),
            TestConfig {
                test_runner_bundle_id: "com.example.RunnerUITests.xctrunner".into(),
                xctest_config_name: "RunnerUITests.xctest".into(),
                args: vec!["-verbose".into()],
                env,
                tests_to_run: login_tests(),
                tests_to_skip: Some(vec!["LoginTests/testSlow".into()]),
                xctest: false,
                target_app_name: Some("Example".into()),
            }
        );
    }

    #[test]
    fn parsing_v2() {
        let c = parse_xctestrun(&fixture("format_version_2.xctestrun")).unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].name, "Default");
        let t = &c[0].targets;
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].test_host_bundle_identifier, "com.example.Example");
        assert_eq!(t[0].skip_test_identifiers, Some(vec!["FlakyTests".into()]));
        assert_eq!(t[0].only_test_identifiers, None);
        assert!(!t[0].is_ui_test_bundle);
        assert_eq!(t[1], ui_target());
        let unit = t[0].build_test_config();
        assert!(unit.xctest && unit.env.is_empty() && unit.target_app_name.is_none());
        assert_eq!(unit.xctest_config_name, "ExampleTests.xctest");
    }

    #[test]
    fn v2_without_configurations_is_an_error() {
        let e = parse_xctestrun(&fixture("no_configurations.xctestrun")).unwrap_err();
        assert!(
            e.0.contains("does not contain any test configurations"),
            "{e}"
        );
    }

    #[test]
    fn failed_test_cases_are_counted() {
        let m = |args: &[NS]| Msg {
            aux: args.iter().map(Aux::archived).collect(),
            ..Default::default()
        };
        let finished = "_XCT_testCaseWithIdentifier:didFinishWithStatus:duration:";
        let id = NS::obj("XCTTestIdentifier", vec![("c", NS::Array(vec![]))]);
        assert!(test_failed(
            finished,
            &m(&[id.clone(), NS::str("failure"), NS::Real(0.1)])
        ));
        assert!(!test_failed(finished, &m(&[id.clone(), NS::str("passed")])));
        assert!(!test_failed(
            finished,
            &m(&[id, NS::str("expected failure")])
        ));
        assert!(!test_failed("_XCT_logMessage:", &m(&[NS::str("failure")])));
    }

    #[test]
    fn configuration_archives() {
        let c = parse_xctestrun(&fixture("format_version_1.xctestrun")).unwrap()[0].targets[0]
            .build_test_config();
        let apps = Apps {
            runner_path: "/private/var/containers/Bundle/Application/X/R.app".into(),
            target: Some(("a.b".into(), "/p/A.app".into())),
        };
        let ns = xctest_configuration(&c, [1; 16], &apps, true);
        let back = nskeyed::unarchive(&nskeyed::archive_bin(&ns)).unwrap();
        assert_eq!(
            back.get("targetApplicationBundleID")
                .and_then(|v| v.as_str()),
            Some("a.b")
        );
        assert_eq!(back.get("sessionIdentifier"), Some(&NS::Uuid([1; 16])));
        assert!(
            matches!(back.get("testBundleURL"), Some(NS::Url { relative, .. }) if relative.ends_with("R.app/PlugIns/RunnerUITests.xctest"))
        );
        assert!(matches!(back.get("testsToRun"), Some(NS::Set(s)) if s.len() == 2));
    }
}
