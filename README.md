# rxctools

**Xcode's iPhone tools, without Xcode.**

rxctools is a Rust implementation of what Xcode's command-line tools do with physical iPhones and
the apps that go on them: list devices, install, launch and kill apps, take screenshots, run XCTest,
mount developer disk images, turn on Developer Mode, sign apps. It runs on macOS and Linux with no
Xcode and no root, and talks to the phone over usbmuxd (or a relay that speaks its protocol) and the
iOS 17+ tunnel.

Its one binary, `rxc`, works like `xcrun`: the name of the Xcode tool comes first, then that tool's
own commands, options and JSON output. A script written for Xcode moves over by swapping `xcrun`
for `rxc`:

```bash
xcrun devicectl device process launch --device <udid> com.apple.Preferences   # macOS with Xcode
rxc devicectl device process launch --device <udid> com.apple.Preferences     # macOS or Linux
```

## Tools

| Xcode tool | rxctools | Covers |
|---|---|---|
| `xcrun devicectl` | `rxc devicectl` | `list devices`; `device info details`, `apps`, `processes`, `ddiServices`; `device install app`, `device uninstall app`; `device process launch`, `terminate`; `device capture screenshot`; `manage ddis update` |
| `xcodebuild` | `rxc xcodebuild` | `test-without-building` for iOS 17+ |
| `devmodectl` | `rxc devmodectl` | `single` |
| none, Xcode keeps its tunnels to itself | `rxc tunnel` | `run`, `list` |
| `codesign` and Xcode's signing step | `rxc sign` | `app`: re-signs an .app or .ipa with a .p12 and a provisioning profile |
| none | `rxc lockdown` | `get`, `set`: the device's lockdown values, such as `ProductVersion` or `Language` |

## Getting started

```bash
cargo build --release
export PATH=$PWD/target/release:$PATH
rxc devicectl list devices
rxc devicectl device info ddiServices         # mounts the developer disk image when it is missing
rxc tunnel run &                              # iOS 17+: processes, launches, screenshots and tests go through it
rxc devicectl device process launch com.apple.Preferences
```

Each `v*` tag publishes ready-built `rxc` on the repository's Releases page: `rxc-x86_64-unknown-linux-musl.tar.gz`
(static, any Linux distribution), `rxc-aarch64-apple-darwin.tar.gz` and `rxc-x86_64-apple-darwin.tar.gz`,
with their SHA-256 in `SHA256SUMS`.

## Supported platforms

- **macOS**: nothing else to install. rxc uses the system's usbmuxd, which pairs a phone once you
  tap Trust on it.
- **Linux**: a phone on USB needs the usbmuxd daemon (`apt install usbmuxd` on Debian and Ubuntu),
  which pairs it the same way.
- **A phone attached to another machine**: point `USBMUXD_SOCKET_ADDRESS` at a usbmux relay
  (`host:port`); nothing else is needed on either OS. The relay sends the phone's pairing keys
  unencrypted, so reach it only over a trusted network or an SSH tunnel.
- **iPhones**: iOS 17 and later; the commands that go through the tunnel need iOS 17.4. Tested on
  iOS 18 and 27.

## Commands

| Command | Notes |
|---|---|
| `rxc devicectl list devices`, `device info details` | details add `developerModeStatus` and `ddiServicesAvailable` |
| `rxc devicectl device info apps [--include-default-apps] [--include-all-apps] [--bundle-id <id>]` | third-party apps unless asked for Apple's |
| `rxc devicectl device install app <.app or .ipa>`, `device uninstall app <bundle-id>` | |
| `rxc devicectl device info ddiServices [--no-auto-mount-ddis]` | mounts the iOS 17+ personalized developer disk image, signed for the device by Apple's TSS. With Developer Mode off it shows the toggle in Settings, as Xcode does |
| `rxc devicectl manage ddis update` | only downloads that image, into `~/.cache/rxc/ddis` |
| `rxc devicectl device info processes`, `device process launch [--terminate-existing] [--environment-variables <json>] [--payload-url <url>] <bundle-id> [<arguments> ...]`, `device process terminate --pid <pid> [--kill]`, `device capture screenshot --destination <png>` | need `rxc tunnel run` |
| `rxc xcodebuild test-without-building -xctestrun <file> -destination id=<udid>` | needs `rxc tunnel run`; the runner's output goes to stdout |
| `rxc devmodectl single <udid>` | turns Developer Mode on, waits for the restart and confirms it |
| `rxc tunnel run`, `rxc tunnel list` | holds the iOS 17+ tunnel open in user space, without root, and tells the commands above where to find it on `--tunnel` (default `127.0.0.1:50550`) |
| `rxc sign app <.app or .ipa> --p12 <file> --profile <mobileprovision> [--p12-password <password>] [--output <path>] [--bundle-id <id>] [--install]` | signs the way Xcode does for iOS, nested bundles and dylibs included, with entitlements from the profile; app extensions get the profile too, and FairPlay-encrypted (App Store) builds are refused; no keychain needed |
| `rxc lockdown get [--domain <domain>] [<key>]`, `rxc lockdown set [--domain <domain>] <key> <string value>` | e.g. `get PasswordProtected`, `get --domain com.apple.fmip IsAssociated`, `set --domain com.apple.international Language en` |

Common options are devicectl's: `--device`/`-d` (the first device when left out), `-v`, `-q`, and
`--json-output`/`-j <path or ->`, which writes the document devicectl would, with results shaped
like devicectl's. Human-readable output goes to stdout, or to stderr when the JSON does.

Not implemented yet: devicectl's other commands (file copy, profiles, other settings, openURL,
screen recording, reboot, sysdiagnose), devmodectl's `info`, `list` and `streaming`, syslog, crash
reports, pairing, and anything below iOS 17 that needs the developer disk image or the tunnel.

## Speed

An iPhone 15 with iOS 18.7, reached over a network relay:

| | |
|---|---|
| launch an app, first time (tunnel start + launch) | 1.3 s |
| launch an app, tunnel already up | 1.0 s |
