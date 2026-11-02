#!/usr/bin/env python3
"""Times the four steps of argent's relayed-iPhone driver, done with rxc commands:
reinstall-app, launch-app, first tap (runner install + launch) and later taps.

usage: bench.py --rxc <binary> --udid <udid> --xctestrun <file> [--app <.app>] [--taps N]
Needs USBMUXD_SOCKET_ADDRESS (host:port) in the environment, like the driver.
"""
import argparse, json, os, plistlib, socket, struct, subprocess, sys, tempfile, time, uuid

RUNNER_PORT = 27042  # argent's RELAY_RUNNER_PORT


def usbmux_sock():
    host, port = os.environ["USBMUXD_SOCKET_ADDRESS"].rsplit(":", 1)
    return socket.create_connection((host, int(port)))


def usbmux_call(s, msg, tag=1):
    body = plistlib.dumps(msg)
    s.sendall(struct.pack("<IIII", 16 + len(body), 1, 8, tag) + body)
    hdr = recv_exact(s, 16)
    n = struct.unpack("<I", hdr[:4])[0]
    return plistlib.loads(recv_exact(s, n - 16))


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def device_connect(udid, port):
    s = usbmux_sock()
    devs = usbmux_call(s, {"MessageType": "ListDevices", "ProgName": "bench", "ClientVersionString": "bench"})
    ids = [d["DeviceID"] for d in devs["DeviceList"] if d["Properties"]["SerialNumber"] == udid]
    s.close()
    s = usbmux_sock()
    r = usbmux_call(s, {"MessageType": "Connect", "DeviceID": ids[0], "PortNumber": socket.htons(port),
                        "ProgName": "bench", "ClientVersionString": "bench"})
    if r.get("Number", 1) != 0:
        s.close()
        raise ConnectionError(f"usbmux connect refused: {r}")
    return s


def runner_post(udid, body, timeout=90):
    """One command per connection, like argent's runner-http.ts."""
    s = device_connect(udid, RUNNER_PORT)
    s.settimeout(timeout)
    payload = json.dumps(body).encode()
    s.sendall(b"POST /command HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
              b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(payload) + payload)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    return json.loads(data.split(b"\r\n\r\n", 1)[1])


class Driver:
    def __init__(self, binary, udid, home):
        self.binary, self.udid, self.home = binary, udid, home
        self.tunnel = None
        self.api = None

    def run(self, *args, tunnel=False, check=True):
        argv = [self.binary, *args, "--device", self.udid]
        if tunnel:
            self.ensure_tunnel()
            argv += ["--tunnel", self.api]
        r = subprocess.run(argv, cwd=self.home, capture_output=True, text=True, timeout=180)
        if check and r.returncode != 0:
            raise RuntimeError(f"{' '.join(args)} failed: {r.stdout[-500:]} {r.stderr[-500:]}")
        return r.stdout

    def ensure_tunnel(self):
        if self.tunnel and self.tunnel.poll() is None:
            # the driver checks the tunnel with a process listing on every use
            r = subprocess.run([self.binary, "devicectl", "device", "info", "processes", "--device", self.udid, "--tunnel", self.api],
                               cwd=self.home, capture_output=True, timeout=5)
            if r.returncode == 0:
                return
            self.stop()
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.api = "127.0.0.1:%d" % s.getsockname()[1]
        s.close()
        self.log = tempfile.TemporaryFile()
        self.tunnel = subprocess.Popen([self.binary, "tunnel", "run", "--device", self.udid, "--tunnel", self.api],
                                       cwd=self.home, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 30
        while time.time() < deadline:
            self.log.seek(0)
            if b"tunnel ready" in self.log.read():
                return
            if self.tunnel.poll() is not None:
                break
            time.sleep(0.25)
        self.log.seek(0)
        raise RuntimeError("tunnel failed: " + self.log.read()[-1000:].decode(errors="replace"))

    def stop(self):
        for p in (self.tunnel, getattr(self, "xctest", None)):
            if p and p.poll() is None:
                p.terminate()
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()


def bundle_id(app):
    with open(os.path.join(app, "Info.plist"), "rb") as f:
        return plistlib.load(f)["CFBundleIdentifier"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rxc", required=True)
    ap.add_argument("--udid", required=True)
    ap.add_argument("--xctestrun", required=True)
    ap.add_argument("--app", help="app for reinstall-app (default: the xctestrun's UI target app)")
    ap.add_argument("--launch", default="com.apple.Preferences")
    ap.add_argument("--taps", type=int, default=5)
    ap.add_argument("--steps", default="reinstall,launch,tap", help="comma separated subset of reinstall,launch,tap")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    steps = set(a.steps.split(","))

    with open(a.xctestrun, "rb") as f:
        doc = plistlib.load(f)
    root = os.path.dirname(os.path.abspath(a.xctestrun))
    target = next(v for k, v in doc.items() if not k.startswith("__"))
    host_app = target["TestHostPath"].replace("__TESTROOT__", root)
    ui_app = target["UITargetAppPath"].replace("__TESTROOT__", root)
    runner_id = target["TestHostBundleIdentifier"]
    app = a.app or ui_app

    home = tempfile.mkdtemp(prefix="bench-home-")
    d = Driver(os.path.abspath(a.rxc), a.udid, home)
    res = {}
    try:
        return run_steps(a, d, doc, root, host_app, ui_app, runner_id, app, home, res, steps)
    finally:
        d.stop()


def run_steps(a, d, doc, root, host_app, ui_app, runner_id, app, home, res, steps):
    if True:
        if "tap" in steps:  # clean slate: the first tap installs the runner apps
            for b in (runner_id, bundle_id(ui_app)):
                d.run("devicectl", "device", "uninstall", "app", b, check=False)

        if "reinstall" in steps:
            t = time.time()  # reinstall-app = uninstall + install
            d.run("devicectl", "device", "uninstall", "app", bundle_id(app), check=False)
            d.run("devicectl", "device", "install", "app", app)
            res["reinstall-app"] = time.time() - t

        if "launch" in steps:
            t = time.time()  # launch-app; the first use starts the tunnel
            d.run("devicectl", "device", "process", "launch", a.launch, tunnel=True)
            res["launch-app (cold)"] = time.time() - t

            t = time.time()  # launch-app again: tunnel health probe + launch
            d.run("devicectl", "device", "process", "launch", a.launch, tunnel=True)
            res["launch-app (warm)"] = time.time() - t

        if "tap" not in steps:
            if a.json:
                print(json.dumps(res))
            else:
                for k, v in res.items():
                    print(f"{k:22s} {v:6.2f} s")
            return

        # first tap: install and launch the runner, wait for it, tap
        t = time.time()
        apps = json.loads(d.run("devicectl", "device", "info", "apps", "-j", "-"))["result"]["apps"]
        installed = {x["bundleIdentifier"] for x in apps}
        for path, bid in ((host_app, runner_id), (ui_app, bundle_id(ui_app))):
            if bid not in installed:
                d.run("devicectl", "device", "install", "app", path)
        pinned = os.path.join(home, "runner.xctestrun")
        for k, v in doc.items():
            if not k.startswith("__"):
                for env in ("EnvironmentVariables", "TestingEnvironmentVariables"):
                    v.setdefault(env, {})["ARGENT_RUNNER_PORT"] = str(RUNNER_PORT)
        with open(pinned, "wb") as f:
            plistlib.dump(doc, f)
        # __TESTROOT__ would resolve next to the copy; point it at the real build products
        with open(pinned, "rb") as f:
            text = f.read().replace(b"__TESTROOT__", root.encode())
        with open(pinned, "wb") as f:
            f.write(text)
        d.ensure_tunnel()
        xlog = open(os.path.join(home, "runner.log"), "wb")
        d.xctest = subprocess.Popen([d.binary, "xcodebuild", "test-without-building", "-xctestrun", pinned, "-destination", f"id={a.udid}",
                                     "--tunnel", d.api], cwd=home, stdout=xlog, stderr=xlog)
        deadline = time.time() + 120
        while True:
            try:
                runner_post(a.udid, {"command": "status"}, timeout=5)
                break
            except Exception:
                if d.xctest.poll() is not None or time.time() > deadline:
                    raise RuntimeError("runner never came up; log: " + open(xlog.name, "rb").read()[-2000:].decode(errors="replace"))
                time.sleep(0.25)
        tap = lambda: runner_post(a.udid, {"command": "tap", "appBundleId": a.launch, "x": 200, "y": 70,
                                           "commandId": str(uuid.uuid4())})
        r = tap()
        res["first tap"] = time.time() - t
        if not r.get("ok", True):
            print("tap reply:", r, file=sys.stderr)

        times = []
        for _ in range(a.taps):
            t = time.time()
            tap()
            times.append(time.time() - t)
        res["later taps (avg)"] = sum(times) / len(times)
        res["later taps (min)"] = min(times)

    if a.json:
        print(json.dumps(res))
    else:
        for k, v in res.items():
            print(f"{k:22s} {v:6.2f} s")


if __name__ == "__main__":
    main()
