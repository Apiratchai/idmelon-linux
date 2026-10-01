#!/usr/bin/env python3
"""IDmelon Pairing Tool for Linux (unofficial port).
Reverse-engineered from macOS 1.1.5 + Windows 3.1.13.
Flow: REST https://idmp.idmelon.com/v2/apps + SocketIO path=/connect + UHID virtual FIDO HID.

Usage:
  python3 idmelon_linux.py            # interactive menu (recommended)
  python3 idmelon_linux.py register   # first time (POST /v2/apps)
  python3 idmelon_linux.py qr         # show pairing QR (GET /v2/apps/QRCode)
  python3 idmelon_linux.py status     # show paired phone (GET .../smartphones/last)
  sudo python3 idmelon_linux.py run   # bridge browser <-> phone (needs /dev/uhid)
  sudo python3 idmelon_linux.py run --ble  # also advertise BLE proximity (opt-in, rarely needed)
  python3 idmelon_linux.py test      # offline selftest (framing roundtrips, no root/net needed)

Config: ~/.config/idmelon-linux/config.json (your token, never commit it)
"""
import json, os, sys, uuid, socket, struct, random, threading
import pwd
from pathlib import Path

from ctaphid import (
    BROADCAST_CID, CTAP_CANCEL, CTAP_CBOR, CTAP_INIT, CTAP_KEEPALIVE,
    CTAP_PING, INIT_BUILD, INIT_CAPS, INIT_PROTOCOL, INIT_VER_MAJOR,
    INIT_VER_MINOR, HidReassembler, hid_split,
)
from uhid import Uhid, parse_output

IDMP = "https://idmp.idmelon.com"
APPVERSION = "3.1.13"

# Server needs os as an object; any name/version is accepted (Windows values
# were used initially, but plain Linux values register fine).
def _linux_os():
    name, version = "Linux", "unknown"
    try:
        import platform
        version = platform.release() or version
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    name = line.split("=", 1)[1].strip().strip('"')
                    break
    except Exception:
        pass
    return name, version


REAL_OS_NAME, REAL_OS_VERSION = _linux_os()

# Last-resort CID when a Response arrives for an unknown request (shouldn't happen).
UNKNOWN_CID = 0x01020304


def _real_home():
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and os.geteuid() == 0:
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return Path.home()


def _config_path():
    # sudo changes HOME to /root; keep config with the real user
    return _real_home() / ".config" / "idmelon-linux" / "config.json"


CONFIG = _config_path()

if os.geteuid() == 0 and os.environ.get("SUDO_USER"):
    # sudo doesn't see the user's `pip install --user` packages; add them back
    for _p in (_real_home() / ".local" / "lib").glob("python*/site-packages"):
        if str(_p) not in sys.path:
            sys.path.insert(0, str(_p))

# FIDO HID report descriptor from IDmelon dext (standard FIDO usage page F1D0)
HID_REPORT_DESC = bytes.fromhex(
    "06d0f10901a1010920150026ff007508954081020921150026ff00750895409102c0")

HID_TO_BLE = {0x91: 0xBE, 0x86: 0x86, 0x90: 0x83, 0x3F: 0xBF,
              0xBB: 0x82, 0x83: 0x83, 0x81: 0x81}
BLE_TO_HID = {0xBE: 0x91, 0x86: 0x86, 0xBF: 0x3F, 0x82: 0xBB,
              0x83: 0x90, 0x81: 0x81, 0x90: 0x90}


def load_config():
    if CONFIG.exists():
        return json.loads(CONFIG.read_text())
    return {}


def save_config(cfg):
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2))
    os.replace(tmp, CONFIG)
    print(f"saved {CONFIG}")


def http(method, path, token=None, data=None, timeout=20):
    import urllib.request
    url = IDMP + path
    body = json.dumps(data).encode() if data is not None else None
    hdrs = {"User-Agent": f"IDmelonPairingTool/{APPVERSION} (Microsoft Windows)",
            "accept": "application/json"}
    if token:
        hdrs["Authorization"] = token
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def unique_id():
    cfg = load_config()
    if cfg.get("uniqueId"):
        return cfg["uniqueId"]
    try:
        mid = Path("/etc/machine-id").read_text().strip()
    except Exception:
        mid = uuid.uuid4().hex
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"linux-{mid}-{socket.gethostname()}"))


def cmd_register():
    uid = unique_id()
    body = {"uniqueId": uid, "os": {"name": REAL_OS_NAME, "version": REAL_OS_VERSION},
            "appversion": APPVERSION, "PCName": socket.gethostname(), "ip": "1.2.3.4"}
    res = http("POST", "/v2/apps", data=body)
    cfg = {"uniqueId": uid, "appId": res["appId"], "token": res["token"],
           "idmp": IDMP, "pcName": socket.gethostname()}
    save_config(cfg)
    print(f"appId={res['appId']}")
    print(f"QR={res['QRCodeValue']}")


def cmd_qr():
    cfg = load_config()
    assert cfg.get("token"), "run register first"
    res = http("GET", "/v2/apps/QRCode", token=cfg["token"])
    url = res["QRCodeValue"]
    print(url)
    print(f"expires={res.get('QRCodeExpireTime')}")
    try:
        import qrcode
        qr = qrcode.QRCode(border=1)
        qr.add_data(url)
        qr.make()
        qr.print_ascii(invert=True)
        out = Path.cwd() / "idmelon-qr.png"
        qr.make_image().save(out)
        print(f"png saved to {out} (open it and scan with IDmelon Authenticator)")
    except ImportError:
        print("pip install qrcode  # for terminal QR + png")


def cmd_status():
    cfg = load_config()
    assert cfg.get("token"), "run register first"
    print(json.dumps(http("GET", "/v2/apps/smartphones/last", token=cfg["token"]), indent=2))


def cmd_run():
    cfg = load_config()
    assert cfg.get("token"), "run register first"
    # refresh device list (also PUTs PC info like Windows SendApplicationInfo)
    try:
        http("PUT", "/v2/apps", token=cfg["token"],
             data={"os": {"name": REAL_OS_NAME, "version": REAL_OS_VERSION},
                   "appversion": APPVERSION, "PCName": socket.gethostname()})
    except Exception as e:
        print(f"PUT info failed (non-fatal): {e}")
    last = http("GET", "/v2/apps/smartphones/last", token=cfg["token"])
    ls = last.get("lastSmartphone") or {}
    info = ls.get("info") or {}
    smartphone_id = ls.get("_id") or info.get("_id", "")
    getinfo = ls.get("getInfo", "")
    if smartphone_id:
        print(f"paired phone: {info.get('model')} id={smartphone_id}")
    else:
        print("no phone paired yet. Scan QR first (run `qr` in another terminal).")
        print("waiting for pairing... Ctrl-C to stop")
    proximity_id = ""
    if "--ble" in sys.argv:
        proximity_id = make_proximity_id()
        stop_ble = start_ble_advertising(proximity_id)
        if not stop_ble:
            proximity_id = ""
    else:
        stop_ble = None
    try:
        bridge(cfg["token"], smartphone_id, getinfo, proximity_id)
    finally:
        if stop_ble:
            stop_ble()


# ---------- SocketIO bridge ----------

def hid_to_ble_hex(cmd, data):
    ble_cmd = HID_TO_BLE.get(cmd, cmd)
    return (bytes([ble_cmd]) + struct.pack(">H", len(data)) + bytes(data)).hex()


def ble_hex_to_hid(ble_hex):
    raw = bytes.fromhex(ble_hex)
    ble_cmd, ln = raw[0], struct.unpack(">H", raw[1:3])[0]
    data = raw[3:3 + ln]
    return BLE_TO_HID.get(ble_cmd, ble_cmd), bytes(data)


def _keepalive_loop(uhid, cid, stop):
    # Windows does the same (StartSendingKeepalive): hold the browser
    # while the phone round-trip takes seconds (user taps approve)
    while not stop.wait(0.1):
        try:
            for pkt in hid_split(cid, CTAP_KEEPALIVE, b"\x01"):
                uhid.send_input(pkt)
        except OSError:
            return


BLE_COMPANY_ID = 0x4944  # 'ID' - same as IDmelon Windows client


def make_proximity_id():
    return "IDme" + os.urandom(4).hex() + "1111"


def start_ble_advertising(proximity_id):
    """Advertise ManufacturerData CompanyId 0x4944 like the Windows client.
    Returns stop() or None. Needs Experimental=true in bluetoothd."""
    try:
        import dbus
        import dbus.service
        from dbus.mainloop.glib import DBusGMainLoop
        from gi.repository import GLib
    except ImportError as e:
        print(f"BLE advertise skipped ({e})")
        return None
    try:
        DBusGMainLoop(set_as_default=True)
        bus = dbus.SystemBus()
        adv_path = "/com/idmelon/adv0"
        payload = dbus.ByteArray(proximity_id.encode("ascii"))

        class Advertisement(dbus.service.Object):
            @dbus.service.method("org.freedesktop.DBus.Properties",
                                 in_signature="s", out_signature="a{sv}")
            def GetAll(self, interface):
                if interface != "org.bluez.LEAdvertisement1":
                    return {}
                return {"Type": "peripheral",
                        "ManufacturerData": dbus.Dictionary(
                            {dbus.UInt16(BLE_COMPANY_ID): payload},
                            signature="qv")}

            @dbus.service.method("org.bluez.LEAdvertisement1")
            def Release(self):
                pass

        adv = Advertisement(bus, adv_path)
        loop = GLib.MainLoop()
        t = threading.Thread(target=loop.run, daemon=True)
        t.start()  # dispatch D-Bus replies before the blocking call below
        mgr = dbus.Interface(
            bus.get_object("org.bluez", "/org/bluez/hci0"),
            "org.bluez.LEAdvertisingManager1")
        mgr.RegisterAdvertisement(adv_path, {}, timeout=20)

        def stop():
            try:
                mgr.UnregisterAdvertisement(adv_path)
            except Exception:
                pass
            loop.quit()

        print(f"BLE advertising as {proximity_id}")
        return stop
    except Exception as e:
        print(f"BLE advertise failed (non-fatal, server may reject): {e}")
        return None


def bridge(token, smartphone_id, cached_getinfo="", proximity_id=""):
    try:
        import socketio
    except ImportError:
        sys.exit("pip install 'python-socketio[client]' qrcode")
    if os.geteuid() != 0 and not os.access("/dev/uhid", os.W_OK):
        sys.exit("need /dev/uhid write access: re-run with sudo")
    uhid = Uhid()
    uhid.create("IDmelon FIDO", report_desc=HID_REPORT_DESC)
    print("UHID FIDO device created (check chrome://device-log or fido2-token -L)")
    print("press Ctrl-C to stop")
    sio = socketio.Client(logger=False, engineio_logger=False)
    state = {"req_id": random.randint(1, 60000), "pending": {}, "keepalive": {},
             "getinfo": cached_getinfo}
    reasm = HidReassembler()

    @sio.event
    def connect():
        print("socket connected")

    @sio.event
    def disconnect():
        print("socket disconnected")

    @sio.on("*")
    def any_ev(ev, data=None):
        print(f"socket event {ev}: {str(data)[:300]}")

    @sio.on("Response")
    def on_response(resp):
        try:
            if isinstance(resp, list):
                resp = resp[0] if resp else {}
            if isinstance(resp, str):
                resp = json.loads(resp)
            rid = int(resp.get("requestId", 0))
            pend = state["pending"].pop(rid, None)
            ka = state["keepalive"].pop(rid, None)
            if ka:
                ka.set()
            ack = {"smartphoneId": pend["phone"] if pend else smartphone_id,
                   "token": token, "requestId": str(rid)}
            sio.emit("ResponseACK", json.dumps(ack))
            ble_hex = resp.get("msgResponse") or resp.get("data") or ""
            if not ble_hex:
                print(f"empty Response for req {rid}")
                return
            print(f"<- socket Response id={rid} ble={ble_hex[:60]}...")
            if resp.get("getInfo"):
                state["getinfo"] = resp["getInfo"]
                print("getInfo cache updated")
            hcmd, hdata = ble_hex_to_hid(ble_hex)
            cid = pend["cid"] if pend else UNKNOWN_CID
            for pkt in hid_split(cid, hcmd, hdata):
                uhid.send_input(pkt)
        except Exception as e:
            print(f"Response handling failed: {e}")

    query = f"token={token}" + (f"&smartphoneId={smartphone_id}" if smartphone_id else "")
    sio.connect(f"https://idmp.idmelon.com?{query}", socketio_path="/connect",
                transports=["websocket"], wait_timeout=15)
    # Windows sends {"token","smartphoneId","msgRequest","requestId","channelId"[,"accessToken","BTInfo"]} as event "Request"
    try:
        while True:
            ev = uhid.recv(timeout=0.2)
            if ev is None:
                continue
            typ, payload = parse_output(ev)
            if typ == "get_report":
                continue
            if typ != "output":
                print(f"UHID ev={typ}")
                continue
            raw = bytes(payload)
            print(f"UHID output size={len(raw)} head={raw[:8].hex()}")
            if len(raw) == 65 and raw[0] == 0:
                raw = raw[1:]  # strip report ID
            msg = reasm.feed(raw)
            if not msg:
                continue
            cid, cmd, data = msg
            print(f"HID cmd={cmd:#04x} cid={cid:#010x} len={len(data)}")
            if cmd == CTAP_INIT and cid == BROADCAST_CID:
                nonce = data[:8]
                new_cid = random.randint(1, 0xFFFFFFFE)
                print(f"INIT local reply new_cid={new_cid:#010x}")
                resp = nonce + struct.pack(">I", new_cid) + bytes(
                    [INIT_PROTOCOL, INIT_VER_MAJOR, INIT_VER_MINOR, INIT_BUILD, INIT_CAPS])
                for pkt in hid_split(cid, CTAP_INIT, resp):
                    uhid.send_input(pkt)
                continue
            if cmd == CTAP_PING:
                print("PING local echo")
                for pkt in hid_split(cid, cmd, data):
                    uhid.send_input(pkt)
                continue
            if cmd == CTAP_CBOR and data[:1] == b"\x04" and state["getinfo"]:
                # authenticatorGetInfo: Windows answers from cache, no phone round-trip
                print("GetInfo local reply")
                try:
                    hcmd, hdata = ble_hex_to_hid(state["getinfo"])
                    for pkt in hid_split(cid, hcmd, hdata):
                        uhid.send_input(pkt)
                except Exception as e:
                    print(f"local GetInfo failed: {e}")
                continue
            # forward CBOR/MSG/etc. to phone
            state["req_id"] = (state["req_id"] + 1) % 65536 or 1
            rid = state["req_id"]
            msg_hex = hid_to_ble_hex(cmd, data)
            print(f"-> socket Request id={rid} ble={msg_hex[:60]}...")
            pkt = {"token": token, "smartphoneId": smartphone_id, "msgRequest": msg_hex,
                   "requestId": str(rid), "channelId": cid}
            if proximity_id:
                pkt["BTInfo"] = proximity_id
            state["pending"][rid] = {"cid": cid, "phone": smartphone_id}
            stop = threading.Event()
            state["keepalive"][rid] = stop
            threading.Thread(target=_keepalive_loop, args=(uhid, cid, stop),
                             daemon=True).start()

            def _ack(*args):
                print(f"server ACK id={rid}: {str(args)[:200]}")

            try:
                sio.emit("Request", json.dumps(pkt), callback=_ack)
            except Exception as e:
                stop.set()
                state["pending"].pop(rid, None)
                state["keepalive"].pop(rid, None)
                print(f"emit failed id={rid}: {e}")
    except KeyboardInterrupt:
        pass
    finally:
        try:
            sio.disconnect()
        except Exception:
            pass
        uhid.destroy()


def cmd_selftest():
    for cmd, data in [(CTAP_CBOR, b"\x04"), (CTAP_CBOR, bytes(range(200))),
                      (CTAP_INIT, b"12345678"), (CTAP_CBOR, bytes(500))]:
        pkts = hid_split(0x01020304, cmd, data)
        assert all(len(p) == 64 for p in pkts)
        r = HidReassembler()
        out = None
        for p in pkts:
            out = r.feed(p)
        assert out == (0x01020304, cmd, data), (cmd, len(data))
    for hcmd in [CTAP_CBOR, CTAP_INIT, CTAP_PING, CTAP_CANCEL, CTAP_KEEPALIVE]:
        hx = hid_to_ble_hex(hcmd, b"\x04\x01\x02")
        assert ble_hex_to_hid(hx) == (hcmd, b"\x04\x01\x02"), hcmd
    pkts = hid_split(0x01020304, CTAP_KEEPALIVE, b"\x01")
    assert len(pkts) == 1 and struct.unpack(">IBH", pkts[0][:7]) == (0x01020304, 0xBB, 1)
    payload = bytes(range(64))
    ev = struct.pack("<L4096sHB", 6, payload, 64, 0)
    assert parse_output(ev) == ("output", payload)
    pid = make_proximity_id()
    assert pid.startswith("IDme") and pid.endswith("1111") and len(pid) == 16
    print("selftest OK")


def cmd_menu():
    print("IDmelon Pairing Tool for Linux (unofficial)")
    cfg = load_config()
    phone = "unknown"
    if cfg.get("token"):
        try:
            ls = http("GET", "/v2/apps/smartphones/last",
                      token=cfg["token"], timeout=8).get("lastSmartphone") or {}
            phone = (ls.get("info") or {}).get("model", "not paired")
        except Exception:
            pass
    while True:
        cfg = load_config()
        reg = "registered" if cfg.get("token") else "not registered"
        print(f"\nPC: {reg} | Phone: {phone}")
        print("1) register this PC (first time only)")
        print("2) show pairing QR (scan with phone)")
        print("3) show paired phone")
        print("4) run security-key bridge (needs root, keep running)")
        print("5) quit")
        try:
            c = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if c == "1":
            cmd_register()
        elif c == "2":
            cmd_qr()
        elif c == "3":
            cmd_status()
        elif c == "4":
            if os.geteuid() != 0:
                print("need root for /dev/uhid, re-running with sudo...")
                os.execvp("sudo", ["sudo", sys.executable,
                                   os.path.abspath(__file__), "run"])
            cmd_run()
        elif c == "5":
            return


if __name__ == "__main__":
    if len(sys.argv) < 2:
        cmd_menu()
    elif sys.argv[1] in ("register", "qr", "status", "run", "menu", "test"):
        {"register": cmd_register, "qr": cmd_qr, "status": cmd_status,
         "run": cmd_run, "menu": cmd_menu, "test": cmd_selftest}[sys.argv[1]]()
    else:
        sys.exit("usage: idmelon_linux.py [register|qr|status|run|menu|test]")
