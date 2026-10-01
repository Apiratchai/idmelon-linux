# IDmelon Pairing Tool for Linux (unofficial)

Reverse-engineered port of IDmelon Pairing Tool (macOS 1.1.5 / Windows 3.1.13).
REST + SocketIO + UHID virtual FIDO key. Not affiliated with IDmelon/HID. Use your own account.

## Use

```
pip install 'python-socketio[client]' qrcode
python3 idmelon_linux.py   # menu: 1 register, 2 QR, 3 status, 4 run
```

Manual (same as menu):
```
python3 idmelon_linux.py register
python3 idmelon_linux.py qr
python3 idmelon_linux.py status
sudo python3 idmelon_linux.py run
python3 idmelon_linux.py test
```
Only run needs root (/dev/uhid). Append --ble to run only if a site ever enforces proximity (untested path, needs bluetoothd Experimental=true).

## Steps

- register: introduces PC to server, saves token to ~/.config/idmelon-linux/config.json. Expect appId + QR link.
- qr: fresh pairing QR (ascii + idmelon-qr.png). Scan with IDmelon Authenticator > Pair with a PC.
- status: {} = not paired yet; phone model = paired.
- run: creates HID key, connects socket, relays browser <-> phone. Log in on a site, approve on phone.
- test: offline framing roundtrips, no root/net needed.

## Notes

os is reported honestly (distro + kernel), server accepts any os object.
No BLE proximity needed, server doesn't enforce it.
Token lives in config.json, never commit it (.gitignore covers it).

## Files

idmelon_linux.py is the tool. uhid.py (virtual HID devices) and ctaphid.py
(CTAP framing) are generic, import them in your own projects.
