# IDmelon Pairing Tool for Linux (unofficial)

Reverse-engineered port of IDmelon Pairing Tool (macOS 1.1.5 / Windows 3.1.13).
REST + SocketIO + UHID virtual FIDO key. Not affiliated with IDmelon/HID. Use your own account.

## Use

```
pip install 'python-socketio[client]' qrcode
python3 idmelon_linux.py   # menu: 1 register, 2 QR, 3 status, 4 run
```

Manual: register | qr | status | sudo ... run | test. Only run needs root (/dev/uhid).
Append --ble to run only if a site ever enforces proximity (untested path, needs bluetoothd Experimental=true).

## Steps

- register: introduces PC to server, saves token to ~/.config/idmelon-linux/config.json. Expect appId + QR link.
- qr: fresh pairing QR (ascii + idmelon-qr.png). Scan with IDmelon Authenticator > Pair with a PC.
- status: {} = not paired yet; phone model = paired.
- run: creates HID key, connects socket, relays browser <-> phone. Log in on a site, approve on phone.
- test: offline framing roundtrips, no root/net needed.

## Notes

os is spoofed as Windows 11, server rejects anything else (see SPOOF_OS_* in code).
No BLE proximity needed, server doesn't enforce it.
Token lives in config.json, never commit it (.gitignore covers it).
