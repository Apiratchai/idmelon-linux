"""CTAP HID framing (FIDO authenticator USB transport). Stdlib only.

Splits messages into 64-byte reports (INIT + CONT packets) and reassembles
them back. No IDmelon specifics here.
"""
import struct

CTAP_INIT, CTAP_PING, CTAP_MSG, CTAP_LOCK = 0x86, 0x81, 0x83, 0x84
CTAP_CBOR, CTAP_CANCEL, CTAP_KEEPALIVE, CTAP_WINK = 0x90, 0x91, 0xBB, 0x88
BROADCAST_CID = 0xFFFFFFFF

# U2FHID_INIT response fields. Caps 0x05 = WINK | LARGEBLOBS, same as real keys.
INIT_PROTOCOL, INIT_VER_MAJOR, INIT_VER_MINOR, INIT_BUILD = 2, 0, 1, 1
INIT_CAPS = 0x05


def hid_split(cid, cmd, data):
    """Split message into 64-byte HID reports (INIT + CONT)."""
    ln = len(data)
    out = [struct.pack(">IBH", cid, cmd, ln) + data[:57]]
    seq = 0
    rest = data[57:]
    while rest:
        out.append(struct.pack(">IB", cid, seq) + rest[:59])
        rest = rest[59:]
        seq += 1
    return [p.ljust(64, b"\x00")[:64] for p in out]


class HidReassembler:
    def __init__(self):
        self.reset()

    def reset(self):
        self.cid = None
        self.cmd = None
        self.length = 0
        self.buf = bytearray()

    def feed(self, pkt):
        """Feed 64-byte report. Returns (cid, cmd, data) when complete, else None."""
        if len(pkt) < 7:
            return None
        cid, = struct.unpack(">I", pkt[:4])
        b5 = pkt[4]
        if b5 & 0x80:
            cmd, ln = pkt[4], struct.unpack(">H", pkt[5:7])[0]
            self.cid, self.cmd, self.length = cid, cmd, ln
            self.buf = bytearray(pkt[7:7 + min(ln, 57)])
        else:
            seq = b5
            if cid != self.cid:
                return None
            self.buf += pkt[5:5 + min(self.length - len(self.buf), 59)]
        if len(self.buf) >= self.length:
            return self.cid, self.cmd, bytes(self.buf[:self.length])
        return None
