"""User-space HID devices via /dev/uhid. Stdlib only.

Lets any program create a virtual HID device that shows up as /dev/hidraw*
and works with browsers and libfido2. No IDmelon specifics here.
"""
import os
import select
import struct

UHID_DESTROY, UHID_START, UHID_STOP = 1, 2, 3
UHID_OPEN, UHID_CLOSE, UHID_OUTPUT = 4, 5, 6
UHID_GET_REPORT, UHID_GET_REPORT_REPLY = 9, 10
UHID_CREATE2, UHID_INPUT2 = 11, 12
BUS_USB = 3
UHID_EVENT_SIZE = 4380

# Browsers match FIDO keys by HID usage page (F1D0), not VID/PID, so any IDs do.
UHID_VID, UHID_PID = 0xAAAA, 0xAAAA


class Uhid:
    def __init__(self):
        self.fd = os.open("/dev/uhid", os.O_RDWR | os.O_NONBLOCK)

    def create(self, name="Virtual HID", vid=UHID_VID, pid=UHID_PID, report_desc=b""):
        ev = struct.pack("<L128s64s64sHHLLLL4096s", UHID_CREATE2,
                         name.encode()[:127], b"", b"", len(report_desc),
                         BUS_USB, vid, pid, 0, 0, report_desc)
        os.write(self.fd, ev)

    def destroy(self):
        try:
            os.write(self.fd, struct.pack("<L", UHID_DESTROY))
        except OSError:
            pass

    def send_input(self, data):
        d = bytes(data[:64])
        os.write(self.fd, struct.pack("<LH4096s", UHID_INPUT2, len(d), d))

    def recv(self, timeout=0.1):
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return None
        try:
            return os.read(self.fd, UHID_EVENT_SIZE)
        except BlockingIOError:
            return None


def parse_output(ev):
    typ, = struct.unpack("<L", ev[:4])
    if typ == UHID_START:
        return ("start", None)
    if typ == UHID_STOP:
        return ("stop", None)
    if typ == UHID_OPEN:
        return ("open", None)
    if typ == UHID_CLOSE:
        return ("close", None)
    if typ == UHID_OUTPUT:
        data, size, _rtype = struct.unpack("<4096sHB", ev[4:4103])
        return ("output", bytes(data[:size]))
    if typ == UHID_GET_REPORT:
        return ("get_report", ev[4:16])
    return (typ, None)
