#!/usr/bin/env python3
"""Reproduce the observed Brother update-query/download protocol.

1. Read @PJL INFO BRFIRMWARE over port 9100.
2. Send REQUESTINFO XML to the vendor fileUpdate endpoint.
3. Read VERSIONCHECK, FIRMID, PATH, and LATESTVERSION.
4. Download PATH when supplied. This tool never flashes firmware.

--query-only contacts only the selected printer. A download request contacts
Brother's server and can include the printer serial number. Review output
before sharing it publicly.
"""
import argparse
import re
import socket
import sys
import urllib.request
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

URL = "https://firmverup.brother.co.jp/kne_bh7_update_nt_ssl/ifax2.asmx/fileUpdate"
UEL = b"\x1b%-12345X"


def query_printer(host, port=9100, timeout=10):
    """Return the raw @PJL INFO BRFIRMWARE response."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(UEL + b"@PJL INFO BRFIRMWARE\r\n" + UEL)
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\x0c" in chunk:  # PJL responses end with a form feed
                    break
        except socket.timeout:
            pass
    return data.decode("latin-1")


def parse_brfirmware(text):
    """Parse MODEL, SPEC, FIRMID and FIRMVER from PJL key/value lines."""
    info = {"firms": []}
    firmid = None
    for key, val in re.findall(r'^\s*(\w+)\s*=\s*"?([^"\r\n]*)"?', text, re.M):
        key = key.upper()
        if key == "MODEL":
            info["name"] = val
        elif key == "SPEC":
            info["spec"] = val
        elif key == "SERIAL":
            info["serial"] = val
        elif key == "FIRMID":
            firmid = val
        elif key == "FIRMVER" and firmid:
            info["firms"].append((firmid, val))
            firmid = None
    return info


def build_request(name, spec, firms, serial="", category="MAIN", os_="WIN_NATIVE", driver=None):
    # Structure recovered from FirmwareUpdater.exe (function 0x40315f):
    #  - no AREA; OSVERSION is the Windows major version; INSPECTMODE must be 0
    #  - DRIVER must not be empty, or the server supplies no PATH
    #  - VERSIONCHECK: 0 = update available (with PATH),
    #    1 = current, 2 = newer than server / invalid
    driver = driver or f"{name} Printer"
    firm_xml = "".join(
        f"<FIRM><ID>{escape(i)}</ID><VERSION>{escape(v)}</VERSION></FIRM>" for i, v in firms
    )
    return (
        "<REQUESTINFO>"
        "<FIRMUPDATETOOLINFO>"
        f"<FIRMCATEGORY>{category}</FIRMCATEGORY><OS>{os_}</OS><OSVERSION>10</OSVERSION>"
        "<INSPECTMODE>0</INSPECTMODE>"
        "</FIRMUPDATETOOLINFO>"
        "<FIRMUPDATEINFO>"
        f"<MODELINFO><SELIALNO>{escape(serial)}</SELIALNO><NAME>{escape(name)}</NAME>"
        f"<SPEC>{escape(spec)}</SPEC><DRIVER>{escape(driver)}</DRIVER>"
        f"<FIRMINFO>{firm_xml}</FIRMINFO></MODELINFO>"
        "<DRIVERCNT>1</DRIVERCNT><LOGNO>2</LOGNO><ERRBIT></ERRBIT><NEEDRESPONSE>1</NEEDRESPONSE>"
        "</FIRMUPDATEINFO>"
        "</REQUESTINFO>"
    )


def post(xml):
    req = urllib.request.Request(
        URL, data=xml.encode("utf-8"), headers={"Content-Type": "text/xml"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--printer", help="Printer IP address or hostname (PJL port 9100)")
    ap.add_argument("--query-only", action="store_true",
                    help="Read PJL device information only; no vendor query or download")
    ap.add_argument("--name", help="Model name, for example MFC-J5720DW")
    ap.add_argument("--spec", help="Printer SPEC code")
    ap.add_argument("--serial", default="")
    ap.add_argument("--firm", action="append", default=[], metavar="ID=VERSION")
    ap.add_argument("--category", default="MAIN")
    ap.add_argument("-o", "--outdir", default=".")
    ap.add_argument("--dry-run", action="store_true", help="Display the vendor request without sending it")
    ap.add_argument("--force", action="store_true",
                    help="Report an older version when requesting an original firmware download")
    a = ap.parse_args()
    if a.query_only and not a.printer:
        ap.error("--query-only requires --printer")

    info = {"firms": []}
    if a.printer:
        raw = query_printer(a.printer)
        print("--- Printer PJL response ---\n" + raw.strip() + "\n--------------------------------")
        info = parse_brfirmware(raw)
        if a.query_only:
            return
    name = a.name or info.get("name")
    spec = a.spec or info.get("spec", "")
    serial = a.serial or info.get("serial", "")
    firms = [tuple(f.split("=", 1)) for f in a.firm] or info["firms"]
    if not name or not firms:
        sys.exit("Missing model or firmware versions; use --printer or --name/--firm.")

    if a.force:  # Keep the version prefix and use an older date; another prefix can produce an empty response
        firms = [(i, v[0] + "2301010000") for i, v in firms]
    xml = build_request(name, spec, firms, serial, a.category)
    print("Request:", xml)
    if a.dry_run:
        return
    resp = post(xml)
    print("Response:", resp)

    root = ET.fromstring(resp)
    path = root.findtext("FIRMUPDATEINFO/PATH")
    if not path:
        print("No download PATH in response (VERSIONCHECK=%s)."
              % root.findtext("FIRMUPDATEINFO/VERSIONCHECK"))
        return
    fname = path.rstrip("/").rsplit("/", 1)[-1] or "firmware.bin"
    from pathlib import Path
    Path(a.outdir).mkdir(parents=True, exist_ok=True)
    out = str(Path(a.outdir)/fname)
    print("Downloading", path, "->", out)
    with urllib.request.urlopen(path, timeout=300) as r, open(out, "wb") as f:
        while chunk := r.read(1 << 16):
            f.write(chunk)
    print("Saved:", out)


if __name__ == "__main__":
    main()
