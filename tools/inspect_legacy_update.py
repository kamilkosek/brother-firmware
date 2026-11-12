#!/usr/bin/env python3
"""Offline checks for the observed legacy download path. Does not send data.

The parser and CRC checks below model recovered static code. Passing these
checks does not prove that a live printer enables or accepts this update path.
"""
import argparse
import hashlib
import json
from pathlib import Path
from verify_update_signature import verify


def crc_table():
    values=[]
    for byte in range(256):
        value=byte
        for _ in range(8):value=(value>>1)^(0x8408 if value&1 else 0)
        values.append(value)
    return tuple(values)

TABLE=crc_table()


def crc16(data,state=0):
    for byte in data:state=(state>>8)^TABLE[(state^byte)&0xff]
    return state


def inspect(blob):
    signature=verify(blob)
    body=memoryview(blob)[signature['signed_start']:signature['signed_end_exclusive']]
    model=bytes(body[:0x20]).split(b'\0',1)[0].decode('ascii')
    stored=int.from_bytes(body[0x20:0x22],'big')
    calculated=crc16(body[0x22:])
    residue=crc16(bytes([body[0x21],body[0x20]]),calculated)
    return dict(original_signature_valid=signature['signature_valid'],
        legacy_body_start=signature['signed_start'],legacy_body_end_exclusive=signature['signed_end_exclusive'],
        legacy_body_size=len(body),legacy_body_sha256=hashlib.sha256(body).hexdigest(),
        model_code=model,model_in_observed_static_tables=model in ['8CA-U29-001','8CA-U29-002'],
        stored_crc16=hex(stored),calculated_crc16=hex(calculated),legacy_crc_residue=hex(residue),
        legacy_crc_valid=residue==0,crc_polynomial_reflected='0x8408',crc_initial_value=0,
        live_path_verified=False,signature_gate_absent_in_observed_legacy_flash_routine=True,
        limitations=['State-machine reachability and live transport acceptance are not verified',
                     'Static model tables are initial values, not a live RAM observation',
                     'No update, print job or flash command has been sent'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('input',type=Path)
    p.add_argument('--report',type=Path);a=p.parse_args()
    text=json.dumps(inspect(a.input.read_bytes()),indent=2)+'\n';print(text,end='')
    if a.report:a.report.write_text(text)
