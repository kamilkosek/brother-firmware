#!/usr/bin/env python3
"""Apply the pinned R2401191337 counter-EMPTY instruction patch offline.

Returns an unframed RO image, not an uploadable container. The complete builder
adds framing and the control payload. Other cartridge and fault gates remain.
"""
import argparse
import hashlib
import json
from pathlib import Path
from extract_djf import extract

SOURCE_SHA256='e57db7c645a5add6cfe5a486ad7755de154870cd4f228b63ce4ca7addb822eca'
RO_SHA256='59ec7a5549069485fc33ce17a963de7147600953be37413da792d8114dedaa3f'
ADDRESS=0x403e8434
BASE=0x40037000
BEFORE=bytes.fromhex('0f09') # Thumb: lsrs r1,r1,#28
AFTER=bytes.fromhex('2100')  # Thumb: movs r1,#0


def candidate(source):
    if hashlib.sha256(source.read_bytes()).hexdigest()!=SOURCE_SHA256:
        raise ValueError('Unsupported firmware: exact original R file required')
    logical,streams,report=extract(source)
    raw=next(raw for label,raw,info in streams if label=='ro')
    if hashlib.sha256(raw).hexdigest()!=RO_SHA256:
        raise ValueError('Unexpected extracted RO image')
    offset=ADDRESS-BASE
    if raw[offset:offset+2]!=BEFORE:raise ValueError('Instruction mismatch')
    patched=raw[:offset]+AFTER+raw[offset+2:]
    assert len(patched)==len(raw)
    assert patched[:offset]==raw[:offset] and patched[offset+2:]==raw[offset+2:]
    return patched,dict(status='offline-research-only',flashable=False,hardware_tested=False,
        source_sha256=SOURCE_SHA256,original_ro_sha256=RO_SHA256,
        candidate_ro_sha256=hashlib.sha256(patched).hexdigest(),
        address=hex(ADDRESS),ro_offset=hex(offset),before=BEFORE.hex(),after=AFTER.hex(),
        effect='Force only the dot-count wrapper empty_color output to zero; retain its near_color bits',
        limitations=['The normal signed path remains signed; the complete builder uses the model-specific legacy path',
                     'Other sensor/chip/persistent-state paths can still report empty',
                     'This raw RO image alone is not an update package'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path);p.add_argument('output_directory',type=Path)
    a=p.parse_args();raw,report=candidate(a.source)
    a.output_directory.mkdir(parents=True,exist_ok=True)
    (a.output_directory/'ro-counter-candidate.research.bin').write_bytes(raw)
    (a.output_directory/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
