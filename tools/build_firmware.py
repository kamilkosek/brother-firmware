#!/usr/bin/env python3
"""Build custom 0.3 counter-control firmware offline; never sends it."""
import argparse
import hashlib
import importlib.util
import shutil
import json
import os
import re
from pathlib import Path
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SRC = ROOT/'src'
PROFILE = ROOT/'profiles/mfc-j5720dw-r'
sys.path.insert(0, str(HERE.parent))
from repack_counter_candidate import rebuild
from make_counter_candidate import SOURCE_SHA256

FLASH = 0x08e00000
ROM0 = 0x08020000
RO = 0x40037000
HOOK = 0x406efc00


def run(args, **kwargs):
    subprocess.run([str(x) for x in args], check=True, **kwargs)


def payload_from_elf(data):
    if data[:7] != b'\x7fELF\x01\x02\x01' or struct.unpack_from('>H',data,18)[0] != 40:
        raise ValueError('Wrong payload ELF architecture/byte order')
    entry, phoff = struct.unpack_from('>II',data,24)
    flags = struct.unpack_from('>I',data,36)[0]
    phsize, phcount = struct.unpack_from('>HH',data,42)
    if not entry & 1 or flags & 0x00800000:
        raise ValueError('Payload must use Thumb entry and BE32 instructions')
    regions=[]
    for i in range(phcount):
        kind,off,addr,paddr,size,memsize,permissions,align=struct.unpack_from('>8I',data,phoff+i*phsize)
        if kind != 1 or not size:
            continue
        if addr < FLASH or addr+memsize > 0x08f00000:
            raise ValueError('Payload segment outside its reserved flash window')
        if memsize != size or permissions & 2:
            raise ValueError('Payload must not require writable RAM/BSS initialization')
        regions.append((addr,data[off:off+size]))
    if not regions or not FLASH <= (entry & ~1) < max(a+len(b) for a,b in regions):
        raise ValueError('Missing payload load segments/entry')
    blob=bytearray(b'\xff'*(max(a+len(b) for a,b in regions)-FLASH))
    for addr,part in regions:
        blob[addr-FLASH:addr-FLASH+len(part)]=part
    return bytes(blob),entry


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--zig',type=Path,help='Zig 0.13.0 executable; otherwise use PATH or the ziglang package')
    p.add_argument('--source',type=Path,default=ROOT/'inputs/LZ5014_R.djf')
    p.add_argument('--output',type=Path,default=ROOT/'build/control')
    p.add_argument('--installed-firmware',required=True,help='Exact version currently reported by the printer, e.g. R2401191337:F58C')
    a=p.parse_args()
    profile=json.loads((PROFILE/'profile.json').read_text())
    if profile['source_sha256']!=SOURCE_SHA256:p.error('Profile and compiled source-hash guard disagree')
    if a.zig is None:
        found=shutil.which('zig')
        module=importlib.util.find_spec('ziglang') if not found else None
        a.zig=Path(found) if found else (Path(module.origin).parent/'zig' if module and module.origin else None)
    if a.zig is None or not a.zig.is_file():p.error('Zig 0.13.0 is required; install requirements-dev.txt or pass --zig')
    if subprocess.run([str(a.zig),'version'],check=True,capture_output=True,text=True).stdout.strip()!='0.13.0':p.error('This target is pinned to Zig 0.13.0')
    if not re.fullmatch(r'R2401191337:[0-9A-F]{4}',a.installed_firmware):p.error('The installed version must belong to the supported R2401191337 family')
    if not a.source.is_file():p.error('Original firmware missing; place your own exact R image in inputs/ or use --source')
    a.output.mkdir(parents=True,exist_ok=True)
    linker=a.output/'payload.ld'
    linker.write_text('''ENTRY(cfw_status_renderer)
SECTIONS {
  . = 0x08e00000;
  .text : { *(.text*) }
  .rodata : { *(.rodata*) }
  .ARM.exidx : { *(.ARM.exidx*) }
  /DISCARD/ : { *(.comment) *(.ARM.attributes) }
}
''')
    elf=a.output/'control-payload.elf'
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str((ROOT/'build/zig-global').resolve()),
             ZIG_LOCAL_CACHE_DIR=str((ROOT/'build/zig-local').resolve()))
    run([a.zig,'cc','-target','thumbeb-freestanding-eabi','-mcpu=arm926ej_s',
         '-mthumb','-ffreestanding','-fno-builtin','-fno-stack-protector',
         '-Wall','-Wextra','-Werror','-O2','-nostdlib','-Wl,-T,'+str(linker),
         '-Wl,--entry=cfw_status_renderer',
         '-Wl,-u,cfw_count_based_sensor',
         SRC/'control_payload.c',SRC/'native_backend.c',SRC/'web_request.c',SRC/'native_level_model.c',
         '-o',elf],env=env)
    unresolved=subprocess.run(['nm','-u',str(elf)],check=True,text=True,capture_output=True).stdout.strip()
    if unresolved:raise ValueError('Unresolved payload symbols: '+unresolved)
    blob,entry=payload_from_elf(elf.read_bytes())
    symbol_lines=subprocess.run(['nm','-g',str(elf)],check=True,text=True,capture_output=True).stdout.splitlines()
    sensor_symbols=[int(line.split()[0],16) for line in symbol_lines if line.split()[-1:]==['cfw_count_based_sensor']]
    if len(sensor_symbols)!=1 or not sensor_symbols[0]&1:raise ValueError('Missing Thumb sensor entry')
    sensor_entry=sensor_symbols[0]
    changed_ro=None

    def transform(ro):
        nonlocal changed_ro
        offset=HOOK-RO
        if ro[offset:offset+4] != bytes.fromhex('406ef197'):
            raise ValueError('Status callback differs from the reviewed R firmware')
        changed_ro=bytearray(ro)
        changed_ro[offset:offset+4]=entry.to_bytes(4,'big')
        sensor_at=0x402a47e2-RO
        before=bytes.fromhex('b5380004f13df8121c43')
        if ro[sensor_at:sensor_at+10]!=before:raise ValueError('Unexpected original near-sensor entry')
        veneer=bytes.fromhex('4b01471846c0')+sensor_entry.to_bytes(4,'big')
        changed_ro[sensor_at:sensor_at+10]=veneer
        return bytes(changed_ro), {'feature':'authenticated-counter-calibration-and-count-based-near-source',
            'hook':hex(HOOK),'before':'406ef197','after':f'{entry:08x}',
            'sensor_hook':{'address':'0x402a47e2','before':before.hex(),'after':veneer.hex(),'entry':hex(sensor_entry)},
            'payload_address':hex(FLASH),'payload_size':len(blob),
            'payload_sha256':hashlib.sha256(blob).hexdigest()}

    def append_payload(logical):
        footer=logical[-27:]
        prefix=logical[:-27]
        target=FLASH-ROM0
        if len(prefix)>target:raise ValueError('No flash space for control payload')
        return prefix+b'\xff'*(target-len(prefix))+blob+footer

    data,report=rebuild(a.source,ro_transform=transform,logical_transform=append_payload)
    report['status']='offline-validated-custom-control-candidate'
    report['features']={'visible_custom_firmware_label':True,'read_only_counter_panel':False,
        'authenticated_post_validation':True,'web_counter_editing':True,
        'new_counter_write_code_present':True,'count_based_near_source':True,
        'raw_adc_diagnostic_sample_preserved':True,'single_color_commit':True,
        'write_readback_verification':True,'rollback_on_failure':True}
    report['required_installed_firmware']=a.installed_firmware
    report['profile_id']='mfc-j5720dw-r'
    report['output_file']='firmware.bin'
    report['source_code_language']='English'
    report['code_patch']['counter_only_ro_sha256']=report['code_patch'].pop('candidate_ro_sha256')
    report['code_patch']['candidate_ro_sha256']=hashlib.sha256(changed_ro).hexdigest()
    report['limitations']=[
        'Original German-language control build was reported working by its operator; this English rebuild has not been tested on hardware',
        'Changes real total/sensor counters and the selected native near-state mirrors',
        'Near detection deliberately follows total consumption rather than the optical near sensor',
        'Transactions block native printer starts; power-loss atomicity is not provided',
        'Only one explicitly selected color and targets 1..100 are accepted',
        'Existing EMPTY suppression is retained; sensor/cartridge gates can still block printing',
        'No upload was performed by this build tool']
    report['code_patch']['limitations']=report['limitations']
    (a.output/'firmware.bin').write_bytes(data)
    (a.output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'firmware':report['candidate_firmware'],
        'size':len(data),'sha256':report['output_sha256'],'payload_entry':hex(entry),
        'sensor_entry':hex(sensor_entry),'counter_editing':True},indent=2))


if __name__=='__main__':
    main()
