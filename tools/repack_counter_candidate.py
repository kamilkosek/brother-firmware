#!/usr/bin/env python3
"""Build and verify the R counter patch for the observed legacy update path.

Offline only: never connects to a printer. The output is an untested legacy
transport candidate, not an official signed update. Reconstructs all observed
length/checksum layers and independently extracts the rebuilt container before
publishing the candidate. Exact original R input is required.
"""
import argparse
import hashlib
import json
import re
import struct
import tempfile
import zlib
from pathlib import Path
from extract_djf import extract,encode_rom0_frames
from make_counter_candidate import candidate,SOURCE_SHA256
from verify_update_signature import verify
from inspect_legacy_update import inspect as inspect_legacy,crc16

HERE=Path(__file__).resolve().parent


def sha(data):return hashlib.sha256(data).hexdigest()


def update_header_field(logical,name,value):
    off=logical[:0x400].find(name.encode()+b'\0')
    if off<0:raise ValueError('Missing logical header field '+name)
    struct.pack_into('>I',logical,off+20,value)


def update_ascii_pair(blob,name,delta):
    pattern=re.escape(name.encode())+rb' = ([0-9a-f]{16})'
    hits=list(re.finditer(pattern,blob[:0x236]))
    if len(hits)!=1:raise ValueError('Missing or repeated flash header '+name)
    match=hits[0];encoded=match.group(1)
    value=int(encoded[:8],16);inverse=int(encoded[8:],16)
    if value^inverse!=0xffffffff:raise ValueError('Complement mismatch in '+name)
    value+=delta
    if not 0<=value<=0xffffffff:raise ValueError('Flash-header integer overflow')
    replacement=f'{value:08x}{value^0xffffffff:08x}'.encode()
    blob[match.start(1):match.end(1)]=replacement
    return value


def rebuild(source, ro_transform=None, logical_transform=None):
    original=source.read_bytes()
    if sha(original)!=SOURCE_SHA256:raise ValueError('Exact original R firmware required')
    sig=verify(original)
    if not sig['signature_valid']:raise ValueError('Original signature invalid')
    logical,streams,layout=extract(source)
    patched_ro,patch_report=candidate(source)
    if ro_transform is not None:
        patched_ro, extra_report = ro_transform(patched_ro)
        patch_report['additional_changes'] = extra_report
    stream_map={label:(raw,info) for label,raw,info in streams}
    ro_info=stream_map['ro'][1]
    compressor=zlib.compressobj(level=9,wbits=13)
    packed=compressor.compress(patched_ro)+compressor.flush()
    old_end=ro_info['offset']+ro_info['compressed_size']
    new_logical=bytearray(logical[:ro_info['offset']-4]+struct.pack('>I',len(packed))+packed+logical[old_end:])
    if logical_transform is not None:
        new_logical = bytearray(logical_transform(new_logical))
    update_header_field(new_logical,'Rom0Size',len(new_logical))
    checksum=sum(new_logical[:-2])&0xffff
    new_logical[-2:]=checksum.to_bytes(2,'big')
    if new_logical[-27:-7]!=b'MFC-J572USAProgramOK':raise ValueError('Unexpected ROM0 trailer')
    if 0x08020000+len(new_logical)>0x09600000:raise ValueError('ROM0 overlaps ROM1 flash address')
    sizes=[];remaining=len(new_logical)-27-0x100
    while remaining:
        size=min(remaining,0xfff);sizes.append(size);remaining-=size
    sizes.append(27)
    new_frames=encode_rom0_frames(new_logical,sizes)
    frame_start=layout['rom0_file_start']-8
    frame_end=layout['rom0_file_end']+2
    delta=len(new_frames)-(frame_end-frame_start)
    rebuilt=bytearray(original[:frame_start]+new_frames+original[frame_end:])
    rom1_relative=update_ascii_pair(rebuilt,'UpdRom1Offset',delta)
    file_size=update_ascii_pair(rebuilt,'UpdProgramFileSize',delta)
    start=sig['signed_start'];end=sig['signed_end_exclusive']+delta
    for relative in [0x1c,0x2c]:
        old=int.from_bytes(original[start+relative:start+relative+4],'big')
        rebuilt[start+relative:start+relative+4]=(old+delta).to_bytes(4,'big')
    pjl=list(re.finditer(rb'PROGRAMLENG=([0-9a-f]{8})',rebuilt[:start]))
    if len(pjl)!=1:raise ValueError('Unexpected PJL length field')
    old_length=int(pjl[0].group(1),16)
    rebuilt[pjl[0].start(1):pjl[0].end(1)]=f'{old_length+delta:08x}'.encode()
    crc=crc16(memoryview(rebuilt)[start+0x22:end])
    rebuilt[start+0x20:start+0x22]=crc.to_bytes(2,'big')
    # Re-read the rebuilt package using the independent parser and signature checker.
    with tempfile.TemporaryDirectory(prefix='brother-repack-check-') as td:
        check_path=Path(td)/'repacked.djf';check_path.write_bytes(rebuilt)
        checked_logical,checked_streams,checked_layout=extract(check_path)
    checked_map={label:raw for label,raw,info in checked_streams}
    if checked_logical!=new_logical:raise ValueError('Re-extracted ROM0 differs from rebuilt ROM0')
    if checked_map['ro']!=patched_ro:raise ValueError('Re-extracted RO differs from candidate')
    if checked_map['rw']!=stream_map['rw'][0]:raise ValueError('RW changed unexpectedly')
    old_rom1=original.find(b'ROM1',layout['rom0_file_end'])
    new_rom1=rebuilt.find(b'ROM1',checked_layout['rom0_file_end'])
    if old_rom1<0 or new_rom1!=old_rom1+delta:raise ValueError('ROM1 offset mismatch')
    if rebuilt[new_rom1:end]!=original[old_rom1:sig['signed_end_exclusive']]:
        raise ValueError('ROM1 changed unexpectedly')
    if start+0x44+rom1_relative!=new_rom1:raise ValueError('Flash-header ROM1 offset mismatch')
    if start+0x44+file_size+1!=end:raise ValueError('Flash-header file size mismatch')
    if int.from_bytes(rebuilt[start+0x2c:start+0x30],'big')+0x30!=end-start:
        raise ValueError('Outer section length mismatch')
    new_sig=verify(rebuilt)
    if new_sig['signature_valid']:raise ValueError('Modified data unexpectedly retains original signature')
    legacy=inspect_legacy(rebuilt)
    if not legacy['legacy_crc_valid'] or not legacy['model_in_observed_static_tables']:
        raise ValueError('Legacy CRC or model check failed')
    definitions=json.loads((HERE.parent/'profiles/mfc-j5720dw-r/legacy-download-prefixes.json').read_text())
    prefix=definitions['prefix'].encode('ascii')+bytes.fromhex(definitions['variants'][0]['bytes_hex'])
    if len(prefix)!=47:raise ValueError('Unexpected legacy prefix length')
    body=bytes(rebuilt[start:end])
    output=prefix+body
    report=dict(status='offline-validated-legacy-candidate',hardware_tested=False,
        live_update_path_verified=False,official_signed_update=False,
        original_sha256=sha(original),output_sha256=sha(output),output_size=len(output),
        body_sha256=sha(body),prefix_size=len(prefix),container_size_delta=delta,
        code_patch=patch_report,original_firmware='R2401191337:F58C',
        candidate_firmware=f'R2401191337:{checksum:04X}',
        compression={'level':9,'window_bits':13,'zlib_runtime':zlib.ZLIB_RUNTIME_VERSION,
                     'original_ro_size':ro_info['compressed_size'],'candidate_ro_size':len(packed)},
        validation={'re_extraction_matches_patch':True,'rom0_roundtrip_bytes':True,'rw_unchanged':True,'rom1_unchanged':True,
                    'frame_checksums':True,'rom0_checksum':True,'legacy_crc':True,
                    'model_code':legacy['model_code'],'normal_rsa_signature_valid':False,
                    'rom1_relative_offset':rom1_relative,'inner_file_size':file_size},
        limitations=['No live update has been attempted',
                     'Legacy update acceptance is specific to the evaluated model and firmware',
                     'The patch suppresses counter-derived EMPTY only; sensor/chip paths can still block printing',
                     'The low-ink warning is intentionally retained'])
    return output,report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path);p.add_argument('output_directory',type=Path)
    a=p.parse_args();output,report=rebuild(a.source)
    a.output_directory.mkdir(parents=True,exist_ok=True)
    (a.output_directory/'legacy-counter-candidate.research.bin').write_bytes(output)
    (a.output_directory/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
