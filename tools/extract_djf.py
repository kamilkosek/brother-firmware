#!/usr/bin/env python3
"""Read-only extractor for the observed LZ5014 P/R ROM0 container layout.

Checks frame offsets, lengths, frame checksums, ROM0 size, compressed sizes,
zlib checksums and expanded RO/RW lengths. Signature verification is a separate tool. Outputs are analysis files, never flashable update files.
"""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path


def field(data,name):
    needle=name.encode()+b'\0'
    at=data[:0x400].find(needle)
    if at<0:raise ValueError(f'Missing header field {name}')
    return struct.unpack_from('>I',data,at+20)[0]


def encode_rom0_frames(logical,frame_sizes):
    """Rebuild only ROM0 framing; this does not generate a signed update."""
    if len(logical)<0x100:raise ValueError('ROM0 header too short')
    initial=struct.pack('>HI',0xa100,0)+logical[:0x100]
    framed=bytearray(b'\xff\x00'+initial)
    checksum=sum(initial)&0xffff
    offset=0x100
    for size in frame_sizes:
        if not 0<size<=0xfff:raise ValueError('Invalid frame size')
        payload=logical[offset:offset+size]
        if len(payload)!=size:raise ValueError('Frame exceeds ROM0')
        body=struct.pack('>HI',0xa000|len(payload),offset)+payload
        framed.extend(struct.pack('>H',checksum)+body)
        checksum=sum(body)&0xffff
        offset+=size
    if offset!=len(logical):raise ValueError('Frame sizes do not cover ROM0')
    framed.extend(struct.pack('>H',checksum))
    return bytes(framed)


def extract(path):
    blob=path.read_bytes()
    if not blob.startswith(b'\x1b%-12345X@PJL EXECUTE BRDOWNLOAD'):
        raise ValueError('Unexpected PJL header')
    start=blob.find(b'header\0\0MAIN')
    if start<0:raise ValueError('Missing MAIN header')
    if blob[start-8:start]!=bytes.fromhex('ff00a10000000000'):
        raise ValueError('Unexpected initial ROM0 frame')
    pos=start+0x100
    logical=bytearray(blob[start:pos]);frames=[]
    expected_checksum=sum(blob[start-6:pos])&0xffff
    while pos+8<=len(blob):
        checksum,tag,offset=struct.unpack_from('>HHI',blob,pos)
        if checksum!=expected_checksum:
            raise ValueError(f'Frame checksum mismatch at {pos:#x}')
        if tag>>12!=0xa:break
        size=tag&0xfff
        if not size or offset!=len(logical) or pos+8+size>len(blob):
            raise ValueError(f'Invalid frame at {pos:#x}')
        frames.append(dict(file_offset=pos,logical_offset=offset,size=size,checksum=checksum))
        expected_checksum=sum(blob[pos+2:pos+8+size])&0xffff
        logical.extend(blob[pos+8:pos+8+size]);pos+=8+size
    if len(logical)!=field(logical,'Rom0Size'):
        raise ValueError('ROM0 size mismatch')
    firmware_checksum=sum(logical[:-2])&0xffff
    if int.from_bytes(logical[-2:],'big')!=firmware_checksum:
        raise ValueError('ROM0 firmware checksum mismatch')
    if encode_rom0_frames(logical,[f['size'] for f in frames])!=blob[start-8:pos+2]:
        raise ValueError('ROM0 framing round-trip mismatch')
    cursor=field(logical,'PrgInfoSize')+0x100
    streams=[]
    for label,size_field,address_field in [('ro','ROsize','ROstart'),('rw','RWsize','RWstart')]:
        length=struct.unpack_from('>I',logical,cursor)[0];cursor+=4
        packed=logical[cursor:cursor+length]
        if len(packed)!=length:raise ValueError('Truncated compressed stream')
        dec=zlib.decompressobj();raw=dec.decompress(packed,64*1024*1024)
        if not dec.eof or dec.unused_data or dec.unconsumed_tail:
            raise ValueError('Incomplete or oversized zlib stream')
        if len(raw)!=field(logical,size_field):raise ValueError('Expanded size mismatch')
        streams.append((label,raw,dict(offset=cursor,compressed_size=length,
                       expanded_size=len(raw),load_address=field(logical,address_field),
                       sha256=hashlib.sha256(raw).hexdigest())))
        cursor+=length
    report=dict(input=str(path),sha256=hashlib.sha256(blob).hexdigest(),rom0_file_start=start,
                rom0_file_end=pos,rom0_size=len(logical),frame_count=len(frames),
                frame_checksums_verified=True,signature_verified=False,
                framing_roundtrip_exact=True,
                rom0_checksum_verified=True,firmware_checksum=f'{firmware_checksum:04X}',
                streams={label:info for label,raw,info in streams},frames=frames)
    return logical,streams,report

if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('input',type=Path);ap.add_argument('output',type=Path)
    a=ap.parse_args();logical,streams,report=extract(a.input)
    a.output.mkdir(parents=True,exist_ok=True)
    (a.output/'rom0.bin').write_bytes(logical)
    for label,raw,info in streams:(a.output/f'{label}.bin').write_bytes(raw)
    (a.output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='frames'},indent=2))
