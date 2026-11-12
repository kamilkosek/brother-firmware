#!/usr/bin/env python3
"""Wrap immutable firmware bytes in an analysis-only ARM big-endian ELF.

This file is not a firmware update and must not be sent to the printer.
"""
import argparse
import struct
from pathlib import Path


def wrap(raw, base, entry_offset=0, thumb=True, seeds=()):
    entry = (base + entry_offset) | int(thumb)
    names = b'\0.text\0.symtab\0.strtab\0.shstrtab\0'
    strings = b'\0$t\0loader\0' if thumb else b'\0$a\0loader\0'
    syms = bytes(16) + struct.pack('>IIIBBH', 1, base, 0, 0, 0, 1)
    syms += struct.pack('>IIIBBH', 4, entry, len(raw)-entry_offset, 0x12, 0, 1)
    for address in seeds:
        if not base<=address<base+len(raw):raise ValueError('Seed outside image')
        name_offset=len(strings)
        strings+=f'seed_{address:x}'.encode()+b'\0'
        syms+=struct.pack('>IIIBBH',name_offset,address|int(thumb),0,0x12,0,1)
    start = 84
    payload = raw + syms + strings + names
    shoff = (start + len(payload) + 3) & ~3
    header = struct.pack('>16sHHIIIIIHHHHHH', b'\x7fELF\x01\x02\x01'+bytes(9),
                         2, 40, 1, entry, 52, shoff, 0x04000000, 52, 32, 1, 40, 5, 4)
    ph = struct.pack('>8I', 1, start, base, base, len(raw), len(raw), 5, 2)
    sections = [(0,)*10, (1,1,6,base,start,len(raw),0,0,2,0),
                (7,2,0,0,start+len(raw),len(syms),3,2,4,16),
                (15,3,0,0,start+len(raw)+len(syms),len(strings),0,0,1,0),
                (23,3,0,0,start+len(raw)+len(syms)+len(strings),len(names),0,0,1,0)]
    return header+ph+payload+bytes(shoff-start-len(payload))+b''.join(struct.pack('>10I',*s) for s in sections)

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('input',type=Path);p.add_argument('output',type=Path)
    p.add_argument('--base',type=lambda s:int(s,0),required=True)
    p.add_argument('--entry-offset',type=lambda s:int(s,0),default=0)
    p.add_argument('--size',type=lambda s:int(s,0))
    p.add_argument('--arm',action='store_true',help='ARM entry rather than Thumb')
    p.add_argument('--seed',action='append',type=lambda s:int(s,0),default=[])
    a=p.parse_args();raw=a.input.read_bytes();raw=raw[:a.size] if a.size else raw
    a.output.write_bytes(wrap(raw,a.base,a.entry_offset,thumb=not a.arm,seeds=a.seed))
