#!/usr/bin/env python3
"""Inspect the prepared candidate; --send explicitly performs a real transfer.

No automatic retries: a transport failure can occur after the printer received
part of the data. A successful transfer alone does not prove flash completion.
"""
import argparse
import hashlib
import json
import socket
import sys
from datetime import datetime,timezone
from pathlib import Path
from inspect_legacy_update import crc16

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
from firmware_download import query_printer,parse_brfirmware
from make_counter_candidate import SOURCE_SHA256


def load_candidate(directory):
    manifest=json.loads((directory/'manifest.json').read_text())
    filename=manifest.get('output_file','firmware.bin')
    if Path(filename).name!=filename:raise ValueError('Manifest output must be a plain filename')
    data=(directory/filename).read_bytes()
    if len(data)!=manifest['output_size'] or hashlib.sha256(data).hexdigest()!=manifest['output_sha256']:
        raise ValueError('Candidate hash or size differs from reviewed manifest')
    if manifest.get('profile_id')!='mfc-j5720dw-r':raise ValueError('Unexpected build profile')
    if not manifest.get('required_installed_firmware'):raise ValueError('Missing installed-version guard')
    if manifest['original_sha256']!=SOURCE_SHA256:raise ValueError('Unexpected source firmware')
    definitions=json.loads((HERE.parent/'profiles/mfc-j5720dw-r/legacy-download-prefixes.json').read_text())
    prefix=definitions['prefix'].encode('ascii')+bytes.fromhex(definitions['variants'][0]['bytes_hex'])
    if not data.startswith(prefix) or len(prefix)!=47:raise ValueError('Unexpected legacy prefix')
    body=memoryview(data)[len(prefix):]
    if bytes(body[:32]).split(b'\0')[0]!=b'8CA-U29-001':raise ValueError('Wrong model code')
    if int.from_bytes(body[44:48],'big')+48!=len(body):raise ValueError('Body length mismatch')
    if int.from_bytes(body[32:34],'big')!=crc16(body[34:]):raise ValueError('Body CRC mismatch')
    for name in ['re_extraction_matches_patch','rw_unchanged','rom1_unchanged','frame_checksums','rom0_checksum','legacy_crc']:
        if manifest['validation'].get(name) is not True:raise ValueError('Required offline check missing: '+name)
    return data,manifest


def preflight(host, expected_firmware='R2401191337:F58C'):
    info=parse_brfirmware(query_printer(host,timeout=5))
    if info.get('name')!='MFC-J5720DW' or info.get('spec')!='0003' or ('FIRM',expected_firmware) not in info['firms']:
        raise ValueError('Unexpected printer or firmware; no candidate sent')
    return {'name':info['name'],'spec':info['spec'],'firms':info['firms']}


def send_candidate(host,data,progress):
    sent=0;received=b''
    try:
        with socket.create_connection((host,9100),timeout=10) as stream:
            stream.settimeout(20)
            view=memoryview(data)
            while sent<len(data):
                count=stream.send(view[sent:sent+65536])
                if count<=0:raise OSError('Connection stopped accepting data')
                sent+=count
                progress['bytes_sent']=sent
            stream.shutdown(socket.SHUT_WR)
            stream.settimeout(5)
            try:received=stream.recv(4096)
            except socket.timeout:progress['response_timeout']=True
        progress['transfer_completed']=True
    except Exception as error:
        progress['transfer_completed']=False
        progress['error']=f'{type(error).__name__}: {error}'
        raise
    finally:
        progress['response_hex']=received.hex()
        progress['utc_end']=datetime.now(timezone.utc).isoformat()

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('candidate_directory',type=Path)
    p.add_argument('--host',help='Printer address; required with --send')
    p.add_argument('--send',action='store_true')
    p.add_argument('--report',type=Path)
    a=p.parse_args()
    if a.send and (not a.host or not a.report):p.error('--send requires --host and --report')
    data,manifest=load_candidate(a.candidate_directory)
    report={'host':a.host,'candidate_sha256':manifest['output_sha256'],'candidate_size':len(data),
        'expected_firmware':manifest['candidate_firmware'],'send_requested':a.send,
        'utc_start':datetime.now(timezone.utc).isoformat(),'bytes_sent':0,'flash_completion_verified':False}
    try:
        if a.send:
            if not a.report:p.error('--send requires --report')
            report['preflight']=preflight(a.host,manifest['required_installed_firmware'])
            a.report.parent.mkdir(parents=True,exist_ok=True)
            a.report.write_text(json.dumps(report,indent=2)+'\n')
            send_candidate(a.host,data,report)
    finally:
        rendered=json.dumps(report,indent=2)+'\n'
        if a.report:a.report.write_text(rendered)
        print(rendered,end='')
