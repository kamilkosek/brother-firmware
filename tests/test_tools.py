"""Firmware-independent regression tests. No printer or network access."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from firmware_download import parse_brfirmware,build_request
from extract_djf import encode_rom0_frames
from inspect_legacy_update import crc16
from build_firmware import payload_from_elf,FLASH
from transfer_firmware import load_candidate,preflight
from make_counter_candidate import SOURCE_SHA256


def mock_candidate(directory):
    definitions=json.loads((ROOT/'profiles/mfc-j5720dw-r/legacy-download-prefixes.json').read_text())
    prefix=definitions['prefix'].encode()+bytes.fromhex(definitions['variants'][0]['bytes_hex'])
    body=bytearray(96);body[:11]=b'8CA-U29-001\0'
    body[44:48]=(len(body)-48).to_bytes(4,'big')
    body[32:34]=crc16(body[34:]).to_bytes(2,'big')
    data=prefix+body
    flags={x:True for x in ['re_extraction_matches_patch','rw_unchanged','rom1_unchanged','frame_checksums','rom0_checksum','legacy_crc']}
    manifest={'profile_id':'mfc-j5720dw-r','output_file':'firmware.bin','original_sha256':SOURCE_SHA256,
              'output_sha256':hashlib.sha256(data).hexdigest(),'output_size':len(data),
              'required_installed_firmware':'R2401191337:F58C','validation':flags}
    (directory/'firmware.bin').write_bytes(data)
    (directory/'manifest.json').write_text(json.dumps(manifest))
    return data,manifest


def small_elf(*,address=FLASH,permissions=5,memory_size=2,flags=0x05000200,entry=None):
    entry=address|1 if entry is None else entry
    header=struct.pack('>16sHHIIIIIHHHHHH',b'\x7fELF\x01\x02\x01'+bytes(9),2,40,1,
                       entry,52,0,flags,52,32,1,40,0,0)
    ph=struct.pack('>8I',1,84,address,address,2,memory_size,permissions,2)
    return header+ph+b'\x47\x70'


class SourceTests(unittest.TestCase):
    def test_crc_vector(self):
        self.assertEqual(crc16(b'123456789'),0x2189)

    def test_pjl_multiple_firmware_ids(self):
        parsed=parse_brfirmware('MODEL="MFC-J5720DW"\nSPEC="0003"\nSERIAL="REDACTED"\nFIRMID="FIRM"\nFIRMVER="R2401191337:F58C"\n')
        self.assertEqual(parsed['name'],'MFC-J5720DW')
        self.assertEqual(parsed['firms'],[('FIRM','R2401191337:F58C')])

    def test_vendor_request_escapes_untrusted_values(self):
        data=build_request('A&B','<x>',[('FIRM','a&b')])
        self.assertIn('A&amp;B',data)
        self.assertIn('&lt;x&gt;',data)
        self.assertNotIn('<SPEC><x>',data)

    def test_frame_encoder_rejects_wrong_coverage(self):
        with self.assertRaises(ValueError):encode_rom0_frames(bytearray(258),[1])
        with self.assertRaises(ValueError):encode_rom0_frames(bytearray(258),[0])
        with self.assertRaises(ValueError):encode_rom0_frames(bytearray(258),[4096])

    def test_payload_elf_uses_expected_flash_and_thumb(self):
        blob,entry=payload_from_elf(small_elf())
        self.assertEqual(blob,b'\x47\x70')
        self.assertEqual(entry,FLASH|1)

    def test_payload_rejects_writable_or_uninitialized_state(self):
        for kwargs in [{'permissions':7},{'memory_size':4},{'address':FLASH-4096},
                       {'entry':FLASH},{'flags':0x05800200}]:
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):payload_from_elf(small_elf(**kwargs))

    def test_upload_inspection_never_connects(self):
        with tempfile.TemporaryDirectory() as td,patch('transfer_firmware.socket.create_connection') as network:
            p=Path(td);data,manifest=mock_candidate(p)
            self.assertEqual(load_candidate(p)[0],data)
            network.assert_not_called()

    def test_upload_rejects_hash_and_crc_corruption(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);data,manifest=mock_candidate(p)
            changed=bytearray(data);changed[-1]^=1;(p/'firmware.bin').write_bytes(changed)
            with self.assertRaises(ValueError):load_candidate(p)
            manifest['output_sha256']=hashlib.sha256(changed).hexdigest();(p/'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'CRC'):load_candidate(p)

    def test_upload_rejects_missing_guards_or_path_traversal(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);data,base=mock_candidate(p)
            for key,value in [('profile_id','other'),('required_installed_firmware',''),('output_file','../outside.bin')]:
                manifest=dict(base);manifest[key]=value;(p/'manifest.json').write_text(json.dumps(manifest))
                with self.subTest(key=key),self.assertRaises(ValueError):load_candidate(p)

    def test_preflight_requires_exact_model_spec_and_version(self):
        good='MODEL="MFC-J5720DW"\nSPEC="0003"\nFIRMID="FIRM"\nFIRMVER="R2401191337:F58C"\n'
        with patch('transfer_firmware.query_printer',return_value=good):
            self.assertEqual(preflight('printer.example')['name'],'MFC-J5720DW')
            with self.assertRaises(ValueError):preflight('printer.example','R2401191337:39B9')
        for bad in [good.replace('MFC-J5720DW','OTHER'),good.replace('0003','9999')]:
            with patch('transfer_firmware.query_printer',return_value=bad),self.assertRaises(ValueError):preflight('printer.example')

    def test_send_requires_explicit_host_and_report(self):
        result=subprocess.run([sys.executable,str(ROOT/'tools/transfer_firmware.py'),'missing','--send'],text=True,capture_output=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('--send requires --host and --report',result.stderr)

    def test_wrong_source_is_rejected_before_package_output(self):
        from make_counter_candidate import candidate
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'wrong.djf';p.write_bytes(b'wrong source')
            with self.assertRaisesRegex(ValueError,'exact original'):candidate(p)


if __name__=='__main__':unittest.main()
