"""Optional tests using private original images; never accesses a printer."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from extract_djf import extract,encode_rom0_frames
from make_counter_candidate import candidate,ADDRESS,BASE,BEFORE,AFTER,SOURCE_SHA256
from verify_update_signature import verify
from repack_counter_candidate import rebuild

FIRMWARE=Path(os.environ.get('BROTHER_FIRMWARE_DIR',str(ROOT/'inputs')))
R=FIRMWARE/'LZ5014_R.djf'


@unittest.skipUnless(R.is_file(),'Provide the private original R image through BROTHER_FIRMWARE_DIR')
class FirmwareIntegrationTests(unittest.TestCase):
    def test_original_identity_and_signature(self):
        self.assertEqual(hashlib.sha256(R.read_bytes()).hexdigest(),SOURCE_SHA256)
        self.assertTrue(verify(R.read_bytes())['signature_valid'])

    def test_extract_roundtrip(self):
        logical,streams,report=extract(R)
        self.assertEqual([len(raw) for _,raw,_ in streams],[29038256,709124])
        self.assertEqual(encode_rom0_frames(logical,[f['size'] for f in report['frames']]),R.read_bytes()[report['rom0_file_start']-8:report['rom0_file_end']+2])

    def test_only_declared_instruction_changes(self):
        patched,report=candidate(R)
        original=next(raw for name,raw,_ in extract(R)[1] if name=='ro');at=ADDRESS-BASE
        self.assertEqual(original[at:at+2],BEFORE);self.assertEqual(patched[at:at+2],AFTER)
        self.assertEqual(patched[:at],original[:at]);self.assertEqual(patched[at+2:],original[at+2:])

    def test_frame_corruption_rejected(self):
        original=R.read_bytes()
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'bad.djf';bad=bytearray(original);bad[0x5000]^=1;p.write_bytes(bad)
            with self.assertRaises(ValueError):extract(p)

    def test_reframed_rom0_corruption_rejected(self):
        logical,_,report=extract(R);logical[0x20]^=1
        replacement=encode_rom0_frames(logical,[f['size'] for f in report['frames']])
        original=R.read_bytes()
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'bad.djf';p.write_bytes(original[:report['rom0_file_start']-8]+replacement+original[report['rom0_file_end']+2:])
            with self.assertRaisesRegex(ValueError,'ROM0 firmware checksum'):extract(p)

    def test_signature_corruption_rejected(self):
        original=bytearray(R.read_bytes());original[0x5000]^=1
        self.assertFalse(verify(original)['signature_valid'])
        with self.assertRaises(ValueError):verify(original[:-40])

    def test_complete_repacker_roundtrip(self):
        output,report=rebuild(R)
        self.assertEqual(hashlib.sha256(output).hexdigest(),report['output_sha256'])
        self.assertTrue(report['validation']['rom0_roundtrip_bytes'])
        self.assertTrue(report['validation']['rw_unchanged']);self.assertTrue(report['validation']['rom1_unchanged'])
        self.assertFalse(report['validation']['normal_rsa_signature_valid'])

    @unittest.skipUnless((FIRMWARE/'LZ5014_P.djf').is_file(),'Optional private P comparison image not supplied')
    def test_other_revision_rejected(self):
        with self.assertRaises(ValueError):candidate(FIRMWARE/'LZ5014_P.djf')
        self.assertTrue(verify((FIRMWARE/'LZ5014_P.djf').read_bytes())['signature_valid'])


if __name__=='__main__':unittest.main()
