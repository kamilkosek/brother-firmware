#!/usr/bin/env python3
"""Verify the observed LZ5014 RSA-2048/SHA-256 update signature offline.

By default the public key is extracted from the file itself. That establishes
internal consistency, not manufacturer authenticity. Supply --reference-key
with a separately trusted DER key to pin the verification key.
No printer access, flashing, private keys or external dependencies are needed.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path

DER_PREFIX=bytes.fromhex('30820122300d06092a864886f70d010101')
SHA256_DIGESTINFO=bytes.fromhex('3031300d060960864801650304020105000420')


def tlv(data,offset,tag):
    if offset+2>len(data) or data[offset]!=tag:raise ValueError('Unexpected DER tag')
    size=data[offset+1];offset+=2
    if size&128:
        count=size&127
        if not 1<=count<=4 or offset+count>len(data):raise ValueError('Invalid DER length')
        size=int.from_bytes(data[offset:offset+count],'big');offset+=count
    end=offset+size
    if end>len(data):raise ValueError('Truncated DER value')
    return data[offset:end],end


def public_numbers(der):
    spki,end=tlv(der,0,0x30)
    if end!=len(der):raise ValueError('Trailing public-key bytes')
    algorithm,at=tlv(spki,0,0x30)
    bits,end=tlv(spki,at,3)
    if end!=len(spki) or not bits or bits[0]!=0:raise ValueError('Invalid public-key bit string')
    rsa,end=tlv(bits,1,0x30)
    if end!=len(bits):raise ValueError('Trailing RSA key bytes')
    modulus,at=tlv(rsa,0,2);exponent,end=tlv(rsa,at,2)
    if end!=len(rsa):raise ValueError('Trailing RSA numbers')
    n=int.from_bytes(modulus,'big');e=int.from_bytes(exponent,'big')
    if n.bit_length()!=2048 or e!=65537:raise ValueError('Unexpected RSA parameters')
    return n,e


def embedded_key(blob):
    offset=blob.find(DER_PREFIX)
    if offset<0 or blob.find(DER_PREFIX,offset+1)>=0:raise ValueError('Expected one RSA public key')
    der=blob[offset:offset+294];public_numbers(der)
    return der,offset


def verify(blob,reference_key=None):
    at=blob.find(b'DATA=',0,256)
    if at<0:raise ValueError('Missing PJL DATA header')
    start=at+5
    if start+0x30>len(blob):raise ValueError('Truncated signed header')
    signed_length=int.from_bytes(blob[start+0x2c:start+0x30],'big')+0x30
    marker=start+signed_length
    if blob[marker:marker+11]!=b'[SIGNATURE]':raise ValueError('Signature marker does not match signed length')
    if marker+16>len(blob):raise ValueError('Truncated signature header')
    version=blob[marker+11];size=int.from_bytes(blob[marker+12:marker+16],'big')
    if version!=0 or size!=256:raise ValueError('Unexpected signature version or size')
    signature=blob[marker+16:marker+16+size]
    if len(signature)!=size:raise ValueError('Truncated signature')
    image_key,key_offset=embedded_key(blob)
    key=image_key if reference_key is None else reference_key
    n,e=public_numbers(key);value=int.from_bytes(signature,'big')
    if value>=n:raise ValueError('RSA signature outside modulus')
    digest=hashlib.sha256(memoryview(blob)[start:marker]).digest()
    recovered=pow(value,e,n).to_bytes(256,'big')
    di=SHA256_DIGESTINFO+digest
    expected=b'\0\x01'+b'\xff'*(256-len(di)-3)+b'\0'+di
    valid=hmac.compare_digest(recovered,expected)
    return dict(signature_valid=valid,algorithm='RSA-2048 PKCS#1 v1.5 / SHA-256',
        signed_start=start,signed_end_exclusive=marker,signed_length=signed_length,
        signature_version=version,signature_size=size,payload_sha256=digest.hex(),
        public_key_offset=key_offset,public_key_sha256=hashlib.sha256(key).hexdigest(),
        reference_key_supplied=reference_key is not None,
        embedded_key_matches_reference=hmac.compare_digest(key,image_key),
        trust_note='Internal consistency only unless the reference key is independently trusted')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('input',type=Path);p.add_argument('--reference-key',type=Path)
    p.add_argument('--report',type=Path)
    a=p.parse_args();report=verify(a.input.read_bytes(),a.reference_key.read_bytes() if a.reference_key else None)
    text=json.dumps(report,indent=2)+'\n';print(text,end='')
    if a.report:a.report.write_text(text)
    raise SystemExit(0 if report['signature_valid'] else 1)
