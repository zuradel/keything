#!/usr/bin/env python3
"""
Auto keybox hot-swap generator for the rawuaiq ROM (DEVICE/STRONG forge layer).

Public "free" Google attestation keyboxes get REVOKED by Google's CRL fast, and a revoked keybox
silently fails Play-Integrity DEVICE/STRONG. This scrapes the known public keybox feeds, decodes
each (plaintext keybox.xml / base64-wrapped / AES-ECB blob), validates structure + EC priv↔cert
match + CRL revocation, and re-emits the FIRST still-alive keybox in the exact wire format the ROM
reads:  keyb01x.txt = base64( AES/ECB/PKCS5(keybox.xml, "YourSecretKey123") )  (public key, from
PropsKeyboxService.decryptAES). Run by the update-pif action so keyb01x.txt hot-swaps away from a
dead keybox automatically.

Related public projects (all attestation-keybox / Play-Integrity):
  Yurii0307/yurikey        — plaintext keybox.xml feed
  5ec1cff/TrickyStore      — keybox-injection mechanism (users supply keybox.xml)
  KOWX712/PlayIntegrityFix — the autopif fingerprint logic (see gen_safetyfing.py)
"""
import base64
import json
import re
import subprocess
import sys
import urllib.request

AES_KEY = b"YourSecretKey123"  # public, from PropsKeyboxService (AES/ECB/PKCS5Padding)
CRL_URL = "https://android.googleapis.com/attestation/status"
OUT = "keyb01x.txt"

# Public keybox feeds, tried in order. First VALID + UNREVOKED wins.
SOURCES = [
    "https://raw.githubusercontent.com/PhoneChangerOS/google_playIntegrity/refs/heads/main/keyb01x.txt",
    "https://raw.githubusercontent.com/PhoneChangerOS/google_playIntegrity/refs/heads/main/keyb00x.txt",
    "https://raw.githubusercontent.com/Yurii0307/yurikey/main/key",
]

_B64_LINE = re.compile(r"^[A-Za-z0-9+/=]+$")


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def load_crl():
    try:
        entries = json.loads(fetch(CRL_URL))["entries"]
        return {k.lower().lstrip("0") for k in entries}
    except Exception:
        return set()


def openssl(args, stdin):
    return subprocess.run(args, input=stdin, capture_output=True).stdout


def decode_keybox(raw):
    """Return keybox XML str, decoding plaintext / base64-xml / AES-ECB blob. None if undecodable."""
    s = raw.strip()
    if s[:5] == b"<?xml" or s.startswith(b"<AndroidAttestation"):
        return s.decode("utf-8", "replace")
    # base64 wrapper?
    try:
        dec = base64.b64decode(s + b"=" * (-len(s) % 4))
    except Exception:
        dec = b""
    if b"<AndroidAttestation" in dec:
        return dec.decode("utf-8", "replace")
    # AES-ECB/PKCS5 blob (PhoneChangerOS style)
    if dec:
        pt = openssl(["openssl", "enc", "-d", "-aes-128-ecb", "-K", AES_KEY.hex()], dec)
        if b"<AndroidAttestation" in pt:
            return pt.decode("utf-8", "replace")
    return None


def strip_ads(xml):
    return re.sub(r"<!--.*?-->", "", xml, flags=re.S)


def clean_pem(block, label):
    body = "\n".join(x for l in block.splitlines() if (x := l.strip()) and _B64_LINE.match(x))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"


def validate(xml, crl):
    """Return (ok, reason). Checks: has certs, EC priv↔leaf-cert match, no revoked serial."""
    if "<AndroidAttestation" not in xml:
        return False, "not a keybox"
    certs = re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", xml, re.S)
    if not certs:
        return False, "no certificates"
    leaf = clean_pem(certs[0], "CERTIFICATE")
    for block in certs:
        pem = clean_pem(block, "CERTIFICATE")
        out = openssl(["openssl", "x509", "-noout", "-serial"], pem.encode()).decode()
        if "serial=" in out:
            ser = out.split("serial=")[1].strip().lower().lstrip("0")
            if ser in crl:
                return False, f"REVOKED serial {ser}"
    # EC private key must match the leaf (batch-attestation) cert public key
    pm = re.search(r"-----BEGIN ((?:EC )?PRIVATE KEY)-----(.*?)-----END (?:EC )?PRIVATE KEY-----", xml, re.S)
    if not pm:
        return False, "no private key"
    priv = clean_pem(pm.group(2), pm.group(1))
    pub_from_priv = openssl(["openssl", "pkey", "-pubout"], priv.encode())
    pub_from_cert = openssl(["openssl", "x509", "-noout", "-pubkey"], leaf.encode())
    if not pub_from_priv or pub_from_priv.strip() != pub_from_cert.strip():
        return False, "priv/cert mismatch"
    return True, "ok"


def encrypt_wire(xml):
    """keybox.xml -> base64( AES/ECB/PKCS5(xml, key) ) — the ROM's keyb01x.txt format."""
    blob = openssl(["openssl", "enc", "-aes-128-ecb", "-K", AES_KEY.hex()], xml.encode())
    return base64.b64encode(blob).decode()


def main():
    crl = load_crl()
    print(f"[crl] {len(crl)} revoked serials")
    for url in SOURCES:
        try:
            xml = decode_keybox(fetch(url))
        except Exception as e:
            print(f"[skip] {url}: fetch/decode error {e}")
            continue
        if not xml:
            print(f"[skip] {url}: undecodable (unknown encryption)")
            continue
        xml = strip_ads(xml)
        ok, why = validate(xml, crl)
        dev = re.search(r'DeviceID="([^"]*)"', xml)
        dev = dev.group(1) if dev else "?"
        if not ok:
            print(f"[dead] {url}: {dev} -> {why}")
            continue
        with open(OUT, "w") as f:
            f.write(encrypt_wire(xml))
        print(f"[live] {url}: {dev} -> re-encrypted to {OUT}")
        return
    sys.exit("! no live keybox found in any source")


if __name__ == "__main__":
    main()
