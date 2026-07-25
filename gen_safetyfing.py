#!/usr/bin/env python3
"""
Auto-PIF Pixel-Canary fingerprint feed generator (vendored autopif logic, KOWX712/PlayIntegrityFix).

Fetches the LATEST Pixel Canary fingerprint straight from Google (developer.android.com beta device
list + flash.android.com Flash-Station key + content-flashstation-pa.googleapis.com/v1/builds +
source.android.com bulletin) and writes `safetyfing.txt` in the exact 2-line format the rawuaiq ROM
(PropsKeyboxService) parses — same shape as the PhoneChangerOS feed:

    safetyinfo=BRAND/MANUFACTURER/DEVICE/PRODUCT/MODEL/ID/SECURITY_PATCH/DEVICE_INITIAL_SDK_INT/RELEASE
    safetyfing=google/PRODUCT/DEVICE:CANARY/ID/INCREMENTAL:user/release-keys

Run by .github/workflows/update.yml on a schedule so the fingerprint stays current (a stale/beta
print is the usual Play-Integrity BASIC-fail cause).
"""
import json
import re
import sys
import urllib.request

UA = "Mozilla/5.0 (X11; Linux x86_64) rawuaiq-autopif"
FLASH_API = "https://content-flashstation-pa.googleapis.com/v1/builds"
LAUNCH_SDK = 33  # DEVICE_INITIAL_SDK_INT for the cheetah-era canaries (Pixel 7/8 launched 33/34)


def get(url, referer=None):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    if referer:
        req.add_header("Referer", referer)
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def beta_devices():
    versions = get("https://developer.android.com/about/versions")
    latest = sorted(set(re.findall(r"about/versions/(\d+)", versions)), key=int)[-1]
    page = get(f"https://developer.android.com/about/versions/{latest}")
    out, order = {}, []
    for kind in ("download", "download-ota"):
        m = re.search(rf'href="([^"]*{kind}[^"]*qpr[^"]*)"', page) or re.search(rf'href="([^"]*{kind}[^"]*)"', page)
        if not m:
            continue
        html = get("https://developer.android.com" + m.group(1))
        rows = re.findall(r'<tr id="([a-z0-9_]+)">.*?<td>([^<]+)</td>', html, re.S)
        if len(rows) > len(order):
            out = {p + "_beta": mdl.strip() for p, mdl in rows}
            order = [p + "_beta" for p, _ in rows]
    return [(p, out[p]) for p in order], int(latest)


def newest_canary(product, key):
    try:
        raw = get(f"{FLASH_API}?product={product}&key={key}", referer="https://flash.android.com")
        d = json.loads(raw, strict=False)
    except Exception:
        return None
    can = [b for b in d.get("flashstationBuild", []) if b.get("previewMetadata", {}).get("canary")]
    return can[-1] if can else None


def security_patch(canary_id):
    key = re.sub(r"canary-(\d{4})(\d{2})", r"\1-\2", canary_id)
    try:
        html = get("https://source.android.com/docs/security/bulletin/pixel")
        m = re.search(rf"<td>{key}-(\d{{2}})</td>", html)
        return f"{key}-{m.group(1)}" if m else f"{key}-05"
    except Exception:
        return f"{key}-05"


def main():
    m = re.search(r"AIza[A-Za-z0-9_-]+", get("https://flash.android.com"))
    if not m:
        sys.exit("! could not extract Flash Station key")
    flash_key = m.group(0)
    devices, latest = beta_devices()
    devices.sort(key=lambda pm: (pm[0] != "cheetah_beta",))  # cheetah reliably carries canaries
    for product, model in devices:
        b = newest_canary(product, flash_key)
        if not b:
            continue
        device = product.replace("_beta", "")
        rc, inc, cid = b["releaseCandidateName"], b["buildId"], b["previewMetadata"]["id"]
        patch = security_patch(cid)
        fp = f"google/{product}/{device}:CANARY/{rc}/{inc}:user/release-keys"
        info = f"google/Google/{device}/{product}/{model}/{rc}/{patch}/{LAUNCH_SDK}/{latest}"
        with open("safetyfing.txt", "w") as f:
            f.write(f"safetyinfo={info}\n\nsafetyfing={fp}\n")
        print(f"[ok] {model} ({product}) {cid} {rc}/{inc} patch {patch}")
        print(f"safetyfing={fp}")
        return
    sys.exit("! no beta device with a canary build found")


if __name__ == "__main__":
    main()
