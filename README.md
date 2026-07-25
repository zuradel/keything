# keything

Auto-updated **Play-Integrity fingerprint feed** for the rawuaiq ROM — modeled on
[PhoneChangerOS/google_playIntegrity](https://github.com/PhoneChangerOS/google_playIntegrity), but
self-hosted so we stay independent if that feed stops updating.

## Files

| File | What it is | Refresh |
|------|-----------|---------|
| `safetyfing.txt` | Latest Pixel **Canary** fingerprint (`safetyinfo=` + `safetyfing=` lines) that `PropsKeyboxService` applies to `gms.unstable` for the MEETS_BASIC verdict | **auto** — `.github/workflows/update-pif.yml` runs `gen_safetyfing.py` every 8h |
| `keyb01x.txt` | Keybox for the DEVICE/STRONG forge (Clover), wire format `base64(AES/ECB(keybox.xml,"YourSecretKey123"))` | **auto** — `gen_keybox.py` scrapes public feeds, drops revoked ones (Google CRL), re-emits the first live keybox; runs in the same 8h action |

## How the fingerprint is fetched

`gen_safetyfing.py` pulls the newest Pixel Canary straight from Google (no third party):

1. `developer.android.com/about/versions` → latest Android version → beta device list (products + models)
2. `flash.android.com` → extract the Flash-Station API key (`AIza…`)
3. `content-flashstation-pa.googleapis.com/v1/builds?product=<p>&key=<k>` → newest build where `previewMetadata.canary == true`
4. `source.android.com/.../bulletin/pixel` → security-patch date
5. emit the 2-line feed in the exact format `PropsKeyboxService` parses

## How the keybox stays alive

`gen_keybox.py` scrapes the public keybox feeds (PhoneChangerOS `keyb01x`/`keyb00x`, yurikey),
decodes each (plaintext / base64-wrapped / AES-ECB blob), and validates:

1. structure + EC private-key ↔ leaf-cert match
2. **revocation** against Google's CRL (`android.googleapis.com/attestation/status`)

The first still-alive keybox is re-encrypted to the ROM wire format and written to `keyb01x.txt`.
A revoked keybox silently fails DEVICE/STRONG, so this hot-swaps away from a dead one automatically.
(A valid Google-signed keybox can only be *sourced*, never generated — the auto part is picking a
live one from the public feeds, not minting new ones.)

## Consumed by

rawuaiq ROM `PropsKeyboxService`:
- `SAFETYFING_URL` → `https://raw.githubusercontent.com/zuradel/keything/main/safetyfing.txt`
- `KEYBOX_URL` → `https://raw.githubusercontent.com/zuradel/keything/main/keyb01x.txt`
