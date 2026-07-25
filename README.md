# keything

Auto-updated **Play-Integrity fingerprint feed** for the rawuaiq ROM — modeled on
[PhoneChangerOS/google_playIntegrity](https://github.com/PhoneChangerOS/google_playIntegrity), but
self-hosted so we stay independent if that feed stops updating.

## Files

| File | What it is | Refresh |
|------|-----------|---------|
| `safetyfing.txt` | Latest Pixel **Canary** fingerprint (`safetyinfo=` + `safetyfing=` lines) that `PropsKeyboxService` applies to `gms.unstable` for the MEETS_BASIC verdict | **auto** — `.github/workflows/update-pif.yml` runs `gen_safetyfing.py` every 8h |
| `keyb01x.txt` | Base64 keybox for the DEVICE/STRONG forge (Clover). Static mirror — a valid Google-signed keybox is sourced, not generated | manual |

## How the fingerprint is fetched

`gen_safetyfing.py` pulls the newest Pixel Canary straight from Google (no third party):

1. `developer.android.com/about/versions` → latest Android version → beta device list (products + models)
2. `flash.android.com` → extract the Flash-Station API key (`AIza…`)
3. `content-flashstation-pa.googleapis.com/v1/builds?product=<p>&key=<k>` → newest build where `previewMetadata.canary == true`
4. `source.android.com/.../bulletin/pixel` → security-patch date
5. emit the 2-line feed in the exact format `PropsKeyboxService` parses

## Consumed by

rawuaiq ROM `PropsKeyboxService.SAFETYFING_URL` →
`https://raw.githubusercontent.com/zuradel/keything/main/safetyfing.txt`
