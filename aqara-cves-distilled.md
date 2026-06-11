# Aqara — CVE submission package for runZero

**Researcher:** Sammy Azdoufal (`https://github.com/xn0tsa`)
**Coordinator:** Tod Beardsley / runZero
**Vendor contact:** `security@aqara.com` (in active dialogue since 2026-03-13)
**Disclosure deadline:** **2026-06-11** (90 days from first vendor contact)
**Affected vendor:** Lumi United Technology Co., Ltd. (Shenzhen, China) — brand "Aqara"
**Primary affected product:** Aqara Home Android `com.lumiunited.aqarahome` 6.0.0 + the Aqara cloud platform (`*.aqara.com`, `*.aqara.cn`)

---

## Executive summary

Ten CVEs proposed. Four chain into a **fully unauthenticated takeover of every Aqara device on the platform** (CVE-2026-50082 → CVE-2026-50083 → CVE-2026-50084 → CVE-2026-50085). The other six are independent product flaws (CORS, AES oracle, OAuth redirect handling, hardcoded mobile-SDK keys).

A separate batch of operator-side findings (Odoo CRM open DB manager, Spring Boot Actuator, hardcoded GitHub creds, Discourse forum default config, etc.) is documented in the public-facing repo's `Other findings (no CVE)` section but not proposed for CVE assignment — they are misconfigurations of third-party software hosted by Aqara, not flaws in the Aqara product itself.

**Vendor remediation status: 26 of 27 reported findings (14 Critical + 12 High; H-09 omitted) marked Fixed by Aqara in a written acknowledgment table attached to their April 20, 2026 email** (image reproduced in `DISCLOSURE_TIMELINE.md`). Independent re-test of the Fixed status is pending and will be completed before publication. CVE-2026-50091 (hardcoded mobile-SDK keys) is marked Fixed but the claim is technically improbable without a coordinated firmware + app update across the deployed fleet; flagged for clarification.

The April 20 acknowledgment is the most useful artefact for CVE coordination: it removes any "is this real" debate. Each CVE proposed below maps to a row Aqara explicitly recognised.

---

## The chain (CVE-2026-50082 → CVE-2026-50083 → CVE-2026-50084 → CVE-2026-50085)

```
[CVE-2026-50082] register dev account with any email     → Appid + Keyid
[CVE-2026-50083] test1:123456 grant_type=client_credentials → 57-yr scope=all token
[CVE-2026-50084] MD5 sign + foreign user_id in body      → cross-account API call
[CVE-2026-50085] /board/downstream/api/debug             → MQTT command to any device
```

Each step is reproducible from any internet-connected machine. No physical access, no prior account, no MITM. CVE-2026-50082 alone makes the chain unauthenticated; the other three turn that into device control.

---

# CVE-2026-50082 — Developer portal: account-creation auth code deliverable to any email

**Affected product:** Aqara Cloud Developer Portal (`developer.aqara.com`)
**CWE:** CWE-306 Missing Authentication for Critical Function
**Estimated CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` (**6.5 Medium**)
**Note on score:** Direct-impact only. Standalone, this CVE issues an attacker-controlled developer account; the platform-wide impact comes from chaining with CVE-2026-50083 + CVE-2026-50084 + CVE-2026-50085. CVSS scope is intentionally not S:C here — see `Attacker value` for the chain context.

`POST /open-server/authcode/get` accepts any email address, sends a verification code to that address, and lets the requester complete a developer-account signup with no approval workflow. The resulting account holds a valid `Appid` and `Keyid` that the production API at `open-cn.aqara.com` accepts as authorization to call user-scope endpoints (see CVE-2026-50084).

**Repro:**

```http
POST /open-server/authcode/get HTTP/1.1
Host: developer.aqara.com
Content-Type: application/json

{"email":"attacker@example.com","type":1}
```
→ `HTTP 200, {"code":0,"message":"Success"}`

**Attacker value:** Entry point of the four-step chain. Without it, the rest doesn't reach unauthenticated attackers.

**Vendor status:** Marked **Fixed** in Aqara's April 20 acknowledgment table. Independent re-test pending.

---

# CVE-2026-50083 — Hardcoded OAuth client credentials issue 57-year `scope=all` tokens

**Affected product:** Aqara IAM/SSO gateway (`gw-builder.aqara.com`)
**CWE:** CWE-798 Use of Hard-coded Credentials
**Estimated CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (**9.1 Critical**)
**Note on score:** A:N because token issuance does not directly cause availability impact. Scope U because the IAM gateway is the trust boundary of the issued token.

Two OAuth client credentials are hardcoded in the platform and accepted by `gw-builder.aqara.com`. Both issue tokens with `scope=all`:

| client_id | client_secret | expires_in | active until |
|---|---|---|---|
| `test1` | `123456` | 1799999999 sec | September 2083 |
| `test`  | `123456` | 172799 sec    | 48 hours |

A third client (`app`) exists; its grant_type is unknown. Tokens survive password changes; no rate limiting on issuance.

**Repro:**

```http
POST /iam/oauthToken/openapi/client/token HTTP/1.1
Host: gw-builder.aqara.com
Content-Type: application/x-www-form-urlencoded

client_id=test1&client_secret=123456&grant_type=client_credentials
```
→ `{"access_token":"<uuid>","expires_in":1799999999,"scope":"all"}`

Verify scope via `POST /iam/oauth/check_token` → `{"scope":["all"], "active":true, "exp":3573430446}`.

**Attacker value:** Step 2 of the chain. Provides the bearer needed for any privileged call against the IAM gateway. Combined with CVE-2026-50084, becomes platform-wide read/write.

**Vendor status:** Marked **Fixed** in Aqara's April 20 acknowledgment table. Independent re-test pending.

---

# CVE-2026-50084 — Production API signing scheme accepts any developer Appid for cross-account access

**Affected product:** Aqara Cloud Production API (`open-cn.aqara.com/v3.0/open/api`)
**CWE:** CWE-862 Missing Authorization
**Estimated CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` (**9.6 Critical**)
**Note on score:** PR:L because any developer Appid (legitimately registered or fraudulently obtained via CVE-2026-50082) is sufficient. Scope C because the API authorisation failure crosses from the developer trust boundary into the user-account trust boundary. A:N because the direct read/write impact does not include availability disruption (any device-DoS would be a downstream effect). CWE-862 (rather than CWE-863) because there is no per-user authorization check at all on the targeted resource — not an incorrect check, a missing check.

The production API authenticates each call with an MD5 signature derived from the request:

```
Sign = MD5(
  "Appid"+appid + "Keyid"+keyid +
  "Nonce"+nonce + "Time"+ts +
  "Content-SHA256"+SHA256(body)
).toUpperCase()
```

The signing primitive is sound. The flaw is in **what** it authorizes: any valid developer `Appid` (CVE-2026-50082 issues these for free to any email) is accepted as authorization to call user-scope endpoints against arbitrary user accounts on the platform. There is no per-account ownership check on the targeted resource.

Differential confirmation:
- garbage signature → `code:302` (signature error)
- valid signature math + unknown Appid → `code:2002` (Appid not found)
- valid signature math + real Appid + foreign `user_id`/`email`/`device_id` in body → `code:0`

**Repro:** see worked example in the public-facing README, CVE-2026-50084 section.

**Attacker value:** Step 3 of the chain. Converts an unauthenticated developer registration (CVE-2026-50082) plus a `scope=all` token (CVE-2026-50083) into a full read/write surface against arbitrary Aqara user accounts.

**Vendor status:** Marked **Fixed** in Aqara's April 20 acknowledgment table. Independent re-test pending.

---

# CVE-2026-50085 — Missing authentication on Board IoT device debug API

**Affected product:** Aqara Board service (operations host `193.112.163.150`, also reachable as `op-test.aqara.com`)
**CWE:** CWE-306 Missing Authentication for Critical Function
**Estimated CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L` (**8.6 High**)
**Note on score:** I:H confirmed (broker accepts publish attempts on attacker-supplied topics). C:L because the data exfiltration path requires a separate broker subscribe primitive; not directly observed. A:L because device disruption is plausible but per-topic ACL governs delivery to physical devices — full device control is not proven end-to-end. Scope U because the Board service and the HiveMQ broker are within the same Aqara backend trust boundary. Score may be revised upward (S:C → 9.9) if a worked PoC of unauthenticated device delivery is demonstrated; conservative 8.6 chosen pending that.

`POST /board/downstream/api/debug` accepts arbitrary MQTT command payloads and forwards them to the platform's HiveMQ broker (`172.16.201.20`) without authentication. The companion endpoint `/board/downstream/panel/config/down` shows the same behaviour (`code:0` on POST). The Board service runs as `root` per the Spring Boot Actuator output (operator-side finding) and exposes a `websocket.no.auth = true` flag enabling unauthenticated WebSocket connections at `/board/ws`.

The endpoint had served **18,537 production requests** at the time of the audit.

**Repro:**

```http
POST /board/downstream/api/debug HTTP/1.1
Host: 193.112.163.150
Content-Type: application/json

{"action":"query"}
```
→ `HTTP 200, {"code":0,"message":"success"}`

With a real `topic` and `payload`, the broker accepts a publish attempt (per-topic ACL governs delivery to physical devices).

**Attacker value:** Step 4 of the chain. Direct device command surface for smart locks, cameras, hubs, sensors. Independent of CVE-2026-50084 — does not require an `Appid` or signed request.

**Vendor status:** Independently re-tested as blocked on March 30 (board actuator + debug endpoint both rejecting unauthenticated POSTs). Confirmed Fixed by Aqara in the April 20 acknowledgment table.

---

# CVE-2026-50086 — Unauthenticated AES encrypt/decrypt oracle (ECB mode)

**Affected product:** Aqara IAM/SSO gateway (`gw-builder.aqara.com`)
**CWE:** CWE-306 Missing Authentication for Critical Function, CWE-327 Use of a Broken or Risky Cryptographic Algorithm
**Estimated CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (**7.5 High**)
**Note on score:** CWE-306 (rather than CWE-863) because the oracle endpoints have no authentication at all, not an incorrect authorization check. C:H reflects the ability to decrypt arbitrary captured ciphertexts under the platform key. I:N because forging a ciphertext is possible but the integrity impact depends on which downstream component validates it (varies by use site).

Two endpoints expose bidirectional AES round-trips against the platform's signing key without authentication:

```
POST /iam/oauthToken/aseEncrypt?encryptStr=<plaintext>
POST /iam/oauthToken/aseDecrypt?decryptStr=<base64-ciphertext>
```

ECB mode confirmed: identical 16-byte plaintext blocks produce identical ciphertext blocks. Known ciphertext samples were observed (`admin → o3icZFqAnrbLNYAvMjKpZA==`, `Aqara@2024 → hBFguW5XxndB4Jv1G15CaA==`) and round-trip via the decrypt endpoint.

Combined with CVE-2026-50087 (CORS), the oracle is callable cross-origin from any browser.

**Attacker value:** Allows an attacker to convert any captured ciphertext (cookies, tokens, structured payloads) to plaintext and to forge new ciphertexts under the platform's key. No per-account binding on the oracle.

**Vendor status:** Marked **Fixed** in Aqara's April 20 acknowledgment table. Independent re-test pending.

---

# CVE-2026-50087 — Permissive CORS on production SSO gateway

**Affected product:** Aqara IAM/SSO gateway (`gw-builder.aqara.com`)
**CWE:** CWE-942 Permissive Cross-domain Policy with Untrusted Domains
**Estimated CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` (**8.2 High**)
**Note on score:** UI:R because the victim must visit a malicious page. Scope C because the misconfigured policy lets attacker-origin code reach the IAM trust boundary. I:L (rather than I:H) because the cross-origin reads grant full credential exposure but the integrity actions an attacker can take through the SSO endpoints are limited to what the user is themselves authorised for; for full integrity impact the attacker still needs a follow-on action surface.

Endpoints under `/iam/*` reflect the request's `Origin` header into `Access-Control-Allow-Origin` and set `Access-Control-Allow-Credentials: true`. No origin allowlist.

**Repro:**

```http
POST /iam/ucauth/openapi/login HTTP/1.1
Host: gw-builder.aqara.com
Origin: https://evil.example.com
Content-Type: application/json

{"email":"victim@example.com","password":"x"}
```
→ Response includes `Access-Control-Allow-Origin: https://evil.example.com` and `Access-Control-Allow-Credentials: true`.

Confirmed on `/iam/ucauth/openapi/login`, `/iam/ucauth/sendAuthCode`, `/iam/ucauth/resetPassword`, `/iam/ucauth/toUniAuthUrl/google`, `/iam/oauthToken/aseEncrypt`, `/iam/oauthToken/aseDecrypt`.

**Attacker value:** Any malicious webpage reads SSO responses from the victim's browser session: account oracle results, auth codes, OAuth URLs. Combines naturally with CVE-2026-50086 (cross-origin AES oracle) and CVE-2026-50088 (developer portal CORS).

**Vendor status:** Marked **Fixed** in Aqara's April 20 acknowledgment table. Independent re-test pending.

---

# CVE-2026-50088 — Permissive CORS on developer portal (null origin, GitHub Pages)

**Affected product:** Aqara developer portal (`developer.aqara.com`) and shared test environments (`developer-test.aqara.com`, `aiot-test.aqara.com`)
**CWE:** CWE-942 Permissive Cross-domain Policy with Untrusted Domains
**Estimated CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` (**8.2 High**)
**Note on score:** Same vector as CVE-2026-50087, intentionally — same severity profile. Distinct CVE because it affects a different host group and exposes a different functional surface (developer-portal account creation flow vs. SSO gateway).

Two adjacent CORS misconfigurations:

- `developer.aqara.com/open-server/*`: `Origin: null` and `Origin: https://*.github.io` both reflect into `Access-Control-Allow-Origin: *`. Sandboxed iframes (`<iframe sandbox="allow-scripts">`) issue null-origin requests by default — exploitation is trivial from any web page.
- `developer-test.aqara.com` and `aiot-test.aqara.com`: `Access-Control-Allow-Origin: *` on actual GET/POST responses for any origin. **These test environments share the production user database**: same account-existence oracle (`code:10023` vs `code:10024`) returns identical results.

**Attacker value:** Combined with CVE-2026-50082, any web page can register a developer account in the victim's name (the auth code goes to whatever email the attacker chose) and enumerate developer accounts via the victim's IP.

**Vendor status:** Marked **Fixed** in Aqara's April 20 acknowledgment table. Independent re-test pending.

---

# CVE-2026-50089 — SSO open redirect via `skipToUcAuthUrl`

**Affected product:** Aqara IAM/SSO gateway (`gw-builder.aqara.com`)
**CWE:** CWE-601 URL Redirection to Untrusted Site
**Estimated CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (**6.1 Medium**)

`GET /iam/ucauth/skipToUcAuthUrl?callBackUrl=<URL>` issues an HTTP 302 to the attacker-controlled URL after the user authenticates, carrying SSO parameters in the redirected URL. No allowlist on the `callBackUrl` parameter.

**Repro:**

```bash
curl -i 'https://gw-builder.aqara.com/iam/ucauth/skipToUcAuthUrl?callBackUrl=https://evil.example.com'
# → HTTP 302, Location: https://uc.aqara.com/creator-hub/signin?appId=68&service=https://evil.example.com
```

**Attacker value:** Phishing surface; SSO ticket / auth code leaks to attacker-controlled domain after user consent.

**Vendor status:** Marked **Fixed** in Aqara's April 20 acknowledgment table. Independent re-test pending.

---

# CVE-2026-50090 — OAuth `redirect_uri` validation bypass via suffix match

**Affected product:** Aqara Cloud OAuth authorization endpoint (`open-cn.aqara.com/oauth/authorize`)
**CWE:** CWE-1289 Improper Validation of Unsafe Equivalence in Input
**Estimated CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` (**9.3 Critical**)
**Note on score:** I:H because once the attacker holds the OAuth code they can perform actions on behalf of the victim across the full granted scope — for Aqara, OAuth grants typically include device read and command surfaces. Scope C because the victim's authorization decision crosses into the attacker's trust boundary. If you prefer a more conservative reading where the OAuth scope is narrow (read-only profile), drop to I:L for 8.2 High.

`GET /oauth/authorize` validates the `redirect_uri` parameter by suffix match instead of exact match. Any URL ending in `aqara.com` passes validation, including `https://aqara.com.evil.example.com`. The OAuth authorization code is delivered to the attacker-controlled host after the victim grants consent.

**Repro:**

```
GET https://open-cn.aqara.com/oauth/authorize?
    response_type=code&
    client_id=<valid>&
    redirect_uri=https://aqara.com.evil.example.com&
    state=<state>
```

After user consent, the auth code arrives at `aqara.com.evil.example.com`.

**Attacker value:** Standard OAuth account takeover for any third-party integration that authorizes via Aqara SSO.

**Vendor status:** Marked **Fixed** in Aqara's April 20 acknowledgment table. Independent re-test pending.

---

# CVE-2026-50091 — Hardcoded cryptographic keys in mobile SDK (`liblumidevsdk.so`)

**Affected product:** Aqara Home Android `com.lumiunited.aqarahome` 6.0.0 (and white-label clients embedding the same `liblumidevsdk.so`)
**CWE:** CWE-321 Use of Hard-coded Cryptographic Key
**Estimated CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (**9.1 Critical**)
**Note on score:** I:H because the attacker can forge camera authentication signatures and impersonate device pairing flows once the keys are recovered. Scope U on the conservative reading: the keys are scoped to the mobile SDK + companion firmware, both within the Aqara product trust boundary. An aggressive S:C reading (the keys protect cross-component flows that ought to be independently authorized) would push the score to 10.0; staying at S:U / 9.1 to keep the vector defensible.

Two static cryptographic keys are baked into the native library `liblumidevsdk.so`. Both are recoverable via `strings` from any installation.

| Key | Length | Algorithm | Native callsites |
|---|---|---|---|
| `89JFSjo8HUbhou5776NJOMp9i90ghg7Y78G78t68899y79HY7g7y87y9ED45Ew30O0jkkl` | 68 chars | AES-GCM | `getCameraSign`, `aesEncryptedContent`, `aesDecryptedContent` |
| `Uw4i98shjoeUQdaD` | 16 chars | AES-128 | `getDevicePairMessage` |

Both keys are identical across every install of the app and every white-label build. They control camera authentication signatures, device pairing payloads, and content encryption between client and platform. They cannot be rotated without a coordinated firmware + app update across the entire ecosystem.

**Attacker value:** Forgery of camera authentication signatures, impersonation of device pairing flows, decryption of encrypted content captured from MITM positions.

**Vendor status:** Marked **Fixed** in Aqara's April 20 acknowledgment table. **Claim flagged as technically improbable**: rotating keys baked into `liblumidevsdk.so` (shipped in the Android client) and into the deployed device firmware requires a coordinated firmware + app update across the entire ecosystem, observable from a fresh APK pull and a fresh device fingerprint. A server-side patch alone cannot achieve this. Pending clarification from Aqara on what was actually deployed; assume not effectively fixed until a fresh APK + device verification is completed.

---

## Operator-side findings (NOT proposed for CVE assignment)

These are vendor misconfigurations on Aqara's own infrastructure / third-party deployments, not flaws in the Aqara product itself. Documented in the public-facing repo for completeness, listed here for Tod's awareness (in case any of them is judged CVE-worthy on review):

1. **Odoo CRM Database Manager fully open** — `crm.aqara.com/web/database/manager` (Odoo 10.0 Enterprise / Python 2.7 EOL). Backup, drop, create, restore endpoints unauthenticated.
2. **CRM XMLRPC `admin:admin` superuser** on databases `aqara`, `odoo`, `lumi`, `lumiunited`. Also `admin:Aqara@2024`, `admin:(empty)` on `template1`.
3. **CRM attachment IDOR** — sequential IDs to 1,728,410, 90.7% hit rate, 1.7M+ attachments enumerable unauthenticated.
4. **Spring Boot Actuator fully open** on `op-test.aqara.com:80` (HTTP, bypasses Istio). Leaks K8s topology including MySQL master/slave (`172.16.201.11/19`), Redis (`.118`), RocketMQ (`.144`), HiveMQ (`.20`), Apollo (`.3:18080`), all internal IPs, all credentials.
5. **Op-Test Operations Platform reachable from the public internet** — internal device debugger, OTA management, payment orders dashboard, magic-pair token generator, all reachable.
6. **Discourse forum at `forum.aqara.com` configured without `login_required`** — 194,654 users + 309,373 posts fully searchable via JSON API.
7. **Production API credentials hardcoded in public GitHub repos** `aqara/aqara-iot-app-sdk-python` and `aqara/home-assistant`. Companion repo leaks an `aiot-mqtt-test.aqara.cn:1883` MQTT username/password.
8. **2,942 active OAuth bearer tokens dumpable via single unauthenticated request** — `getAuth2AccessTokens` endpoint. **Mitigated mid-disclosure** (HTTP 500 on known clientIds).
9. **Sixteen third-party API keys hardcoded in the Android client** — Facebook, Google Maps, Google OAuth, Mapbox, Alibaba Push (key+secret), AMap, Tencent QQ, Vivo Push, UMENG, Bugly, Honor Push, Huawei HMS, RM module secret.
10. **Weaver OA leak** — `oa.aqara.com/api/ec/dev/app/getCheckSystemInfo` returns internal IP `172.16.102.15:8999` and enterprise-messaging URL unauthenticated. Weaver Ecology has multiple known public CVEs.

---

## Coordination notes

- Vendor has been on disclosure notice since 2026-04-01 (full report sent), with the 90-day window communicated explicitly in the April 8 email and reiterated in the May 2 email. Disclosure date: **2026-06-11**.
- Vendor invited me to handle CVE assignment independently *or* coordinate with their team. Opening through runZero is the chosen path.
- I will keep `security@aqara.com` informed of the assigned CVE IDs as they materialise.
- Public-facing repository (currently private, will go public on disclosure date): `https://github.com/xn0tsa/aqara-keys-to-the-kingdom`.
- I am available for technical questions, repro session, or revised CVSS/CWE assessments at any point.
