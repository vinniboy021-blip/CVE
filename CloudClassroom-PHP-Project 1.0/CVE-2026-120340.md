# CloudClassroom-PHP-Project 1.0 — Session cookie without security flags + improper logout

| Field | Value |
|-------|-------|
| **Internal ID** | CC-2026-24 |
| **Product** | CloudClassroom-PHP-Project 1.0 |
| **Vendor** | Vishal Mathur (`mathurvishal`) |
| **File(s)** | `(global session configuration)`, `logoutadmin.php`, `logoutfaculty.php`, `logoutstudent.php` |
| **Class** | Session Management Weaknesses |
| **CWE** | CWE-1004: Sensitive Cookie Without HttpOnly, CWE-1275: Sensitive Cookie with Improper SameSite, CWE-614: Sensitive Cookie Without Secure, CWE-613: Insufficient Session Expiration |
| **OWASP** | A07:2021 – Identification and Authentication Failures |
| **Method / Parameter(s)** | GET/POST — `PHPSESSID (cookie)` |
| **Authentication** | None |
| **User Interaction** | Required (chaining with XSS/CSRF) |
| **CVSS v3.1** | **5.4 (Medium)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` |
| **EPSS** | N/A — low estimate. |
| **Public Status** | Novel |

---

## 1. Executive Summary

Session cookie is issued without `HttpOnly`/`SameSite`/`Secure` (amplifies XSS and CSRF). Logout contains `==` bug (comparison vs assignment) and never calls `session_destroy()`/`session_regenerate_id()`; ID remains valid after 'logout'.

## 2. Preconditions

Amplifier — impact materializes chained with XSS (item 03+) and CSRF (item 23).

## 3. Code Analysis (Root Cause)

**`logoutadmin.php`**

```php
session_start();
$_SESSION["umail"]=="";   // BUG: '==' is comparison; zeros nothing
session_unset('umail');    // session_unset() ignores arguments
header('Location:index.php'); // no session_destroy(); ID preserved
```

## 4. Step-by-Step Exploitation

1. Request page with `session_start()` (e.g., welcomeadmin.php) and inspect `Set-Cookie` header.
2. Confirm absence of `HttpOnly`, `SameSite`, `Secure`.
3. Steal cookie via stored XSS (`document.cookie`) — possible due to missing HttpOnly.
4. Confirm logout does not invalidate session (no `session_destroy`).

## 5. Proof of Concept (PoC)

Executable and non-destructive script: **`poc.sh`** (usage: `bash poc.sh [http://target:port]`).

```bash
curl -s -i http://192.168.95.131:9292/welcomeadmin.php | grep -i "set-cookie"
# -> Set-Cookie: PHPSESSID=...; path=/   (no HttpOnly/SameSite/Secure)
```

**Evidence observed in lab (http://192.168.95.131:9292/):**

```
Set-Cookie: PHPSESSID=...; path=/  → HttpOnly ABSENT, SameSite ABSENT, Secure ABSENT.
```

### 5.1 Visual Evidence (live re-validation on 2026-08-02)

Attack reproduced live against http://192.168.95.131:9292/ in a non-destructive manner (reads/error-based, and state injections with automatic value restoration).

**a) Execution in browser** — real server response rendered in Chromium, with evidence band (request + payload + verdict):

<img width="1180" height="886" alt="evidencia-web-24-session-cookie-logout" src="https://github.com/user-attachments/assets/b495b91e-0623-462a-b229-7ad1cba783fc" />

**b) Vulnerable code line** — source code snippet with sink highlighted (`(global session configuration)`):

<img width="2360" height="920" alt="evidencia-codigo-24-session-cookie-logout" src="https://github.com/user-attachments/assets/fcb45a36-6944-443f-b56e-96d4f8a2888a" />

## 6. Impact

Session theft via XSS (HttpOnly absent); CSRF facilitation (SameSite absent); sessions not terminated.

## 7. Severity Assessment (CVSS v3.1)

Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` — **Base 5.4 (Medium)**

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | None (N) |
| User Interaction (UI) | Required (R) |
| Scope (S) | Unchanged (U) |
| Confidentiality (C) | Low (L) |
| Integrity (I) | Low (L) |
| Availability (A) | None (N) |

**EPSS:** N/A — low estimate.

## 8. Remediation

- `session_set_cookie_params(['httponly'=>true,'secure'=>true,'samesite'=>'Strict'])` before `session_start()`.
- `session_regenerate_id(true)` on login; on logout: `$_SESSION=[]; session_unset(); session_destroy();`

## 9. Novelty / Duplication Check

No known CVE covering these session weaknesses.

## 10. References

- https://cwe.mitre.org/
- https://www.first.org/cvss/calculator/3.1
- https://cvefeed.io/vuln/product/161371/vishalmathurcloudclassroom-php_project/

## 11. Timeline

- 2026-08-02 — Discovery (static analysis) and dynamic lab confirmation.
- 2026-08-02 — Disclosure package preparation (this report).

---
- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
