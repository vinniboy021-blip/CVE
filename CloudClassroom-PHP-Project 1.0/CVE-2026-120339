# CloudClassroom-PHP-Project 1.0 — Stored XSS in updatedetailsfromstudent.php
| Field | Value |
|-------|-------|
| **Internal ID** | CC-2026-34 |
| **Product** | CloudClassroom-PHP-Project 1.0 |
| **Vendor** | Vishal Mathur (`mathurvishal`) |
| **File(s)** | `updatedetailsfromstudent.php` |
| **Class** | Stored / Persistent Cross-Site Scripting |
| **CWE** | CWE-79: Cross-site Scripting |
| **OWASP** | A03:2021 – Injection |
| **Method / Parameter(s)** | POST — `fname`, `lname`, `faname`, `addrs`, `gender`, `course`, `phno`, `email`, `pass` |
| **Authentication** | None to inject (via item 00) |
| **User Interaction** | Required (victim opens page that renders the data) |
| **CVSS v3.1** | **6.1 (Medium)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| **EPSS** | N/A (no CVE) — low estimate. |
| **Public Status** | Novel |

---

## 1. Executive Summary

Fields `fname`, `lname`, `faname`, `addrs`, `gender`, `course`, `phno`, `email`, `pass` are persisted without sanitization and re-displayed in `value="..."` attribute without HTML-encoding. SELF-SERVICE screen of student (eno). FName varchar(30): use short vector (`"><svg onload=alert(1)>`).

## 2. Preconditions

None to inject (item 00). Authenticated victim (admin/faculty) needs to view the record.

## 3. Code Analysis (Root Cause)

**`updatedetailsfromstudent.php`**

```php
<input ... name="fname" value="<?php echo $row[...]; ?>">
```

## 4. Step-by-Step Exploitation

1. Send POST to `updatedetailsfromstudent.php` recording breakout payload in field `fname`.
2. Payload: `"><svg onload=alert(1)>` (breaks value attribute).
3. Re-open the page; payload is reflected WITHOUT encoding and executes.
4. Chain with cookie without HttpOnly (item 24) for admin session theft.

## 5. Proof of Concept (PoC)

Executable and non-destructive script: **`poc.sh`** (usage: `bash poc.sh [http://target:port]`).

```bash
# non-destructive cycle (capture->inject->verify->restore):
python3 ../_lib/xss_poc.py "http://192.168.95.131:9292" "updatedetailsfromstudent.php?..." \
  fname '"><svg onload=alert(1)>' --fields fname,lname,faname,addrs,gender,course,phno,email,pass
```

**Evidence observed in lab (http://192.168.95.131:9292/):**

```
payload reflected WITHOUT encoding: "><svg onload=alert(1)>
```

### 5.1 Visual Evidence (live re-validation on 2026-08-02)

Attack reproduced live against http://192.168.95.131:9292/ in a non-destructive manner (reads/error-based, and state injections with automatic value restoration).

**a) Execution in browser** — real server response rendered in Chromium, with evidence band (request + payload + verdict):

<img width="1180" height="1357" alt="evidencia-web-33-updatedetailsfromfaculty-stored-xss" src="https://github.com/user-attachments/assets/1acb8975-2b03-4ddd-9b73-590ae885468e" />

**b) Vulnerable code line** — source code snippet with sink highlighted (`updatedetailsfromstudent.php`):
<img width="2360" height="880" alt="evidencia-codigo-33-updatedetailsfromfaculty-stored-xss" src="https://github.com/user-attachments/assets/2b660ef1-4ee9-471e-844e-e5598a7c9ee5" />

## 6. Impact

JavaScript execution in context of authenticated admins/teachers: session cookie theft, CSRF-like actions-as-victim, pivot for account takeover.

## 7. Severity Assessment (CVSS v3.1)

Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` — **Base 6.1 (Medium)**

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | None (N) |
| User Interaction (UI) | Required (R) |
| Scope (S) | Changed (C) |
| Confidentiality (C) | Low (L) |
| Integrity (I) | Low (L) |
| Availability (A) | None (N) |

**EPSS:** N/A (no CVE) — low estimate.

## 8. Remediation

- Encode all dynamic output with `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` in correct context.
- Validate/limit input content and use Content-Security-Policy.
- Prepared statements in persistence (defense in depth).

## 9. Novelty / Duplication Check

No public CVE for this file/parameter in Vishal Mathur product nor in the twin 'CodeAstro Online Classroom' codebase. Verified in NVD/cvefeed on 2026-08-02.

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
