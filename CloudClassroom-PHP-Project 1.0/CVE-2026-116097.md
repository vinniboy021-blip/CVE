# Security Advisory — Stored XSS in addnewstudent.php (executes in studentdetails.php)

> **Identifier:** Pending CVE assignment / Internal ID **CC-2026-18**
> **Publication Date:** 02/08/2026
> **Last Updated:** 02/08/2026
> **Severity:** Medium
> **CVSS:** 6.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79: Cross-site Scripting
> **Status:** Unpatched

---

## 1. Executive Summary

A vulnerability was identified in **CloudClassroom-PHP-Project 1.0** (Vishal Mathur — `mathurvishal`), in the component **addnewstudent.php, studentdetails.php**, that allows **an attacker (None to inject (via item 00); user interaction: Required (victim opens page that renders the data))** to exploit a **Stored / Persistent Cross-Site Scripting** flaw.

Fields `fname`, `lname`, `faname`, `addrs`, `course` are persisted without sanitization and re-displayed in `value="..."` attribute without HTML-encoding. Name is rendered without encoding in admin listing studentdetails.php (context <td>, no breakout).

Successful exploitation may result in **JavaScript execution in context of authenticated admins/teachers: session cookie theft, CSRF-like actions-as-victim, pivot for account takeover.**

Disclosure follows responsible/coordinated policy; formal vendor notification is planned in the disclosure package (see sections 13 and 14). As of now no patch is available.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---:|---:|---|
| CloudClassroom-PHP-Project | 1.0 (and prior) | None | Affected |
| Component: addnewstudent.php, studentdetails.php | 1.0 | None | Affected |

- **Repository / Ecosystem:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
- **Evaluated Stack:** PHP + MySQLi, Apache/2.4.41 (Ubuntu), MariaDB 10.3.39

### Unaffected Products

- No other version/product evaluated in this advisory.

---

## 3. Vulnerability Description

The vulnerability occurs due to **Stored / Persistent Cross-Site Scripting** in the component **addnewstudent.php**.

Fields `fname`, `lname`, `faname`, `addrs`, `course` are persisted without sanitization and re-displayed in `value="..."` attribute without HTML-encoding. Name is rendered without encoding in admin listing studentdetails.php (context <td>, no breakout).

**Root cause (source code snippet):**

**`addnewstudent.php`**

```php
<input ... name="fname" value="<?php echo $row[...]; ?>">
```

### Necessary Conditions

- Authentication: None to inject (via item 00)
- User Interaction: Required (victim opens page that renders the data)
- Attack Vector: Remote (network) — method POST
- Preconditions: None to inject (item 00). Authenticated victim (admin/faculty) needs to view the record.

---

## 4. Impact

Exploitation may allow:

- JavaScript execution in context of authenticated admins/teachers: session cookie theft, CSRF-like actions-as-victim, pivot for account takeover

### Impact on Confidentiality

Low — partial/limited information exposure.

### Impact on Integrity

Low — limited data/state modification.

### Impact on Availability

None — no direct availability impact.

---

## 5. Classification

### CVSS

- **Score:** 6.1
- **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

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

### CWE

- CWE-79: Cross-site Scripting

### CAPEC

- **CAPEC-63 – Cross-Site Scripting (XSS)**

---

## 6. Exploitation Scenario

A possible exploitation scenario occurs as follows:

1. Send POST to `addnewstudent.php` recording breakout payload in field `fname`.
2. Payload: `"><svg onload=alert(1)>` (breaks value attribute).
3. Re-open the page / studentdetails.php; payload is reflected WITHOUT encoding and executes.
4. Chain with cookie without HttpOnly (item 24) for admin session theft.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): addnewstudent.php, studentdetails.php
Parameter(s): fname, lname, faname, addrs, course
Method: POST · Authentication: None to inject (via item 00)
```

### Example Request

```http
POST /addnewstudent.php HTTP/1.1
Host: 192.168.95.131:9292
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<session — dispensable via item 00 (Broken Access Control)>

fname=<value>&lname=<value>&faname=<value>&addrs=<value>&course=<value>
```

### Observed Response

```text
payload reflected WITHOUT encoding: "><svg onload=alert(1)>
```

### Result

Reproduced live in authorized lab (http://192.168.95.131:9292/) on 02/08/2026, in a non-destructive manner. Observed behavior confirms the Stored / Persistent Cross-Site Scripting flaw.

**a) Execution in browser** (real server response rendered, with evidence band):

<img width="1180" height="1357" alt="evidencia-web-18-addnewstudent-stored-xss" src="https://github.com/user-attachments/assets/b07b1f4f-9175-4093-9df2-26c01bd2f77a" />

**b) Vulnerable code line** (`addnewstudent.php`):

<img width="2360" height="860" alt="evidencia-codigo-18-addnewstudent-stored-xss" src="https://github.com/user-attachments/assets/db21e347-d17f-404c-b320-49ad41f27328" />

---

## 8. Proof of Concept

The PoC below demonstrates only vulnerable behavior and should be used exclusively in authorized environments. Executable and non-destructive script: **`poc.sh`**.

```bash
# non-destructive cycle (capture->inject->verify->restore):
python3 ../_lib/xss_poc.py "http://192.168.95.131:9292" "addnewstudent.php?..." \
  fname '"><svg onload=alert(1)>' --fields fname,lname,faname,addrs,course
```

### Expected Result

```text
payload reflected WITHOUT encoding: "><svg onload=alert(1)>
```


### PoC Limitations

- Does not cause intentional unavailability.
- Does not remove or modify third-party data (state injections are restored; error-based aborts before persisting).
- Does not create persistence or backdoor.
- Does not contain real credentials (lab test data only).
- Does not automate mass exploitation.

---

## 9. Reproduction Steps

1. Access an instance of **CloudClassroom-PHP-Project 1.0**.
2. Configure the prerequisite: None to inject (item 00). Authenticated victim (admin/faculty) needs to view the record.
3. Access the component **addnewstudent.php** (parameter(s): fname, lname, faname, addrs, course).
4. Send the request/input described in sections 7 and 8.
5. Observe the vulnerable result: payload reflected WITHOUT encoding: "><svg onload=alert(1)>
6. Compare with expected safe behavior (properly validated/sanitized/authorized input, without payload reflection or unintended execution).

---

## 10. Mitigation

Until the definitive fix is applied, recommended:

- Encode all dynamic output with `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` in correct context.
- Validate/limit input content and use Content-Security-Policy.
- Prepared statements in persistence (defense in depth).

Additional compensatory measures:

- Restrict access to affected component (network/ACL/WAF).
- Apply WAF/reverse proxy rules to block known attack patterns.
- Review associated permissions and privileges; invalidate potentially exposed sessions/credentials.
- Maintain logs and evidence for investigation.

> Mitigations reduce risk but may not completely eliminate the vulnerability.

---

## 11. Fix

**No official fix available as of this advisory date (unpatched product).**

When made available, recommended:

1. Update to patched version or later.
2. Restart affected services, if necessary.
3. Invalidate old sessions and credentials.
4. Review logs prior to update.
5. Confirm vulnerable behavior can no longer be reproduced.

### Recommended Change to Vendor

- Encode all dynamic output with `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` in correct context.
- Validate/limit input content and use Content-Security-Policy.
- Prepared statements in persistence (defense in depth).

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Values persisted via `addnewstudent.php` containing `<script`, `onerror=`, `onload=`, `<svg` or `</textarea>`.

### Example Log Search

```text
grep -Ei "(union|select|extractvalue|concat|<script|onerror|onload|</textarea)" access.log | grep "addnewstudent.php"
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 02/08/2026 | Vulnerability identified (static analysis) |
| 02/08/2026 | Confirmed dynamically in authorized lab |
| 02/08/2026 | Re-validated live with evidence (browser + code) |
| 25/09/2026 | Disclosure package prepared (this advisory) |
| (pending) | Vendor notification |
| (pending) | CVE requested/reserved |
| (pending) | Fix made available |
| (pending) | Advisory publication |

---

## 14. Vendor Communication

- **Vendor:** Vishal Mathur (`mathurvishal`)
- **Channel used:** Private GitHub Security Advisory of repository / maintainer email.
- **Date of first notification:** (pending)
- **Response status:** Awaiting notification/response
- **Vendor positioning:** N/A at this time

---

## 15. Credits

The vulnerability was identified and reported by:

- **Researcher:** vinniboy021@gmail.com
- **Organization:** Independent security research
- **Contact:** vinniboy021@gmail.com

---

## 16. References

- https://cwe.mitre.org/
- https://www.first.org/cvss/calculator/3.1
- https://cvefeed.io/vuln/product/161371/vishalmathurcloudclassroom-php_project/
- https://github.com/mathurvishal/CloudClassroom-PHP-Project
- https://www.first.org/cvss/calculator/3.1

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 02/08/2026 | Initial publication |

---

## 18. Legal Notice

This advisory is published for educational, defensive and security improvement purposes.

Information presented was obtained in authorized environment and disclosed responsibly or coordinately. The author does not encourage use of this information for unauthorized access, service interruption, privacy violation or any illegal activity.

Use of information in this document is solely the reader's responsibility.

---

## 19. Contact

For corrections, updates or additional information:

- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
