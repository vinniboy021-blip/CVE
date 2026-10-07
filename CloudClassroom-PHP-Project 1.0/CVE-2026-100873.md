# Security Advisory — Cross-Site Request Forgery (CSRF) throughout the application

> **Identifier:** Pending CVE assignment / Internal ID **CC-2026-23**
> **Publication Date:** 02/08/2026
> **Last Updated:** 02/08/2026
> **Severity:** High
> **CVSS:** 8.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`
> **CWE:** CWE-352: Cross-Site Request Forgery
> **Status:** Unpatched

---

## 1. Executive Summary

A vulnerability was identified in **CloudClassroom-PHP-Project 1.0** (Vishal Mathur — `mathurvishal`), in the component **addnewfaculty.php, addnewstudent.php, update*.php, makeresult.php, manageassessment2.php, managevideos2.php, *details.php (delete via GET)**, that allows **an attacker (Authenticated victim (admin/faculty); user interaction: Required)** to exploit a **Cross-Site Request Forgery** flaw.

Application has no anti-CSRF tokens and session cookie lacks `SameSite`. No endpoint validates `Origin`/`Referer`. Any state-changing action is forjable; destructive operations via GET (`?deleteid=N`) allow CSRF via simple `<img>`.

Successful exploitation may result in **Privileged actions as victim: account creation, grade changes, mass removal and data destruction (I:H/A:H).**

Disclosure follows responsible/coordinated policy; formal vendor notification is planned in the disclosure package (see sections 13 and 14). As of now no patch is available.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---:|---:|---|
| CloudClassroom-PHP-Project | 1.0 (and prior) | None | Affected |
| Component: addnewfaculty.php, addnewstudent.php, update*.php, makeresult.php, manageassessment2.php, managevideos2.php, *details.php (delete via GET) | 1.0 | None | Affected |

- **Repository / Ecosystem:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
- **Evaluated Stack:** PHP + MySQLi, Apache/2.4.41 (Ubuntu), MariaDB 10.3.39

### Unaffected Products

- No other version/product evaluated in this advisory.

---

## 3. Vulnerability Description

The vulnerability occurs due to **Cross-Site Request Forgery** in the component **addnewfaculty.php**.

Application has no anti-CSRF tokens and session cookie lacks `SameSite`. No endpoint validates `Origin`/`Referer`. Any state-changing action is forjable; destructive operations via GET (`?deleteid=N`) allow CSRF via simple `<img>`.

**Root cause (source code snippet):**

**`studentdetails.php:16-18`**

```php
if(isset($_REQUEST['deleteid'])){ $sql="DELETE FROM `studenttable` WHERE Eno = $deleteid"; }
// no token; no Origin/Referer check; DELETE via GET
```

### Necessary Conditions

- Authentication: Authenticated victim (admin/faculty)
- User Interaction: Required
- Attack Vector: Remote (network) — method GET/POST
- Preconditions: Induce authenticated admin/teacher to open malicious page.

---

## 4. Impact

Exploitation may allow:

- Privileged actions as victim: account creation, grade changes, mass removal and data destruction (I:H/A:H)

### Impact on Confidentiality

None — the flaw does not directly expose confidentiality data.

### Impact on Integrity

High — data, configuration or records can be created, altered or removed arbitrarily.

### Impact on Availability

High — service or data can be interrupted, degraded or destroyed.

---

## 5. Classification

### CVSS

- **Score:** 8.1
- **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | None (N) |
| User Interaction (UI) | Required (R) |
| Scope (S) | Unchanged (U) |
| Confidentiality (C) | None (N) |
| Integrity (I) | High (H) |
| Availability (A) | High (H) |

### CWE

- CWE-352: Cross-Site Request Forgery

### CAPEC

- **CAPEC-62 – Cross Site Request Forgery**

---

## 6. Exploitation Scenario

A possible exploitation scenario occurs as follows:

1. Create page with `<img src=.../studentdetails.php?deleteid=N>` tag (GET destructive) or auto-submit form (POST).
2. Authenticated victim opens page; browser attaches session cookie (no SameSite).
3. Action executes in victim's context (delete/create/edit records, change grades).

---

## 7. Technical Evidence

### Affected Component

```text
File(s): addnewfaculty.php, addnewstudent.php, update*.php, makeresult.php, manageassessment2.php, managevideos2.php, *details.php (delete via GET)
Parameter(s): (all state-changing actions)
Method: GET/POST · Authentication: Authenticated victim (admin/faculty)
```

### Example Request

```http
POST /addnewfaculty.php HTTP/1.1
Host: 192.168.95.131:9292
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<session — dispensable via item 00 (Broken Access Control)>

<form fields>
```

### Observed Response

```text
'success' response with foreign Origin and no token → absence of CSRF protection.
```

### Result

Reproduced live in authorized lab (http://192.168.95.131:9292/) on 02/08/2026, in a non-destructive manner. Observed behavior confirms the Cross-Site Request Forgery flaw.

**a) Execution in browser** (real server response rendered, with evidence band):

<img width="1180" height="842" alt="evidencia-web-23-csrf" src="https://github.com/user-attachments/assets/8c3f89c3-6bc8-4ae7-a253-b9d04e6d901d" />

**b) Vulnerable code line** (`addnewfaculty.php`):

<img width="2360" height="800" alt="evidencia-codigo-23-csrf" src="https://github.com/user-attachments/assets/92f1c46f-08b7-483f-bf23-4de513d23555" />

---

## 8. Proof of Concept

The PoC below demonstrates only vulnerable behavior and should be used exclusively in authorized environments. Executable and non-destructive script: **`poc.sh`**.

```bash
# non-destructive proof (accepts foreign Origin, no token):
curl -s -H "Origin: https://evil.example" \
  "http://192.168.95.131:9292/updateguest.php?gid=Anil21@gmail.com" \
  --data-urlencode "gname=Anil Rawat" --data-urlencode "update=Update!" | grep -oi success
# see also poc-get-delete.html and poc-post-addfaculty.html
```

### Expected Result

```text
'success' response with foreign Origin and no token → absence of CSRF protection.
```


Additional HTML PoCs (require authenticated victim): `poc-get-delete.html`, `poc-post-addfaculty.html`

### PoC Limitations

- Does not cause intentional unavailability.
- Does not remove or modify third-party data (state injections are restored; error-based aborts before persisting).
- Does not create persistence or backdoor.
- Does not contain real credentials (lab test data only).
- Does not automate mass exploitation.

---

## 9. Reproduction Steps

1. Access an instance of **CloudClassroom-PHP-Project 1.0**.
2. Configure the prerequisite: Induce authenticated admin/teacher to open malicious page.
3. Access the component **addnewfaculty.php** (parameter(s): (all state-changing actions)).
4. Send the request/input described in sections 7 and 8.
5. Observe the vulnerable result: 'success' response with foreign Origin and no token → absence of CSRF protection.
6. Compare with expected safe behavior (properly validated/sanitized/authorized input, without payload reflection or unintended execution).

---

## 10. Mitigation

Until the definitive fix is applied, recommended:

- Anti-CSRF tokens per session (synchronizer token) in all forms.
- Use POST for state-changing actions (never GET for DELETE); validate `Origin`/`Referer`.
- Cookie `SameSite=Strict`.

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

- Anti-CSRF tokens per session (synchronizer token) in all forms.
- Use POST for state-changing actions (never GET for DELETE); validate `Origin`/`Referer`.
- Cookie `SameSite=Strict`.

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Anomalous access to `addnewfaculty.php` and unusual patterns in parameter `(all state-changing actions)`.

### Example Log Search

```text
grep -Ei "(union|select|extractvalue|concat|<script|onerror|onload|</textarea)" access.log | grep "addnewfaculty.php"
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 02/08/2026 | Vulnerability identified (static analysis) |
| 02/08/2026 | Confirmed dynamically in authorized lab |
| 02/08/2026 | Re-validated live with evidence (browser + code) |
| 02/08/2026 | Disclosure package prepared (this advisory) |
| (pending) | Vendor notification |
| (pending) | CVE requested/reserved |
| (pending) | Fix made available |
| (pending) | Advisory publication |

---

## 14. Vendor Communication

- **Vendor:** Vishal Mathur (`mathurvishal`)
- **Channel used:** Private GitHub Security Advisory of repository / maintainer email (see `VENDOR-EMAIL.md`)
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
