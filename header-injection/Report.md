### **Vulnerability Title**

HTTP Header Injection

### **Severity Rating**

**Medium to High** (CVSS: 3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N - **6.1 Medium🟡** for Open Redirect; can be higher for XSS or cache poisoning)

### **Description**

HTTP Header Injection occurs when an attacker can control part of an HTTP response header. While Go's standard `net/http` library protects against the most severe form, "HTTP Response Splitting," by sanitizing newline characters, a vulnerability still exists if user-controlled input is placed into headers without proper validation. This can be exploited to perform other attacks, such as tricking users into visiting malicious websites (Open Redirect), executing scripts in their browser (Cross-Site Scripting), or poisoning web caches.

### **Technical Description (for security pros)**

The `net/http` package in Go automatically removes `\r` and `\n` characters from values written via `Header().Set()` and `Header().Add()`. This effectively prevents classic HTTP Response Splitting (CWE-113), where an attacker injects a CRLF sequence (`\r\n`) to terminate one header and forge new ones or even a new response body.

However, the vulnerability of "Header Injection" (CWE-74) persists at a logical level. The server is not compromised, but it can be tricked into sending a legitimate-looking response with malicious content in a header value. For example, if a developer takes a URL from a query parameter and places it directly into a `Location` header for a redirect, an attacker can supply an external, malicious URL. The browser, trusting the response from the valid domain, will redirect the user to the attacker's site. This is known as an Open Redirect (CWE-601).

### **Common Mistakes That Cause This**

  * **Trusting User Input for Redirects:** Directly using a query parameter or form value as the destination URL in a `Location` header.
  * **Reflecting Input without Validation:** Setting custom headers (e.g., `X-Custom-Header`) with raw, unvalidated data from the request.
  * **Improper `Content-Disposition` Construction:** Building a `Content-Disposition` header with a user-supplied filename without sanitizing path characters or quotes, which can lead to XSS in some older browsers.
  * **Manual Response Crafting:** Bypassing `http.Header` methods and writing a raw HTTP response directly to the `io.Writer` of the `http.ResponseWriter`, thereby bypassing Go's built-in CRLF sanitization.

### **Exploitation Goals**

  * **Phishing:** Using Open Redirects to send users to a convincing fake login page to steal credentials.
  * **Cross-Site Scripting (XSS):** Injecting scriptable content into headers that might be rendered by a browser or client.
  * **Session Fixation:** Manipulating session-related headers to fix a user's session ID.
  * **Cache Poisoning:** Tricking a caching proxy into storing a malicious response for a given URL.

### **Affected Components or Files**

Any Go file that handles HTTP requests and sets response headers using user-provided data. The most common sinks are:

  * `w.Header().Set("Location", userInput)`
  * `w.Header().Set("Content-Disposition", "attachment; filename="+userInput)`
  * `http.Redirect(w, r, userInput, http.StatusFound)`

### **Vulnerable Code Snippet**

This code snippet demonstrates a classic Open Redirect vulnerability. The application takes a `redirect_url` from the query string and uses it to redirect the user.

```go
package main

import (
	"log"
	"net/http"
)

// Vulnerable handler that redirects to a user-specified URL.
func vulnerableRedirectHandler(w http.ResponseWriter, r *http.Request) {
	// Get the redirect destination from a query parameter.
	redirectURL := r.URL.Query().Get("redirect_url")

	// Input is not validated. An attacker can provide an external URL.
	if redirectURL != "" {
		// VULNERABLE: Setting the Location header with untrusted input.
		w.Header().Set("Location", redirectURL)
		w.WriteHeader(http.StatusFound) // 302 Found
		return
	}

	w.Write([]byte("No redirect URL provided."))
}

func main() {
	http.HandleFunc("/redirect", vulnerableRedirectHandler)
	log.Println("Server starting on :8080...")
	// The server is vulnerable to an open redirect.
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
```

### **Detection Steps**

1.  **Static Application Security Testing (SAST):** Use SAST tools to trace data flow from user input sources (like `r.URL.Query()`) to header-writing function sinks (like `w.Header().Set()`).
2.  **Dynamic Application Security Testing (DAST):** Use a web vulnerability scanner to probe endpoints. DAST tools are particularly effective at identifying Open Redirects by supplying external domains in parameters and observing the `Location` header in the response.
3.  **Manual Code Review:** Search the codebase for instances where response headers are set. For each instance, verify that any user-controllable data is being strictly validated against a whitelist of expected values or formats.

### **Proof of Concept (PoC)**

For the vulnerable code above, an attacker can craft a URL to redirect users to a malicious site.

1.  Run the vulnerable Go server.
2.  The attacker convinces a victim to click the following link:
    `http://localhost:8080/redirect?redirect_url=http://evil-site.com`
3.  Use `curl` to observe the server's response:
    ```sh
    curl -v "http://localhost:8080/redirect?redirect_url=http://evil-site.com"
    ```
4.  **Result:** The server responds with a `302 Found` status and a `Location` header pointing to the malicious site. The user's browser will automatically navigate to `http://evil-site.com`.
    ```http
    > GET /redirect?redirect_url=http://evil-site.com HTTP/1.1
    > Host: localhost:8080
    >
    < HTTP/1.1 302 Found
    < Location: http://evil-site.com  <-- Malicious redirect injected
    < Date: ...
    < Content-Length: 0
    ```

### **Risk Classification**

  * **CWE-601:** URL Redirection to Untrusted Site ('Open Redirect')
  * **CWE-74:** Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')
  * **OWASP Top 10 2021:** A03:2021 - Injection

### **Fix & Patch Guidance**

The primary defense is **strict input validation**. Never trust user-provided data for security-sensitive headers.

**Patched Code Snippet:**

```go
package main

import (
	"log"
	"net/http"
	"net/url"
)

// A whitelist of allowed redirect hosts.
var allowedRedirectHosts = map[string]bool{
	"safe-local-site.com": true,
	"another-trusted-app.com": true,
}

// Secure handler that validates the redirect URL.
func secureRedirectHandler(w http.ResponseWriter, r *http.Request) {
	redirectURLStr := r.URL.Query().Get("redirect_url")
	if redirectURLStr == "" {
		http.Error(w, "Bad Request: redirect_url is required", http.StatusBadRequest)
		return
	}

	// FIX: Parse the URL and validate its host against a whitelist.
	parsedURL, err := url.Parse(redirectURLStr)
	if err != nil {
		http.Error(w, "Bad Request: invalid redirect_url", http.StatusBadRequest)
		return
	}

	// Ensure the URL is relative (e.g., "/dashboard") OR the host is in the allowlist.
	if (parsedURL.Host != "" && !allowedRedirectHosts[parsedURL.Host]) || parsedURL.Scheme == "" {
		http.Error(w, "Forbidden: redirect to this host is not allowed", http.StatusForbidden)
		return
	}

	// If validation passes, perform the redirect.
	http.Redirect(w, r, parsedURL.String(), http.StatusFound)
}

func main() {
	http.HandleFunc("/redirect", secureRedirectHandler)
	log.Println("Server starting on :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
```

### **Scope and Impact**

  * **Scope:** The direct impact is on the end-user's browser, which is made to perform an unsafe action (e.g., redirect or execute a script).
  * **Impact:** A successful exploit can lead to credential theft through phishing, unauthorized actions on behalf of the user, information disclosure, and a general loss of trust in the application.

### **Remediation Recommendation**

1.  **Validate Input:** Always validate any user-controlled data used in response headers against a strict whitelist of allowed values or patterns.
2.  **Avoid Reflecting Input:** Do not "reflect" user input back into response headers. If you must, ensure it is properly sanitized and validated first.
3.  **Use Whitelists for Redirects:** When performing redirects, validate the target URL. The safest approach is to check if the destination is a local path (e.g., `/profile`) or if the URL's hostname belongs to a predefined list of trusted domains.
4.  **Use SAST/DAST Tools:** Integrate automated security testing into your CI/CD pipeline to catch injection flaws early.

### **Summary**

While Go's `net/http` package provides robust protection against classic HTTP Response Splitting, the broader vulnerability of Header Injection remains a threat. It typically manifests as logical flaws like Open Redirects, where unvalidated user input is used to set the value of a sensitive header like `Location`. The primary defense is not to rely on Go's sanitization alone, but to implement strict, whitelist-based validation for all user-provided data before it is placed into a response header.

### **References**

  * [OWASP: HTTP Header Injection](https://www.google.com/search?q=https://owasp.org/www-community/attacks/HTTP_Header_Injection)
  * [OWASP: Open Redirect Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
  * [Go Documentation: `http.Header.Set`](https://www.google.com/search?q=%5Bhttps://pkg.go.dev/net/http%23Header.Set%5D\(https://pkg.go.dev/net/http%23Header.Set\))
  * [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)