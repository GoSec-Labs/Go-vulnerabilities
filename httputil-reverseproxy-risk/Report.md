### **Vulnerability Title**

Insecure Usage of `httputil.ReverseProxy`

### **Severity Rating**

**Medium to High** (CVSS: 3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:N - **8.2 High🟠** for scenarios leading to SSRF or header injection)

### **Description**

This vulnerability arises from the improper configuration and implementation of Go's `net/http/httputil.ReverseProxy`. A misconfigured reverse proxy can be tricked by an attacker into forwarding requests to unintended backend servers, including internal-only services. This can lead to serious security flaws such as Server-Side Request Forgery (SSRF), bypassing access controls, information disclosure, and cache poisoning.

### **Technical Description (for security pros)**

The core of the vulnerability lies in the custom logic developers write for the proxy, typically within the `Director` function or the newer `Rewrite` hook. A common but dangerous mistake is to blindly trust and use components from the incoming `http.Request`, such as the `Host` header or the URL path, to construct the request that is sent to the backend.

For example, if the proxy's `Director` function sets the destination `Host` based on the incoming request's `Host` header, an attacker can manipulate this header to force the proxy to send a request to an arbitrary server, both internal and external. This effectively turns the proxy into an open relay for launching attacks, a classic example of Server-Side Request Forgery (SSRF). Additionally, historical vulnerabilities (e.g., CVE-2022-2880, CVE-2024-24791) in the `httputil` package itself have led to issues like query parameter smuggling and denial of service, emphasizing the need to keep the Go runtime updated.

### **Common Mistakes That Cause This**

  * **Reflecting the Host Header:** Copying the `Host` from the incoming request (`r.Host`) to the outgoing request (`req.Host`) allows attackers to control the request's destination.
  * **Not Sanitizing the Request URI:** Forwarding the path and query parameters without cleaning or validation can lead to path traversal attacks on the backend or parameter smuggling.
  * **Passing All Headers:** Copying all headers from the client to the backend can leak internal information or allow an attacker to inject malicious headers like `X-Forwarded-For`.
  * **Using the Outdated `Director` Hook:** In Go 1.20+, using the `Director` function instead of the safer `Rewrite` hook can lead to hop-by-hop headers being stripped after they are set, nullifying security headers.

### **Exploitation Goals**

  * **Server-Side Request Forgery (SSRF):** The primary goal. Attackers use the proxy to scan internal networks and access internal services (e.g., admin panels, metadata services like the AWS EC2 metadata endpoint, databases) that are not exposed to the internet.
  * **Bypassing Access Controls:** Accessing restricted endpoints on a legitimate backend server by manipulating the request path or headers.
  * **Web Cache Poisoning:** Tricking a downstream cache into storing a malicious response for a legitimate URL.
  * **Information Disclosure:** Leaking sensitive information from backend error messages or headers.

### **Affected Components or Files**

Any Go file where `httputil.ReverseProxy` is instantiated and configured, especially the implementation of its `Director` or `Rewrite` function.

### **Vulnerable Code Snippet**

This snippet shows a reverse proxy with a vulnerable `Director` that sets the backend target based on the incoming request's `Host` header.

```go
package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// Vulnerable director that allows Host header to control the backend target.
func vulnerableDirector(req *http.Request) {
	// The scheme is hardcoded, but the Host is taken directly from the incoming request.
	// This is the core of the vulnerability.
	req.URL.Scheme = "http"
	req.URL.Host = req.Host // VULNERABLE: Attacker controls this value.

	// To make the attack work, we also need to unset the Host field on the request
	// so the http.Transport uses the Host from req.URL.Host.
	// Note: In some Go versions or configs, this behavior might differ, but the
	// principle of trusting req.Host is the flaw.
	req.Host = req.URL.Host
}

func main() {
	proxy := &httputil.ReverseProxy{Director: vulnerableDirector}

	log.Println("Vulnerable reverse proxy starting on :8080...")
	// An attacker can use this proxy to send requests to any server.
	if err := http.ListenAndServe(":8080", proxy); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
```

### **Detection Steps**

1.  **Manual Code Review:** Scrutinize all `httputil.ReverseProxy` implementations. Pay close attention to the `Director` and `Rewrite` functions. Look for any instance where `req.URL.Host` or `req.Host` is set using data from the incoming request (`r.Host`, `r.Header`, etc.).
2.  **Dynamic Analysis (DAST) / Penetration Testing:** Use a web proxy like Burp Suite to intercept requests to the Go proxy. Modify the `Host` header to point to an internal IP address or a public server you control (like a Burp Collaborator client) and observe if the proxy forwards the request.

### **Proof of Concept (PoC)**

An attacker can exploit the vulnerable code above to make a request to an internal admin service that is not publicly accessible.

1.  Run the vulnerable Go server on a machine with IP `1.2.3.4`.

2.  Assume an internal, unexposed service is running at `http://127.0.0.1:9000/admin`.

3.  The attacker uses `curl` to send a request to the proxy, but manipulates the `Host` header to target the internal service.

    ```sh
    # The proxy is at 1.2.3.4:8080. The Host header tells the proxy
    # to forward the request to http://127.0.0.1:9000.
    curl -H "Host: 127.0.0.1:9000" http://1.2.3.4:8080/admin
    ```

4.  **Result:** The vulnerable proxy will receive the request, see the `Host` header, and forward the request to `http://127.0.0.1:9000/admin`. The attacker successfully accesses the internal admin endpoint.

### **Risk Classification**

  * **CWE-918:** Server-Side Request Forgery (SSRF)
  * **CWE-444:** Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')
  * **OWASP Top 10 2021:** A10:2021 - Server-Side Request Forgery

### **Fix & Patch Guidance**

The proxy must be the sole authority on where to send requests. Never trust client-provided data to make this decision.

**Patched Code Snippet:**

```go
package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// Secure director that sends all requests to a single, trusted backend.
func secureDirector(target *url.URL) func(*http.Request) {
	return func(req *http.Request) {
		// FIX: The scheme, host, and path are determined by the hardcoded target.
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = target.Path + req.URL.Path

		// FIX: Explicitly set the Host header to prevent Host header injection attacks.
		req.Host = target.Host

		// Clean up headers for security.
		req.Header.Del("X-Forwarded-For")
	}
}

func main() {
	// The backend target is non-negotiable and configured at startup.
	targetURL, err := url.Parse("http://my-trusted-backend-service:8000")
	if err != nil {
		log.Fatalf("Invalid target URL: %v", err)
	}

	proxy := &httputil.ReverseProxy{Director: secureDirector(targetURL)}

	log.Println("Secure reverse proxy starting on :8080...")
	if err := http.ListenAndServe(":8080", proxy); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
```

### **Scope and Impact**

  * **Scope:** The vulnerability extends the attack surface from the proxy itself to any machine or service the proxy can reach on its network.
  * **Impact:** A successful SSRF exploit can be critical. It can lead to the complete compromise of internal infrastructure, data exfiltration from internal databases, and pivoting to other systems within the network. The impact is often a total loss of confidentiality and integrity for backend systems.

### **Remediation Recommendation**

1.  **Explicitly Define Targets:** Never use the incoming `Host` header to determine the backend. The proxy's destination should be hardcoded or derived from a trusted configuration source.
2.  **Sanitize and Whitelist:** Sanitize the request path and query. Use a whitelist to control which headers are passed from the client to the backend.
3.  **Use the `Rewrite` Hook:** If using Go 1.20 or newer, prefer the `Rewrite` hook over the `Director` function to avoid issues with hop-by-hop header handling.
4.  **Keep Go Updated:** Regularly update your Go version to receive patches for any newly discovered vulnerabilities in the `net/http` and `net/http/httputil` packages.

### **Summary**

The "Insecure usage of `httputil.ReverseProxy`" vulnerability is a critical misconfiguration that turns a helpful utility into a launchpad for Server-Side Request Forgery (SSRF) and other attacks. The flaw originates from trusting user-controllable input, especially the `Host` header, to direct traffic. Proper remediation involves writing a secure `Director` or `Rewrite` function that strictly defines the backend target and sanitizes all data passed to it.

### **References**

  * [Go Documentation: `httputil.ReverseProxy`](https://www.google.com/search?q=%5Bhttps://pkg.go.dev/net/http/httputil%23ReverseProxy%5D\(https://pkg.go.dev/net/http/httputil%23ReverseProxy\))
  * [OWASP: Server-Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
  * [PortSwigger: Host Header Attacks](https://portswigger.net/web-security/host-header)
  * [Ory Blog: Hop-by-hop Header Vulnerability](https://www.ory.sh/blog/hop-by-hop-header-vulnerability-go-standard-library-reverse-proxy)
  * [CVE-2022-2880: Query Parameter Smuggling](https://www.cvedetails.com/cve/CVE-2022-2880/)