# Vulnerability Title

Unsafe `net.Dial` to Attacker-Controlled Address (Potential Server-Side Request Forgery - SSRF)

## Severity Rating

**High🟠 to Critical🔴** (depending on the network environment and services accessible by the server)

## Description

This vulnerability occurs when a Go application uses the `net.Dial` function (or related functions like `http.Get` which use it internally) with a network address (IP address or hostname and port) that is fully or partially controlled by an attacker. This can allow an attacker to coerce the server into making arbitrary network connections to internal or external systems, leading to Server-Side Request Forgery (SSRF) or other network-level attacks.

## Technical Description (for security pros)

When `net.Dial(network, address)` is called and the `address` string can be manipulated by user input, an attacker can specify arbitrary IP addresses or hostnames. This allows them to:

1.  Scan internal networks (port scanning) by observing connection success/failure or error messages/timing.
2.  Access internal services that are not directly exposed to the internet but are accessible from the application server (e.g., internal APIs, databases, metadata services like AWS EC2 instance metadata).
3.  Interact with and potentially exploit vulnerable services on internal or external systems.
4.  Perform reflection attacks or use the server as a proxy for other malicious activities.

The `network` argument (e.g., "tcp", "udp") also influences the type of connection made. If an attacker can also control this, the risk might be compounded.

## Common Mistakes That Cause This

  * **Directly using user-supplied input as the address:** Taking a hostname, IP, or full URL from a user request (e.g., query parameter, JSON payload) and passing it directly to `net.Dial`, `http.Get`, `http.Client.Do` without proper validation or allow-listing.
  * **Insufficient validation or sanitization:** Attempting to validate the address but using flawed logic, incomplete blocklists, or bypassable regular expressions. For example, only checking for `localhost` but not `127.0.0.1` or other loopback variations, or not properly handling DNS rebinding.
  * **Trusting internal services or configurations:** Fetching connection details from a database or configuration that could be indirectly influenced by an attacker.
  * **Complex string concatenations to form the address:** Building the target address from multiple parts, where one or more parts can be influenced by user input.
  * **Ignoring or misinterpreting error messages:** Error messages from `net.Dial` can leak information about the internal network if not handled carefully.

## Exploitation Goals

  * **Internal Network Reconnaissance:** Discovering live hosts and open ports within the server's network.
  * **Accessing Internal Services:** Interacting with internal APIs, databases (e.g., Redis, Elasticsearch without authentication), administrative interfaces, or cloud provider metadata services (e.g., AWS EC2 IMDS to steal credentials).
  * **Bypassing Firewalls:** Using the server as a proxy to connect to systems that the server has access to but the attacker does not.
  * **Data Exfiltration:** Forcing the server to send internal data to an attacker-controlled external system.
  * **Remote Code Execution (RCE) on Internal Systems:** If the server can be made to interact with a vulnerable internal service that leads to RCE.
  * **Denial of Service (DoS):** Forcing the server to connect to a sinkhole or a service that hangs connections, potentially exhausting resources.

## Affected Components or Files

  * Any Go source file (`.go`) that uses `net.Dial`, `net.DialTimeout`, `http.Get`, `http.Post`, `http.NewRequest` (and then `http.Client.Do`), or any other library function that ultimately makes an outgoing network connection where the target address is derived from untrusted input.
  * Modules responsible for webhook processing, fetching remote resources, proxying requests, or any feature that involves making network calls based on user-provided URLs or hostnames.

## Vulnerable Code Snippet

```go
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
)

// Vulnerable function that dials an address provided in an HTTP request
func fetchResourceHandler(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url") // User controls this value
	if targetURL == "" {
		http.Error(w, "Missing 'url' parameter", http.StatusBadRequest)
		return
	}

	// Attempt to parse the URL to get host and port for net.Dial
	// This is a simplified example; real-world parsing might be more complex
	// and could also use http.Get(targetURL) directly which is also vulnerable.

	parsedURL, err := url.Parse(targetURL)
	if err != nil || parsedURL.Host == "" {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		// Default to port 80 if not specified
		if parsedURL.Scheme == "https" {
			port = "443" // Though net.Dial doesn't handle TLS directly
		} else {
			port = "80"
		}
	}
	
	addressToDial := net.JoinHostPort(host, port)
	log.Printf("Attempting to dial: %s", addressToDial)

	// Unsafe net.Dial: Attacker controls 'addressToDial' via the 'url' parameter
	conn, err := net.DialTimeout("tcp", addressToDial, 5*time.Second)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect: %v", err), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// In a real scenario, you might read from conn here.
	// For this PoC, just a success message.
	fmt.Fprintf(w, "Successfully connected to %s", addressToDial)

    // If http.Get was used:
    /*
    resp, err := http.Get(targetURL) // Also vulnerable
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch URL: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	w.Write(body)
    */
}

func main() {
	http.HandleFunc("/fetch", fetchResourceHandler)
	log.Println("Server starting on :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
```

*(Note: The snippet requires `import "net/url"` for `url.Parse` and `net.JoinHostPort`)*

In this example, an attacker can provide URLs like:

  * `http://localhost:8080/fetch?url=http://127.0.0.1:22` (to check for an SSH server on localhost)
  * `http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/` (to attempt to access AWS EC2 instance metadata)
  * `http://localhost:8080/fetch?url=http://internal-service.local:8000/admin` (to access an internal service)

## Detection Steps

1.  **Manual Code Review:**
      * Search for usages of `net.Dial`, `net.DialTimeout`.
      * Search for usages of `http.Get`, `http.Post`, `http.Client.Do`, `http.NewRequest`.
      * Trace the origin of the `address` or `URL` argument passed to these functions. If it originates from user input (HTTP parameters, headers, body, database values controllable by users) without strict validation against an allowlist, it's a potential vulnerability.
2.  **Static Application Security Testing (SAST):**
      * Tools like `gosec` can detect some instances of SSRF or unsafe `net.Dial` usage with taint analysis (tracking data flow from untrusted sources to sensitive sinks).
      * `gosec` rule G107 (`SSRFAddress`) is specifically for this.
3.  **Dynamic Application Security Testing (DAST):**
      * Use DAST tools or manual penetration testing to craft requests with payloads targeting internal IP addresses, localhost, or known metadata endpoints.
      * Fuzz input fields that are used to construct target URLs or addresses.
4.  **Dependency Scanning:** While this vulnerability is primarily in the application code, a vulnerable third-party library that makes network requests could also introduce it. Tools that detect vulnerable dependencies might indirectly help.

## Proof of Concept (PoC)

Using the vulnerable code snippet above:

1.  **Save the code:** Save the snippet as `main.go`.
2.  **Run the server:** `go run main.go`. It will start listening on port 8080.
3.  **Attempt to access an internal service (e.g., a common port like 22/SSH on localhost):**
    Open a web browser or use `curl`:
    ```bash
    curl "http://localhost:8080/fetch?url=http://127.0.0.1:22"
    ```
      * **If port 22 is open and listening:** The server might respond with "Successfully connected to 127.0.0.1:22" or an error related to the SSH protocol if `conn.Read` was attempted. The key is that the connection was attempted.
      * **If port 22 is closed:** The server will respond with an error like "Failed to connect: dial tcp 127.0.0.1:22: connect: connection refused".
4.  **Attempt to access AWS EC2 Instance Metadata (if running on EC2):**
    ```bash
    curl "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    ```
    If successful and the server attempts to read from the connection (or if `http.Get` was used), it could leak IAM credentials.

The PoC demonstrates that an attacker can direct the server to make TCP connections to arbitrary hosts and ports based on the `url` parameter.

## Risk Classification

  * **OWASP Top 10 (2021):** A10 - Server-Side Request Forgery (SSRF)
  * **CWE-918:** Server-Side Request Forgery (SSRF)
  * **CVSS v3.1 Score:** Typically High (e.g., 7.5 to 9.1, AV:N/AC:L/PR:N/UI:N/S:U or S:C/C:H/I:L/A:N, depending on information exposed and internal system impact). If it leads to RCE on internal systems or metadata exposure, it can be Critical (9.0-10.0).

## Fix & Patch Guidance

1.  **Strict Allowlist Validation:**
      * The most robust solution is to validate the user-provided host or URL against a pre-defined list of allowed targets (hostnames, IPs, and ports).
      * Reject any request that does not match an entry in the allowlist.
    <!-- end list -->
    ```go
    var allowedHosts = map[string]bool{
        "api.example.com:443": true,
        "partner-service.com:80": true,
    }
    // ...
    targetHostPort := net.JoinHostPort(host, port)
    if !allowedHosts[targetHostPort] {
        http.Error(w, "Target host not allowed", http.StatusForbidden)
        return
    }
    // Proceed with net.Dial
    ```
2.  **Disallow IP Addresses / Enforce DNS Resolution to Allowed IPs:**
      * If possible, do not allow direct IP address connections. Require hostnames.
      * After resolving the hostname, verify that the resolved IP address(es) belong to an allowed range or set of IPs. This helps mitigate DNS rebinding attacks if implemented carefully (check all resolved IPs).
3.  **Network Segmentation / Firewalls:**
      * Run the application server in a segmented network with strict egress firewall rules, limiting where it can connect. This is a defense-in-depth measure.
4.  **Dedicated HTTP Clients with Stricter Controls:**
      * When using `http.Client`, configure its `Transport` with a custom `DialContext` function that enforces these checks.
    <!-- end list -->
    ```go
    func NewSafeHTTPClient(allowedHosts map[string]struct{}) *http.Client {
        return &http.Client{
            Transport: &http.Transport{
                DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
                    // `addr` will be "hostname:port"
                    host, _, err := net.SplitHostPort(addr)
                    if err != nil {
                        return nil, fmt.Errorf("invalid address format: %w", err)
                    }

                    // 1. Check if host is in allowlist (most direct)
                    // if _, ok := allowedHosts[host]; !ok { // Or allowedHosts[addr] if port specific
                    //    return nil, fmt.Errorf("host %s not allowed", host)
                    // }

                    // 2. Or, resolve and check IP (more complex, handles CNAMEs etc.)
                    ips, err := net.LookupIP(host)
                    if err != nil {
                        return nil, fmt.Errorf("failed to resolve host %s: %w", host, err)
                    }
                    
                    isAllowedIP := false
                    for _, ip := range ips {
                        // Implement your IP allowlist check here
                        // For example, check if ip.IsLoopback(), ip.IsPrivate(), or in a specific range
                        if ip.IsLoopback() || ip.IsPrivate() { // Example: disallow loopback/private for external calls
                             return nil, fmt.Errorf("resolved IP %s for host %s is not allowed", ip.String(), host)
                        }
                        // More robust: check against a list of allowed IPs/ranges
                    }
                    // If checks pass:
                    var d net.Dialer
                    return d.DialContext(ctx, network, addr)
                },
            },
            Timeout: 10 * time.Second,
        }
    }
    ```
5.  **Avoid Directly Using User Input for `network` type:** The `network` argument in `net.Dial(network, address)` should typically be hardcoded (e.g., "tcp", "tcp4") and not user-controlled.
6.  **Careful Error Handling:** Do not return raw error messages from `net.Dial` or HTTP clients to the user, as they can leak information about the internal network structure.

## Scope and Impact

  * **Scope:** Affects any part of a Go application that makes network requests to destinations determined by external input without proper validation.
  * **Impact:**
      * **Information Disclosure:** Exposure of internal network topology, service banners, and potentially sensitive data from internal services (e.g., cloud metadata, internal APIs).
      * **Integrity Compromise:** Ability to send requests to internal systems, potentially modifying data or state if those systems are writable without strong authentication.
      * **Denial of Service:** The application or internal systems can be targeted for DoS.
      * **Complete System Compromise:** If the SSRF leads to exploitation of a vulnerable internal service that results in RCE on that internal host, or if cloud credentials are stolen, the impact can be severe.

## Remediation Recommendation

1.  **Primary: Implement Strict Allowlist Validation:** Validate any user-supplied address (hostname and port) against a well-defined allowlist of permitted targets. Deny by default.
2.  **Secondary: Input Sanitization/Normalization:** If an allowlist is too restrictive, carefully sanitize and normalize input. For example, resolve hostnames and check if the resulting IPs are within an allowed range. Be wary of DNS rebinding.
3.  **Network Controls:** Use egress firewalls to limit the network connectivity of the server running the Go application.
4.  **Use `gosec`:** Integrate `gosec -exclude=G107 ./...` (if you've audited all G107 warnings) or `gosec ./...` into your CI/CD pipeline to catch potential SSRF vulnerabilities.
5.  **Principle of Least Privilege:** Ensure the application server only has network access to the specific internal/external resources it absolutely needs.
6.  **Regular Security Audits and Penetration Testing:** Specifically test for SSRF vulnerabilities in features that involve external network requests.
7.  **Educate Developers:** Ensure developers are aware of SSRF risks and how to prevent them when using functions like `net.Dial` or `http.Client`.

## Summary

Unsafe use of `net.Dial` or HTTP client methods with attacker-controlled addresses in Go applications is a serious vulnerability that leads to Server-Side Request Forgery (SSRF). This allows attackers to coerce the server into making unauthorized network connections to internal or external systems, potentially leading to information disclosure, internal system compromise, or other attacks. Remediation focuses on strict allowlist validation of target addresses, careful input sanitization, network segmentation, and using security analysis tools.

## References

  * **OWASP SSRF Prevention Cheat Sheet:** [https://cheatsheetseries.owasp.org/cheatsheets/Server\_Side\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
  * **Go `net` package documentation:** [https://pkg.go.dev/net](https://pkg.go.dev/net)
  * **Go `net/http` package documentation:** [https://pkg.go.dev/net/http](https://pkg.go.dev/net/http)
  * **`gosec` (Go Security Checker) G107 rule:** [https://github.com/securego/gosec\#available-rules](https://www.google.com/search?q=https://github.com/securego/gosec%23available-rules) (Look for G107)
  * **CWE-918: Server-Side Request Forgery (SSRF):** [https://cwe.mitre.org/data/definitions/918.html](https://cwe.mitre.org/data/definitions/918.html)
  * **PortSwigger - Server-side request forgery (SSRF):** [https://portswigger.net/web-security/ssrf](https://portswigger.net/web-security/ssrf)
