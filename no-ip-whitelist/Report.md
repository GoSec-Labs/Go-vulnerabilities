## Vulnerability Title

No IP whitelisting on critical endpoints (no-ip-whitelist)

----
An attacker with knowledge of an administrative or internal endpoint that lacks IP whitelisting can directly access it from any location on the internet. This allows them to bypass a crucial layer of security, enabling them to attempt to exploit any other vulnerabilities that may exist in the endpoint's authentication or business logic, such as brute-forcing passwords or injecting malicious payloads. The core of the exploitation is the ability to reach and interact with an endpoint that should have been network-restricted.


### Affected Components or Files

The vulnerability typically resides in the application's routing and middleware logic. In a Golang application, this would most likely be found in:

  * **`main.go`**: Or any file where the HTTP server and routes are defined.
  * **`internal/middleware` or `pkg/middleware`**: A directory containing custom middleware, which is where IP whitelisting logic should be but is absent.
  * **Router Configuration**: Files that configure the HTTP router (e.g., using frameworks like Gin, Chi, or Gorilla Mux) and define handlers for specific paths.


### Vulnerable Code Snippet

Here's a simple example using Go's standard `net/http` library, where an `/admin` endpoint is exposed without any IP-based access control.

```go
package main

import (
    "fmt"
    "log"
    "net/http"
)

// A handler for a sensitive administrative endpoint.
func adminHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    fmt.Fprintln(w, "Welcome to the Admin Panel!")
}

func main() {
    // Public endpoint, accessible to everyone.
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintln(w, "This is the public page.")
    })

    // Critical endpoint without IP whitelisting.
    http.HandleFunc("/admin", adminHandler)

    log.Println("Server is starting on port 8080...")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatalf("Could not start server: %s\n", err)
    }
}
```

In this snippet, the `/admin` route is available to any IP address that can reach the server.

-----

### Detection Steps

1.  **Identify Critical Endpoints**: Review the application's source code or API documentation to identify endpoints that should be for internal or administrative use only (e.g., paths containing `/admin`, `/internal`, `/management`).
2.  **Manual Access Attempts**: From an external and untrusted IP address, use a tool like `curl` or a web browser to attempt to access the identified critical endpoints.
3.  **Check HTTP Response**: If the server responds with a `200 OK` or any other success-like status code, and not a `403 Forbidden` or a network-level rejection, the endpoint is not protected by IP whitelisting.
4.  **Code Review**: Manually inspect the Go source code for the handlers of critical endpoints. Verify the absence of any middleware or logic that checks the request's remote IP address.

-----

### Proof of Concept (PoC)

1.  **Run the vulnerable Go application** provided in the snippet above.

2.  **From a machine with any IP address**, execute the following command:

    ```sh
    curl http://<server-ip-or-domain>:8080/admin
    ```

3.  **Expected Vulnerable Outcome**: The server will respond with:

    ```
    Welcome to the Admin Panel!
    ```

    This successful response from an unauthorized IP address proves the vulnerability.

-----

### Risk Classification

  * **CWE-284: Improper Access Control**
  * **CVSS 3.1 Score: 7.5 (High)** - Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
      * This score assumes the endpoint exposes sensitive information. The impact could be higher if it allows for modification (`I:H`) or denial of service (`A:H`).

-----

### Fix & Patch Guidance

Implement a middleware function that checks the incoming request's IP address against a predefined list of allowed IPs.

Here is a patched version of the code:

```go
package main

import (
    "fmt"
    "log"
    "net"
    "net/http"
)

// ipWhitelistMiddleware wraps a handler and restricts access to a list of IPs.
func ipWhitelistMiddleware(next http.Handler, whitelistedIPs []string) http.Handler {
    // Create a map for quick IP lookup.
    ipMap := make(map[string]struct{})
    for _, ip := range whitelistedIPs {
        ipMap[ip] = struct{}{}
    }

    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Get the client's IP address.
        ip, _, err := net.SplitHostPort(r.RemoteAddr)
        if err != nil {
            http.Error(w, "Forbidden", http.StatusForbidden)
            log.Printf("Could not parse remote address: %v", err)
            return
        }

        // Check if the IP is in the whitelist.
        if _, ok := ipMap[ip]; !ok {
            http.Error(w, "Forbidden", http.StatusForbidden)
            log.Printf("Blocked access from non-whitelisted IP: %s", ip)
            return
        }

        // If the IP is whitelisted, serve the request.
        next.ServeHTTP(w, r)
    })
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    fmt.Fprintln(w, "Welcome to the Admin Panel!")
}

func main() {
    // In a real application, load this from a config file or environment variable.
    adminWhitelist := []string{"127.0.0.1", "::1"}

    // Public endpoint.
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintln(w, "This is the public page.")
    })

    // Wrap the admin handler with the IP whitelist middleware.
    adminRouter := http.NewServeMux()
    adminRouter.HandleFunc("/admin", adminHandler)
    http.Handle("/admin", ipWhitelistMiddleware(adminRouter, adminWhitelist))

    log.Println("Server is starting on port 8080...")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatalf("Could not start server: %s\n", err)
    }
}
```

-----

### Scope and Impact

The **scope** of this vulnerability is limited to the unprotected endpoints. However, the **impact** can be organization-wide if those endpoints control critical functionalities. An attacker gaining unauthorized access to an admin panel could lead to:

  * **Complete data compromise**: Theft of user data, financial records, or intellectual property.
  * **System-wide disruption**: The attacker could modify or delete data, change system configurations, or shut down services.
  * **Reputational damage**: Loss of customer trust following a breach.
  * **Further network penetration**: The compromised application could be used as a pivot point to attack other internal systems.

-----

### Remediation Recommendation

1.  **Audit all endpoints** to identify those that should not be publicly accessible.
2.  **Implement IP whitelisting** for all identified critical endpoints using a middleware approach as demonstrated in the patched code.
3.  **Externalize the whitelist configuration**: Store the list of allowed IP addresses in a configuration file or environment variables, not hardcoded in the application. This allows for easier management of the whitelist without requiring a code change and redeployment.
4.  **Handle Proxies Correctly**: If your application is behind a reverse proxy or load balancer, ensure you are correctly extracting the original client's IP from headers like `X-Forwarded-For` or `X-Real-IP`. Be careful to only trust these headers when the request comes directly from your trusted proxy.
5.  **Regularly review and update** the IP whitelist to remove IPs that are no longer needed and add new ones as required.

-----

### Summary

The absence of IP whitelisting on critical endpoints is a significant security misconfiguration that exposes sensitive parts of a Golang application to unnecessary risk. It allows attackers to directly interact with administrative interfaces from anywhere on the internet. Implementing a simple IP-based access control middleware is an effective first line of defense to drastically reduce the attack surface and prevent unauthorized access attempts.

-----

### References

  * [OWASP - Improper Access Control](https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control)
  * [Go `net/http` Package Documentation](https://www.google.com/search?q=%5Bhttps://pkg.go.dev/net/http%5D\(https://pkg.go.dev/net/http\))
  * [Go `net` Package Documentation](https://www.google.com/search?q=%5Bhttps://pkg.go.dev/net%5D\(https://pkg.go.dev/net\))