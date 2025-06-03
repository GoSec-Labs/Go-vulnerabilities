## Vulnerability Title

Leaky nodeinfo over HTTP (nodeinfo-http-leak)

### Severity Rating

**Low🟢 to Medium🟡**

The severity of this vulnerability depends heavily on the sensitivity of the information being exposed. It is typically rated as low to medium but can be elevated if the leaked data enables further, more severe attacks.

### Description

This vulnerability is a specific type of information disclosure that occurs when a server or application, often referred to as a "node" in peer-to-peer or distributed systems, exposes internal state, configuration, or metadata over an unauthenticated and unencrypted HTTP endpoint. This information, commonly structured in a "nodeinfo" or similar status endpoint, can provide attackers with valuable intelligence about the system's architecture, software versions, and operational state, which can be used for reconnaissance and to plan further attacks.

### Technical Description (for security pros)

In distributed systems like blockchain nodes, federated social networks (which use the NodeInfo protocol), or CI/CD runners, it is common for nodes to have an API for status monitoring or administration. A "nodeinfo-http-leak" occurs when this endpoint is inadvertently exposed to the public internet over plain HTTP without proper authentication or authorization controls. An attacker can simply make a GET request to a known or guessable path (e.g., `/status`, `/nodeinfo`, `/info`) and receive a response containing sensitive data. This could include software versions, network peer lists, uptime, hardware specifications, user counts, or other internal metrics that should not be public.

### Common Mistakes That Cause This

  * **Default Endpoints Enabled:** Developers may forget to disable or protect default debugging, health check, or metrics endpoints provided by a framework or library.
  * **Lack of Authentication:** Creating a status or info endpoint for internal use but failing to implement any authentication or IP-based access control, leaving it open to the public.
  * **Binding to Public Interfaces:** Binding the HTTP server for this endpoint to a public network interface (`0.0.0.0`) instead of a private one (`localhost` or a specific internal IP).
  * **Overly Verbose Information:** Including too much sensitive detail in the status response, such as specific patch versions of software, internal IP addresses, or user-specific data.

### Exploitation Goals

The primary goal is **reconnaissance**. An attacker exploits this vulnerability to:

  * **Fingerprint the System:** Identify the exact software and versions being used to find known CVEs.
  * **Map the Network:** In distributed systems, discover the IP addresses and identities of other nodes (peers) in the network.
  * **Identify High-Value Targets:** Analyze the node's metadata to determine if it is a critical or high-activity node worth targeting.
  * **Gather Operational Intelligence:** Understand the system's normal behavior to better craft attacks that can go unnoticed.

### Affected Components or Files

This vulnerability typically resides in the part of the Go application that sets up and registers HTTP handlers.

  * **`net/http` handlers:** The functions responsible for serving the leaky endpoint.
  * **Application Configuration:** Files that define which host and port the admin/status server listens on.
  * **Framework-specific modules:** Any module or library that automatically exposes a status endpoint (e.g., some Prometheus client libraries if misconfigured).

### Vulnerable Code Snippet

This snippet shows a simple Go web server that exposes a struct containing sensitive node information via an unauthenticated HTTP endpoint.

```go
package main

import (
	"encoding/json"
	"net/http"
	"runtime"
)

// NodeInfo contains potentially sensitive information about the running instance.
type NodeInfo struct {
	Version      string   `json:"version"`
	GoVersion    string   `json:"go_version"`
	Peers        []string `json:"peers"` // List of connected peer IP addresses
	PendingJobs  int      `json:"pending_jobs"`
	InternalHost string   `json:"internal_host"`
}

func main() {
	// Example info that should not be public
	info := NodeInfo{
		Version:      "1.2.3-alpha", // Exposes pre-release version
		GoVersion:    runtime.Version(), // Exposes exact Go version
		Peers:        []string{"10.0.1.5:9090", "10.0.1.6:9090"}, // Leaks internal network topology
		PendingJobs:  15,
		InternalHost: "prod-worker-7.internal.local", // Leaks internal hostname
	}

	// This handler exposes the sensitive info to anyone who accesses it.
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	}
	
	// The server is bound to all interfaces, making it publicly accessible if not firewalled.
	http.ListenAndServe(":8080", nil)
}
```

### Detection Steps

1.  **Automated Web Scanning:** Use a web vulnerability scanner to probe for common information-disclosure endpoints like `/info`, `/status`, `/health`, `/metrics`, `/version`, etc.
2.  **Manual Probing:** Manually try to access these common endpoints with a web browser or `curl`.
3.  **Source Code Review:** Review the application's routing and HTTP handler registrations. Look for any endpoints that return system state information and check if they have authentication middleware.
4.  **Network Monitoring:** Monitor network traffic from the application to see if it responds to requests on unexpected ports or paths with structured data.

### Proof of Concept (PoC)

An attacker can simply use `curl` to access the exposed endpoint and retrieve the sensitive information.

1.  Identify the IP address of the target server running the vulnerable Go application (e.g., `198.51.100.10`).
2.  Make a simple HTTP GET request to the `/status` endpoint.

<!-- end list -->

```sh
curl http://198.51.100.10:8080/status
```

3.  The attacker receives the sensitive JSON payload:

<!-- end list -->

```json
{
  "version": "1.2.3-alpha",
  "go_version": "go1.21.5",
  "peers": [
    "10.0.1.5:9090",
    "10.0.1.6:9090"
  ],
  "pending_jobs": 15,
  "internal_host": "prod-worker-7.internal.local"
}
```

This information can then be used to find exploits for `go1.21.5` or to attempt to connect to the internal peer IPs.

### Risk Classification

  * **OWASP Top 10 2021:** A01:2021 – Broken Access Control (as the endpoint lacks access control).
  * **CWE-200:** Exposure of Sensitive Information to an Unauthorized Actor.

### Fix & Patch Guidance

The primary fix is to ensure that sensitive information is not exposed publicly.

1.  **Use a Separate Admin Server:** Run the handler for sensitive information on a separate HTTP server that binds only to a localhost or internal network interface.
2.  **Implement Authentication:** Protect the endpoint with authentication and authorization middleware, ensuring only legitimate administrators can access it.
3.  **Reduce Verbosity:** Remove any unnecessary sensitive data from the public-facing status endpoints. A public health check should simply return an "OK" status.
4.  **Use Firewalls:** Configure network firewalls to block external access to the port serving the sensitive endpoint.

**Fixed Code Example:**

```go
// ... (NodeInfo struct remains the same)

func main() {
    // ... (info struct initialization)

    adminMux := http.NewServeMux()
    // This handler is now on a separate mux
    adminMux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
        // In a real app, add authentication middleware here
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(info)
    })

    // Public server for general traffic
    go func() {
        // ... setup public handlers ...
        http.ListenAndServe(":8080", nil)
    }()

    // Admin server bound only to localhost
    http.ListenAndServe("127.0.0.1:9091", adminMux)
}
```

### Scope and Impact

The scope is limited to the information exposed by the endpoint. The direct impact is information disclosure. The indirect impact can be much higher, as this information provides a roadmap for attackers to launch more targeted and effective attacks on the system or other nodes in its network.

### Remediation Recommendation

  * **Audit all HTTP endpoints** exposed by your application.
  * **Separate public and administrative interfaces.** Administrative or status endpoints should never be exposed on the same interface as the public-facing application if they contain sensitive data.
  * **Apply a principle of least privilege** to the data exposed by any endpoint. If the public doesn't need to know it, don't show it.
  * **Use network policies and firewalls** as a defense-in-depth measure to restrict access to sensitive endpoints.

### Summary

The "Leaky nodeinfo over HTTP" vulnerability is an information disclosure flaw where sensitive metadata about a server or node is exposed through an unauthenticated HTTP endpoint. While often low in direct severity, it provides crucial intelligence for attackers to perform reconnaissance and plan more significant attacks. Remediation focuses on applying proper access controls, such as authentication and binding administrative endpoints to private network interfaces, to ensure that internal state is not accessible to unauthorized actors.

### References

  * [OWASP: Information Disclosure](https://www.google.com/search?q=https://owasp.org/www-community/attacks/Information_Leakage)
  * [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
  * [NodeInfo Protocol Documentation](https://github.com/jhass/nodeinfo) (For context on the formal protocol)