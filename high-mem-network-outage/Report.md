### **Vulnerability Title**

High Memory Consumption Leading to Denial of Service (Resource Exhaustion)

### **Severity Rating**

**High🟠** (CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H - **7.5**)

### **Description**

This vulnerability allows a remote, unauthenticated attacker to cause a complete Denial of Service (DoS) by sending a request with an extremely large body. If the server application attempts to read this unbounded request body into memory, it will consume an excessive amount of RAM. This can lead to the application crashing due to an Out-Of-Memory (OOM) error or becoming unresponsive, effectively causing a network outage for the service.

### **Technical Description (for security pros)**

By default, Go's standard `net/http` server does not enforce a limit on the size of an incoming request body. A common but dangerous pattern is to read the entire body using `io.ReadAll(r.Body)`. This function will continue to read bytes from the underlying network connection until it encounters an EOF or an error.

An attacker can exploit this by initiating a request and sending a continuous stream of data without ever closing the stream (or sending a body of many gigabytes). The Go application will dutifully attempt to buffer this entire stream into a single byte slice in memory. This unbounded memory allocation will quickly exhaust available system resources, leading the operating system's OOM killer to terminate the process, or causing the system to thrash due to memory swapping, rendering it unavailable.

### **Common Mistakes That Cause This**

  * Reading an HTTP request body with `io.ReadAll()` without first applying a size limit.
  * Decoding structured data (e.g., JSON, XML) directly from a request body without limiting the input stream's size.
  * Assuming that a frontend proxy like Nginx or a load balancer will enforce strict enough limits, without implementing safeguards in the application itself.
  * Failing to handle errors returned from readers when a limit is exceeded, thus not stopping the malicious request gracefully.

### **Exploitation Goals**

The primary and sole goal is **Denial of Service (DoS)**. The attacker aims to make the application and its resources unavailable to legitimate users by crashing the server process.

### **Affected Components or Files**

Any Go file containing code that reads from an untrusted network source without a size limitation is at risk. This is most common in:

  * `http.Handler` or `http.HandlerFunc` implementations.
  * gRPC service methods.
  * Any TCP/UDP server logic that processes incoming data streams.

### **Vulnerable Code Snippet**

This snippet shows a typical HTTP handler that is vulnerable to memory exhaustion because it reads the entire request body without any limits.

```go
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

// Vulnerable handler that reads the entire request body into memory.
func vulnerableUploadHandler(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: io.ReadAll will read from r.Body until EOF.
	// An attacker can send gigabytes of data, causing the server to run out of memory.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	// The application would normally process the body here.
	log.Printf("Received request with body size: %d bytes\n", len(body))
	fmt.Fprintf(w, "Successfully received %d bytes\n", len(body))
}

func main() {
	http.HandleFunc("/upload", vulnerableUploadHandler)
	log.Println("Server starting on :8080...")
	// This server will crash if it receives a request with a very large body.
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
```

### **Detection Steps**

1.  **Manual Code Review:** Search the codebase for usages of `io.ReadAll(r.Body)`, `json.NewDecoder(r.Body)`, or other functions that read from `r.Body`. Verify that the `r.Body` has been wrapped by `http.MaxBytesReader` beforehand.
2.  **Static Analysis (SAST):** Use tools that can detect uncontrolled data reads from network sources.
3.  **Dynamic/Penetration Testing:** Actively test endpoints by sending requests with very large bodies (e.g., 1GB+). Use tools to monitor the server's memory usage in real-time during these tests.

### **Proof of Concept (PoC)**

An attacker can use a simple `curl` command to send an infinite stream of zero-bytes (or a very large file) to the vulnerable endpoint, triggering the OOM condition.

1.  Run the vulnerable Go server.
2.  From a terminal, execute the following command. This will pipe data from `/dev/zero` as the request body.
    ```sh
    # This command sends a continuous stream of data.
    # Monitor the server's memory usage; it will grow until the process is killed.
    curl -X POST --data-binary @/dev/zero http://localhost:8080/upload
    ```
3.  **Result:** The server's memory consumption will rapidly increase. Within seconds, it will likely be terminated by the OS, and the `curl` command will fail with a connection error.

### **Risk Classification**

  * **CWE-400:** Uncontrolled Resource Consumption
  * **CWE-789:** Uncontrolled Memory Allocation
  * **OWASP API Security Top 10:** API4:2023 - Unrestricted Resource Consumption

### **Fix & Patch Guidance**

The idiomatic and correct way to fix this in Go is to wrap the request body with `http.MaxBytesReader`. This wrapper enforces a byte limit on the reader.

**Patched Code Snippet:**

```go
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

const MAX_UPLOAD_SIZE = 10 * 1024 * 1024 // 10 MB

// Secure handler that limits the request body size.
func secureUploadHandler(w http.ResponseWriter, r *http.Request) {
	// FIX: Wrap the request body with http.MaxBytesReader to enforce a limit.
	r.Body = http.MaxBytesReader(w, r.Body, MAX_UPLOAD_SIZE)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		// http.MaxBytesReader returns a specific error type when the limit is exceeded.
		log.Printf("Error reading body: %v", err)
		http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	log.Printf("Received request with body size: %d bytes\n", len(body))
	fmt.Fprintf(w, "Successfully received %d bytes\n", len(body))
}

func main() {
	http.HandleFunc("/upload", secureUploadHandler)
	log.Println("Server starting on :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
```

### **Scope and Impact**

  * **Scope:** The vulnerability directly affects the server application process.
  * **Impact:** A successful exploit causes a complete **Denial of Service**. The impact can extend to the host machine, as extreme memory pressure can slow down or crash other running processes. This leads to service downtime, potential data loss for in-flight requests, and a poor user experience.

### **Remediation Recommendation**

1.  **Enforce Limits:** Always wrap request bodies with `http.MaxBytesReader` before reading from them. Choose a sensible limit that is appropriate for the endpoint's function.
2.  **Global Middleware:** For APIs, consider applying a limiting middleware to all incoming requests to enforce a default maximum size, preventing any single endpoint from being overlooked.
3.  **Monitoring:** Implement application performance monitoring (APM) to track memory usage and set up alerts for abnormal spikes, which can provide early warning of a potential attack or memory leak.
4.  **Resource Management:** For containerized deployments (e.g., Docker, Kubernetes), set hard memory limits on the container to contain the impact of a memory exhaustion bug and prevent it from taking down the entire host node.

### **Summary**

The "High Memory Consumption" vulnerability is a critical Denial of Service flaw where a Go network service performs an unbounded read from an untrusted source, typically an HTTP request body. This allows an attacker to exhaust server memory and crash the application. The standard Go library provides a direct solution: `http.MaxBytesReader`, which must be used to limit the size of request data before it is processed.

### **References**

  * [Go Documentation: `http.MaxBytesReader`](https://www.google.com/search?q=%5Bhttps://pkg.go.dev/net/http%23MaxBytesReader%5D\(https://pkg.go.dev/net/http%23MaxBytesReader\))
  * [Go Documentation: `io.ReadAll`](https://www.google.com/search?q=%5Bhttps://pkg.go.dev/io%23ReadAll%5D\(https://pkg.go.dev/io%23ReadAll\))
  * [OWASP: Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
  * [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)

### **Vulnerability Title**

High Memory Consumption Leading to Denial of Service (Resource Exhaustion)

### **Severity Rating**

**High** (CVSS: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H - **7.5**)

### **Description**

This vulnerability allows a remote, unauthenticated attacker to cause a complete Denial of Service (DoS) by sending a request with an extremely large body. If the server application attempts to read this unbounded request body into memory, it will consume an excessive amount of RAM. This can lead to the application crashing due to an Out-Of-Memory (OOM) error or becoming unresponsive, effectively causing a network outage for the service.

### **Technical Description (for security pros)**

By default, Go's standard `net/http` server does not enforce a limit on the size of an incoming request body. A common but dangerous pattern is to read the entire body using `io.ReadAll(r.Body)`. This function will continue to read bytes from the underlying network connection until it encounters an EOF or an error.

An attacker can exploit this by initiating a request and sending a continuous stream of data without ever closing the stream (or sending a body of many gigabytes). The Go application will dutifully attempt to buffer this entire stream into a single byte slice in memory. This unbounded memory allocation will quickly exhaust available system resources, leading the operating system's OOM killer to terminate the process, or causing the system to thrash due to memory swapping, rendering it unavailable.

### **Common Mistakes That Cause This**

  * Reading an HTTP request body with `io.ReadAll()` without first applying a size limit.
  * Decoding structured data (e.g., JSON, XML) directly from a request body without limiting the input stream's size.
  * Assuming that a frontend proxy like Nginx or a load balancer will enforce strict enough limits, without implementing safeguards in the application itself.
  * Failing to handle errors returned from readers when a limit is exceeded, thus not stopping the malicious request gracefully.

### **Exploitation Goals**

The primary and sole goal is **Denial of Service (DoS)**. The attacker aims to make the application and its resources unavailable to legitimate users by crashing the server process.

### **Affected Components or Files**

Any Go file containing code that reads from an untrusted network source without a size limitation is at risk. This is most common in:

  * `http.Handler` or `http.HandlerFunc` implementations.
  * gRPC service methods.
  * Any TCP/UDP server logic that processes incoming data streams.

### **Vulnerable Code Snippet**

This snippet shows a typical HTTP handler that is vulnerable to memory exhaustion because it reads the entire request body without any limits.

```go
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

// Vulnerable handler that reads the entire request body into memory.
func vulnerableUploadHandler(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: io.ReadAll will read from r.Body until EOF.
	// An attacker can send gigabytes of data, causing the server to run out of memory.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	// The application would normally process the body here.
	log.Printf("Received request with body size: %d bytes\n", len(body))
	fmt.Fprintf(w, "Successfully received %d bytes\n", len(body))
}

func main() {
	http.HandleFunc("/upload", vulnerableUploadHandler)
	log.Println("Server starting on :8080...")
	// This server will crash if it receives a request with a very large body.
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
```

### **Detection Steps**

1.  **Manual Code Review:** Search the codebase for usages of `io.ReadAll(r.Body)`, `json.NewDecoder(r.Body)`, or other functions that read from `r.Body`. Verify that the `r.Body` has been wrapped by `http.MaxBytesReader` beforehand.
2.  **Static Analysis (SAST):** Use tools that can detect uncontrolled data reads from network sources.
3.  **Dynamic/Penetration Testing:** Actively test endpoints by sending requests with very large bodies (e.g., 1GB+). Use tools to monitor the server's memory usage in real-time during these tests.

### **Proof of Concept (PoC)**

An attacker can use a simple `curl` command to send an infinite stream of zero-bytes (or a very large file) to the vulnerable endpoint, triggering the OOM condition.

1.  Run the vulnerable Go server.
2.  From a terminal, execute the following command. This will pipe data from `/dev/zero` as the request body.
    ```sh
    # This command sends a continuous stream of data.
    # Monitor the server's memory usage; it will grow until the process is killed.
    curl -X POST --data-binary @/dev/zero http://localhost:8080/upload
    ```
3.  **Result:** The server's memory consumption will rapidly increase. Within seconds, it will likely be terminated by the OS, and the `curl` command will fail with a connection error.

### **Risk Classification**

  * **CWE-400:** Uncontrolled Resource Consumption
  * **CWE-789:** Uncontrolled Memory Allocation
  * **OWASP API Security Top 10:** API4:2023 - Unrestricted Resource Consumption

### **Fix & Patch Guidance**

The idiomatic and correct way to fix this in Go is to wrap the request body with `http.MaxBytesReader`. This wrapper enforces a byte limit on the reader.

**Patched Code Snippet:**

```go
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

const MAX_UPLOAD_SIZE = 10 * 1024 * 1024 // 10 MB

// Secure handler that limits the request body size.
func secureUploadHandler(w http.ResponseWriter, r *http.Request) {
	// FIX: Wrap the request body with http.MaxBytesReader to enforce a limit.
	r.Body = http.MaxBytesReader(w, r.Body, MAX_UPLOAD_SIZE)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		// http.MaxBytesReader returns a specific error type when the limit is exceeded.
		log.Printf("Error reading body: %v", err)
		http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	log.Printf("Received request with body size: %d bytes\n", len(body))
	fmt.Fprintf(w, "Successfully received %d bytes\n", len(body))
}

func main() {
	http.HandleFunc("/upload", secureUploadHandler)
	log.Println("Server starting on :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
```

### **Scope and Impact**

  * **Scope:** The vulnerability directly affects the server application process.
  * **Impact:** A successful exploit causes a complete **Denial of Service**. The impact can extend to the host machine, as extreme memory pressure can slow down or crash other running processes. This leads to service downtime, potential data loss for in-flight requests, and a poor user experience.

### **Remediation Recommendation**

1.  **Enforce Limits:** Always wrap request bodies with `http.MaxBytesReader` before reading from them. Choose a sensible limit that is appropriate for the endpoint's function.
2.  **Global Middleware:** For APIs, consider applying a limiting middleware to all incoming requests to enforce a default maximum size, preventing any single endpoint from being overlooked.
3.  **Monitoring:** Implement application performance monitoring (APM) to track memory usage and set up alerts for abnormal spikes, which can provide early warning of a potential attack or memory leak.
4.  **Resource Management:** For containerized deployments (e.g., Docker, Kubernetes), set hard memory limits on the container to contain the impact of a memory exhaustion bug and prevent it from taking down the entire host node.

### **Summary**

The "High Memory Consumption" vulnerability is a critical Denial of Service flaw where a Go network service performs an unbounded read from an untrusted source, typically an HTTP request body. This allows an attacker to exhaust server memory and crash the application. The standard Go library provides a direct solution: `http.MaxBytesReader`, which must be used to limit the size of request data before it is processed.

### **References**

  * [Go Documentation: `http.MaxBytesReader`](https://www.google.com/search?q=%5Bhttps://pkg.go.dev/net/http%23MaxBytesReader%5D\(https://pkg.go.dev/net/http%23MaxBytesReader\))
  * [Go Documentation: `io.ReadAll`](https://www.google.com/search?q=%5Bhttps://pkg.go.dev/io%23ReadAll%5D\(https://pkg.go.dev/io%23ReadAll\))
  * [OWASP: Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
  * [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)