## Vulnerability Title
Running Debug HTTP Servers in Production (Exposed `net/http/pprof` Endpoints)

### Severity Rating
**High🟠**

### Description
Applications built with Go (Golang) often include the `net/http/pprof` package for runtime profiling and debugging. When imported, this package automatically exposes a set of HTTP endpoints, typically under `/debug/pprof/`, that provide detailed performance and diagnostic information about the running application. If these endpoints are left enabled and accessible in a production environment, they can inadvertently expose sensitive internal application data, performance metrics, and even potentially enable denial-of-service (DoS) attacks.

### Technical Description (for security pros)
The `net/http/pprof` package registers handlers on the default HTTP mux. When imported, it exposes endpoints like:
* `/debug/pprof/`: Index page listing available profiles.
* `/debug/pprof/profile`: Generates a CPU profile (30-second duration by default).
* `/debug/pprof/heap`: Provides a heap memory profile.
* `/debug/pprof/goroutine`: Shows active goroutines with stack traces.
* `/debug/pprof/block`: Block profile showing goroutine blocking events.
* `/debug/pprof/threadcreate`: Thread creation profile.
* `/debug/pprof/trace`: Generates an execution trace.

Exposure of these endpoints in production allows unauthorized access to:
1. **Sensitive Internal Information:** Function names, file paths, and internal data structures revealed in profiles can aid attackers in understanding the application's logic and identifying further vulnerabilities.
2. **Performance Degradation/DoS:** Requesting CPU or trace profiles can be computationally expensive, potentially leading to performance degradation or a denial of service if continuously triggered by an attacker.
3. **Information Disclosure:** Memory profiles can expose sensitive data (e.g., credentials, user data) that might be temporarily present in memory during processing. Goroutine stack traces can reveal sensitive code paths and data in a live system.

### Common Mistakes That Cause This
* **Accidental Import:** Developers might include `_ "net/http/pprof"` for local debugging or development and forget to remove it before deploying to production.
* **Lack of Environment-Specific Configuration:** Applications are not configured to disable or restrict access to debug endpoints based on the deployment environment (e.g., `production` vs. `development`).
* **Using DefaultServeMux for Debugging:** The `pprof` handlers are registered on `http.DefaultServeMux`. If the main application server also uses `http.DefaultServeMux`, the debug endpoints become publicly accessible.
* **Insufficient Network Segmentation:** Even if debug servers are intended for internal use, a lack of proper firewall rules or network segmentation can expose them to the public internet.

### Exploitation Goals
* **Information Gathering:** Obtain insights into application architecture, dependencies, and internal logic.
* **Sensitive Data Disclosure:** Extract credentials, API keys, or user data from memory profiles.
* **Denial of Service (DoS):** Exhaust server resources (CPU, memory) by repeatedly requesting expensive profiles, rendering the application unavailable.
* **Further Exploitation:** Use gathered information to identify and exploit other vulnerabilities (e.g., code injection, logic flaws).

### Affected Components or Files
* Any Go application that imports `net/http/pprof` and serves HTTP requests without properly segregating or disabling these endpoints.
* Specifically, the default HTTP server if `http.DefaultServeMux` is used.

### Vulnerable Code Snippet
```go
package main

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" // This line is the culprit
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello World!")
	})
	log.Fatal(http.ListenAndServe(":8080", nil)) // Uses DefaultServeMux
}
```

### Detection Steps
1. **Manual Inspection:** Review Go application source code for `_ "net/http/pprof"` imports in production-bound codebases.
2. **Network Scanning:** Scan public-facing IP addresses and ports for web servers.
3. **URL Probing:** Once a web server is identified, attempt to access `/debug/pprof/` and its sub-paths (e.g., `/debug/pprof/heap`, `/debug/pprof/profile`). A successful response (e.g., a 200 OK with profiling data or an index page) indicates exposure.
4. **Automated Scanners:** Utilize static application security testing (SAST) tools that can detect the `net/http/pprof` import in Go projects.
5. **Runtime Analysis:** Monitor network traffic for unexpected requests to `/debug/pprof` endpoints.

### Proof of Concept (PoC)
1. Compile and run the vulnerable code snippet above on a publicly accessible server.
2. Open a web browser or use `curl` to navigate to `http://<your-server-ip>:8080/debug/pprof/`.
3. You will see an index page listing the available profiles.
4. To demonstrate data exposure and DoS potential, visit `http://<your-server-ip>:8080/debug/pprof/heap` (for memory profile) or `http://<your-server-ip>:8080/debug/pprof/profile` (for CPU profile). The CPU profile will typically download a file (`profile`) after a 30-second delay, indicating CPU consumption on the server.

### Risk Classification
* **Confidentiality:** High (sensitive internal data, code paths, potentially PII or credentials)
* **Integrity:** Low (direct integrity impact is unlikely, but information gained can aid other attacks)
* **Availability:** Medium (DoS potential through resource exhaustion)

### Fix & Patch Guidance
The primary fix is to ensure that `net/http/pprof` endpoints are **not exposed in production environments.**

1. **Remove the Import:** The simplest and most effective solution is to remove the `_ "net/http/pprof"` import from production builds. Use build tags or conditional compilation to include it only in development/debugging builds.

   **Example (using build tags):**
   Create a file (e.g., `debug_pprof.go`):
   ```go
   // +build debug

   package main

   import _ "net/http/pprof"
   ```
   Then, when building for production, use `go build -tags=release` (assuming your production build tag is `release` and the `debug_pprof.go` file is not tagged for `release`). Or simply don't include this file in production builds.

2. **Separate Debug Server:** If profiling is absolutely necessary in production (e.g., for specific diagnostic purposes), run the `pprof` server on a *separate, internal-only* port and IP address, accessible only by authorized personnel and tightly controlled by firewall rules.

   ```go
   package main

   import (
       "fmt"
       "log"
       "net/http"
       _ "net/http/pprof" // Still needed for the debug server
   )

   func main() {
       // Application server
       http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
           fmt.Fprintf(w, "Hello World!")
       })

       // Start pprof server on a separate, local-only port
       go func() {
           log.Println(http.ListenAndServe("localhost:6060", nil)) // Listen only on localhost
       }()

       // Main application server
       log.Fatal(http.ListenAndServe(":8080", nil))
   }
   ```
   *Note: Even with `localhost` binding, ensure proper network segmentation to prevent port forwarding or tunneling from exposing this port.*

3. **Custom Mux for Pprof:** If you're using a custom HTTP multiplexer (`http.NewServeMux`) for your main application, you can explicitly register the `pprof` handlers to a *different* multiplexer, which is then served on a restricted interface.

   ```go
   package main

   import (
       "fmt"
       "log"
       "net/http"
       "net/http/pprof" // Import directly for explicit handler registration
   )

   func main() {
       // Main application mux
       appMux := http.NewServeMux()
       appMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
           fmt.Fprintf(w, "Hello World!")
       })

       // Pprof mux (for internal use only)
       debugMux := http.NewServeMux()
       debugMux.HandleFunc("/debug/pprof/", pprof.Index)
       debugMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
       debugMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
       debugMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
       debugMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
       // Register other pprof handlers as needed

       // Start pprof server on a separate, local-only port
       go func() {
           log.Println(http.ListenAndServe("localhost:6060", debugMux))
       }()

       // Main application server
       log.Fatal(http.ListenAndServe(":8080", appMux))
   }
   ```

### Scope and Impact
This vulnerability affects any Go application that inadvertently exposes `net/http/pprof` endpoints. The impact ranges from minor information disclosure to severe denial-of-service, depending on the attacker's intent and capabilities, and the sensitivity of the data processed by the application. It can significantly aid reconnaissance phases of more complex attacks.

### Remediation Recommendation
Prioritize the removal of `net/http/pprof` imports from production builds. If profiling in production is a strict requirement, implement a highly restricted, separate debug server that is only accessible from a secure, internal network, ideally behind a VPN or bastion host, with strong authentication and authorization controls. Regularly audit deployed applications for exposed debug endpoints.

### Summary
Leaving Go's `net/http/pprof` debug servers exposed in a production environment is a critical security oversight. It provides attackers with a wealth of information about the application's internals, can be used to mount denial-of-service attacks, and potentially leak sensitive data. The fix involves either removing the debug package from production builds or running the debug server on a highly restricted, internal network interface with strict access controls.

### References
* [Go Profiling - The net/http/pprof package](https://pkg.go.dev/net/http/pprof)
* [Your pprof is showing: IPv4 scans reveal exposed net/http/pprof endpoints](https://mmcloughlin.com/posts/your-pprof-is-showing)
* [Golang Security Best Practices](https://hub.corgea.com/articles/go-lang-security-best-practices)
* [Insecure Configuration - Debug Profiling is Accessible to the Internet - GuardRails](https://docs.guardrails.io/docs/vulnerabilities/go/insecure_configuration)