# Developer Tools Accessible in Production (prod-exposed-devtools) in Golang Applications

## Severity Rating

**Overall Severity: Medium🟡 to High🟠**

The exposure of developer tools such as `pprof` and `expvar` in production Golang applications presents a variable risk, generally ranging from Medium to High. The precise severity depends on several factors, including the specific tools and endpoints exposed, the nature of the information revealed, the public accessibility of the endpoints, and the criticality of the application.

The Common Vulnerability Scoring System (CVSS) v3.1 provides a framework for assessing this severity. Below are illustrative scoring scenarios:

| Scenario Description | CVSS v3.1 Vector | CVSS Base Score | Severity Level | Justification |
| --- | --- | --- | --- | --- |
| `expvar` exposing only default `memstats` | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 | Medium | Exposes low-sensitivity runtime memory statistics. Access is typically unauthenticated over the network. |
| `expvar` exposing `cmdline` with sensitive arguments | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 | High | Command-line arguments (`cmdline`) may contain credentials, API keys, or other secrets, leading to a high confidentiality impact. |
| `pprof` index page or basic profiles accessible | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L` | 6.1 | Medium | Exposure of profile index or less sensitive profiles (e.g., goroutine list) reveals some internal structure. Minor performance impact if profiles are triggered by an attacker. |
| `pprof` exposing detailed heap/CPU profiles | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L` | 8.2 | High | Detailed heap or CPU profiles can reveal application logic, internal data structures, and potentially sensitive data in memory. Active profiling can also degrade performance. |
| `pprof` endpoints enabling Denial of Service (DoS) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | 7.5 | High | Attackers can trigger resource-intensive profiling operations (e.g., CPU or heap profiling for extended durations), leading to excessive resource consumption and service unavailability. |

The "Attacker Value" of the exposed information significantly influences the Confidentiality impact. Generic runtime statistics offer low value for direct exploitation, whereas exposed credentials or detailed insights into proprietary application logic are of high value. Similarly, the ease with which an attacker can trigger resource exhaustion and the resulting impact on service availability determine the Availability score, particularly for `pprof` endpoints. For instance, endpoints like `/debug/pprof/profile` or `/debug/pprof/heap` can be manipulated with parameters (e.g., `?seconds=`, `?gc=1`) to induce heavy load.

The prevalence of these tools in Go development and the simplicity of their accidental exposure (often via a single import line) mean that even findings initially assessed as "Medium" (such as basic `expvar` exposure) can pose a broader risk. If attackers can identify numerous such instances across an organization's services through automated scanning, the likelihood of discovering a more critical exposure (e.g., one leaking sensitive `cmdline` arguments) increases. This effectively elevates the aggregate risk, as attackers may be incentivized to probe these common misconfigurations more deeply. The CVSS scores for DoS vulnerabilities in Go, often rated 7.5 (High) , and information disclosure vulnerabilities, which can range from Medium (e.g., 5.7 for a specific CWE-200 instance ) to High, further support this assessment.

## Description

Developer tools accessible in production, often referred to by the shorthand `prod-exposed-devtools`, is a security vulnerability affecting Golang applications. It occurs when Go's built-in debugging, profiling, and metrics exposition packages—primarily `net/http/pprof` for profiling and `expvar` for public variables—are unintentionally left accessible in a live production environment. These tools are invaluable during the development lifecycle for performance analysis, debugging, and monitoring application health. However, their exposure in production introduces significant security risks.

The primary danger lies in the sensitive nature of the information these tools can reveal and their potential for abuse. The `pprof` package provides detailed runtime profiling data, including CPU usage, memory allocation (heap profiles), goroutine states and stack traces, and contention on synchronization primitives like mutexes and channels. The `expvar` package exposes public variables, which by default include command-line arguments (`cmdline`) used to start the application and detailed memory statistics (`memstats`). Applications can also publish custom variables via `expvar`, which might inadvertently include sensitive operational data.

This vulnerability often arises due to the convenient design of these Go packages. In many cases, simply importing them (e.g., `import _ "net/http/pprof"`) is sufficient to register their respective HTTP handlers on Go's default HTTP server mux (`http.DefaultServeMux`). While this simplifies setup for developers during the debugging phase, it can lead to unintentional exposure if the application uses the default mux for its main services and these imports are not conditionally excluded from production builds. This oversight transforms helpful development utilities into security liabilities, potentially leading to information disclosure or Denial of Service (DoS) conditions.

Fundamentally, this issue is a form of security misconfiguration, aligning with OWASP Top 10 A05:2021 – Security Misconfiguration. It also contravenes principles outlined in security standards like the OWASP Application Security Verification Standard (ASVS), which mandate the disabling or securing of debugging and development-assisting features in production environments (e.g., ASVS V14.1.2, V14.2.3). The exposure indicates a gap in secure deployment practices and production hardening processes.

## Technical Description (for security pros)

The technical underpinnings of the `prod-exposed-devtools` vulnerability in Golang applications lie in the behavior of the `net/http/pprof` and `expvar` standard library packages, particularly how they integrate with the HTTP serving mechanism.

**`net/http/pprof` Package:**
When the `net/http/pprof` package is imported, typically as a blank import (`_ "net/http/pprof"`), its `init()` function is executed. This function registers several HTTP handlers on the `http.DefaultServeMux`, which is Go's global, default HTTP request multiplexer. If an application then starts an HTTP server using `http.ListenAndServe(addr, nil)`, it uses this `http.DefaultServeMux`, and consequently, the `pprof` endpoints become active on that server instance.

The primary `pprof` endpoints registered under the `/debug/pprof/` path include:

- `/debug/pprof/`: An HTML index page listing available profiles.
- `/debug/pprof/allocs`: A sampling of all past memory allocations.
- `/debug/pprof/block`: Stack traces that led to blocking on synchronization primitives. Requires `runtime.SetBlockProfileRate` to be called..
- `/debug/pprof/cmdline`: The command line invocation of the current program.
- `/debug/pprof/goroutine`: Stack traces of all current goroutines.
- `/debug/pprof/heap`: A sampling of memory allocations of live objects. Can be parameterized with `gc=1` to run GC before profiling.
- `/debug/pprof/mutex`: Stack traces of holders of contended mutexes. Requires `runtime.SetMutexProfileFraction` to be called..
- `/debug/pprof/profile`: CPU profile. Duration can be specified with the `seconds` query parameter (e.g., `?seconds=30`).
- `/debug/pprof/threadcreate`: Stack traces that led to the creation of new OS threads.
- `/debug/pprof/trace`: A trace of execution of the current program. Duration can be specified with the `seconds` query parameter.
- `/debug/pprof/symbol`: Looks up program counters and maps them to function names.

These endpoints provide deep insights into the application's runtime behavior, memory allocation patterns, concurrency issues, and CPU utilization. While invaluable for developers, this information can be exploited by attackers for reconnaissance or to orchestrate DoS attacks by repeatedly requesting resource-intensive profiles like CPU or heap profiles.

**`expvar` Package:**
Similarly, importing the `expvar` package (e.g., `_ "expvar"`) causes its `init()` function to register an HTTP handler for the `/debug/vars` path on `http.DefaultServeMux`. This endpoint serves a JSON object containing public variables.
By default, `expvar` exposes:

- `cmdline`: An array of strings representing the command-line arguments used to start the application. This can inadvertently leak sensitive information if secrets (passwords, API keys) are passed as arguments.
- `memstats`: Detailed memory statistics from the Go runtime (`runtime.MemStats`), including information about heap allocation, garbage collection, and other memory metrics.
Applications can also publish custom variables using `expvar.NewString`, `expvar.NewInt`, `expvar.NewFloat`, `expvar.NewMap`, or `expvar.Func`. If these custom variables contain sensitive operational data, their exposure via `/debug/vars` becomes a security risk.

**Role of `http.DefaultServeMux`:**
The reliance on `http.DefaultServeMux` is a critical factor. It's a global, shared multiplexer. If an application uses this for its primary request handling (e.g., `http.HandleFunc("/", mainAppHandler)`) and also imports `net/http/pprof` or `expvar`, the debug routes become available on the same network interface and port as the main application services, often without explicit intent from the developer for production environments. This design choice, prioritizing ease of use in development, can become a security oversight if not managed for production.

Starting with Go 1.22, changes in HTTP routing introduced stricter pattern matching. This can lead to panics at startup if a general handler like `http.Handle("GET /", h)` conflicts with the more specific `/debug/vars` or `/debug/pprof/` paths when registered on the same mux. While a panic prevents the application from starting (and thus prevents exposure in that specific conflict scenario), it highlights the inherent complexities and potential issues of relying on global side effects for handler registration. The resolution might involve making the debug routes more specific (e.g., `GET /debug/vars`), but they could still reside on the main, publicly exposed router if not carefully segregated. This underscores that language-level routing improvements do not automatically resolve the underlying security misconfiguration without developer awareness and deliberate secure design choices.

## Common Mistakes That Cause This

The exposure of developer tools in production Golang environments typically stems from a few common mistakes and oversights made during development and deployment:

1. **Unconditional Import of Profiling Packages:** The most frequent cause is the direct, unconditional import of `net/http/pprof` and/or `expvar` in the main application code, often using blank imports (e.g., `_ "net/http/pprof"`). These imports are sufficient to register the debug HTTP handlers globally, making them active if an HTTP server is started using the default ServeMux. Developers may include these for debugging during development and forget to remove or conditionally compile them for production builds.
2. **Using `http.DefaultServeMux` for All Endpoints:** Many simple Go web applications or services use `http.DefaultServeMux` by calling `http.ListenAndServe(addr, nil)`. If `net/http/pprof` or `expvar` are imported, their handlers are automatically registered to this default mux, co-hosting them with application endpoints on the same port and interface, thus exposing them publicly if the application server is public.
3. **Lack of Environment-Specific Configurations:** A failure to differentiate build or runtime configurations between development, staging, and production environments is a significant contributor. Ideally, debug tools should be enabled only in non-production environments. Without mechanisms like build tags or environment variables to control their inclusion or activation, these tools often carry over into production.
4. **Misconfigured Reverse Proxies:** Even if debug endpoints are active, a reverse proxy (like Nginx or Apache) could theoretically block access to them. However, misconfigurations, such as overly permissive proxy rules or failing to explicitly deny paths like `/debug/pprof/` and `/debug/vars`, can lead to their exposure.
5. **Insufficient Access Control:** In rare cases where debug endpoints are intentionally enabled in production (e.g., for emergency diagnostics), failing to protect them with strong authentication (e.g., Basic Auth, mTLS, OAuth2 proxy) and strict IP whitelisting is a critical error. These tools lack built-in authentication.
6. **Ignoring Security Linter/SAST Warnings:** Modern static analysis security testing (SAST) tools and linters can often detect the import of `net/http/pprof` and flag it as a potential issue for production code (e.g., DeepSource GO-S2108 ). Ignoring these warnings can lead to vulnerable deployments.
7. **Misunderstanding of "Safe for Production" Claims:** Go's official documentation mentions that `pprof` is "safe to use in production". This statement primarily refers to the performance overhead of *disabled-by-default* profiles (like CPU profiling, which needs to be actively triggered) rather than the security implications of *exposed HTTP endpoints*. This nuance can be overlooked, leading to a false sense of security about leaving the HTTP handlers active. The performance overhead of an idle `pprof` HTTP listener might be low, but the information disclosure and DoS risks from an *accessible* endpoint are significant.

These mistakes often occur because the "path of least resistance" during development—simply importing a package—is not re-evaluated for its production security implications. The ease of enabling these tools contrasts with the effort required to implement more secure alternatives like conditional compilation or separate, authenticated internal servers. This disparity, coupled with a potential lack of DevSecOps culture or mature CI/CD pipelines that incorporate security checks, allows such misconfigurations to persist into production environments.

## Exploitation Goals

Attackers who discover exposed developer tools like `pprof` and `expvar` in a production Golang application typically have several goals:

1. **Information Gathering and Reconnaissance:** This is often the primary initial goal.
    - **Discovering Application Internals:** `pprof` profiles (heap, goroutine, CPU) and `expvar` output can reveal sensitive details about the application's internal workings. This includes memory layout, data structures, active goroutines and their stack traces (which can show function names and call flows), and custom metrics that might hint at business logic or internal state.
    - **Identifying Secrets and Configuration Data:** The `cmdline` variable exposed by `expvar` is particularly dangerous as it can reveal command-line arguments, which might include hardcoded secrets like API keys, database connection strings, or other sensitive configuration parameters. Even stack traces or memory dumps from `pprof` could inadvertently contain such secrets.
    - **Technology Stack and System Details:** Exposed information can help identify the Go runtime version, build paths, operating system details (from certain profiles), and other libraries or components used by the application. This aids in fingerprinting the system for known vulnerabilities.
    - **Mapping Internal Network Services:** In some cases, profiling data (e.g., network activity within a trace) or custom `expvar` metrics might reveal information about internal services the application communicates with, such as internal API endpoints or database hosts. This was noted in the context of exposed Prometheus Node Exporter metrics revealing internal API endpoints.
2. **Denial of Service (DoS):**
    - **Resource Exhaustion via `pprof`:** Certain `pprof` endpoints, particularly those for CPU profiling (`/debug/pprof/profile`) and heap profiling (`/debug/pprof/heap`), can be triggered to perform resource-intensive operations. Attackers can abuse these by requesting profiles for extended durations (e.g., `/debug/pprof/profile?seconds=3000`) or making frequent requests, thereby overwhelming the server's CPU and/or memory resources. This can lead to severe performance degradation, service unresponsiveness, or even Out Of Memory (OOM) kills, especially in resource-constrained environments like containers. This attack vector is potent because it uses legitimate functionality; the profiling tools are designed to inspect and potentially stress the application.
3. **Identifying Further Vulnerabilities:**
    - The information gathered from exposed developer tools can significantly lower the barrier for discovering and exploiting other vulnerabilities. For instance, knowing specific library versions from profiling data can allow an attacker to search for known CVEs affecting those versions. Understanding internal code paths from CPU or goroutine profiles might reveal logical flaws or unvalidated inputs in less-tested parts of the application.
4. **Causing Performance Degradation:**
    - Even if not aiming for a full DoS, repeated or concurrent access to profiling endpoints by unauthorized parties can consume server resources and degrade the performance of the application for legitimate users.

The information disclosed through these tools can act as a critical "enabler" vulnerability. For example, if command-line arguments exposed by `expvar` reveal a cloud provider API key with broad permissions, an attacker might bypass many other security controls and gain significant unauthorized access. This makes the `prod-exposed-devtools` vulnerability a valuable target for attackers as an initial foothold or a way to escalate privileges and impact.

## Affected Components or Files

The exposure of developer tools in a production Golang application primarily affects the application binary itself, but the consequences can extend to other system components and data:

1. **The Golang Application Binary:** This is the most directly affected component, as it is the process that hosts the HTTP server and exposes the `pprof` and `expvar` endpoints. The binary's runtime state, performance, and availability are at risk.
2. **Configuration Files and Environment Variables:** While the vulnerability doesn't typically grant direct read access to arbitrary files on the filesystem (unlike path traversal), the content of configuration files or environment variables can be indirectly exposed if:
    - They are passed as command-line arguments and revealed by `expvar`'s `cmdline` output.
    - Their values are present in memory and captured within heap dumps or other profiling data accessible via `pprof`.
    - Paths to configuration files are revealed in stack traces or error messages embedded within profiling output.
3. **Source Code and Internal Logic:** Direct source code leakage is not a typical outcome. However, `pprof` profiles (CPU, goroutine, heap) can reveal:
    - Function names and call graphs.
    - Execution paths and hotspots in the code.
    - Internal data structures and their memory layouts.
    This information provides attackers with significant insights into the application's architecture and internal logic, which can be used to identify other weaknesses or craft more targeted attacks.
4. **Host or Container Resources:** In the case of Denial of Service attacks exploiting `pprof` endpoints, the underlying host system or container's resources (CPU and memory) are directly affected. This can lead to the Go application becoming unresponsive or crashing, and potentially impacting other processes running on the same host or within the same container orchestration environment.
5. **Other Internal Systems (in Microservice Architectures):** If the compromised Go application interacts with other internal services (e.g., databases, message queues, other microservices), information exposed through `pprof` or `expvar` could potentially reveal details about these internal systems. For example:
    - Network activity captured in a `pprof` trace might show internal IP addresses and ports of backend services.
    - Custom `expvar` variables or command-line arguments might contain connection strings or API endpoints for these internal services.
    This "indirect" exposure can widen the attack surface and compromise the security of other parts of the infrastructure, even if those other services do not directly expose their own developer tools.

The "blast radius" of this vulnerability, therefore, is not limited to the Go binary itself. It can act as a conduit, exposing sensitive data the application has access to or revealing information about the environment it operates in, thereby increasing the overall risk to the system.

## Vulnerable Code Snippet

The following Go program demonstrates a common way `pprof` and `expvar` endpoints become unintentionally exposed. The vulnerability arises from the combination of blank importing these packages and using the `http.DefaultServeMux` (implicitly, by passing `nil` to `http.ListenAndServe`).

```go
package main

import (
	"expvar" // Registers /debug/vars on http.DefaultServeMux
	"log"
	"net/http"
	_ "net/http/pprof" // Blank import registers /debug/pprof/* handlers on http.DefaultServeMux
	"os"
	"runtime"
	"time"
)

// Example custom expvar variable
var (
	requestsProcessed = expvar.NewInt("my_app.requests_processed")
	lastRequestTime   = expvar.NewString("my_app.last_request_time")
)

// Example application handler
func mainAppHandler(w http.ResponseWriter, r *http.Request) {
	requestsProcessed.Add(1)
	lastRequestTime.Set(time.Now().Format(time.RFC3339))
	w.Write(byte("Hello from Main Application!"))
}

func main() {
	// Publish another custom expvar variable using Func
	expvar.Publish("runtime.num_goroutine", expvar.Func(func() interface{} {
		return runtime.NumGoroutine()
	}))

	// Register a main application handler on the DefaultServeMux
	http.HandleFunc("/", mainAppHandler)

	log.Println("Starting server on :8080...")
	log.Printf("Main application available at http://localhost:8080/")
	log.Printf("Pprof endpoints available at http://localhost:8080/debug/pprof/")
	log.Printf("Expvar endpoint available at http://localhost:8080/debug/vars")
	log.Printf("Command line arguments (exposed via expvar's 'cmdline'): %v", os.Args)

	// Start HTTP server using http.DefaultServeMux
	// If this server is exposed to the internet, pprof and expvar will also be exposed.
	if err := http.ListenAndServe(":8080", nil); err!= nil {
		log.Fatalf("ListenAndServe failed: %v", err)
	}
}
```

**Explanation of Vulnerability:**

1. **`_ "net/http/pprof"`:** The blank import of `net/http/pprof` causes its `init()` function to run. This function registers various profiling handlers (e.g., for heap, goroutines, CPU) under the `/debug/pprof/` path on `http.DefaultServeMux`.
2. **`import "expvar"`:** Importing `expvar` (even without a blank import if its functions like `expvar.Publish` are used, or with a blank import if only default vars are needed) also typically leads to its `init()` function registering the `/debug/vars` handler on `http.DefaultServeMux`. This handler exposes default variables like `cmdline` and `memstats`, as well as any custom variables published by the application (e.g., `my_app.requests_processed`, `my_app.last_request_time`, `runtime.num_goroutine`).
3. **`http.ListenAndServe(":8080", nil)`:** This line starts an HTTP server on port 8080. Passing `nil` as the second argument instructs the server to use `http.DefaultServeMux`.
4. **Combined Effect:** Because both the application handler (`mainAppHandler`) and the debug handlers (`pprof`, `expvar`) are registered on the same `http.DefaultServeMux`, they are all served on port 8080. If this port is accessible from an untrusted network (e.g., the internet), then the debug endpoints become inadvertently exposed.

This code snippet exemplifies how Go's design for developer convenience (automatic handler registration via package initialization) can lead to security vulnerabilities if not explicitly managed for production environments. The "magic" of blank imports performing actions like HTTP handler registration can obscure the fact that network-accessible endpoints are being created, especially if a developer is unaware of these side effects or if there isn't a clear separation between development and production configurations.

## Detection Steps

Detecting exposed developer tools in Golang applications involves a combination of manual checks, automated scanning, and code review.

1. **Manual Verification via HTTP Requests:**
    - Identify the host and port(s) on which the Golang application is listening.
    - Using a web browser or a command-line tool like `curl`, attempt to access the default debug paths:
        - For `expvar`: `http://<host>:<port>/debug/vars`
            - A successful response will typically be a JSON object. Look for keys like `"cmdline"` and `"memstats"`.
        - For `pprof`: `http://<host>:<port>/debug/pprof/`
            - A successful response will typically be an HTML page listing available profiles (e.g., heap, goroutine, profile).
    - Attempt to access specific `pprof` profiles, e.g., `http://<host>:<port>/debug/pprof/heap` or `http://<host>:<port>/debug/pprof/goroutine?debug=2`.
2. **Automated Vulnerability Scanning:**
    - Utilize web application vulnerability scanners that include checks for common debug endpoints. Some commercial and open-source scanners may have signatures for `pprof` and `expvar` exposure. The Nessus scanner, for example, has a plugin to detect exposed Pprof debug files.
    - Employ specialized tools like Nuclei, which uses YAML-based templates to detect specific vulnerabilities. There are publicly available Nuclei templates for detecting Golang `expvar` exposure (e.g., checking for `/debug/vars` and the presence of `"memstats":` and `"cmdline":` in the response).
3. **Static Application Security Testing (SAST) and Code Review:**
    - **SAST Tools:** Some SAST tools can identify the import of `net/http/pprof` or `expvar` packages in the Go source code and flag them as potential security risks for production builds (e.g., DeepSource issue GO-S2108 for `net/http/pprof` exposure).
    - **Manual Code Review:**
        - Search the codebase for imports: `import _ "net/http/pprof"` and `import "expvar"`.
        - Examine how HTTP servers and handlers are initialized. Specifically, check if `http.ListenAndServe` is called with `nil` (indicating use of `http.DefaultServeMux`) or if a custom mux is used.
        - If a custom mux is used (e.g., from frameworks like Gin or Echo, or a custom `http.NewServeMux()`), verify how and where `pprof` and `expvar` handlers are registered to it.
4. **Network Reconnaissance:**
    - Perform port scanning on target servers to identify all open HTTP/HTTPS ports.
    - For each identified web service, conduct the manual verification steps described above.
    - Utilize internet-wide scanning services like Shodan or Censys. These services may index publicly accessible Go applications that are inadvertently exposing `pprof` or `expvar` endpoints. Reports have indicated large numbers of exposed services, such as Prometheus servers (often Go-based and including `pprof`), discoverable through such means.

The effectiveness of these detection methods can vary. If debug endpoints are exposed on non-standard paths or ports, simple path checking might miss them. In such cases, code review or more comprehensive authenticated scans (if internal access is possible) become crucial. The public availability of scanning tools and templates for these vulnerabilities means that attackers can also easily and broadly scan for these misconfigurations, increasing the urgency for defenders to detect and remediate them.

## Proof of Concept (PoC)

This Proof of Concept demonstrates how to access exposed `expvar` and `pprof` endpoints on a vulnerable Golang application, such as the one described in the "Vulnerable Code Snippet" section, assumed to be running on `localhost:8080`.

**Prerequisites:**

- A Golang application with `expvar` and/or `net/http/pprof` imported and their handlers exposed via `http.DefaultServeMux` or another publicly accessible HTTP server. For this PoC, assume the vulnerable code from section 8 is compiled and running: `go run vulnerable_app.go`.
- A command-line tool like `curl` or a web browser.

**PoC 1: Accessing `expvar` Data**

1. **Action:** Open a terminal and execute the following `curl` command:Bash
    
    `curl http://localhost:8080/debug/vars`
    
2. **Expected Outcome:** The command will output a JSON object containing public variables. This will include:JSON
    - `"cmdline"`: An array showing the command-line arguments used to start the application (e.g., `["./vulnerable_app"]`).
    - `"memstats"`: A nested JSON object with detailed Go runtime memory statistics.
    - Custom variables published by the application (e.g., `"my_app.requests_processed": 0`, `"my_app.last_request_time": ""`, `"runtime.num_goroutine": <number>`).
    
    Example (partial) output:
    
    ```go
    {
      "cmdline": ["./vulnerable_app"],
      "memstats": {
        "Alloc": 156672,
        "TotalAlloc": 156672,
        //... many other memory stats...
        "Sys": 69804088,
        "NumGC": 0
      },
      "my_app.last_request_time": "",
      "my_app.requests_processed": 0,
      "runtime.num_goroutine": 2
    }
    ```
    
    This demonstrates unauthorized access to potentially sensitive command-line arguments and internal application metrics.
    

**PoC 2: Accessing `pprof` Data (Heap Profile Example)**

1. **Action:** Open a terminal and execute the following `curl` command to fetch a heap profile:
Bash
    
    `curl -o heap.prof http://localhost:8080/debug/pprof/heap`
    
2. **Expected Outcome:** A file named `heap.prof` will be created in the current directory containing the binary heap profile data.
3. **Verification (Optional but Recommended):** To verify the contents and demonstrate the type of data retrieved, use the `go tool pprof`:
Bash
This will open the `pprof` interactive console. Typing `top` will show the functions allocating the most memory. Typing `web` (if Graphviz is installed) would attempt to generate a visual graph. This step confirms that sensitive profiling data detailing memory allocations and function calls is accessible. 
    
    `go tool pprof heap.prof`
    

**PoC 3: Demonstrating `pprof` DoS Potential (Conceptual)**

While a full DoS might require scripting or multiple concurrent requests, the potential can be illustrated by initiating a long-running CPU profile.

1. **Action:** Open a terminal and execute:
Bash
(Note: For a real DoS attempt, an attacker might use a much larger value for `seconds` or make many simultaneous requests to this or other profiling endpoints like `/debug/pprof/heap?gc=1`).
    
    `curl "http://localhost:8080/debug/pprof/profile?seconds=30"`
    
2. **Observation:** During these 30 seconds, the Go application will be actively profiling CPU usage. On a resource-constrained system or with sufficiently aggressive requests, this can lead to noticeable performance degradation or high CPU usage on the server hosting the Go application.
3. **Expected Outcome (Conceptual for DoS):** If an attacker sends multiple, long-duration profiling requests to endpoints like `/debug/pprof/profile` or `/debug/pprof/heap`, they can exhaust server CPU and memory, leading to a Denial of Service.

These PoCs demonstrate the ease with which an attacker can retrieve sensitive information and potentially impact service availability using standard HTTP tools, highlighting the risks of exposing these developer interfaces in production. The simplicity of using `curl` for information disclosure underscores the low barrier to exploitation once an endpoint is discovered. The `pprof` DoS vector leverages the intended functionality of the tool, making it a subtle attack that is not necessarily blocked by simple input validation; robust access control is the key defense.

## Risk Classification

The exposure of developer tools in production Golang applications is classified based on the type of weakness and its potential impact, aligning with industry-standard taxonomies.

- **CWE (Common Weakness Enumeration):**
    - **CWE-200: Exposure of Sensitive Information to an Unauthorized Actor:** This is the primary classification for the information disclosure aspect of the vulnerability. Exposed `expvar` data (like `cmdline` arguments or custom variables) and `pprof` profiles (heap dumps, goroutine stacks) can reveal internal application state, configurations, potential secrets, and operational data to unauthorized parties.
    - **CWE-400: Uncontrolled Resource Consumption:** This classification applies to the Denial of Service (DoS) risk, particularly from abusing `pprof` endpoints. Triggering CPU or heap profiling for extended periods or with high frequency can lead to excessive CPU and memory usage, potentially exhausting server resources and causing service unavailability.
    - **CWE-215: Insertion of Sensitive Information into Log File / CWE-532: Information Exposure Through Log Files (variant):** While a secondary risk, if sensitive information exposed by `pprof` or `expvar` (e.g., command-line arguments containing secrets) is then logged by an intermediary system (like a reverse proxy logging full URLs with query parameters, or the application itself logging debug output), this could lead to sensitive data being written to logs. This is more about how the exposed data might be further mishandled.
- **OWASP Top 10 2021:**
    - **A05:2021 – Security Misconfiguration:** This vulnerability is a classic example of security misconfiguration. Developer tools intended for debugging and profiling in controlled environments are incorrectly left enabled and accessible in production. This often results from default configurations not being hardened, insecure deployment practices, or a lack of environment-specific controls.
- **OWASP ASVS (Application Security Verification Standard):**
The exposure of these tools typically violates several ASVS requirements, particularly within V14 Configuration. For instance:
    - **ASVS V14.1.2 (Build and Deployment):** This section (though the specific text for 14.1.2 isn't in the provided snippets, V14.1 generally covers secure build/deployment) would likely imply that debug features should be stripped or disabled during the production build process.
    - **ASVS V14.2.3 (Application Configuration):** This section (similarly, specific text not provided, but V14.2 covers hardening) would require that development and debugging functionality is not present or is securely disabled in production environments. Snippet  generally states, "Configurations for production should be hardened to protect against common attacks, such as debug consoles..." which aligns with this.
- **Likelihood:**
    - **High:** The ease of accidental exposure (e.g., via blank imports of `net/http/pprof` and `expvar` using the default HTTP mux) combined with the increasing availability of automated scanning tools and public templates (like Nuclei templates ) makes discovery by attackers relatively straightforward for publicly accessible applications.
- **Impact:**
    - **Information Disclosure:** Medium to High. Exposure of generic runtime statistics might be Low impact, but `cmdline` arguments containing secrets, or detailed `pprof` profiles revealing proprietary logic or in-memory sensitive data, can lead to High confidentiality impact.
    - **Denial of Service:** Medium to High. Abusing `pprof` endpoints can lead to significant resource consumption and service outages. The impact depends on the application's resilience and the attacker's resources.
    - **Overall:** The combined potential for significant information leakage and service disruption warrants a Medium to High impact rating.

The classification under OWASP A05 is particularly pertinent because it frames the issue not as an inherent flaw within the Go language or its standard library tools (`pprof`, `expvar`), but as a failure in the secure configuration and deployment of applications utilizing these tools. This perspective correctly shifts the focus towards improving operational security, build processes, and developer awareness regarding production hardening. The ASVS requirements further solidify this, providing a recognized baseline that explicitly calls for the disabling or securing of such debug features in production environments, indicating an industry consensus on the associated risks.

## Fix & Patch Guidance

Addressing the `prod-exposed-devtools` vulnerability requires a multi-layered approach, focusing on preventing the inclusion or exposure of these tools in production environments. The most robust solutions involve compile-time controls, followed by runtime segregation and network-level restrictions as defense-in-depth measures.

The following table compares various remediation techniques:

| Technique | Pros | Cons | Typical Implementation Effort | Recommended for Production? |
| --- | --- | --- | --- | --- |
| **1. Conditional Compilation (Build Tags)** | Completely removes debug code from production binaries; most secure. | Requires careful code organization; can add complexity to build process if not planned early. | Medium | **Strongly Recommended** |
| **2. Conditional Registration (Env Variables)** | Flexible runtime control; easier to toggle for specific prod instances if absolutely needed. | Debug code still present in binary; relies on correct env var setup (misconfiguration risk). | Low to Medium | Use with caution |
| **3. Separate HTTP Server (localhost-bound)** | Isolates debug traffic; debug endpoints not on the main application port/interface. | Adds slight complexity (managing another server); still requires code for debug server in binary. | Medium | Recommended (if 1 is hard) |
| **4. Non-Default HTTP ServeMux (Internal)** | Finer-grained control than `http.DefaultServeMux`; can apply specific middleware. | Debug code still in binary; relies on correct mux configuration and access control. | Medium | Use with caution |
| **5. Authentication & Authorization** | Provides access control if endpoints *must* be exposed (highly discouraged). | Adds complexity; auth can have flaws; still exposes attack surface. | Medium to High | Last resort; high scrutiny |
| **6. Reverse Proxy Blocking** | Network-level defense; can be applied externally without code changes. | Can be bypassed by internal threats or proxy misconfiguration; debug code still active on app server. | Low to Medium | Good defense-in-depth |
| **7. Disable `pprof` Profiling Rates** | Reduces performance impact of *active* block/mutex profiling if accidentally enabled. | Does not prevent endpoint exposure or other profile types from being accessed/triggered. | Low | Good practice, not a full fix |

**Detailed Guidance:**

1. **Conditional Compilation using Go Build Tags (Preferred Method):**
This is the most effective way to ensure that `net/http/pprof` and `expvar` are not included in production builds.
    - Isolate the import of `net/http/pprof`, `expvar`, and any associated handler registration logic into separate Go files (e.g., `debug_enabled.go`).
    - Add a build tag to these files, for example, `//go:build debug` or `//go:build pprof_enabled`.
    - Create corresponding stub files (e.g., `debug_disabled.go`) with the opposite build tag (e.g., `//go:build!debug`) that do not import these packages or register handlers.
    - Compile production builds without the debug tag (e.g., `go build.`) and development/staging builds with the tag (e.g., `go build -tags=debug.`).
    - This ensures the profiling code and HTTP handlers are entirely absent from the production binary.
2. **Conditional Registration via Environment Variables (Alternative):**
If build tags are difficult to integrate into an existing build system, use environment variables to control the registration of debug handlers at application startup.
    - The application checks for an environment variable (e.g., `ENABLE_DEBUG_ENDPOINTS=true`).
    - Only if the variable is set to true (or a specific value indicating a non-production environment) should the `net/http/pprof` and `expvar` packages be (conditionally) imported or their handlers registered.
    - Libraries like `github.com/anacrolix/envpprof` can simplify this by enabling `pprof` features based on the `GOPPROF` environment variable.
    - **Caution:** The debug code is still present in the binary, and misconfiguration of the environment variable can lead to exposure.
3. **Separate HTTP Server for Debug Endpoints:**
Run the `pprof` and `expvar` handlers on a completely separate `http.Server` instance.
    - This debug server should listen on a different port than the main application server (e.g., `localhost:6061` or an internal-only IP address).
    - Ensure this debug port is not exposed externally (e.g., blocked by firewall rules, not mapped in Docker/Kubernetes service definitions for public access).
    - Example:
    Go
        
        ```go
        // In a debug-only build or controlled environment
        debugMux := http.NewServeMux()
        debugMux.HandleFunc("/debug/vars", expvar.Handler())
        debugMux.HandleFunc("/debug/pprof/", pprof.Index)
        //... register other pprof handlers
        go func() {
            log.Println("Starting debug server on localhost:6061")
            if err := http.ListenAndServe("localhost:6061", debugMux); err!= nil {
                log.Printf("Debug server failed: %v", err)
            }
        }()
        ```
        
4. **Use a Non-Default, Isolated HTTP ServeMux:**
If debug endpoints must run within the same server process as the main application (less ideal than a separate server), do not use `http.DefaultServeMux`.
    - Create a new `http.ServeMux` specifically for debug endpoints.
    - Register `pprof` and `expvar` handlers to this dedicated mux.
    - This debug mux should then be exposed only on an internal path or port, potentially with additional middleware for access control, and not on the primary application listener if that listener is public. Frameworks like Gin or Echo allow registering `pprof` on specific router groups which can then have middleware applied.
5. **Authentication and Authorization (Use with Extreme Caution):**
If there's an unavoidable, audited requirement for production access to debug endpoints (e.g., for live, emergency troubleshooting by authorized personnel), implement strong authentication.
    - Wrap the debug handlers (or the entire debug mux/router group) with robust authentication middleware (e.g., HTTP Basic Authentication over HTTPS, mTLS, or an OAuth2/OIDC proxy).
    - Combine with IP address whitelisting to restrict access to specific trusted sources.
    - Ensure all access is logged and audited.
    - This approach still carries risk and should be a last resort.
6. **Reverse Proxy Configuration:**
As a defense-in-depth measure, configure any internet-facing reverse proxies (e.g., Nginx, Apache HTTPD, cloud load balancers) to explicitly block external requests to known debug paths like `/debug/vars` and `/debug/pprof/`.
    - **Nginx Example:**Nginx
        
        `location /debug/ {
            deny all;
            return 403;
        }`
        
    - **Apache HTTPD Example:**Apache
        
        `<Location /debug/>
            Require all denied
        </Location>`
        
    - This should not be the sole defense, as it doesn't remove the handlers from the Go application itself, which might still be accessible internally or if the proxy is misconfigured.
7. **Disable `pprof` Profiling Rates:**
If block or mutex profiling has been enabled programmatically (e.g., via `runtime.SetBlockProfileRate(1)` or `runtime.SetMutexProfileFraction(1)`), ensure they are set back to 0 (disabled) in production code to avoid continuous background profiling overhead, unless explicitly needed and controlled. This primarily addresses performance, not endpoint exposure, but is good practice.

By combining these strategies, particularly prioritizing compile-time exclusion and runtime segregation, organizations can significantly reduce the risk of `prod-exposed-devtools`.

## Scope and Impact

The scope and impact of exposed developer tools in Golang applications vary depending on the specific information or functionality made accessible and the context of the application.

**Confidentiality Impact:**

- **High:** If highly sensitive data is exposed. This can occur if:
    - `expvar`'s `cmdline` output reveals credentials (database passwords, API keys), private keys, or sensitive configuration parameters passed as command-line arguments.
    - Custom `expvar` variables publish sensitive application state or business data.
    - `pprof` heap dumps contain sensitive data in memory (e.g., user session data, unencrypted PII, cryptographic keys) that an attacker can extract and analyze.
    - Detailed `pprof` profiles (CPU, goroutine) reveal proprietary algorithms, internal application logic, or system architecture details that could be used to plan further attacks or for intellectual property theft.
- **Low to Medium:** If the exposed information is less sensitive, such as:
    - Generic runtime statistics from `expvar` (`memstats` without sensitive custom variables).
    - `pprof` goroutine lists or basic profiling information that doesn't reveal critical operational details or secrets.
    Even less sensitive information can still aid an attacker in fingerprinting the application and its environment.

**Integrity Impact:**

- **None Directly:** The `pprof` and `expvar` HTTP endpoints are typically read-only concerning the application's persistent data or configuration. Accessing them does not directly modify files or database records.
- **Indirectly Low to High:** If information disclosed through these endpoints (e.g., credentials, session tokens, exploitable configuration details) is subsequently used by an attacker to gain unauthorized access to other systems or interfaces with write capabilities, then the integrity of data or system configurations can be compromised. For example, an API key exposed via `cmdline` could be used to modify data via that API. The impact here depends on the privileges associated with the compromised credentials/access.

**Availability Impact:**

- **High:** If `pprof` endpoints are abused for Denial of Service (DoS) attacks. As discussed, certain `pprof` operations like CPU profiling (`/debug/pprof/profile`) or heap profiling (`/debug/pprof/heap`, especially with `gc=1`) are resource-intensive. An attacker can trigger these operations repeatedly or for extended durations, leading to:
    - CPU exhaustion.
    - Memory exhaustion, potentially causing Out Of Memory (OOM) errors and application crashes.
    - Overall service unresponsiveness or complete outage.
- **Low:** If only `expvar` is exposed, the direct availability impact is generally low. Requesting `/debug/vars` is typically lightweight unless custom `expvar.Func` implementations are computationally expensive. However, even frequent polling of `expvar` by many unauthorized clients could add some load. The primary availability risk comes from `pprof`.

**Scope (CVSS Metric):**

- **Typically Unchanged (U):** In most CVSS scoring scenarios for this vulnerability, the scope remains Unchanged. This means the exploit impacts components within the same security authority as the vulnerable Go application itself (e.g., the application crashes, or its data is exposed). The vulnerability does not, by itself, typically grant the attacker control over a separate security authority (like the underlying operating system with different privileges, or a completely separate administrative domain).
- **Consideration for "Effective Scope":** While the CVSS Scope metric might be Unchanged for the vulnerability itself, the *effective scope* of a successful exploitation can be much wider and should be considered in the overall risk assessment. If exposed credentials grant administrative access to other critical systems (e.g., cloud provider consoles, databases, identity management systems), the ultimate impact transcends the initially compromised Go application. This distinction is crucial for communicating the true business risk. An attacker obtaining AWS root credentials via an exposed `cmdline` argument has effectively achieved a scope change in terms of business impact, even if the `prod-exposed-devtools` vulnerability itself is scored S:U.

In summary, the impact ranges from moderate information disclosure and minor performance degradation to severe data breaches and complete denial of service, contingent on the specifics of the exposure.

## Remediation Recommendation

A robust remediation strategy for "Developer tools accessible in production" involves a defense-in-depth approach, prioritizing the complete removal of these tools from production builds where possible, and layering additional controls if some level of internal access is deemed necessary.

**Primary Recommendation:**

1. **Exclude Debug Packages from Production Builds using Go Build Tags:**
This is the most secure and highly recommended approach. It ensures that `net/http/pprof`, `expvar`, and any associated handler registration code are entirely absent from the production binaries.
    - **Action:** Isolate all imports of `net/http/pprof` and `expvar`, along with any code that registers their HTTP handlers or publishes custom `expvar` variables, into specific Go files (e.g., `debug_setup.go`, `profiling.go`).
    - Apply a build tag to these files, such as `//go:build debugtools` or `//go:build dev`.
    Go
        
        `// File: debug_setup.go
        //go:build debugtools`
        
        ```go
        package main
        
        import (
        	"expvar"
        	"log"
        	"net/http"
        	_ "net/http/pprof" // Auto-registers on http.DefaultServeMux
        	"runtime"
        )
        
        func init() {
        	log.Println("DEBUG_TOOLS: pprof and expvar enabled via build tag.")
        	// Example: ensure expvar is fully set up if not using DefaultServeMux
        	// or publishing custom vars. Default vars are auto-published.
        	expvar.Publish("custom.goroutines", expvar.Func(func() interface{} {
        		return runtime.NumGoroutine()
        	}))
        }
        ```
        
    - Create corresponding empty or stub files for production builds with an inverse tag (e.g., `//go:build!debugtools`).
    - Compile development/staging builds using `go build -tags=debugtools.`.
    - Compile production builds without this tag: `go build.`.
    - **Benefit:** This method offers the strongest guarantee against accidental exposure as the sensitive code is not present in the production artifact.

**Secondary Recommendations (Defense-in-Depth or when Primary is not immediately feasible):**

1. **Run Debug Interfaces on a Separate, Internal-Only HTTP Server:**
If debug tools are needed in an environment that is production-like (e.g., a dedicated performance testing environment, or for rare, controlled production diagnostics), run them on a separate HTTP server instance.
    - **Action:** Instantiate a new `http.Server` and `http.ServeMux`. Register `pprof` and `expvar` handlers exclusively to this dedicated mux.
    - Bind this server to `localhost` or a specific internal network interface and a distinct port (e.g., `localhost:6061`) that is not publicly accessible.
    - Ensure firewall rules and network configurations prevent external access to this debug-specific port.
    - Example:
    Go
        
        ```go
        // Conditional on a build tag or environment variable for non-production
        // import "net/http/pprof"
        // import "expvar"
        
        debugMux := http.NewServeMux()
        debugMux.HandleFunc("/debug/vars", expvar.Handler()) // expvar.Handler() serves all registered expvars
        debugMux.HandleFunc("/debug/pprof/", pprof.Index)
        debugMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
        debugMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
        debugMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
        debugMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
        // For other pprof profiles like heap, goroutine, etc., use pprof.Handler("heap"), pprof.Handler("goroutine")
        
        go func() {
            log.Println("Starting internal debug server on localhost:6061")
            if err := http.ListenAndServe("localhost:6061", debugMux); err!= nil {
                log.Printf("Internal debug server failed: %v", err)
            }
        }()
        ```
        
2. **Use a Dedicated, Non-Default `http.ServeMux` with Access Controls:**
If a separate server process is not feasible but isolation from `http.DefaultServeMux` is desired, register debug handlers to a dedicated `http.ServeMux` instance within the main application. This mux should then be exposed only on an internal path or port, ideally with strict access controls (authentication, IP whitelisting) applied specifically to it. This is common when using web frameworks like Gin or Echo, where `pprof` can be added as middleware to a specific router group.

**Tertiary Recommendation (Network-Level Defense):**

1. **Configure Reverse Proxies or Web Application Firewalls (WAFs) to Block Debug Paths:**
As an additional layer of security, configure any internet-facing reverse proxies (Nginx, Apache HTTPD, Cloud LBs) or WAFs to explicitly deny all external requests to common debug paths like `/debug/vars` and `/debug/pprof/`.
    - **Nginx:**Nginx
        
        `location ~ ^/debug/(pprof|vars) {
            deny all;
            return 403;
        }`
        
    - **Apache HTTPD:**Apache
        
        `<LocationMatch "^/debug/(pprof|vars)">
            Require all denied
        </LocationMatch>`
        
    - **Note:** This should be considered a secondary control and not the primary defense, as proxy misconfigurations can occur, or internal threats might bypass the proxy.

**Conditional Recommendation (If Production Debugging is Unavoidable and Approved):**

1. **Implement Strong Authentication and Auditing:**
In extremely rare and highly controlled scenarios where temporary production access to debug endpoints is deemed absolutely necessary by authorized personnel:
    - Protect these endpoints with robust, non-default authentication mechanisms (e.g., HTTP Basic Authentication *over HTTPS only*, mTLS, or an OAuth2/OIDC proxy).
    - Combine authentication with strict IP address whitelisting.
    - Ensure all access attempts (successful and failed) are thoroughly logged and audited.
    - Enable these endpoints only for the shortest duration necessary and disable them immediately afterward. This approach carries inherent risks and should be subject to rigorous change control and security review.

**Operational Recommendations:**

- **Regular Audits:** Periodically audit production deployments, configurations (application, proxy, firewall), and network accessibility to ensure no debug endpoints are inadvertently exposed.
- **CI/CD Integration:** Incorporate automated checks into CI/CD pipelines to:
    - Prevent the deployment of builds containing debug packages/imports to production (e.g., by failing the build if `net/http/pprof` is detected in a production-tagged build).
    - Scan deployed applications for exposed debug endpoints as part of post-deployment verification.
- **Developer Education:** Train developers on the security risks associated with `net/http/pprof` and `expvar` in production and the established best practices for managing them. Emphasize that the convenience of these tools in development does not extend to production without careful consideration and controls.

By adopting a defense-in-depth strategy, prioritizing the removal of debug code from production artifacts, and implementing robust access controls and monitoring, organizations can effectively mitigate the risks associated with `prod-exposed-devtools`. Network-level blocking serves as a valuable secondary control but should not be relied upon as the sole defense, as application-level hardening provides more fundamental protection. The most resilient security posture is achieved when technical controls are complemented by strong development processes and security awareness.

## Summary

The exposure of developer tools in production Golang applications (`prod-exposed-devtools`), primarily involving the `net/http/pprof` profiling package and the `expvar` metrics package, constitutes a significant security misconfiguration. These tools, while indispensable for development and debugging, become liabilities when accessible in live environments. They can lead to critical information disclosure—such as application internals, configurations, command-line arguments (potentially containing secrets), and detailed runtime profiles—and can be abused to cause Denial of Service (DoS) by exhausting server resources.

This vulnerability aligns with **OWASP Top 10 A05:2021 – Security Misconfiguration**  and often violates **OWASP ASVS V14** requirements concerning the disabling of debug features in production. The root cause typically lies in the ease with which these tools are enabled (often via simple blank imports that automatically register HTTP handlers on `http.DefaultServeMux`) and a lack of rigorous production hardening practices.

The risks are multifaceted:

- **Confidentiality:** Attackers can gain insights into application logic, discover secrets, and map system architecture, aiding further exploitation (CWE-200).
- **Availability:** `pprof` endpoints can be leveraged to trigger resource-intensive operations, leading to DoS (CWE-400).
- **Performance:** Even non-malicious access can degrade application performance.

Effective remediation requires a defense-in-depth strategy:

1. **Primary:** Utilize Go build tags to completely exclude debug-related code from production binaries. This is the most robust solution.
2. **Secondary:** If compile-time exclusion is challenging, run debug interfaces on a separate HTTP server bound to `localhost` or an internal network, or use a dedicated, non-default `http.ServeMux` with stringent access controls.
3. **Tertiary:** Implement network-level blocking via reverse proxies (Nginx, Apache) or WAFs to prevent external access to known debug paths.
4. **Conditional:** If production access is absolutely unavoidable for critical diagnostics, it must be protected by strong, non-default authentication, IP whitelisting, and comprehensive auditing, and enabled only temporarily.

This vulnerability is preventable. Proactive measures, including secure coding practices, environment-specific build configurations, automated checks in CI/CD pipelines, and developer education on the production implications of development tools, are crucial. Organizations should regularly audit their Golang applications to ensure these powerful diagnostic tools do not become an open door for attackers. The exposure of developer tools is often a symptom of broader gaps in security awareness and production hardening processes, underscoring the need for a holistic approach to application security in Go development.

## References

- Akto. (2025, June 4). *Golang expvar Information Disclosure*. Akto.io.
- Aqua Security. (2024, May 28). *Over 300,000 Prometheus Servers and Exporters Exposed to DoS Attacks and Information Disclosure*. Aqua Security Blog.
- DeepSource. *Profiling endpoint automatically exposed on `/debug/pprof` (GO-S2108)*. DeepSource Directory.
- Veracode. *CWE 209: Information Exposure Through an Error Message | Java*. Veracode.
- Veracode. *CWE 209: Information Exposure Through an Error Message | ASP.NET*. Veracode.
- Oligo Security. (2024, October 1). *Breaking Down OWASP Top 10 for Web Apps, Mobile, API, K8s, and LLMs*. Oligo Security Academy.
- Kubebuilder. *Monitoring Performance with Pprof*. Kubebuilder Book.
- GitHub. (2024, February 14). *net/http: panic: pattern "GET /" conflicts with pattern "/debug/vars" #65723*. Golang/go Issues.
- Netdata. (2025, April 24). *Go applications (expvar) - Monitoring Go application metrics*. Netdata Learn.
- GitHub. (2017, January 25). *[Metricbeat] Golang module to collect pprof metrics #3466*. Elastic/beats Issues.
- NVD. (2024, November 21). *CVE-2021-38561 Detail*. NIST National Vulnerability Database.
- IBM Support. (2024, July 19). *Security Bulletin: Multiple vulnerabilities in Go may affect IBM CICS TX on Cloud, Standard and Advanced*. IBM.
- Bearer. *Usage of active debug code (pprof enabled) - go_gosec_leak_pprof_endpoint*. Bearer Documentation.
- Kubebuilder. *Monitoring Performance with Pprof*. Kubebuilder Book.
- Thomas, G. (2025, March 6). *OWASP Top 10 2021: A05 Security Misconfiguration*. Glen Thomas Blog.
- Oligo Security. (2024, October 1). *Breaking Down OWASP Top 10 for Web Apps, Mobile, API, K8s, and LLMs*. Oligo Security Academy.
- Attaxion. (2024, August 29). *CWE-200 (Information Exposure)*. Attaxion Glossary.
- SonarSource. *Delivering code in production with debug features activated is security-sensitive*. SonarSource Rules.
- 100 Go Mistakes. (2023, November 1). *Mistake 98: Not understanding profiling and execution tracing*. 100 Go Mistakes and How to Avoid Them.
- Reddit. (2017, September 28). *Your pprof is showing! IPv4 scans reveal exposed Go net/http/pprof endpoints*. r/golang.
- Wiz. (2025, March 26). *CVE-2025-20226: Splunk Enterprise vulnerability analysis and mitigation*. Wiz Vulnerability Database.
- Stack Overflow. (2020, September 25). *Is it ok to use Golang pprof on production without affecting performance?*
- PandaBB3356. (2023, August 18). *Integrating pprof with Gin*. PandaBB3356's Blog.
- Akto.io. (2025, June 4). *Golang expvar Information Disclosure*. Akto Test Library.
- Tenable. (2023, May 5). *Pprof Debug Files Detected*. Tenable Plugins.
- Elastic. *Golang integration README*. Elastic Integrations GitHub.
- Sysdig. (2018, November 8). *How to instrument Go code with custom expvar metrics*. Sysdig Blog.
- Bruins Slot, J. (2017, August 11). *Profiling Golang applications running in Docker containers*. Bruins Slot Blog.
- Bruins Slot, J. (2019, November 19). *Profiling Golang applications running in Docker containers (Part 2)*. Bruins Slot Blog.
- GitHub. (2024, August 22). *net/http/pprof: build tag to disable pprof #69030*. Golang/go Issues.
- GitHub. *Datadog Agent Developer Tools*. DataDog/datadog-agent.
- DeepSource. *Profiling endpoint automatically exposed on `/debug/pprof` (GO-S2108)*. DeepSource Directory.
- Kubebuilder. *Monitoring Performance with Pprof*. Kubebuilder Book.
- GitHub Advisories. (2024, March 15). *CWE-200: Exposure of Sensitive Information to an Unauthorized Actor in Undisclosed Product*. GHSA-9h4w-p78f-w2hw.
- NVD. (2023, February 1). *CVE-2023-22611 Detail*. NIST National Vulnerability Database.
- Intigriti. (2024, May 15). *Intigriti Triage Standards - CVSS*. Intigriti Knowledge Base.
- IBM Support. (2025, May 2). *Security Bulletin: systemd, Openssl vulnerabilities affect IBM Storage Ceph*. IBM.
- Iron.io Blog. (2016, Summer). *Gopherfest Summer 2016 Recap*.
- GitHub. *Nuclei Templates - Golang Expvar Detect*. ProjectDiscovery/nuclei-templates.
- ProjectDiscovery. *Running Nuclei*. Nuclei Documentation.
- Stack Overflow. (2021, May 22). *How to ignore a Go file in a module?*
- GitHub. (2019, July 31). *x/tools/gopls: support build tags #33389*. Golang/go Issues.
- Go Fiber. *Pprof Middleware*. Go Fiber Documentation.
- Stack Overflow. (2016, February 12). *Profiling http handler in Go lang*.
- Nginx Documentation. *Debugging NGINX*. Nginx Admin Guide.
- Nginx.org. *Debugging log*. Nginx Documentation.
- Netdata. (2025, April 24). *Go applications (expvar)*. Netdata Learn.
- GitHub. *anacrolix/envpprof*.
- IBM Support. (2025, May 6). *Security Bulletin: Multiple vulnerabilities in commons-beanutils, PHP, JUnit4 affect IBM Engineering Lifecycle Management*. IBM.
- NVD. (2025, May 15). *CVE-2025-24144 Detail*. NIST National Vulnerability Database.
- Intigriti. (2024, May 15). *Intigriti Triage Standards - CVSS*. Intigriti Knowledge Base.
- IBM Support. (2025, May 2). *Security Bulletin: systemd, Openssl vulnerabilities affect IBM Storage Ceph*. IBM.
- AlagZoo. (2024, October 26). *4 Common Pitfalls in Golang Development*. AlagZoo Blog.
- Lorenz, R. (2020, April 19). *Go: Profiling HTTP service with pprof and expvar*. Rafal Lorenz Blog.
- GitHub. *sevennt/echo-pprof*.
- Leapcell Blog. (2024, July 1). *Understanding Go Build Tags*. Leapcell.
- Go Blog. (2014, January 10). *The Go data race detector*. (Build tag example for `!race`)
- Go Package Documentation. *Package net/http/pprof*.
- DomainTools Blog. (2016, October 28). *Remote Profiling of Go Programs*.
- GitHub Gist. (2017, October 12). *Go pprof HTTP server with access control*. sudo-suhas/go_pprof_access_control.go.
- Go Fiber. *Middleware Overview*. Go Fiber Documentation.
- Stack Overflow. (2020, December 14). *How to trigger BasicAuth prompt in conjunction with custom http error handler in Echo?*
- Solo.io. (2023, April 25). *NGINX Configuration: A Comprehensive Guide*. Solo.io Blog.
- DreamHost Knowledge Base. (2023, September 14). *Nginx configuration file locations*.
- Apache HTTP Server Documentation. (Version 2.4). *Sections for Configuration Files*.
- TecMint. (2023, August 11). *How to Allow or Deny Access to a Website Using Apache*.
- FIRST.org. *CVSS v3.1 Calculator*.
- IBM Support. (2025, January 9). *Security Bulletin: Multiple vulnerabilities in Java SE may affect IBM Application Performance Management*. IBM.
- FIRST.org. *CVSS v3.1 Examples*.
- IBM Support. (2025, May 16). *Security Bulletin: Multiple security vulnerabilities are addressed in IBM Process Mining Interim Fix for May 2025*. IBM.
- GitHub. (2015, November 6). *How to use net/http/pprof with echo? #251*. Labstack/echo Issues.
- Before80. *Fiber Middleware - Pprof*. Go Docs CN.
- Stack Overflow. (2014, February 21). *Idiomatic way of requiring HTTP basic auth in Go?*
- Stack Overflow. (2016, March 23). *HTTP Basic Auth with Golang*.
- HCL AppScan. (Version 10.8.0). *OWASP Application Security Verification Standard report*. HCL Software.
- OWASP ASVS GitHub. (Version 4.0). *0x22-V14-Config.md*.
- Echo Framework. *Secure Middleware*. Echo Documentation.
- GitHub. *sevennt/echo-pprof*.