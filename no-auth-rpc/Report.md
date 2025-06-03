# Report on Golang Vulnerability: No Authentication on RPC Endpoints (no-auth-rpc)

## Vulnerability Title

Unauthenticated Golang RPC Endpoints (no-auth-rpc)

## Severity Rating

This vulnerability typically warrants a **High🟠 to Critical🔴** severity rating, depending on the sensitive nature of the exposed functionality and data. The absence of an authentication layer allows any external client to invoke exposed RPC methods and access or manipulate data and functionality as if they were a legitimate, privileged user. Such uncontrolled access can lead to complete system compromise, data breaches, and service disruption.

The consistently high CVSS metrics associated with unauthenticated RPC vulnerabilities underscore that these are not merely consequential but also highly accessible and easily exploitable targets for adversaries. This combination drastically lowers the barrier to entry for attackers, making such endpoints prime candidates for automated scanning and widespread attacks. For instance, a critical Remote Code Execution (RCE) vulnerability (CVE-2022-26809) in Windows RPC runtime, which also arose from unauthenticated access, scored a 9.8 on the CVSS scale, demonstrating the severe potential impact of such exposures. The "zero-click" nature of some unauthenticated RPC exploits and the inherent lack of authentication directly translate to low attack complexity and no privileges required, confirming the ease with which these vulnerabilities can be exploited.

The following table provides a detailed breakdown of the CVSS v3.1 metrics for unauthenticated RPC vulnerabilities:

| CVSS Metric | Value | Justification |
| --- | --- | --- |
| Attack Vector (AV) | Network (N) | The RPC endpoint is accessible over the network, allowing remote attackers to exploit it without physical access. |
| Attack Complexity (AC) | Low (L) | Exploitation typically requires minimal effort, often involving simple network requests to well-known RPC services or easily guessable methods. No complex bypasses or timing attacks are generally needed to achieve initial access. |
| Privileges Required (PR) | None (N) | The fundamental nature of this vulnerability is the complete absence of authentication, meaning no credentials or prior privileges are required for an attacker to interact with the service. |
| User Interaction (UI) | None (N) | The vulnerability can be exploited without any user interaction on the target system. In many cases, it is a "zero-click" vulnerability, meaning an attacker can directly send malicious RPC requests. |
| Scope (S) | Changed (C) or Unchanged (U) | If the compromised RPC service can affect resources beyond its immediate scope (e.g., other applications, operating system functions, or network segments), the scope is "Changed." Given the potential for Remote Code Execution (RCE) and privilege escalation, "Changed" is frequently applicable, indicating a broader impact on the system or network. |
| Confidentiality Impact (C) | High (H) | Unauthorized access can lead to the disclosure of sensitive information, including confidential data, internal configurations, or system state. |
| Integrity Impact (I) | High (H) | Attackers can modify, corrupt, or delete data or system configurations, leading to data integrity loss or system instability. |
| Availability Impact (A) | High (H) | The vulnerability can be exploited to cause a Denial of Service (DoS) by crashing the RPC service, exhausting system resources, or disrupting critical application functions. |
| **Likely CVSS Range** | **9.0 - 10.0 (Critical)** | This range is typical for vulnerabilities with unauthenticated remote code execution or significant data compromise potential. |

## Description

Unauthenticated Golang RPC Endpoints refers to a critical security vulnerability where a Remote Procedure Call (RPC) service, specifically implemented using Go's standard `net/rpc` package, is exposed over a network interface without any authentication or authorization mechanisms. This fundamental lack of access control allows any unprivileged and unauthenticated client to connect to the RPC server and invoke any of its exposed methods.

The `net/rpc` package in Go is designed as a basic, low-level framework for inter-process communication. It facilitates the invocation of methods on a remote object but does not inherently provide any security features such as authentication, encryption (TLS), or granular access control. Developers are entirely responsible for implementing these critical safeguards independently. When these security measures are omitted or improperly configured, the RPC endpoint becomes publicly accessible to anyone on the network, turning it into a significant attack surface.

The core problem of unauthenticated RPC endpoints in `net/rpc` applications stems not from a defect within the `net/rpc` package itself, but rather from a fundamental misconfiguration or oversight by the developer. The `net/rpc` package is a minimalist communication protocol, designed for simplicity and internal use, not as a secure, internet-facing framework. This distinction is crucial for understanding the root cause: the vulnerability arises from an incorrect deployment pattern and a developer's assumption of secure-by-default behavior, rather than a flaw that can be patched within the library. The absence of built-in security features within `net/rpc` is evident from the fact that dedicated authentication middleware, such as `connectrpc/authn-go`, does not directly integrate with `net/rpc`, indicating that `net/rpc` lacks native hooks for such functionality.

## Technical Description (for security pros)

The `net/rpc` package in Go facilitates inter-process communication by allowing a server to register Go objects (structs) whose exported methods can be invoked remotely. These methods must adhere to a specific signature: `func (t *T) MethodName(argType T1, replyType *T2) error`, where `T`, `T1`, and `T2` are types marshallable by `encoding/gob`.

A `net/rpc` server is typically initialized by creating an instance of the service struct and registering it using `rpc.Register(rcvr)` or `rpc.RegisterName(name, rcvr)`. The server then establishes a network listener, commonly via `net.Listen("tcp", address)`, and begins serving requests using `rpc.Accept(listener)` or `rpc.ServeConn(conn)` for raw TCP connections. For RPC over HTTP, `rpc.HandleHTTP()` registers handlers on the default `/_goRPC_` and `/debug/rpc` paths.

The core of this vulnerability lies in the fact that the `net/rpc` framework, by design, performs no authentication or authorization checks on incoming connections or method invocations. When the server listens on a broad network interface (e.g., `0.0.0.0`) or an interface accessible to untrusted parties, and no custom authentication logic is implemented *before* the `rpc.Accept` call or within the RPC methods themselves, the endpoint becomes entirely open. Any client capable of establishing a TCP connection or sending an HTTP POST request to the RPC endpoint can then enumerate and invoke any registered, exported method without providing any credentials.

The "frozen upstream" status of the `net/rpc` package reveals a fundamental architectural limitation: the package was not designed with modern internet-facing security requirements in mind. Discussions within the Go development community indicate that `net/rpc` has "outstanding bugs that are hard to fix" and cannot support TLS without major work, leading to the conclusion that it "should probably be retired". This position from the Go developers themselves indicates that relying on `net/rpc` for secure applications is inherently risky and unsustainable. This forces developers to either deploy insecurely or implement complex, error-prone custom security wrappers, significantly increasing the likelihood of vulnerabilities.

While `net/rpc` can operate over HTTP , it does not conform to a typical RESTful API pattern. It leverages HTTP as a transport layer for its own RPC protocol, often using `encoding/gob` or `jsonrpc` codecs. This means that standard web authentication middleware, such as general `net/http` handlers , might not directly intercept or secure the RPC payload itself without careful and often complex integration. The `DialHTTPPath` function, for example, uses a `CONNECT` method, effectively hijacking the HTTP connection for the `net/rpc` protocol. This is distinct from a standard HTTP request where middleware can easily inspect headers and body. Unless authentication is implemented *before* the RPC protocol takes over the connection, it can be bypassed.

## Common Mistakes That Cause This

The prevalence of unauthenticated Golang RPC endpoints stems from several common developer mistakes and misconceptions regarding the `net/rpc` package's security posture.

- **Failure to Implement Explicit Authentication:** The most prevalent mistake is the assumption that `net/rpc` provides any form of built-in authentication or authorization. Developers often expose RPC endpoints without adding explicit authentication checks in their RPC handler methods or by wrapping the RPC server with a dedicated authentication layer. The basic examples of `net/rpc` server setup are remarkably simple and do not include any security considerations, which can mislead developers into believing that security is either handled implicitly or not necessary.
- **Inadequate Network Segmentation and Exposure:** Binding the RPC server to a broad network interface like `0.0.0.0` (all interfaces) and exposing it directly to the internet or untrusted internal networks without stringent firewall rules or network access controls is a critical error. Even if intended for internal use, a flat network architecture allows an attacker who gains a foothold elsewhere to easily discover and exploit these unauthenticated endpoints.
- **Misconception of "Localhost Only" Security:** Developers might mistakenly believe that binding the RPC server exclusively to `127.0.0.1` (localhost) is a sufficient security measure. While this prevents direct external network access, such endpoints remain vulnerable to Cross-Site Request Forgery (CSRF) attacks if a co-located web application (e.g., a browser) can be tricked into making requests to the RPC endpoint. This is particularly relevant in web wallet or client-side application contexts, where a malicious webpage could trigger unauthenticated actions.
- **Ignoring `net/rpc`'s Architectural Limitations:** Continuing to use the `net/rpc` package for new development or critical services despite its "frozen" status and explicit recommendations for retirement from the Go team is a significant decision that incurs security debt. This decision forces developers to implement complex security features manually, which is error-prone, or to accept significant security risks.
- **Lack of Granular Authorization:** Even if some form of authentication is implemented, a common mistake is the absence of granular authorization checks within individual RPC methods. This can allow authenticated but unauthorized users or services to perform actions they shouldn't, leading to privilege escalation or unintended data manipulation.
- **Neglecting TLS/Encryption:** Transmitting sensitive data over unencrypted `net/rpc` connections, even if authentication is present, makes the communication vulnerable to eavesdropping and Man-in-the-Middle (MitM) attacks. The `net/rpc` package does not natively support TLS, requiring manual and often complex configuration using `crypto/tls`.

These prevalent mistakes highlight a significant gap between developer expectations and the `net/rpc` package's minimalist design. Many modern frameworks are "secure by default," leading developers to assume `net/rpc` shares this posture. This assumption, combined with a lack of explicit security warnings or built-in security examples in `net/rpc` documentation, inadvertently encourages developers to overlook critical security requirements, treating RPC as a simple function call rather than a network-exposed service.

## Exploitation Goals

The broad and severe range of exploitation goals underscores that unauthenticated RPC is not a single-impact vulnerability but a critical gateway to a cascade of further attacks. It serves as a foundational weakness that can enable multiple stages of an attack kill chain, from initial reconnaissance and information gathering to full system compromise, data exfiltration, and persistent presence. The ease of detection combined with these high-impact goals makes such endpoints particularly attractive to adversaries.

Typical exploitation goals include:

- **Service Enumeration and Reconnaissance:** The primary initial objective for an attacker is to discover available RPC services and their exposed methods on a target system. This allows them to map the application's internal attack surface and identify potential entry points or sensitive functionalities.
- **Information Disclosure:** Attackers aim to access sensitive data, configuration details, internal system states, or proprietary business logic that might be exposed through unauthenticated RPC methods. This can include anything from system time (as in the PoC) to user credentials, database contents, or network topology.
- **Unauthorized Function Execution:** A direct goal is to invoke arbitrary RPC methods to perform actions not intended for public access. This can include administrative functions (e.g., creating/deleting users, modifying permissions), data manipulation (e.g., updating records, transferring funds as seen in CryptoNote example), or triggering system commands.
- **Privilege Escalation:** If an exposed RPC method interacts with system-level functions, sensitive files, or allows manipulation of access controls, an attacker could leverage it to escalate their privileges on the compromised host. This often involves gaining higher-level permissions than initially intended.
- **Remote Code Execution (RCE):** The most severe exploitation goal, where an attacker can execute arbitrary code or commands on the vulnerable machine with the privileges of the RPC service. This typically leads to complete system compromise.
- **Data Exfiltration:** Attackers can read and exfiltrate sensitive data from the system by calling RPC methods that access databases, files, or other data stores. This can be achieved by invoking methods that return data or by leveraging the RPC service to initiate outbound connections.
- **Denial of Service (DoS):** Attackers can trigger resource exhaustion, crash the RPC service, or disrupt the application's availability by repeatedly invoking computationally expensive operations, sending malformed requests, or exploiting specific vulnerabilities within the RPC implementation.
- **Lateral Movement:** Once an initial RPC endpoint is compromised, attackers can use it as a pivot point to access and compromise other systems or services within the internal network that are reachable from the vulnerable host. This allows them to expand their foothold and reach higher-value targets.

## Affected Components or Files

This vulnerability is fundamentally a misconfiguration or insecure design pattern rather than a specific CVE within the `net/rpc` library itself. This implies that traditional vulnerability scanning tools focused on identifying known CVEs in libraries might fail to detect this issue. Therefore, a comprehensive security assessment must include application-level security reviews (static and dynamic analysis) and rigorous network-level checks to identify and confirm such exposures. The problem arises from how developers use the package, shifting the focus of detection from merely patching libraries to actively reviewing application code and deployment configurations for insecure patterns.

Affected components and files include:

- **Go Applications utilizing `net/rpc`:** Any Go application that incorporates the `net/rpc` package to expose remote services is potentially vulnerable. This includes applications using both `rpc.ServeConn` for raw TCP connections and `rpc.HandleHTTP` for RPC over HTTP.
- **RPC Server Implementation Files (`.go`):** Specifically, the Go source files (`.go`) that contain the `rpc.Register` calls (which expose the service methods) and the definitions of the actual RPC handler methods themselves. These files typically reside in the server-side component of the application.
- **Network Configuration:** The network interfaces and ports on which the RPC server is configured to listen. This includes explicit listener addresses (e.g., `0.0.0.0:PORT` for public exposure, or specific internal IP addresses) and the associated port numbers.
- **Firewall Rules and Network Access Controls:** Ingress firewall rules or security group configurations that permit unauthenticated access to the RPC ports from untrusted networks or the internet. Misconfigured network access controls are a direct enabler of this vulnerability.
- **Deployment Configuration Files:** Any configuration files (e.g., `.env` files, Kubernetes manifests, Docker Compose files) that dictate the RPC server's binding address, port, or network exposure.

The following table lists commonly used RPC ports and protocols, which can aid in identifying potential `net/rpc` services during network reconnaissance:

| Service | Port/Protocol | Description |
| --- | --- | --- |
| rpcbind | 111/TCP, 111/UDP | Remote procedure call (port mapper) |
| msrpc | 135/TCP | Microsoft Remote Procedure Call |
| NetApp cluster RPC | 900-967/TCP, 7810-7824/TCP | Various internal NetApp cluster RPC ports |
| NDMP | 10000/TCP | Network Data Management Protocol |
| iSCSI target port | 3260/TCP | Internet Small Computer Systems Interface |
| NFS mount | 635/UDP, 4046/TCP | Network File System mount protocol |

## Vulnerable Code Snippet

A typical vulnerable `net/rpc` server setup in Go, demonstrating the lack of authentication:

```go
package main

import (
	"fmt"
	"log"
	"net"
	"net/rpc"
	"time"
)

// Args defines the arguments for an RPC method.
type Args struct {
	A, B int
}

// CalculatorService is the type that exposes RPC methods.
// It does not implement any authentication or authorization logic.
type CalculatorService int

// Add is an exported RPC method that adds two numbers.
// This method can be invoked by any unauthenticated client.
func (t *CalculatorService) Add(args *Args, reply *int) error {
	log.Printf("Received Add request: %d + %d", args.A, args.B)
	*reply = args.A + args.B
	return nil
}

// GetSystemTime is an exported RPC method that returns the current system time.
// This method demonstrates potential information disclosure without authentication.
func (t *CalculatorService) GetSystemTime(args *struct{}, reply *string) error {
	*reply = time.Now().Format(time.RFC3339)
	log.Printf("System time requested by an unauthenticated client.")
	return nil
}

// SensitiveOperation is an example of a critical method that should be protected.
// In a vulnerable setup, this could be invoked by anyone.
func (t *CalculatorService) SensitiveOperation(args *string, reply *string) error {
	log.Printf("Sensitive operation '%s' invoked by an unauthenticated client!", *args)
	*reply = fmt.Sprintf("Operation '%s' completed without authorization.", *args)
	// In a real scenario, this might perform file system operations,
	// database changes, or execute commands.
	return nil
}

func main() {
	// Register the CalculatorService.
	// All exported methods of CalculatorService will be available via RPC.
	calculator := new(CalculatorService)
	err := rpc.Register(calculator)
	if err!= nil {
		log.Fatalf("Failed to register RPC service: %v", err)
	}

	// Create a TCP listener that listens on all network interfaces (0.0.0.0)
	// and a common port (e.g., 12345).
	// Crucially, no authentication middleware or TLS is applied at this listener level.
	listener, err := net.Listen("tcp", "0.0.0.0:12345")
	if err!= nil {
		log.Fatalf("Failed to listen on port 12345: %v", err)
	}
	defer listener.Close()

	log.Println("RPC server listening on 0.0.0.0:12345 without authentication...")

	// Accept and serve RPC requests indefinitely.
	// Any client connecting to this listener can invoke any registered RPC method.
	rpc.Accept(listener) // This call accepts connections and serves RPCs without authentication.
}
```

**Explanation of Vulnerability in Code:**
The extreme simplicity of setting up an `net/rpc` server, requiring only `rpc.Register`, `net.Listen`, and `rpc.Accept`, is a significant contributing factor to this vulnerability. This ease of use, while beneficial for rapid prototyping or internal, trusted environments, inadvertently encourages developers to overlook the critical *missing* security layers. These layers are not explicitly required by the API, leading to a false sense of security or an assumption that security is handled elsewhere.

In the provided snippet:

- The `CalculatorService` struct defines methods (`Add`, `GetSystemTime`, `SensitiveOperation`) intended for RPC calls.
- `rpc.Register(calculator)` makes these methods discoverable and callable. The `net/rpc` package itself does not enforce any authentication or authorization for these methods.
- `net.Listen("tcp", "0.0.0.0:12345")` configures the server to listen on all available network interfaces (`0.0.0.0`) on port `12345`. This makes the RPC endpoint accessible from any host that can route traffic to this port.
- The `rpc.Accept(listener)` function then begins serving RPC requests. Crucially, no authentication middleware or TLS is applied at this listener level or within the RPC methods themselves. Consequently, any client that establishes a TCP connection to `localhost:12345` (or the server's public IP) can invoke `CalculatorService.Add`, `CalculatorService.GetSystemTime`, or `CalculatorService.SensitiveOperation` without providing any credentials.
- The `GetSystemTime` method, while seemingly innocuous, demonstrates how even simple information disclosure can occur. The `SensitiveOperation` method highlights how critical functions, if exposed, can lead to severe compromise.

## Detection Steps

The detection strategy for this vulnerability must be multi-faceted, combining network-level reconnaissance with in-depth application-level source code review and dynamic analysis. Since this vulnerability is a misconfiguration rather than a specific, patchable bug within the `net/rpc` library, automated CVE scanners are unlikely to flag it. This underscores the necessity of comprehensive security assessments that go beyond superficial checks and delve into implementation details and deployment contexts.

### Network Scanning (Nmap)

- **Port and Service Discovery:** Use Nmap to identify open TCP and UDP ports on target systems. Specifically, `nmap -sV <target>` can detect service versions running on open ports, which might identify RPC services.
- **RPC-Specific Scans:** Utilize Nmap's built-in RPC scanning capabilities. The `nmap -sR <target>` option performs an RPC scan to identify RPC services and their associated program numbers and versions.
- **Nmap Scripting Engine (NSE):** Employ relevant NSE scripts. The `rpc-grind.nse` script  can brute-force RPC program numbers and extract supported versions, helping to identify exposed RPC services and their methods. This script works by sending Null call requests with unsupported versions to determine if a program is listening.
- **Firewall Evasion:** When scanning, consider Nmap options like `f` (fragment packets), `-source-port`, or `-data-length` to bypass basic firewall rules that might attempt to block standard scans.

### RPC Method Enumeration and Probing

Once a potential RPC port is identified, an attempt should be made to establish a connection using a generic TCP client or a custom `net/rpc` client. The goal is to call known or guessed RPC methods (e.g., "Service.MethodName") without providing any credentials. A successful response, or an error message indicating "method not found" (e.g., `rpc: can't find method...`) rather than "unauthenticated" or "access denied," strongly indicates an open, unauthenticated endpoint. For HTTP-based `net/rpc` endpoints (typically listening on `/_goRPC_`), `curl` or similar HTTP clients can be used to send POST requests with a `gob`-encoded or JSON-RPC payload (if the `jsonrpc` codec is used) to registered methods, observing HTTP status codes and RPC responses.

### Source Code Review (Static Analysis)

Manual review of Go source code is crucial for identifying this vulnerability. Security professionals should look for the presence and usage of the `net/rpc` package. Specific attention should be paid to `rpc.Register` calls, which expose service methods, and `net.Listen` calls to determine the binding address (e.g., `0.0.0.0` or specific internal IPs) and port. Critically, it is necessary to verify if any authentication middleware or logic is explicitly applied *before* `rpc.Accept` or within the RPC handler methods themselves. The absence of `crypto/tls` configurations or other authentication libraries (e.g., `connectrpc.com/authn` , `go.viam.com/utils/rpc` , `github.com/dgrijalva/jwt-go` ) in the RPC server setup is a strong indicator of vulnerability. While tools like `govulncheck`  help with known CVEs, they may not flag this specific misconfiguration, emphasizing the need for manual security review.

### Dynamic Analysis / Penetration Testing

Penetration testing frameworks (e.g., Metasploit, although primarily Windows-focused, the principles of RPC interaction apply ) or custom scripts can be utilized to programmatically interact with identified RPC endpoints and attempt to invoke methods. Fuzzing RPC inputs can help identify potential crashes (DoS) or unexpected behavior that might reveal vulnerabilities.

## Proof of Concept (PoC)

The following Proof of Concept demonstrates how an unauthenticated client can interact with a vulnerable `net/rpc` server in Go.

### Setup (Vulnerable Server - `server.go`)

Use the `Vulnerable Code Snippet` provided in the previous section. Save the code as `server.go`.
Compile and run the server on a target machine (e.g., `localhost` for local testing):

Bash

`go run server.go`

The server will output: `RPC server listening on 0.0.0.0:12345 without authentication...`

### Exploitation (Client - `client.go`)

Create a separate Go file, `client.go`, with the following content:

```go
package main

import (
	"fmt"
	"log"
	"net/rpc"
)

// Args matches the argument structure of the server's RPC methods.
type Args struct {
	A, B int
}

func main() {
	// Establish a connection to the unauthenticated RPC server.
	// No credentials or authentication headers are provided.
	// Replace "localhost:12345" with the target server's IP and port if running remotely.
	client, err := rpc.Dial("tcp", "localhost:12345")
	if err!= nil {
		log.Fatalf("Failed to dial RPC server: %v", err)
	}
	defer client.Close()

	log.Println("Successfully connected to the RPC server.")

	// --- Exploitation Goal 1: Unauthorized Function Execution (Add) ---
	fmt.Println("\n--- Attempting to call CalculatorService.Add without authentication ---")
	argsAdd := &Args{A: 10, B: 5}
	var replyAdd int
	err = client.Call("CalculatorService.Add", argsAdd, &replyAdd)
	if err!= nil {
		log.Printf("Error calling Add: %v", err)
	} else {
		fmt.Printf("Successfully called Add: %d + %d = %d\n", argsAdd.A, argsAdd.B, replyAdd)
	}

	// --- Exploitation Goal 2: Information Disclosure (GetSystemTime) ---
	fmt.Println("\n--- Attempting to call CalculatorService.GetSystemTime without authentication ---")
	var replyTime string
	err = client.Call("CalculatorService.GetSystemTime", &struct{}{}, &replyTime) // Empty struct for no args
	if err!= nil {
		log.Printf("Error calling GetSystemTime: %v", err)
	} else {
		fmt.Printf("Successfully called GetSystemTime: %s\n", replyTime)
	}

	// --- Exploitation Goal 3: Unauthorized Sensitive Operation (SensitiveOperation) ---
	fmt.Println("\n--- Attempting to call CalculatorService.SensitiveOperation without authentication ---")
	sensitiveArg := "delete_all_data"
	var sensitiveReply string
	err = client.Call("CalculatorService.SensitiveOperation", &sensitiveArg, &sensitiveReply)
	if err!= nil {
		log.Printf("Error calling SensitiveOperation: %v", err)
	} else {
		fmt.Printf("Successfully called SensitiveOperation: %s\n", sensitiveReply)
	}

	// --- Exploitation Goal 4: Probing for non-existent methods (Reconnaissance/Error Handling Test) ---
	fmt.Println("\n--- Attempting to call a non-existent method (Reconnaissance/Error Test) ---")
	var replyNonExistent string
	err = client.Call("CalculatorService.NonExistentMethod", &struct{}{}, &replyNonExistent)
	if err!= nil {
		// Expected error: "rpc: can't find method CalculatorService.NonExistentMethod"
		// This confirms the RPC endpoint is reachable and processing requests,
		// and provides information about valid/invalid methods.
		fmt.Printf("Error calling NonExistentMethod (expected): %v\n", err)
	} else {
		fmt.Printf("Unexpected success calling NonExistentMethod: %s\n", replyNonExistent)
	}
}
```

**Expected Output (Client Side):**

```bash
Successfully connected to the RPC server.

--- Attempting to call CalculatorService.Add without authentication ---
Successfully called Add: 10 + 5 = 15

--- Attempting to call CalculatorService.GetSystemTime without authentication ---
Successfully called GetSystemTime: 2024-XX-XXTXX:XX:XXZ (actual current time)

--- Attempting to call CalculatorService.SensitiveOperation without authentication ---
Successfully called SensitiveOperation: Operation 'delete_all_data' completed without authorization.

--- Attempting to call a non-existent method (Reconnaissance/Error Test) ---
Error calling NonExistentMethod (expected): rpc: can't find method CalculatorService.NonExistentMethod
```

**Demonstration:**
This PoC clearly demonstrates that the client can successfully connect to the `net/rpc` server and invoke its exposed methods (`Add`, `GetSystemTime`, `SensitiveOperation`) without any form of authentication. The ability to call `SensitiveOperation` without authorization highlights the critical risk. The attempt to call a non-existent method shows that the RPC endpoint is active and responds with specific error messages, which can be leveraged by an attacker for further reconnaissance to enumerate valid methods.

## Risk Classification

The risk associated with unauthenticated Golang RPC endpoints is classified as **Critical**. This classification is based on the combination of high impact across confidentiality, integrity, and availability, coupled with the ease of exploitation. The absence of authentication means that any actor with network access to the exposed endpoint can interact with the service as if they were a legitimate, privileged user. This fundamentally undermines the security posture of the affected application and potentially the entire system or network segment. The CVSS score analysis, typically falling within the 9.0-10.0 range, quantitatively supports this critical classification.

## Fix & Patch Guidance

Addressing unauthenticated Golang RPC endpoints requires a multi-layered approach, focusing on implementing robust authentication, authorization, and secure communication channels.

1. **Implement Strong Authentication:**
    - **External Authentication Layer:** The `net/rpc` package does not offer built-in authentication. Therefore, an external authentication layer must be implemented. For RPC over HTTP, this can involve standard HTTP authentication middleware (e.g., Basic Auth, JWT validation) that intercepts requests *before* they are passed to the `net/rpc` handler. Libraries like `connectrpc.com/authn` provide authentication middleware for Connect, gRPC, and gRPC-Web protocols, demonstrating a robust approach to authentication.
    - **Custom Authentication in RPC Methods:** For raw TCP `net/rpc` or if an external layer is insufficient, authentication logic must be integrated directly into each RPC method. This would involve requiring clients to send credentials (e.g., API keys, tokens) as part of the RPC arguments, which are then validated by the server before processing the request. This approach, while more granular, can be complex to manage.
    - **Mutual TLS (mTLS):** For highly sensitive services, implement mTLS to ensure both the client and server authenticate each other using X.509 certificates. This provides strong identity verification and encryption. Go's `crypto/tls` package can be used to configure TLS listeners for `net.Listen`.
2. **Implement Granular Authorization:**
    - Beyond authentication, implement authorization checks within each RPC method to ensure that even authenticated clients only have access to functions and data appropriate for their role or permissions. This prevents privilege escalation.
    - Authorization can be based on roles, scopes (e.g., from JWT claims), or specific access control lists (ACLs).
3. **Enforce Secure Communication (TLS/SSL):**
    - All RPC communication, especially over untrusted networks, must be encrypted using TLS/SSL to prevent eavesdropping and Man-in-the-Middle (MitM) attacks.
    - Since `net/rpc` does not natively support TLS, it must be manually configured by wrapping the underlying `net.Conn` with a `tls.Conn`. This involves loading server certificates and keys and configuring the `tls.Config` for the listener.
4. **Strict Network Segmentation and Firewalling:**
    - Limit network access to RPC endpoints to only trusted hosts or networks. This involves configuring firewalls and security groups to block all unsolicited inbound traffic to RPC ports.
    - Avoid binding RPC services to `0.0.0.0` if they are not intended for public exposure. Instead, bind to specific internal IP addresses or `127.0.0.1` (localhost) if only local communication is required. Even for localhost, consider CSRF protection for web-facing applications.
5. **Migration to Modern RPC Frameworks:**
    - Given that the `net/rpc` package is "frozen upstream" and recommended for retirement by the Go team due to its limitations in security and maintenance , the most robust long-term solution is to migrate to a modern RPC framework that inherently provides better security features.
    - **gRPC:** gRPC is a high-performance RPC framework that uses Protocol Buffers for serialization and HTTP/2 for transport. It offers strong built-in security features, including SSL/TLS integration, and supports various authentication mechanisms like token-based authentication and mTLS. gRPC also supports interceptors for authentication and authorization.
    - **Connect:** Connect is another RPC framework that works with Connect, gRPC, and gRPC-Web protocols and has dedicated authentication middleware.

## Scope and Impact

The scope of unauthenticated Golang RPC endpoints can range from a single application to an entire network, depending on the service's functionality and network exposure. The impact is typically high across confidentiality, integrity, and availability, leading to severe consequences.

- **Confidentiality Impact:** Unauthorized access can lead to the disclosure of sensitive information, including confidential data, internal configurations, system state, and proprietary business logic. This could include user credentials, financial records, intellectual property, or internal network topology.
- **Integrity Impact:** Attackers can modify, corrupt, or delete data or system configurations, leading to data integrity loss or system instability. This could manifest as unauthorized transactions, altered system settings, or defacement of services.
- **Availability Impact:** The vulnerability can be exploited to cause a Denial of Service (DoS) by triggering resource exhaustion, crashing the RPC service, or disrupting critical application functions. This can lead to service outages, financial losses, and reputational damage.
- **Privilege Escalation:** If the RPC service operates with elevated privileges or exposes methods that can manipulate system access controls (e.g., adding users, modifying permissions), an attacker can escalate their privileges on the host system or within the application.
- **Remote Code Execution (RCE):** The most critical impact, allowing an attacker to execute arbitrary code or commands on the vulnerable machine with the privileges of the RPC service. RCE typically leads to full system compromise and the ability to deploy further malware or establish persistence.
- **Lateral Movement:** A compromised RPC endpoint can serve as a pivot point, allowing attackers to move laterally within the network by accessing and compromising other systems or services reachable from the vulnerable host. This expands the attack surface and allows for the targeting of higher-value assets.

## Remediation Recommendation

To mitigate the risk of unauthenticated Golang RPC endpoints, a comprehensive remediation strategy is essential:

1. **Implement Robust Authentication and Authorization:**
    - **Immediate Action:** For existing `net/rpc` applications, integrate an authentication layer. This can be achieved by requiring credentials (e.g., API keys, shared secrets, JWTs) as part of RPC requests and validating them within each RPC handler method.
    - **Best Practice:** Implement mutual TLS (mTLS) for all RPC communications to ensure strong bidirectional authentication and encryption. This provides a robust security foundation by verifying both client and server identities before any application-level communication occurs.
    - **Granular Access Control:** Beyond authentication, implement fine-grained authorization checks within each RPC method to enforce the principle of least privilege, ensuring users or services can only perform authorized actions.
2. **Enforce Network Security Controls:**
    - **Firewall Rules:** Configure network firewalls and security groups to restrict access to RPC ports (e.g., TCP/UDP 111, 135, 445, and application-specific RPC ports) to only explicitly authorized IP addresses or internal networks.
    - **Network Segmentation:** Implement strong network segmentation to isolate RPC services from public internet access and untrusted internal network segments. This limits the blast radius in case of a compromise.
    - **Bind to Specific Interfaces:** Configure RPC servers to listen only on necessary network interfaces (e.g., an internal IP address) rather than `0.0.0.0` (all interfaces), unless explicitly required and secured.
3. **Migrate from `net/rpc` for New or Critical Services:**
    - Given the acknowledged limitations and "frozen" status of the standard `net/rpc` package , it is strongly recommended to use more modern RPC frameworks for new development or when refactoring critical services.
    - **Prioritize gRPC or Connect:** Frameworks like gRPC  or Connect  offer robust built-in security features, including native TLS, authentication interceptors, and better support for modern distributed system patterns. These frameworks provide a more secure-by-design approach, reducing the likelihood of such unauthenticated exposures.
4. **Regular Security Audits and Code Reviews:**
    - Conduct regular security audits, including static application security testing (SAST) and dynamic application security testing (DAST), to identify insecure RPC configurations and other vulnerabilities.
    - Perform manual code reviews, specifically focusing on network listeners and RPC service registrations, to ensure authentication and authorization are correctly implemented.
    - Integrate security scanning tools like `govulncheck`  into CI/CD pipelines to identify known vulnerabilities in dependencies, although this specific misconfiguration may require more in-depth analysis.

## Summary

The vulnerability of "No authentication on RPC endpoints" in Golang applications, particularly those utilizing the `net/rpc` package, represents a critical security risk. This issue arises not from a flaw in the `net/rpc` package itself, but from a common developer oversight where essential authentication and authorization mechanisms are omitted. The `net/rpc` package is a minimalist framework, lacking built-in security features, which places the full burden of securing RPC communications on the developer.

Exploitation of such unauthenticated endpoints is straightforward, requiring no prior privileges or user interaction, leading to a high CVSS score. Attackers can leverage this vulnerability for broad reconnaissance, sensitive information disclosure, unauthorized function execution, privilege escalation, remote code execution, data exfiltration, denial of service, and lateral movement within a network.

Effective remediation requires a multi-faceted approach. Immediate actions include implementing explicit authentication and authorization checks within the RPC methods or via external middleware, and enforcing TLS for all communications. For long-term security, it is strongly recommended to migrate from the `net/rpc` package to modern, secure-by-design RPC frameworks like gRPC or Connect, which offer robust built-in security features and better support for contemporary distributed system architectures. Strict network segmentation, firewalling, and continuous security auditing are also crucial to prevent and detect such exposures.

## References

- https://github.com/connectrpc/authn-go
- https://pkg.go.dev/go.viam.com/utils/rpc
- https://docs.netapp.com/us-en/ontap-technical-reports/ontap-security-hardening/ports-protocols-security.html
- https://stackoverflow.com/questions/40194599/golang-json-rpc-authorization
- https://www.edureka.co/community/311927/what-is-rpc-endpoint-mapping-and-why-is-it-a-risk
- https://www.akamai.com/blog/security/critical-remote-code-execution-vulnerabilities-windows-rpc-runtime
- https://go.dev/doc/security/best-practices
- https://www.reddit.com/r/golang/comments/1k1lmqd/go_security_best_practices_for_software_engineers/
- https://github.com/golang/go/issues/71559
- https://opentelemetry.io/docs/security/cve/
- https://docs.metasploit.com/docs/using-metasploit/advanced/RPC/how-to-use-metasploit-messagepack-rpc.html
- https://www.hackingarticles.in/abusing-ad-dacl-writeowner/
- https://github.com/golang/go/issues/71559
- https://stackoverflow.com/questions/22412164/what-can-cause-a-client-call-rpc-to-return-an-error-in-go-golang
- https://github.com/cryptonotefoundation/cryptonote/issues/172
- https://www.cs.princeton.edu/courses/archive/spring21/cos418/docs/precept3_rpcs_in_go.pdf
- https://www.syxsense.com/wp-content/uploads/syxsense-securityarticles/rpc/syx-1024-10907.html
- https://www.vectra.ai/attack-techniques/remote-procedure-call-rpc-attacks
- https://learn.microsoft.com/en-us/windows-server/security/rpc-interface-restrict
- https://stackoverflow.com/questions/79242367/unauthenticated-desc-transport-per-rpc-creds-failed-due-to-error-credentials
- https://ops.tips/gists/example-go-rpc-client-and-server/
- https://github.com/connectrpc/authn-go
- https://victoriametrics.com/blog/go-grpc-basic-streaming-interceptor/
- https://stackoverflow.com/questions/39034114/what-is-the-difference-between-net-rpc-package-of-golang-and-grpc-framework
- https://www.cs.ubc.ca/~bestchai/teaching/cs416_2015w2/go1.4.3-docs/pkg/net/rpc/index.html
- https://github.com/cryptonotefoundation/cryptonote/issues/172
- https://github.com/golang/go/issues/71559
- https://learn.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-058
- https://www.rabbitmq.com/tutorials/tutorial-six-dotnet
- https://cyberflorida.org/unauthenticated-remote-code-execution-rce-vulnerability-affecting-netscaler/
- https://github.com/ariary/QueenSono
- https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/cheeky-chipmunk/NCSC-MAR-Cheeky-Chipmunk.pdf
- https://grpc.io/docs/guides/status-codes/
- https://cloud.google.com/run/docs/reference/rpc/google.rpc
- https://www.geeksforgeeks.org/nmap-cheat-sheet/
- https://www.infosecinstitute.com/resources/penetration-testing/nmap-cheat-sheet-part-4/
- https://victoriametrics.com/blog/go-grpc-basic-streaming-interceptor/
- https://github.com/connectrpc/authn-go
- https://grpc.io/docs/guides/auth/
- https://gist.github.com/artyom/6897140
- https://ops.tips/gists/example-go-rpc-client-and-server/
- https://github.com/golang/go/blob/master/src/net/rpc/server.go
- https://github.com/golang/go/blob/master/src/net/rpc/client.go?name=release
- https://www.integralist.co.uk/posts/rpc-variations-in-go/
- https://github.com/connectrpc/authn-go
- https://drstearns.github.io/tutorials/gomiddleware/
- https://liambeeton.com/programming/secure-grpc-over-mtls-using-go
- https://victoronsoftware.com/posts/mtls-go-client/
- https://nmap.org/nsedoc/scripts/rpc-grind.html
- https://github.com/Ullaakut/nmap
- https://github.com/golang/go/issues/71559
- https://pkg.go.dev/go.bryk.io/pkg/net/rpc