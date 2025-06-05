# Deserialization to Struct with Unexported Fields in Golang (unexported-deserializeg)

## Vulnerability Title

Deserialization to Struct with Unexported Fields (Permitting Internal State Manipulation)

## Severity Rating

**Overall: Medium🟡 to High🟠 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L-H/I:L-H/A:L-H)**

The severity can range from Medium to Critical depending on the specific impact achieved, which can vary from Denial of Service to Remote Code Execution. The CVSS vector provided is a general representation; specific instances may warrant adjustment based on the exploitability and impact on confidentiality, integrity, and availability.

- **Likelihood:** Medium
- **Impact:** Medium to Critical

## Description

This vulnerability occurs when a Golang application deserializes data from an untrusted source into a struct, and the deserialization process allows an attacker to influence or directly set the values of unexported fields within that struct. Unexported fields (those starting with a lowercase letter) are typically used to maintain an object's internal state and are not meant to be directly manipulated from outside the package.

When an attacker can control these unexported fields, they can potentially corrupt the object's internal state, bypass security controls, escalate privileges, cause a denial of service, or, in some scenarios, achieve remote code execution. The vulnerability arises not from the standard behavior of Go's default deserializers (which generally ignore unexported fields for input), but from flawed custom deserialization logic (e.g., custom `UnmarshalJSON` or `GobDecode` methods) or the misuse of powerful but dangerous packages like `reflect` in conjunction with `unsafe`.

## Technical Description

Understanding this vulnerability requires a grasp of Golang's visibility rules for struct fields and how deserialization mechanisms interact with these rules.

**Golang Struct Field Visibility:**
In Go, the case of the first letter of an identifier determines its visibility.

- **Exported fields:** Start with an uppercase letter (e.g., `User.Name`). They are accessible from any package that imports the defining package.
- **Unexported fields:** Start with a lowercase letter (e.g., `User.internalCounter`). They are only accessible within the package in which they are defined. This encapsulation is a fundamental aspect of Go's design, intended to protect internal state and implementation details.

**Standard Deserializer Behavior for Unexported Fields:**
Go's primary standard library packages for deserialization, `encoding/json` and `encoding/gob`, have specific behaviors regarding unexported fields:

- **`encoding/json`:**
    - By default, `json.Unmarshal` only considers exported fields for unmarshaling data from a JSON object into a Go struct. Incoming JSON object keys that do not match an exported field (or its tag) are ignored, unless `Decoder.DisallowUnknownFields()` is used.
    - Unexported fields are not populated from the JSON input during default unmarshaling. Struct tags on unexported fields are generally not meaningful for unmarshaling, except for `json:"-"` which explicitly ignores a field (even an exported one). The `go-json-experiment/json` package documentation explicitly states, "Unexported fields must not have any `json` tags except for `json:"-"`".
    - A historical issue (Go #24152) in Go 1.10 caused `json.Unmarshal` to panic when decoding into fields inside embedded pointers to unexported struct types, instead of returning an error. This was fixed in Go 1.10.1. This bug was related to error handling rather than a deliberate mechanism to populate unexported fields.
- **`encoding/gob`:**
    - The `gob` package encodes and decodes only the exported fields of structs. Unexported fields are ignored during both encoding and decoding.
    - Struct fields of `chan` or `func` type are treated exactly like unexported fields and are ignored. An issue (Go #2517) confirmed that `gob` should ignore unexported fields, including those of channel or function type, which aligns with its general behavior of skipping unexported fields.

**Vulnerability Pathways:**
The vulnerability of deserializing into unexported fields typically manifests through two primary pathways where developers might deviate from or extend the default safe behaviors:

1. **Custom `UnmarshalJSON` or `GobDecode` Methods:**
Go allows types to define custom deserialization logic by implementing the `json.Unmarshaler` interface (with its `UnmarshalJSON(byte) error` method) or the `gob.GobDecoder` interface (with its `GobDecode(byte) error` method).
    - Within these custom methods, developers have full control over how the byte data is interpreted and mapped to the struct's fields, including unexported ones.
    - A common pattern to handle JSON with unexported fields, or to customize serialization, involves defining an alias type or an intermediate struct with exported fields. The input data is unmarshaled into this auxiliary structure, and then its values are manually assigned to the fields of the original struct, potentially including unexported fields.
    - If data from the untrusted input is assigned to unexported fields within these custom methods *without adequate validation or sanitization*, the vulnerability arises. The developer essentially bypasses the encapsulation provided by unexported fields by explicitly writing to them using attacker-controllable data.
    - A critical pitfall in implementing these custom methods is inadvertently causing recursive calls to `json.Unmarshal` or `gob.Decode` on the same type, leading to a stack overflow. This is typically avoided by unmarshaling into an alias type.
2. **Misuse of `reflect` and `unsafe` Packages:**
    - The `reflect` package provides runtime reflection capabilities, allowing programs to inspect and manipulate objects of arbitrary types. While standard reflection operations generally respect Go's visibility rules (e.g., attempting to set an unexported field via `reflect.Value.Set()` on a `Value` obtained without `unsafe` would typically fail if `Value.CanSet()` is false for that field), these can be bypassed.
    - The `unsafe` package, as its name implies, allows operations that circumvent Go's type safety and memory safety guarantees.
    - Specifically, `reflect.Value.UnsafeAddr()` can return the memory address of an unexported field. This address, cast to an `unsafe.Pointer`, can then be further cast to a typed pointer (e.g., `string`, `int`). Dereferencing this typed pointer allows direct read and write access to the unexported field's memory, completely bypassing visibility checks.
    - A conceptual example of such manipulation, as seen in discussions , might involve:
        
        ```go
        // val := reflect.ValueOf(objectPtr).Elem()
        // field := val.FieldByName("unexportedFieldName")
        // if field.IsValid() && field.CanAddr() { // CanAddr might be true
        //     unsafePtr := unsafe.Pointer(field.UnsafeAddr())
        //     typedPtr := (*FieldType)(unsafePtr)
        //     *typedPtr = attackerControlledValue
        // }
        ```
        
    - If `attackerControlledValue` originates from untrusted deserialized input, this constitutes a direct and dangerous manipulation of an unexported field. Static analysis tools sometimes flag such patterns, for example, Datadog's `go-security/unsafe-reflection` rule.

**Table 1: Handling of Unexported Fields by Go Standard Deserializers**

| Feature | `encoding/json` (Default) | `encoding/json` (Custom `UnmarshalJSON`) | `encoding/gob` (Default) | `encoding/gob` (Custom `GobDecode`) |
| --- | --- | --- | --- | --- |
| **Direct deserialization to unexported fields from input** | No. Unexported fields are ignored. | Possible. Developer controls assignment to unexported fields. | No. Unexported fields are ignored. | Possible. Developer controls assignment to unexported fields. |
| **Treatment of unexported fields not in input** | Ignored. Remain as their zero value or pre-existing value. | Depends on custom logic. May be ignored or set to defaults. | Ignored. Remain as their zero value or pre-existing value. | Depends on custom logic. May be ignored or set to defaults. |
| **Use of struct tags for unexported fields** | `json:"-"` is respected. Other tags generally ignored. | Custom logic can interpret tags in any way, but standard library won't use them for unexported fields during intermediate unmarshaling. | Not applicable for unexported fields as they are ignored. | Custom logic can interpret tags in any way, but standard library won't use them for unexported fields during intermediate decoding. |
| **Official stance on (de)serializing unexported fields** | Not directly populated by default. | Allows flexibility but responsibility lies with the developer. | Not (de)serialized. | Allows flexibility but responsibility lies with the developer. |
| **Potential for direct manipulation of unexported fields via standard library (without custom code or `unsafe`)** | No. | N/A (This column is about custom code) | No. | N/A (This column is about custom code) |

**Gadget Chains and Internal State Manipulation:**
While Golang is not typically associated with the complex "gadget chains" found in languages like Java or PHP during deserialization attacks (where existing code snippets are chained together to achieve arbitrary code execution), the ability to manipulate unexported fields can be a stepping stone to similar outcomes. By altering the internal, unexported state of an object, an attacker can change its behavior in subtle or drastic ways. When methods of this compromised object are subsequently called by the application, they may operate based on the attacker-controlled internal state, leading to unintended actions. For example, an unexported field `initialized bool` could be set to `true` to bypass initialization routines, or an `accessLevel int` field could be modified to grant unauthorized privileges. The attack is often completed not during the deserialization act itself, but by the application's later use of the corrupted object.

The core technical issue is the subversion of Go's encapsulation model. Unexported fields are intended to protect an object's integrity by restricting access. When deserialization provides a means—either through developer oversight in custom code or deliberate circumvention using `unsafe`—to write arbitrary untrusted data into these fields, that protection is lost. This creates a significant attack surface if those fields control critical logic or store sensitive data.

## Common Mistakes That Cause This Vulnerability

Several common mistakes made by developers can lead to the insecure deserialization of data into unexported fields:

- **Blindly Trusting Input in Custom Deserializers:** The most frequent error is implementing `UnmarshalJSON` or `GobDecode` methods and directly assigning data from the input stream to unexported fields without rigorous validation or sanitization. Developers might do this to ensure the complete state of an object, including its private members, can be persisted and reconstructed, overlooking the security implications when the data source is untrusted.
- **Improper Use of `unsafe` and `reflect` Packages:** Resorting to `unsafe.Pointer` in conjunction with the `reflect` package to access and set unexported fields during a deserialization process is a highly dangerous practice if the data being set originates from an external, untrusted source. This is often an attempt to overcome Go's type system limitations or visibility rules but directly introduces a vulnerability by treating the `unsafe` package's capabilities without due caution.
- **Lack of Post-Deserialization Validation:** A common oversight is assuming that if data successfully deserializes into a struct (even if initially only into its exported fields), the resulting object is inherently valid and safe to use. Subsequent internal application logic might then use this partially trusted data to make decisions or perform operations that unsafely modify unexported fields or rely on a compromised state. The deserialization process itself is not a substitute for semantic validation of the data's content and context.
- **Over-reliance on Data Transfer Objects (DTOs) without Proper Mapping Logic:** While using DTOs for initial deserialization is a good practice, vulnerabilities can arise if data is then carelessly or incompletely copied from these DTOs to internal domain objects. If this mapping logic does not validate data before assigning it to properties that influence unexported fields of the domain object, or if it directly maps DTO fields to setters that manipulate unexported state without further checks, the protection offered by DTOs can be undermined.
- **Exposing Internal Domain Structs Directly for Deserialization:** Deserializing data directly into complex internal domain model structs that contain critical unexported fields, rather than using dedicated, simpler DTOs designed specifically for input, increases the risk. This practice tightly couples the external data format to the internal application state, making it harder to enforce boundaries and validate data appropriately for sensitive unexported fields.
- **Ignoring Errors or Insufficient Error Handling During Deserialization:** If errors encountered while parsing or assigning specific fields during a custom deserialization process are ignored or not handled correctly, parts of the object, potentially including unexported fields if custom logic attempts to set them, might be left in an inconsistent, partially initialized, or attacker-controlled state. This can lead to unpredictable behavior later.
- **Misunderstanding Serializer Behavior and Struct Tags:** Developers may incorrectly assume how `encoding/json` or `encoding/gob` handle unexported fields or how struct tags interact with them. For instance, placing a standard `json:"fieldName"` tag on an unexported field will not make it automatically settable by `json.Unmarshal` in its default mode. Such misunderstandings can lead to flawed custom deserialization logic if developers try to "force" behavior that the standard libraries do not provide by default, potentially opening security holes.

These mistakes often stem from a failure to consistently treat all external input as untrusted or from a misunderstanding of the shared responsibility model in security: while a library might parse data, the application developer is ultimately responsible for validating its semantic correctness and ensuring its safe use, especially when it can influence normally protected internal state.

**Table 2: Common Mistakes and Consequences in Unexported Field Deserialization**

| Mistake | Description | Potential Consequence |
| --- | --- | --- |
| **Trusting input for unexported fields in custom unmarshaler** | Custom `UnmarshalJSON`/`GobDecode` directly assigns input data to unexported fields without validation. | State corruption, security bypass, privilege escalation, RCE. |
| **Using `unsafe` with `reflect` for unexported fields from input** | `unsafe.Pointer` and `reflect.UnsafeAddr()` used to write untrusted external data to unexported fields. | Direct memory manipulation, state corruption, security bypass, privilege escalation, RCE. High risk due to bypassing Go's safety mechanisms. |
| **No validation after deserialization, before internal use** | Deserialized object (even if only exported fields initially populated) is used without further validation, and its methods or subsequent logic modify unexported state based on this untrusted data. | Indirect state corruption, logical flaws leading to security vulnerabilities. |
| **Careless mapping from DTO to internal struct's unexported fields** | Data from a DTO is mapped to an internal struct, and this process sets unexported fields based on DTO values without sufficient validation. | Unexported fields in the internal struct are tainted with unvalidated data, leading to similar consequences as direct deserialization. |
| **Direct deserialization into complex internal structs** | Untrusted data is deserialized directly into internal application structs that have critical unexported fields, rather than using simpler, dedicated input DTOs. | Increased attack surface, harder to validate, higher risk of unintended unexported field manipulation. |

## Exploitation Goals

Attackers who successfully exploit vulnerabilities related to deserializing data into unexported fields may aim to achieve several malicious objectives:

- **State Corruption:** The most fundamental goal is to modify the internal, unexported fields of an object to alter its state in a manner that is advantageous to the attacker. This could involve changing flags, counters, status indicators, pointers, or other internal data structures that dictate the object's behavior or its interaction with other parts of the system.
- **Bypassing Security Controls:** Many applications use unexported fields to manage security-critical state, such as `isValidated bool`, `accessLevel int`, or `isAdmin bool`. By manipulating these fields, an attacker can circumvent security checks, bypass authentication or authorization mechanisms, or gain access to functionalities or data they are not entitled to.
- **Privilege Escalation:** If an unexported field determines an object's or a user's privileges within the application, modifying it can lead to privilege escalation. For example, changing an unexported `role` field from "user" to "administrator."
- **Information Disclosure:** An attacker might manipulate unexported fields that control what data an object can access or how it processes information, potentially causing the application to leak sensitive data. This could be data that the unexported fields directly store or data whose access path is determined by these fields.
- **Denial of Service (DoS):** Setting unexported fields to unexpected or invalid values (e.g., nil pointers where objects are expected, out-of-range numerical values for buffer sizes or loop counters, recursive data structures) can cause the application to panic, enter infinite loops, consume excessive resources (CPU, memory), or otherwise become unresponsive when the object's methods are subsequently invoked.
- **Remote Code Execution (RCE):** This is often the most severe exploitation goal. If an unexported field stores data that is later used in an unsafe manner by the application—such as a file path that is opened and executed, a command string passed to a shell, a template that is rendered with potential for template injection, or serialized data that is further deserialized by a more powerful interpreter—an attacker could inject malicious code or commands.
- **Data Tampering:** Attackers can alter unexported fields that represent critical application data. This can lead to incorrect application behavior, corruption of business logic, or the persistent storage of tampered data, undermining the integrity of the application and its data.

The diversity of these goals stems from the fact that unexported fields can control virtually any aspect of a struct's internal logic and interaction with the broader system. The common thread is the attacker's ability to leverage control over this normally inaccessible internal state to achieve an externally observable and detrimental impact.

## Affected Components or Files

The vulnerability of deserializing into unexported fields is not confined to a single file or component but rather emerges from a pattern of coding and data handling practices. The following components and areas are typically involved or at risk:

- **Go Source Files with Struct Definitions:** Files defining structs that contain unexported fields, especially if these fields are critical for managing internal state, security attributes, sensitive data, or control flow logic.
- **Go Source Files with Deserialization Logic:**
    - Code that uses `encoding/json.Unmarshal`, `json.Decoder.Decode`, `encoding/gob.Decode`, or `gob.Decoder.Decode`.
    - Crucially, files containing custom implementations of `UnmarshalJSON` (for the `json.Unmarshaler` interface) or `GobDecode` (for the `gob.GobDecoder` interface) for types that have unexported fields. These custom methods are primary locations for the vulnerability if not implemented securely.
- **Modules Handling Untrusted Data Input:** Any Go package or module responsible for receiving and processing data from untrusted external sources. This includes:
    - HTTP request handlers (e.g., using `net/http` or frameworks like Gin , Echo) that parse request bodies or parameters.
    - Message queue consumers (e.g., Kafka, RabbitMQ).
    - File processing utilities that read and parse data from uploaded or externally sourced files.
    - Network listeners that deserialize data from network streams.
- **Code Utilizing `reflect` and `unsafe` Packages:** Go files that make use of the `reflect` package in conjunction with the `unsafe` package, particularly functions like `reflect.Value.UnsafeAddr()` and `unsafe.Pointer`, to interact with or modify struct fields, especially in contexts related to data processing or deserialization.
- **Standard Library Packages:** The core vulnerability often involves misuse or insecure extension of:
    - `encoding/json`
    - `encoding/gob`
    - `reflect`
    - `unsafe`
- **Third-Party Libraries:** Any third-party libraries that perform deserialization or provide utilities for object manipulation that might internally use `unsafe` reflection or offer insecure ways to handle unexported fields.
- **Specific Go Versions (Historically):** While the primary vulnerability discussed is application-level, specific Go versions have had bugs related to deserialization and unexported fields (e.g., the panic in Go 1.10's `json.Unmarshal` with embedded unexported structs ). However, these are typically fixed in subsequent releases, and the ongoing risk lies more in custom code.

The vulnerability is characterized by a pattern: the presence of structs with meaningful unexported fields, a deserialization pathway for external data, and either custom logic that insecurely bridges the external data to these unexported fields or the use of `unsafe` mechanisms to achieve the same.

## Vulnerable Code Snippet

Below are illustrative examples of how this vulnerability can manifest.

**Example 1: Flawed Custom `UnmarshalJSON`**
This example demonstrates a common pattern where a custom `UnmarshalJSON` method is implemented to allow setting unexported fields from a JSON payload. If the input is not validated, it leads to a vulnerability.

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
)

type User struct {
	ID         int    `json:"id"`
	Username   string `json:"username"`
	isAdmin    bool   // Unexported, critical field controlling admin privileges
	internalIP string // Unexported, potentially sensitive internal data
}

// Custom UnmarshalJSON to allow setting unexported fields from JSON.
// THIS IS A VULNERABLE EXAMPLE.
func (u *User) UnmarshalJSON(databyte) error {
	// Use an alias to avoid recursion when calling json.Unmarshal on User type.
	type Alias User
	// Auxiliary struct to capture fields intended for unexported members from JSON.
	aux := &struct {
		IsAdmin    bool   `json:"isAdmin"`    // Attacker can provide this in JSON
		InternalIP string `json:"internalIP"` // Attacker can also provide this
		*Alias
	}{
		Alias: (*Alias)(u), // Embed alias to User to handle exported fields
	}

	if err := json.Unmarshal(data, &aux); err!= nil {
		return err
	}

	// Directly assigning from potentially malicious input to unexported fields
	// without any validation.
	u.isAdmin = aux.IsAdmin
	u.internalIP = aux.InternalIP
	// Exported fields (ID, Username) are populated via unmarshaling into aux.Alias.

	// Example of a check that could be bypassed
	if u.Username == "admin_logic_check" &&!u.isAdmin {
		// This condition is meant to handle a specific case for a user who is
		// supposed to be an admin by username but whose flag might be false.
		// An attacker setting isAdmin:true bypasses any nuanced logic here.
		log.Println("Admin logic check encountered for non-admin user by username, but isAdmin flag is false.")
	}

	return nil
}

func main() {
	// Attacker-controlled JSON payload.
	// The attacker attempts to set isAdmin to true and specify an internalIP.
	maliciousJSON := `{"id": 1, "username": "attacker", "isAdmin": true, "internalIP": "10.0.0.1"}`
	var user User
	if err := json.Unmarshal(byte(maliciousJSON), &user); err!= nil {
		log.Fatalf("Error unmarshalling: %v", err)
	}

	fmt.Printf("User struct after unmarshalling: %+v\n", user) // Shows isAdmin=true, internalIP="10.0.0.1"

	if user.isAdmin {
		fmt.Println("VULNERABILITY: Attacker successfully set 'isAdmin' to true via deserialization!")
		// Application logic might now grant admin privileges based on this compromised field.
	}
	if user.internalIP!= "" {
		fmt.Printf("VULNERABILITY: Attacker successfully set 'internalIP' to: %s\n", user.internalIP)
		// Application might use this internalIP for internal requests or logging,
		// potentially leading to SSRF or log injection if not handled carefully.
	}
}
```

*Explanation:* In this snippet, the `User` struct has unexported fields `isAdmin` and `internalIP`. The custom `UnmarshalJSON` method defines an auxiliary struct that includes `IsAdmin` and `InternalIP` (note the case change for JSON field matching) which are then used to populate `u.isAdmin` and `u.internalIP` directly from the JSON input. An attacker can craft a JSON payload like `{"isAdmin": true, "internalIP": "attacker_controlled_ip"}` to take control of these normally private fields, bypassing any internal logic that would typically set them. This pattern is based on common approaches to handling JSON with unexported fields  but is made explicitly vulnerable by the lack of validation.

**Example 2: Using `reflect` and `unsafe` to Set Unexported Fields (Conceptual within a Deserialization Context)**
This example demonstrates how the `reflect` and `unsafe` packages can be misused to modify an unexported field. Imagine this logic being part of a broader deserialization or data-handling pipeline where `secretFromUntrustedSource` comes from external input.

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"unsafe"
)

type Config struct {
	PublicSetting string `json:"publicSetting"`
	secretKey     string // Unexported, highly sensitive field
}

// Simulated deserialization process that first unmarshals known exported fields,
// then unsafely sets an unexported field using data from an untrusted source.
// THIS IS A VULNERABLE EXAMPLE.
func DeserializeAndSetSecret(jsonDatabyte, configPtr *Config, secretFromUntrustedSource string) error {
	// Initial unmarshaling for exported fields
	if err := json.Unmarshal(jsonData, configPtr); err!= nil {
		return fmt.Errorf("initial unmarshal of exported fields failed: %w", err)
	}

	// Now, unsafely set the unexported 'secretKey' field.
	// This simulates a scenario where a part of the "deserialization" or
	// object hydration logic involves using reflect and unsafe with external data.
	val := reflect.ValueOf(configPtr).Elem() // Get the Value of the struct Config points to
	field := val.FieldByName("secretKey")    // Get the reflect.Value for the 'secretKey' field

	if field.IsValid() { // Check if the field was found
		if field.CanAddr() { // Check if we can get its address (usually true for fields of a struct obtained via Elem())
			// Get the unsafe pointer to the field's memory location
			ptrUnsafe := unsafe.Pointer(field.UnsafeAddr())
			// Cast this unsafe pointer to a pointer of the field's actual type (*string)
			realPtrToString := (*string)(ptrUnsafe)
			// Dereference the typed pointer and assign the value from the untrusted source
			*realPtrToString = secretFromUntrustedSource
			log.Printf("Unsafely set unexported 'secretKey' to: %s\n", secretFromUntrustedSource)
		} else {
			return fmt.Errorf("cannot get address of secretKey field, cannot set")
		}
	} else {
		return fmt.Errorf("secretKey field not found in Config struct")
	}
	return nil
}

func main() {
	cfg := Config{}
	// JSON data only contains the public setting
	jsonData := `{"publicSetting": "some_safe_value"}`
	// This secret comes from an attacker-controlled source
	attackerSuppliedSecret := "ATTACKER_CONTROLLED_SECRET_KEY_VALUE"

	err := DeserializeAndSetSecret(byte(jsonData), &cfg, attackerSuppliedSecret)
	if err!= nil {
		log.Fatalf("Error in custom deserialization and setting secret: %v", err)
	}

	fmt.Printf("Config struct after operations: %+v\n", cfg) // Shows secretKey populated with attacker's value

	// To demonstrate the impact, imagine internal application logic now uses cfg.secretKey.
	// For this PoC, we'll just show that it has been set.
	// Accessing cfg.secretKey directly here is possible because we are in the same package.
	// The vulnerability is that its value was determined by an external attacker.
	if cfg.secretKey == attackerSuppliedSecret {
		fmt.Printf("VULNERABILITY: Unexported 'secretKey' was compromised and set to: %s\n", cfg.secretKey)
		// If cfg.secretKey was used for encryption/decryption or API calls,
		// the attacker has now compromised those operations.
	}
}
```

*Explanation:* This snippet illustrates a more direct and dangerous method. After a standard JSON unmarshal (which would ignore `secretKey`), the `DeserializeAndSetSecret` function uses `reflect` to find the unexported `secretKey` field and `unsafe.Pointer` along with `field.UnsafeAddr()` to obtain a raw pointer to its memory. This pointer is then cast to `*string`, allowing the attacker-supplied `secretFromUntrustedSource` to be written directly into the unexported field, bypassing Go's visibility and type safety rules. This technique is inspired by discussions on using `unsafe` for field manipulation  and general warnings about unsafe reflection.

These examples highlight that the vulnerability lies in application-specific code that either extends default deserialization behavior insecurely or uses low-level Go features like `unsafe` to break encapsulation with untrusted data.

## Detection Steps

Detecting vulnerabilities related to the deserialization of unexported fields requires a combination of static analysis, dynamic analysis, and manual code review.

**Static Analysis (SAST):**

- **Identify Custom Deserialization Methods:** Scan the codebase for implementations of `UnmarshalJSON(byte) error` (for `json.Unmarshaler`) and `GobDecode(byte) error` (for `gob.GobDecoder`).
    - Within these methods, analyze the data flow. Trace how the input `byte` data is parsed and assigned to the fields of the receiver struct.
    - Specifically look for assignments to unexported fields (e.g., `receiver.unexportedField = parsedValue`).
    - Check if `parsedValue` originates from the input data and whether it undergoes rigorous validation *before* being assigned to the unexported field. The absence of such validation is a strong indicator of a potential vulnerability.
- **Search for `unsafe` and `reflect` Misuse:**
    - Look for the pattern `reflect.Value.UnsafeAddr()` used to get a pointer to a struct field, followed by casting this to `unsafe.Pointer` and then to a typed pointer, which is subsequently dereferenced for a write operation (e.g., `typedPtr = data`).
    - Trace the origin of `data` in such assignments. If `data` can be influenced by external, untrusted input (e.g., parameters from a network request, data read from a file), this is a high-risk pattern.
    - Tools or linters might have specific checks for such unsafe reflection patterns. For example, Datadog's SAST includes a rule `go-security/unsafe-reflection`.
- **Check for `reflect.Value.Set()` on Unexported Fields:** While direct setting of unexported fields via reflection is normally disallowed, if `unsafe` manipulations have made an unexported field settable (e.g., by obtaining a settable `reflect.Value` through `unsafe.Pointer` trickery), uses of `reflect.Value.Set()` or its typed variants (`SetString`, `SetInt`, etc.) on such fields should be scrutinized.
- **Analyze Post-Deserialization Validation:** After any call to `json.Unmarshal`, `gob.Decode`, or similar deserialization functions, check if the resulting object undergoes comprehensive validation before its methods are called or its data is used in security-sensitive operations. Lack of validation is a general concern for insecure deserialization.

**Dynamic Analysis (DAST):**

- **Identify Input Vectors:** Map out application endpoints or input channels that accept serialized data (e.g., JSON or Gob in HTTP request bodies, file uploads, message queue payloads).
- **Fuzzing Payloads:** Craft and send malicious or unexpected payloads to these inputs:
    - If custom unmarshalers are suspected, include JSON/Gob keys that might correspond to known or guessed unexported field names, with various data types and values. For example, if a struct `User` has an unexported `isAdmin bool`, send `{"isAdmin": true}`.
    - Attempt to trigger type confusion errors or exploit edge cases in custom deserialization logic that might indirectly affect unexported fields.
- **Monitor Application Behavior:** Observe the application for:
    - Unexpected state changes that could be externally verified (e.g., an admin panel becoming accessible).
    - Error messages or crashes that might indicate successful manipulation of internal state.
    - Information leakage or altered responses.
    - Direct observation of unexported field manipulation via DAST is challenging unless the change in the unexported field's state leads to an externally observable behavior change.

**Manual Code Review:**

- **Focus on Data Flow:** Manually trace data from all untrusted input sources (HTTP requests, configuration files, databases if they can be tainted, etc.) through the deserialization routines.
- **Identify Critical Structs:** Pay close attention to struct types that have unexported fields responsible for:
    - Security logic (e.g., authentication status, authorization flags, permissions).
    - Storing sensitive data (e.g., cryptographic keys, internal system paths).
    - Managing critical application state or control flow.
- **Scrutinize Custom Deserializers:** Meticulously review any `UnmarshalJSON` or `GobDecode` implementations. Understand how each field is populated, especially unexported ones. Verify that any data assigned to unexported fields from the input stream is thoroughly validated.
- **Investigate `unsafe` Package Usage:** Any use of the `unsafe` package, particularly `unsafe.Pointer` and `reflect.Value.UnsafeAddr()`, warrants deep scrutiny. Understand why it's being used, whether it's to modify struct fields, and critically, where the data being written originates. If it's from an external source, this is a major red flag.
- **Verify Post-Deserialization Validation:** Confirm that comprehensive validation (syntactic and semantic) is performed on the data *after* it has been deserialized into an object and *before* that object (and its internal state, including unexported fields) is used in any security-sensitive operations or business logic.

Effective detection often requires combining these approaches. SAST can highlight suspicious code patterns, DAST can confirm exploitability in some cases, and manual review is essential for understanding the context, the purpose of unexported fields, and the true impact of their potential manipulation.

## Proof of Concept (PoC)

This Proof of Concept demonstrates how an attacker can manipulate an unexported field via a vulnerable custom `UnmarshalJSON` method, thereby bypassing an application's intended security logic.

**Scenario:**
An application uses a `SessionData` struct to manage user sessions. This struct contains an unexported boolean field `isValidated`, which is normally set to `true` by internal application logic only after successful, rigorous validation of the session. However, a flawed custom `UnmarshalJSON` method allows this `isValidated` field to be set directly from the incoming JSON payload.

**Attacker's Goal:**
To create a session object that appears validated to the application (`isValidated = true`) without undergoing the actual validation process, potentially gaining unauthorized access or privileges.

**Vulnerable Go Code (Conceptual):**

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
)

// SessionData struct with an unexported field for validation status.
type SessionData struct {
	SessionID string `json:"sessionID"`
	UserID    int    `json:"userID"`
	// isValidated is unexported and should ideally only be set by trusted internal logic.
	isValidated bool
}

// Vulnerable custom UnmarshalJSON method.
// It allows the 'isValidated' field in JSON to set the unexported 'isValidated' struct field.
func (s *SessionData) UnmarshalJSON(databyte) error {
	// Alias to avoid recursion with json.Unmarshal.
	type Alias SessionData
	// Auxiliary struct to capture 'isValidated' from JSON.
	// Note: The JSON field name could be "isValidated" or "is_validated" etc.,
	// depending on how the attacker guesses or knows the expected JSON structure.
	// For this PoC, we assume the JSON field is "isValidated".
	aux := &struct {
		IsValidated bool `json:"isValidated"` // Attacker can control this via the JSON payload
		*Alias
	}{
		Alias: (*Alias)(s),
	}

	log.Printf("Attempting to unmarshal JSON: %s", string(data))
	if err := json.Unmarshal(data, &aux); err!= nil {
		log.Printf("Error during unmarshalling auxiliary struct: %v", err)
		return err
	}

	// Vulnerable assignment: unexported field 's.isValidated' is set from attacker-controlled input.
	s.isValidated = aux.IsValidated
	log.Printf("After unmarshalling, s.isValidated is: %v", s.isValidated)

	// Exported fields (SessionID, UserID) are populated via aux.Alias.
	return nil
}

// Simulates processing a request that relies on the session's validation status.
func processRequest(jsonData string) {
	var session SessionData
	if err := json.Unmarshal(byte(jsonData), &session); err!= nil {
		log.Fatalf("Failed to unmarshal session data: %v", err)
		return
	}

	fmt.Printf("Processing session: ID=%s, UserID=%d, IsValidated=%v\n",
		session.SessionID, session.UserID, session.isValidated)

	// Application logic checks the 'isValidated' flag.
	if session.isValidated {
		fmt.Println("PoC SUCCESS: Access granted! The session is marked as validated due to attacker manipulation.")
		// In a real application, this could lead to performing privileged operations.
	} else {
		fmt.Println("PoC: Access denied. The session is not validated.")
	}
}

func main() {
	fmt.Println("--- Simulating legitimate (unvalidated) session ---")
	legitimateUnvalidatedJSON := `{"sessionID": "legit-session-001", "userID": 100}`
	processRequest(legitimateUnvalidatedJSON)
	// Expected: PoC: Access denied. The session is not validated. (isValidated defaults to false)

	fmt.Println("\n--- Simulating attacker's attempt to bypass validation ---")
	// Attacker crafts a JSON payload including the 'isValidated' field set to true.
	maliciousJSONPayload := `{"sessionID": "attacker-session-123", "userID": 999, "isValidated": true}`
	processRequest(maliciousJSONPayload)
	// Expected: PoC SUCCESS: Access granted!
}
```

**Attacker's JSON Payload:**

```json
{
  "sessionID": "attacker-session-123",
  "userID": 999,
  "isValidated": true
}
```

**Execution Steps:**

1. The attacker identifies an endpoint or data processing path where the `SessionData` struct (or a similar struct with a flawed custom unmarshaler) is used.
2. The attacker crafts the malicious JSON payload shown above, intentionally including the `isValidated` key with a value of `true`.
3. The attacker submits this payload to the vulnerable application component.
4. The application's deserialization logic calls the custom `UnmarshalJSON` method on a `SessionData` instance.
5. Inside `UnmarshalJSON`, the JSON data is unmarshaled into the `aux` struct. The `aux.IsValidated` field becomes `true` based on the attacker's payload.
6. The line `s.isValidated = aux.IsValidated` then directly sets the unexported `isValidated` field of the main `SessionData` object to `true`.
7. Later, when `processRequest` (or similar application logic) checks `session.isValidated`, it finds the value to be `true`.
8. The application incorrectly grants access or performs privileged operations, believing the session was legitimately validated.

**Outcome:**
The attacker successfully bypasses the intended session validation mechanism by directly setting an unexported state field (`isValidated`) through the deserialization process. This demonstrates how control over unexported fields can undermine critical security logic. This PoC directly applies the vulnerable custom `UnmarshalJSON` pattern  and illustrates a common insecure deserialization outcome.

## Risk Classification

The risk associated with deserializing data into structs with unexported fields is multifaceted and depends on the ease of exploitation and the potential impact.

- **Likelihood: Medium**
    - **Ease of Discovery: Medium.** Identifying this vulnerability often requires source code access to find custom `UnmarshalJSON`/`GobDecode` methods or the use of `unsafe` with `reflect`. SAST tools can aid in flagging these patterns. For black-box testing, it's harder but might be inferred if specific, guessable field names in payloads alter behavior. Public-facing endpoints accepting complex serialized objects are primary targets.
    - **Ease of Exploit: Medium to Hard.** If a custom deserializer naively maps JSON keys to unexported fields, exploitation can be straightforward once field names are known or guessed. Exploiting `unsafe` pathways might be more complex and require deeper system knowledge. The attacker needs to understand which unexported fields are valuable to control and how to craft a payload that successfully modifies them to achieve a desired outcome.
    - **Prevalence: Uncommon to Medium.** While custom deserializers and the `unsafe` package are used in Go development, their specific application in a way that insecurely populates unexported fields from untrusted data is not ubiquitous. However, it's a known anti-pattern where developers might prioritize functionality (like full state persistence) over security.
    - **Attacker Skill: Intermediate to Advanced.** Exploitation typically requires an understanding of Go's deserialization mechanisms, its type system, reflection, and potentially how the `unsafe` package works. For custom deserializers, some reverse engineering or educated guessing of internal struct layouts or JSON mappings might be necessary if source code is unavailable.
- **Impact: Medium to Critical**
    - **Technical Impact:** The technical consequences can range significantly:
        - **Data Corruption/Tampering:** Modification of internal state leading to incorrect data processing or storage.
        - **Denial of Service (DoS):** Causing panics, resource exhaustion, or infinite loops by setting unexported fields to problematic values.
        - **Security Control Bypass / Privilege Escalation:** Altering flags or internal variables to gain unauthorized access or elevated permissions.
        - **Information Disclosure:** Manipulating state to cause leakage of sensitive data.
        - **Remote Code Execution (RCE):** In the most severe cases, if an unexported field's value is used unsafely in a context like command execution or unsafe template rendering, RCE is possible.
    - **Business Impact:** This depends heavily on the application's function and the data it handles. Impacts could range from minor operational disruptions to significant financial loss, reputational damage, regulatory penalties, or complete system compromise in the event of RCE or major data breaches.
- **Overall Risk:**
The overall risk is determined by combining likelihood and impact:
    - If the vulnerability leads to **Remote Code Execution**, the risk is **High to Critical**.
    - If it leads to **Privilege Escalation or significant Security Control Bypass**, the risk is **Medium to High**.
    - If the primary impact is **Denial of Service or limited Information Disclosure/Data Tampering**, the risk is **Medium**.

The "unexported" nature of the targeted fields can sometimes make exploitation less straightforward than if exported fields were the target, as it implies attacking an interface not explicitly designed for external manipulation. However, the potential for severe impact, should such manipulation succeed, keeps the overall risk significant.

## Fix & Patch Guidance

Addressing vulnerabilities related to deserializing data into unexported fields requires a multi-pronged approach, focusing on secure coding practices, proper data handling, and adherence to Go's encapsulation principles.

- **For Standard Library Issues (e.g., historical bugs):**
    - Ensure the Go runtime and standard library are kept up-to-date. For instance, Go 1.10.1 fixed a panic related to `json.Unmarshal` and embedded unexported structs (Issue #24152). Regularly updating the Go version is a fundamental security practice.
- **For Custom Deserializers (`UnmarshalJSON`, `GobDecode`):**
    - **Strongly Prefer Data Transfer Objects (DTOs):** The most robust approach is to avoid deserializing directly into structs that contain critical unexported fields. Instead, define separate DTO structs that only contain exported fields corresponding precisely to the expected external data contract.
        1. Deserialize the untrusted input *only* into an instance of this DTO.
        2. Perform rigorous validation on all fields of the DTO.
        3. After validation, manually and selectively map the validated data from the DTO to your internal domain objects. Any unexported fields in the domain object should be set by trusted internal logic based on the validated DTO data or other business rules, not directly from the raw input.
    - **If DTOs are not used and unexported fields must be populated from input:**
        - This practice is discouraged. If unavoidable, the data intended for unexported fields must be treated with extreme suspicion and subjected to exhaustive validation *before* assignment.
        - Consider whether a field truly needs to be unexported if it's part of the intended serializable contract. If it must remain unexported for internal encapsulation but needs to be restorable, its restoration logic must be exceptionally secure.
    - **Avoid Recursion:** When implementing custom unmarshalers that call the standard library's unmarshaler (e.g., `json.Unmarshal`), always unmarshal into an alias type of the receiver or an auxiliary struct to prevent infinite recursion and stack overflow.
- **Regarding `unsafe` and `reflect` Usage:**
    - **Avoid Using `unsafe` and `reflect` for Deserialization to Unexported Fields:** Do not use `unsafe.Pointer` in conjunction with `reflect.Value.UnsafeAddr()` to bypass visibility rules and write data from untrusted external sources into unexported fields. This is an inherently dangerous practice that subverts Go's type safety.
    - If `unsafe` is deemed absolutely necessary for other low-level performance reasons (which should be rare and well-justified), ensure that such code is isolated, heavily scrutinized, and cannot be influenced by external data to modify arbitrary memory locations or unexported fields of critical structs.
- **General Best Practices for Secure Deserialization:**
    - **Implement Strict Input Validation:** All data deserialized from untrusted sources must be thoroughly validated before being used by the application. This includes checking types, formats, lengths, ranges, and adherence to business logic rules. Validation should occur immediately after deserialization and before the object is used.
    - **Enforce Strict Type Constraints:** Where possible, enforce strict type constraints during deserialization to ensure that only expected data types are processed.
    - **Log Deserialization Exceptions:** Monitor and log any exceptions or errors that occur during the deserialization process. Unusual error patterns can indicate attack attempts.
    - **Principle of Least Data:** Only deserialize the data fields that are strictly necessary for the operation at hand. Avoid populating fields that are not used.

By adhering to these guidelines, developers can significantly reduce the risk of attackers manipulating unexported fields through deserialization pathways, thereby preserving the integrity and security of their Go applications.

## Scope and Impact

**Scope:**
The vulnerability of deserializing data into unexported fields affects Golang applications that:

- Process serialized data (e.g., JSON, Gob) originating from untrusted external sources. These sources include, but are not limited to, HTTP request bodies, URL parameters, cookies, message queue messages, file uploads, and direct network streams.
- Utilize struct types that contain unexported fields. The criticality increases if these unexported fields are responsible for managing sensitive internal state, security attributes (like validation status or permission levels), configuration parameters, or control flow logic.
- Implement custom deserialization logic via `UnmarshalJSON` or `GobDecode` methods for these struct types, especially if this custom logic attempts to populate unexported fields based on the input data.
- Employ the `reflect` package in conjunction with the `unsafe` package to programmatically access and modify unexported struct fields, particularly if the data being written originates from or is influenced by external input.

The scope is therefore any Go application where there's an intersection of untrusted data input, deserialization, and mechanisms (custom or `unsafe`) that could allow this data to influence normally encapsulated unexported fields.

**Impact:**
The impact of successfully exploiting this vulnerability can be severe and varied, affecting the confidentiality, integrity, and availability of the application and its data:

- **Confidentiality:** If unexported fields that control access to data, or themselves store sensitive information (e.g., session tokens, cryptographic keys, internal system details), are compromised, an attacker could gain unauthorized access to this information. This leads to data breaches and loss of privacy.
- **Integrity:** Manipulation of unexported fields can lead to the corruption or unauthorized modification of critical application data or its internal state. This can result in:
    - Incorrect application behavior and flawed business logic execution.
    - Tampering with persistent data if the compromised object's state is saved.
    - Financial or operational damage due to erroneous calculations or actions.
- **Availability:** Attackers might set unexported fields to values that cause the application to crash (e.g., due to nil pointer dereferences), enter infinite loops, consume excessive CPU or memory, or trigger unhandled errors. This can lead to a Denial of Service (DoS), making the application unavailable to legitimate users.
- **Authorization/Access Control Bypass & Privilege Escalation:** This is a significant impact. If unexported fields like `isAdmin`, `isValidated`, `userRole`, or `permissionFlags` are modified, attackers can bypass security mechanisms, escalate their privileges within the application, and perform actions they are not authorized for.
- **Remote Code Execution (RCE):** In the most critical scenarios, if the value of a manipulated unexported field is later used in a context that allows code injection (e.g., used as part of a system command, a script to be executed, a path to an executable file, or within an unsafe template rendering process), an attacker could achieve remote code execution on the server. This represents a full compromise of the affected system.

The specific impact depends on the role of the unexported field(s) targeted. Manipulation of a field controlling a debug log's verbosity might have a low impact, whereas compromising a field that gates administrative access or holds a command string could be catastrophic.

## Remediation Recommendation

To effectively remediate and prevent vulnerabilities associated with deserializing data into unexported fields in Golang applications, a layered approach focusing on clear data boundaries, rigorous validation, and avoidance of unsafe practices is recommended.

- **Primary Recommendation: Utilize Data Transfer Objects (DTOs) for Deserialization:**
    - Define DTO structs specifically for handling incoming data from untrusted sources. These DTOs should *only* contain exported fields that directly correspond to the expected external data contract (e.g., JSON keys).
    - Perform all initial deserialization from untrusted input (e.g., `json.Unmarshal`) exclusively into instances of these DTOs.
    - After successful deserialization into a DTO, conduct comprehensive validation and sanitization on all fields of the DTO. This includes type checks, format validation, range checks, length limitations, and any business-specific rule checks.
    - Only after the DTO's data has been thoroughly validated should it be used. Manually and selectively map the validated data from the DTO to your internal domain objects or application-level structs.
    - Crucially, any unexported fields within your internal domain objects must be set by trusted internal application logic, based on the validated data from the DTO or other internal business rules. **They should never be populated directly from raw, unvalidated external input, even via a DTO field.**
    - *Rationale:* This pattern establishes a strong boundary between untrusted external data and trusted internal application state. DTOs act as a "quarantine zone" for incoming data, ensuring that unexported fields of core domain objects are shielded from direct external influence.
- **Implement Strict and Comprehensive Input Validation:**
    - Regardless of whether fields are exported or unexported, or whether DTOs are used, all data originating from untrusted sources must be rigorously validated *after* deserialization and *before* it is used in any application logic.
    - Validation should be multi-faceted: check data types, enforce length and range constraints, validate formats (e.g., for emails, URLs, dates), and apply any context-specific business rules.
    - As suggested by Fluid Attacks, "Validate the deserialized object before using it. Cast the deserialized object to a specific type to ensure its integrity". This applies to the data within the object as well.
- **Secure Custom Deserialization Methods (If DTOs Are Not Fully Adopted):**
    - If custom `UnmarshalJSON` or `GobDecode` methods are absolutely necessary for types with unexported fields (a practice generally discouraged for direct input handling):
        - Be explicit and minimal about which fields (exported or unexported) are populated from the input data stream.
        - **Avoid populating unexported fields directly from the input data without subjecting that specific piece of data to intense, context-aware validation within the custom method itself.**
        - Critically evaluate if a field truly needs to remain unexported if it is considered part of the serializable contract. If it must be unexported for encapsulation but settable via deserialization, the security burden for validating its input is extremely high.
        - Ensure correct use of type aliases or auxiliary structs when calling standard unmarshalers from within custom ones to prevent infinite recursion and stack overflows.
- **Eliminate or Strictly Isolate `unsafe` Package Usage for Field Modification:**
    - **Strongly avoid using the `unsafe` package in conjunction with `reflect` to modify unexported struct fields using data that originates from or is influenced by external, untrusted sources**. This practice bypasses Go's fundamental safety mechanisms and is a significant security anti-pattern.
    - If the `unsafe` package is indispensable for other legitimate, performance-critical, low-level operations (which should be rare and meticulously justified), ensure such usage is tightly isolated, subject to the highest level of scrutiny and code review, and cannot create pathways for untrusted data to modify arbitrary memory locations or unexported fields of critical structs.
- **Adhere to the Principle of Least Privilege for Deserialized Data:**
    - Objects created or populated via deserialization should not inherently possess elevated privileges or capabilities. Any subsequent security-sensitive operations should rely on explicit, re-verified authorization checks, not merely on the assumed state of deserialized objects (whose internal state might have been compromised).
- **Regularly Update Dependencies and Go Version:**
    - Keep the Go compiler, standard library, and all third-party dependencies updated to their latest stable and patched versions. This helps protect against known vulnerabilities in the underlying platform or libraries.
- **Incorporate Security Testing and Code Reviews:**
    - Utilize Static Application Security Testing (SAST) tools capable of detecting risky patterns such as insecure use of `unsafe` and `reflect`, or potential flaws in deserialization logic.
    - Conduct regular manual security code reviews with a specific focus on data input and output handling, deserialization routines, state management, and any code that interacts with unexported fields of critical structs.

By implementing these recommendations, particularly the robust use of DTOs and comprehensive validation, developers can significantly mitigate the risks associated with deserializing data into structs with unexported fields, thereby enhancing the overall security posture of their Golang applications.

## Summary

The deserialization of data into Golang structs that possess unexported fields introduces a notable security vulnerability when untrusted external input can influence or directly set the values of these normally private, encapsulated fields. This manipulation typically occurs either through flaws within custom `UnmarshalJSON` or `GobDecode` methods, where developers might inadvertently or insecurely assign input data to unexported members, or through the more deliberate and dangerous use of Go's `reflect` package in combination with the `unsafe` package to bypass visibility rules and directly modify memory.

Unexported fields are a cornerstone of Go's encapsulation model, often safeguarding critical internal state, security flags, configuration details, or sensitive data. Allowing attackers to control these fields can lead to severe security consequences. These include the bypass of security controls, unauthorized privilege escalation, corruption of application state and data, denial of service (DoS), and, in worst-case scenarios, remote code execution (RCE). The core of the risk lies in the violation of intended encapsulation, permitting external, untrusted data to dictate the internal workings and integrity of an object.

Effective remediation strategies center on establishing and respecting clear boundaries between external data and internal application state. The primary recommendation is the adoption of Data Transfer Objects (DTOs) for all deserialization of untrusted input; these DTOs should only contain exported fields. Subsequent to DTO deserialization, rigorous and comprehensive validation of all data is paramount before any mapping to internal domain objects occurs. Unexported fields in domain objects should then be populated by trusted internal logic based on this validated data. Furthermore, the use of the `unsafe` package to modify unexported fields with data from external sources should be strictly avoided. Securing custom deserialization logic, if absolutely necessary, requires meticulous validation of any data destined for unexported fields.

A defense-in-depth approach, prioritizing robust input validation, the principle of least privilege, secure coding practices for custom deserializers, and the avoidance of inherently unsafe language features for handling external data, is crucial for mitigating this vulnerability and maintaining the security of Golang applications.

## References

- OWASP Foundation. "Insecure Deserialization."
- OWASP Foundation. "OWASP Top 10: Insecure Deserialization."
- OWASP Foundation. "Deserialization of Untrusted Data."
- Golang Project. `encoding/json` package documentation.
- Golang Project. `encoding/gob` package documentation.
- Golang Project. `reflect` package documentation.
- Golang Project. `unsafe` package documentation. (General Go documentation)
- Golang GitHub Issue #24152: "encoding/json: Unmarshal into embedded unexported struct panics instead of erroring."
- Golang GitHub Issue #2517: "encoding/gob: should ignore unexported fields."
- Fluid Attacks. "Insecure deserialization - Go."
- Datadog. "Unsafe reflection - SAST Rule."
- Stack Overflow. "Golang Marshal/Unmarshal json with both exported and un-exported fields."
- Stack Overflow. "How to gob encode struct with unexported pointer?"
- Stack Overflow. "How do I dump the struct into the byte array without reflection?" (Illustrates custom GobEncoder/Decoder for private fields).
- Reddit r/golang. Discussion on magicjson and setting private fields with unsafe. (Comment by MikeSchinkel).
- PortSwigger. "Insecure deserialization."
- Vaadata. "Exploiting and preventing insecure deserialization vulnerabilities."
- YouTube. Go Security Vulnerabilities video (Implies importance of updates).
- Fluid Attacks. "Lack of data validation - Trust boundary violation - Go." (Relevant to validation principles).
- Reddit r/golang. "Generally when do you expose structs members?" (Discusses unexported field philosophy).
- GitHub emicklei/go-restful Issue #575 (Mentions lack of validation after ReadEntity).
- igventurelli.io. "What Is a DTO and Why You Shouldn’t Return Your Entities in Spring Boot." (General DTO principles, applicable conceptually).
- Reddit r/dotnet. Discussion on DTO patterns. (General DTO benefits).
- Reddit r/golang. "Don't you validate your structs?" (Discussion on struct validation).
- DoltHub Blog. "Go Tags for Versioned Configuration." (Mentions validation tags).
- GeeksforGeeks. "reflect.UnsafeAddr() Function in Golang with Examples."
- Corgea. "Go Lang Security Best Practices." (General secure coding).
- Stack Overflow. "Exported and unexported fields in Go language."