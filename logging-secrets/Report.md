### Vulnerability Title

Logging Keys/Private Data using `fmt`/`log` (logging-secrets)

### Severity Rating

High🟠 (The direct exposure of sensitive cryptographic keys, credentials, or private user data can lead to immediate and severe compromise of systems, accounts, or privacy. The severity can be Critical if master keys are leaked.)

### Description

This vulnerability occurs when a Go application inadvertently logs sensitive information, such as private cryptographic keys, API tokens, passwords, personally identifiable information (PII), or other confidential data, using standard logging functions like `fmt.Printf`, `log.Println`, or similar methods. This sensitive data then ends up in log files, standard output, or monitoring systems, where it can be accessed by unauthorized individuals, leading to data breaches, account compromises, or system takeover.

### Technical Description (for security pros)

The vulnerability stems from the common practice of using Go's `fmt` package (e.g., `fmt.Printf`, `fmt.Sprintf`, `fmt.Println`) or the standard `log` package (e.g., `log.Printf`, `log.Println`, `log.Fatal`) for debugging, informational, or error logging without adequately sanitizing or redacting sensitive data.

When a variable holding a private key, an API token, a password, or PII is directly passed as an argument to a logging function, its string representation (which often includes the full sensitive value) is written to the configured log destination. This can happen in several ways:

  * **Direct Logging:** `log.Printf("Private key: %s", privateKey)`
  * **Default `String()` Method:** Some types (e.g., `*rsa.PrivateKey`, custom structs) might have a `String()` method that, when implicitly called by `fmt.Print` or `log.Print`, exposes sensitive internal fields.
  * **Error Logging:** Logging error objects that inadvertently contain sensitive data (e.g., an error from an authentication failure that includes the attempted password).
  * **Debugging Statements:** Developers often add verbose debug logs during development and forget to remove or properly sanitize them before deployment.

The consequence is that sensitive data, which should be protected at all costs, becomes persistently stored in plaintext within log files. These log files are often less secure than the application's runtime memory, may have broader access permissions, or might be transferred to less secure environments (e.g., log aggregators, cloud storage). An attacker gaining access to these logs (e.g., through a file system exploit, misconfigured S3 bucket, or insider threat) can then immediately compromise affected systems or users.

### Common Mistakes That Cause This

  * **Debugging with Production Logs:** Using `fmt.Println` or `log.Println` for debugging purposes on sensitive variables and forgetting to remove or replace these lines in production code.
  * **Lack of Sensitive Data Awareness:** Developers not recognizing certain data types (e.g., `[]byte` containing a key, specific struct fields) as sensitive.
  * **Over-Verbose Logging:** Configuring logging levels too broadly or logging too much context that includes sensitive details.
  * **Default `String()` Implementations:** Relying on default string representations of complex types that might expose sensitive internal state when logged.
  * **Propagating Sensitive Data in Errors:** Allowing sensitive data to be included in error messages that are subsequently logged.
  * **Copy-Pasting Code:** Reusing code snippets that include logging of sensitive information without proper review.
  * **Lack of Automated Checks:** Absence of static analysis or code review processes specifically looking for sensitive data in log statements.

### Exploitation Goals

  * **Account Takeover:** Using leaked passwords, API tokens, or session IDs to gain unauthorized access to user accounts.
  * **System Compromise:** Utilizing leaked cryptographic keys (e.g., private keys for SSH, TLS, or signing) to impersonate services, decrypt communications, or gain privileged access.
  * **Data Breach:** Extracting PII, financial details, or other confidential information to be exfiltrated and sold.
  * **Lateral Movement:** Using compromised credentials to access other systems within the network.
  * **Bypass Security Controls:** Leveraging leaked secrets to bypass authentication, authorization, or encryption mechanisms.

### Affected Components or Files

Any Go source code file that:

  * Imports `fmt` or `log` (or third-party logging libraries like `logrus`, `zap`, `zerolog`).
  * Directly logs variables or fields that contain sensitive data (e.g., `[]byte` slices of keys, `string` representations of tokens, struct fields holding credentials).
  * This can occur in any part of the application handling sensitive operations:
      * Authentication and authorization modules.
      * Cryptographic operations (key generation, signing, encryption/decryption).
      * Configuration loading.
      * API integrations (handling API keys).
      * Database connection strings.
      * User profile management.

### Vulnerable Code Snippet

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log" // Standard library log
	"os"
)

// simulate a sensitive API Key
const SensitiveAPIKey = "sk_live_verysecret1234567890abcdef"

func generateRSAKeyAndLog() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	// WARNING: Vulnerable logging of private key!
	fmt.Printf("Generated RSA Private Key (VULNERABLE): %v\n", privateKey) // fmt.Printf will use String() method if available, or print struct fields
	log.Printf("Full private key object logged (VULNERABLE): %+v\n", privateKey) // %+v prints struct fields

	// Example of logging a sensitive API key directly
	log.Printf("Sensitive API Key (VULNERABLE): %s\n", SensitiveAPIKey)

	// Example of logging a password during an authentication attempt (bad practice)
	password := "userpassword123!"
	log.Printf("Authentication failed for user 'testuser' with password: %s\n", password)
}

func main() {
	// Configure log output to stdout for demonstration
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	fmt.Println("--- Demonstrating vulnerable logging of sensitive data ---")
	generateRSAKeyAndLog()

	fmt.Println("\n--- End of demonstration ---")
}
```

### Detection Steps

1.  **Code Review:** Manually audit code for `fmt.Print*`, `log.Print*`, `log.Fatal*`, and similar functions from third-party logging libraries. Pay close attention to arguments that are:
      * Variables named `key`, `secret`, `password`, `token`, `credential`, `auth`, `private`.
      * Struct fields known to contain sensitive data.
      * Outputs of cryptographic functions (e.g., `rsa.GenerateKey`).
      * Error messages that might contain sensitive details.
2.  **Static Analysis (SAST):** Utilize SAST tools (e.g., Go's `govulncheck`, CodeQL, commercial SAST solutions) configured with rules to identify patterns of sensitive data being passed to logging functions. Many SAST tools have built-in detectors for "logging of sensitive information."
3.  **Dynamic Analysis/Runtime Monitoring:**
      * During testing or staging, monitor log outputs (stdout, stderr, log files) for any sensitive information.
      * Use log aggregation and monitoring tools to scan logs for patterns matching sensitive data formats (e.g., API key prefixes, specific key structures).
4.  **Security Linters:** Use Go linters that can detect common anti-patterns related to sensitive data logging.

### Proof of Concept (PoC)

The "Vulnerable Code Snippet" serves as a direct PoC.
To execute:

1.  Save the code as `vulnerable_logging.go`.
2.  Run `go run vulnerable_logging.go`.

**Expected Output:**

```
--- Demonstrating vulnerable logging of sensitive data ---
2025/05/27 23:01:28 vulnerable_logging.go:27: Generated RSA Private Key (VULNERABLE): &{[{<big_int_val>} {<big_int_val>} {<big_int_val>} ...]}
2025/05/27 23:01:28 vulnerable_logging.go:28: Full private key object logged (VULNERABLE): &{PublicKey:{N:<big_int_val> E:65537} D:<big_int_val> Primes:[<big_int_val> <big_int_val>] ExpONENTS:[<big_int_val> <big_int_val>]}
2025/05/27 23:01:28 vulnerable_logging.go:31: Sensitive API Key (VULNERABLE): sk_live_verysecret1234567890abcdef
2025/05/27 23:01:28 vulnerable_logging.go:35: Authentication failed for user 'testuser' with password: userpassword123!

--- End of demonstration ---
```

(Note: `<big_int_val>` represents the actual large integer values that would be printed for RSA components, which are highly sensitive.)

This output clearly shows the RSA private key, API key, and password being printed to standard output/log, demonstrating the vulnerability.

### Risk Classification

  * **Confidentiality:** Critical. Direct exposure of secrets.
  * **Integrity:** High. Leaked keys/credentials can lead to unauthorized changes.
  * **Availability:** Low. Not directly impacting availability, but compromise can lead to DoS if systems are taken offline after breach.
  * **CVSS:** 8.0 - 10.0 (High to Critical). Often falls under CWE-532 "Inclusion of Sensitive Information in Log Files."
  * **CWE:** CWE-532: Inclusion of Sensitive Information in Log Files.

### Fix & Patch Guidance

The fundamental fix is to **never log sensitive data in plaintext**.

1.  **Redaction/Masking:**
      * Instead of logging the full value, log only a masked version (e.g., `sk_live_**********ef` for API keys, `********` for passwords).
      * For keys, log only a non-sensitive identifier (e.g., key ID, public key fingerprint/hash).
      * Implement `String()` methods for sensitive structs that redact sensitive fields or return a non-informative string (e.g., `"[REDACTED]"`).
2.  **Avoid Direct Logging of Sensitive Variables:** Do not pass sensitive variables directly to logging functions.
3.  **Structured Logging Best Practices:** Use structured logging libraries (e.g., `zap`, `logrus`, `zerolog`) which often provide features for redacting specific fields or using custom formatters.
4.  **Review Log Levels:** Configure logging levels appropriately. Debug/Trace logs should be disabled in production.
5.  **Remove Debug Statements:** Thoroughly remove all debug logging statements that might expose sensitive data before deployment.
6.  **Secure Error Handling:** Ensure error messages do not propagate sensitive details.
7.  **Secrets Management:** Store and retrieve secrets using dedicated secrets management solutions (e.g., HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager) instead of hardcoding them or fetching them in a way that leads to logging.

**Example of Fixed Code:**

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

// Define a type for sensitive strings to enforce safe logging
type SensitiveString string

// String implements fmt.Stringer to redact output when logged
func (s SensitiveString) String() string {
	if len(s) > 4 {
		return string(s[:4]) + "**********" + string(s[len(s)-4:])
	}
	return "**********"
}

// PrivateKeyWithRedaction wraps rsa.PrivateKey for safe logging
type PrivateKeyWithRedaction struct {
	*rsa.PrivateKey
}

// String implements fmt.Stringer to redact output when logged
func (pk PrivateKeyWithRedaction) String() string {
	if pk.PrivateKey == nil {
		return "[NIL_PRIVATE_KEY]"
	}
	// Instead of logging the key, log its public key hash or ID
	publicKeyHash := sha256.Sum256(pk.PublicKey.N.Bytes())
	return fmt.Sprintf("[RSA_PRIVATE_KEY_REDACTED, Public Key Hash: %s...]", hex.EncodeToString(publicKeyHash[:8]))
}


// simulate a sensitive API Key
const SensitiveAPIKey = SensitiveString("sk_live_verysecret1234567890abcdef") // Use the SensitiveString type

func generateRSAKeyAndLogSafely() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Use the wrapper for safe logging
	safePrivateKey := PrivateKeyWithRedaction{privateKey}
	log.Printf("Generated RSA Private Key (SAFE): %v\n", safePrivateKey)

	// Log a masked API key
	log.Printf("Sensitive API Key (SAFE): %v\n", SensitiveAPIKey)

	// Example of logging a password securely (never log passwords, only hashes or redacted attempts)
	// DO NOT log the actual password. Instead, log a hash or a redacted version if absolutely necessary for debugging.
	passwordAttempt := "userpassword123!"
	log.Printf("Authentication failed for user 'testuser'. Attempted password (REDACTED): %s********\n", passwordAttempt[:4])
	// Better: just log the error message, not the password
	// log.Printf("Authentication failed for user 'testuser'.")
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	fmt.Println("--- Demonstrating SAFE logging of sensitive data ---")
	generateRSAKeyAndLogSafely()
	fmt.Println("\n--- End of demonstration ---")
}
```

### Scope and Impact

The scope of this vulnerability is very broad, as almost all applications use logging. Any application that handles sensitive data is at risk if it doesn't correctly sanitize its log output.

  * **Financial Impact:** Direct financial losses due to compromised accounts, fraudulent transactions, or regulatory fines.
  * **Reputational Damage:** Significant loss of customer trust, negative press, and long-term damage to brand reputation.
  * **Legal and Compliance:** Violations of data privacy regulations (e.g., GDPR, CCPA, HIPAA) can lead to severe penalties.
  * **Operational Disruption:** Attackers can use leaked credentials to disrupt services or destroy data.

### Remediation Recommendation

  * **Implement a "Never Log Secrets" Policy:** Establish a clear organizational policy that no sensitive data (keys, passwords, tokens, PII) should ever be logged in plaintext.
  * **Use `String()` Method for Redaction:** For custom types holding sensitive data, implement the `fmt.Stringer` interface (`String() string` method) to return a redacted or non-informative string representation.
  * **Centralized Logging with Redaction:** If using a centralized logging system, ensure it supports and is configured for automatic redaction of sensitive patterns before logs are stored.
  * **Secrets Management Integration:** Integrate with a robust secrets management solution for handling all sensitive credentials at runtime, minimizing their exposure in code and memory, and eliminating the need to log them.
  * **Security Training:** Conduct regular security training for developers on the importance of data privacy and secure logging practices.
  * **Automated Security Checks:** Incorporate SAST tools into CI/CD pipelines to automatically detect and flag potential sensitive data logging.
  * **Review Log Access:** Restrict access to log files and logging systems to only authorized personnel.

### Summary

The "Logging Keys/Private Data" vulnerability in Go applications stems from inadvertently printing sensitive information (like private keys, passwords, API tokens, or PII) to logs using functions from `fmt` or `log` packages. This exposes critical data to unauthorized individuals, leading to severe consequences such as account takeovers, system compromises, and data breaches. The core fix is to implement strict data redaction or masking before any sensitive information is logged, ideally by using custom `String()` methods for sensitive types and leveraging features of structured logging libraries. This is a high-severity vulnerability requiring immediate attention and robust security practices to prevent unauthorized disclosure of confidential information.

### References

  * [CWE-532: Inclusion of Sensitive Information in Log Files](https://cwe.mitre.org/data/definitions/532.html)
  * [OWASP Cheat Sheet Series: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
  * [OWASP Top 10: A01:2021-Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) (Could be a result of leaked credentials)
  * [OWASP Top 10: A04:2021-Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/) (Often indicates a design flaw in handling secrets)
  * [Go Documentation: `fmt` package](https://www.google.com/search?q=%5Bhttps://pkg.go.dev/fmt%5D\(https://pkg.go.dev/fmt\))
  * [Go Documentation: `log` package](https://www.google.com/search?q=%5Bhttps://pkg.go.dev/log%5D\(https://pkg.go.dev/log\))
  * [Go Documentation: `fmt.Stringer` interface](https://www.google.com/search?q=%5Bhttps://pkg.go.dev/fmt%23Stringer%5D\(https://pkg.go.dev/fmt%23Stringer\))