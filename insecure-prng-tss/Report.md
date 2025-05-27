### Vulnerability Title

Insecure PRNG for TSS Signature Seed (insecure-prng-tss)

### Severity Rating

High🟠 (Typically, the use of insecure PRNGs in cryptographic contexts leads to severe consequences. The actual CVSS score would depend on the specific implementation and context, but generally, it aligns with CWE-338 "Use of Cryptographically Weak Pseudo-Random Number Generator," which often has a high impact.)

### Description

This vulnerability arises when a Go application uses a cryptographically weak pseudo-random number generator (PRNG), such as `math/rand`, to generate a seed for a Threshold Signature Scheme (TSS) signature. TSS relies heavily on strong randomness for the security of its distributed key generation and signing processes. If the seed used is predictable, an attacker could potentially determine the secret shares or signatures, compromising the entire scheme.

### Technical Description (for security pros)

The vulnerability stems from the use of non-cryptographically secure PRNGs (e.g., `math/rand`) for generating entropy that is subsequently used as a seed for cryptographic operations, specifically within a Threshold Signature Scheme (TSS). TSS protocols, such as threshold ECDSA or BLS, depend on the generation of truly unpredictable random numbers for their secret shares, nonces, or other ephemeral cryptographic parameters.

When `math/rand` is used, especially if seeded with predictable values like `time.Now().UnixNano()`, the sequence of "random" numbers becomes deterministic and can be predicted by an attacker who can observe or guess the seed. This predictability can lead to:

  * **Key Compromise:** If the PRNG is used to generate secret shares for a distributed key, an attacker might be able to reconstruct the full private key.
  * **Signature Forgery:** If the PRNG is used for generating ephemeral nonces or other values crucial for signature generation, an attacker might be able to forge signatures.
  * **Breakage of Threshold Properties:** The security of TSS relies on the idea that a certain threshold of participants is required to perform an operation. Predictable random numbers could undermine this, allowing fewer than the required participants (or an external attacker) to bypass the threshold.

In Go, the `math/rand` package is explicitly designed for non-cryptographic purposes due to its deterministic nature, while `crypto/rand` is the designated cryptographically secure PRNG (CSPRNG) that draws entropy from system-level sources like `/dev/urandom` (Unix-like systems) or `CryptGenRandom` (Windows). The failure to use `crypto/rand` in security-sensitive contexts is the root cause.

### Common Mistakes That Cause This

  * **Misunderstanding `math/rand` vs. `crypto/rand`:** Developers often overlook the distinction between `math/rand` (for general-purpose, non-cryptographic randomness) and `crypto/rand` (for security-critical randomness).
  * **Using Predictable Seeds:** Even if `math/rand` were used, seeding it with easily guessable values like timestamps (`time.Now().UnixNano()`) makes the output sequence highly predictable.
  * **Copy-pasting code without security review:** Reusing code snippets that generate randomness without verifying their cryptographic suitability for the specific use case.
  * **Lack of security awareness:** Developers may not be aware of the stringent requirements for randomness in cryptographic applications like TSS.

### Exploitation Goals

  * **Secret Key Reconstruction:** The primary goal is to predict and reconstruct the secret shares of the TSS key.
  * **Signature Forgery:** If direct key reconstruction is not feasible, an attacker may aim to predict the random numbers used in the signing process to forge valid signatures without possessing the full key.
  * **Bypassing Threshold Security:** Subverting the security model of TSS by compromising enough components to perform operations below the intended threshold.
  * **Denial of Service:** While less direct, predictable randomness could potentially be exploited in some protocols to cause failures or lead to invalid states.

### Affected Components or Files

Any Go code module or function that:

  * Implements a Threshold Signature Scheme (TSS).
  * Uses `math/rand` (or a similar non-cryptographically secure PRNG) to generate any part of the TSS key, secret shares, nonces, or other cryptographic parameters.
  * Relies on the output of such an insecure PRNG for any part of its internal state or external interactions related to the TSS protocol.

Specifically, files involving:

  * Key generation (distributed key generation, DKG).
  * Signature share generation.
  * Any protocol step requiring unique, unpredictable random numbers for security.

### Vulnerable Code Snippet

(Hypothetical example; actual vulnerable code would be within a TSS implementation)

```go
package main

import (
	"fmt"
	"math/rand"
	"time"
	// Assume an imaginary TSS library that takes a seed for its operations
	// "github.com/example/tss-library"
)

func generateTSSSeed() int64 {
	// WARNING: This is a vulnerable snippet. Do NOT use in production.
	// Using time.Now().UnixNano() as a seed for math/rand is predictable.
	rand.Seed(time.Now().UnixNano())
	return rand.Int63() // Returns a pseudo-random int63
}

func main() {
	seed := generateTSSSeed()
	fmt.Printf("Generated TSS Seed (INSECURE): %d\n", seed)

	// In a real scenario, this seed would then be used by the TSS library
	// to generate secret shares, nonces, etc.
	// For example:
	// tssParty := tss_library.NewParty(seed, ...)
	// signatureShare := tssParty.Sign(...)
}
```

### Detection Steps

1.  **Code Review:** Manually inspect Go source code for usage of `math/rand` in proximity to cryptographic operations, especially those related to TSS, key generation, or signature creation.
2.  **Static Analysis:** Use static analysis tools (like Go's `govulncheck`, CodeQL, or commercial SAST tools) configured to identify the use of `math/rand` in security-sensitive contexts. These tools often flag `math/rand` usage as an "insecure randomness" issue.
3.  **Dependency Analysis:** Check third-party Go modules used for TSS or cryptography. Ensure they do not rely on insecure PRNGs internally.
4.  **Runtime Analysis/Fuzzing:** For complex cryptographic protocols, observe generated random numbers (if exposed) for patterns or predictability. This is more difficult to do without specific knowledge of the PRNG's internal state.

### Proof of Concept (PoC)

A direct PoC for compromising a TSS signature due to an insecure PRNG is highly dependent on the specific TSS protocol and its implementation details. However, a general concept would involve:

1.  **Observation/Timing:** An attacker observes a series of outputs or interactions from the vulnerable TSS system. If the `math/rand` is seeded with `time.Now().UnixNano()`, the attacker might try to guess the approximate time of seed generation.
2.  **Predicting the Seed:** Based on observed outputs and knowledge of the `math/rand` algorithm, the attacker attempts to reverse-engineer or brute-force the seed value. For `time.Now().UnixNano()`, this could involve trying a range of timestamps around the observed time.
3.  **Reproducing Randomness:** Once the seed is guessed, the attacker can re-initialize their own `math/rand` instance with the same seed and predict the exact sequence of "random" numbers that the vulnerable system would generate.
4.  **Exploiting Predictability in TSS:**
      * If the random numbers were used for generating secret shares, the attacker could generate their own shares and potentially reconstruct the full private key or forge signature shares.
      * If used for nonces in ECDSA (e.g., `k` value), a predictable nonce could lead to private key recovery through standard cryptographic attacks (e.g., if two signatures share the same nonce or a predictable relationship between nonces).

**Example (simplified, not a functional TSS PoC):**

An attacker could try to predict a "secret" number if the system used `math/rand` and `time.Now().UnixNano()`:

```go
package main

import (
	"fmt"
	"math/rand"
	"time"
)

// Vulnerable function (on the server)
func generateSecretValue() int64 {
	r := rand.New(rand.NewSource(time.Now().UnixNano())) // Vulnerable seeding
	return r.Int63n(1000000) // Generate a "secret" number
}

// Attacker's attempt to predict the secret value
func main() {
	fmt.Println("Server generates a secret value...")
	secretValue := generateSecretValue()
	fmt.Printf("Server's Secret Value: %d\n", secretValue)

	fmt.Println("\nAttacker attempting to predict the secret...")
	// Attacker knows the approximate time (e.g., within a few seconds/minutes)
	// and the range of values.
	currentTime := time.Now().UnixNano()

	// Brute-force seeds around the current time
	const searchWindowNs = 5 * time.Second // Search +/- 5 seconds
	found := false
	for i := -searchWindowNs; i <= searchWindowNs; i += time.Millisecond {
		guessedSeed := currentTime + int64(i)
		r := rand.New(rand.NewSource(guessedSeed))
		predictedValue := r.Int63n(1000000)

		if predictedValue == secretValue {
			fmt.Printf("Attacker FOUND the secret! Predicted value: %d (Guessed Seed: %d)\n", predictedValue, guessedSeed)
			found = true
			break
		}
	}

	if !found {
		fmt.Println("Attacker FAILED to find the secret within the search window.")
	}
}
```

This simple PoC demonstrates the predictability. In a TSS context, `secretValue` would correspond to a cryptographic parameter, making the impact much more severe.

### Risk Classification

  * **Confidentiality:** High. Compromise of secret keys or sensitive cryptographic material.
  * **Integrity:** High. Ability to forge signatures, leading to unauthorized transactions or data manipulation.
  * **Availability:** Medium to Low. While not a direct DoS, undermining the cryptographic foundation can lead to a system being untrustworthy or unusable.
  * **CVSS:** Likely in the 7.0-9.0 range (High to Critical), depending on the specific impact on the TSS protocol and the ease of exploitation. CWE-338 "Use of Cryptographically Weak Pseudo-Random Number Generator" is a common classification.

### Fix & Patch Guidance

The core fix is to replace any instance of `math/rand` used for cryptographic purposes with `crypto/rand`.

1.  **Identify all uses of `math/rand`:** Especially look for where its output is used to generate keys, nonces, session IDs, tokens, or any other security-sensitive values.
2.  **Replace with `crypto/rand`:**
      * Instead of `rand.Seed(time.Now().UnixNano())`, remove the seeding call, as `crypto/rand.Reader` is a global, cryptographically secure source of random bytes.
      * Instead of `math/rand.Int()`, use `crypto/rand.Read()` to fill a byte slice with cryptographically secure random bytes. Convert these bytes to the desired integer or other format as needed.

**Example of fixed code:**

```go
package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big" // For generating large random numbers securely
	// Assume an imaginary TSS library
	// "github.com/example/tss-library"
)

// Secure way to generate a random int63 (or similar size)
func generateSecureTSSSeed() (int64, error) {
	// Read random bytes from crypto/rand.Reader
	b := make([]byte, 8) // 8 bytes for int64
	_, err := rand.Read(b)
	if err != nil {
		return 0, fmt.Errorf("failed to read random bytes: %v", err)
	}

	// Convert bytes to int64
	return int64(binary.BigEndian.Uint64(b)), nil
}

// Alternatively, for larger or specific ranges, use math/big with crypto/rand
func generateSecureLargeNumber(max *big.Int) (*big.Int, error) {
	// max.Add(max, big.NewInt(1)) // If you need inclusive upper bound
	return rand.Int(rand.Reader, max)
}

func main() {
	seed, err := generateSecureTSSSeed()
	if err != nil {
		fmt.Printf("Error generating seed: %v\n", err)
		return
	}
	fmt.Printf("Generated TSS Seed (SECURE): %d\n", seed)

	// Example for a large number (e.g., private key component)
	maxVal := new(big.Int)
	maxVal.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16) // A large number for demo
	secureBigInt, err := generateSecureLargeNumber(maxVal)
	if err != nil {
		fmt.Printf("Error generating secure big int: %v\n", err)
		return
	}
	fmt.Printf("Generated Secure Big Int: %s\n", secureBigInt.Text(16))

	// This secure seed/random number would then be used by the TSS library
	// For example:
	// tssParty := tss_library.NewParty(secureBigInt, ...)
	// signatureShare := tssParty.Sign(...)
}
```

### Scope and Impact

The scope of this vulnerability is limited to applications that implement or rely on TSS schemes and mistakenly use insecure PRNGs for their cryptographic parameters. However, within that scope, the impact is severe.

  * **Impact on Confidentiality:** An attacker could potentially deduce secret keys or shares, leading to unauthorized access to funds (in cryptocurrency contexts), sensitive data, or impersonation.
  * **Impact on Integrity:** Forged signatures can lead to unauthorized transactions, corrupted data, or invalid attestations, undermining the trust in the system.
  * **Reputational Damage:** Loss of user trust, financial losses, and significant reputational harm for the organization or project.
  * **Legal/Compliance Issues:** Potential breach of data protection regulations (e.g., GDPR, HIPAA) if sensitive data is compromised.

### Remediation Recommendation

  * **Mandatory Use of `crypto/rand`:** For all security-sensitive random number generation, **always** use the `crypto/rand` package. Never use `math/rand` for cryptographic purposes.
  * **Security Audits:** Conduct thorough security audits, including static analysis and manual code review, to identify and rectify all instances of insecure randomness.
  * **Developer Education:** Educate developers on the critical distinction between `math/rand` and `crypto/rand` and the importance of using cryptographically secure random numbers for all security-related functionalities.
  * **Review Third-Party Libraries:** If using external TSS or cryptographic libraries, verify their internal use of PRNGs. Ensure they adhere to best practices for cryptographic randomness.
  * **Input Validation:** While not directly related to PRNG, ensure that any external inputs that might influence randomness are properly validated to prevent potential attacks.

### Summary

The "Insecure PRNG for TSS Signature Seed" vulnerability in Go applications arises from using the `math/rand` package (a non-cryptographically secure PRNG) to generate seeds or other random values critical for Threshold Signature Schemes (TSS). This allows an attacker to predict these values, potentially leading to the compromise of secret keys, forgery of digital signatures, and a complete breakdown of the TSS security model. The fix involves replacing all instances of `math/rand` with `crypto/rand`, which provides cryptographically secure random numbers. This is a high-severity vulnerability with significant confidentiality and integrity impacts, necessitating immediate remediation and careful security practices for all cryptographic operations.

### References

  * [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)
  * [Go Documentation: `crypto/rand`](https://www.google.com/search?q=%5Bhttps://pkg.go.dev/crypto/rand%5D\(https://pkg.go.dev/crypto/rand\))
  * [Go Documentation: `math/rand`](https://www.google.com/search?q=%5Bhttps://pkg.go.dev/math/rand%5D\(https://pkg.go.dev/math/rand\))
  * [OWASP Top 10: A02:2021-Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
  * [The Go Blog: Secure Randomness in Go 1.22 (Explains `math/rand` vs `crypto/rand`)](https://www.google.com/search?q=%5Bhttps://go.dev/blog/chacha8rand%5D\(https://go.dev/blog/chacha8rand\))