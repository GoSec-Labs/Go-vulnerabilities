# **Security Audit Report: Initialization Vector Reuse in AES-CBC for Golang Infrastructure**

## **1. Severity Rating**

- **Overall Severity:** High🟠
- **CVSS v3.1 Score:** 7.5
- **CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
    - **Attack Vector (AV): Network (N):** The vulnerability can often be exploited over a network if the encrypted data is transmitted.
    - **Attack Complexity (AC): Low (L):** If IVs are statically reused or predictably generated, the technical complexity to exploit the flaw is low.
    - **Privileges Required (PR): None (N):** An attacker typically does not need any special privileges on the system, only access to multiple ciphertexts.
    - **User Interaction (UI): None (N):** No user interaction is required for exploitation.
    - **Scope (S): Unchanged (U):** The exploit impacts the vulnerable component but does not typically affect other components' security.
    - **Confidentiality (C): High (H):** Successful exploitation can lead to the disclosure of sensitive plaintext information.
    - **Integrity (I): None (N):** IV reuse in CBC mode primarily impacts confidentiality, not integrity. CBC mode itself is malleable, but that's a separate issue.
    - **Availability (A): None (N):** The vulnerability does not typically impact system availability.

This rating reflects the potential for significant information disclosure with relatively low attack complexity when AES-CBC IVs are improperly managed. A specific instance of a zero IV vulnerability in ESPTouchV2 using AES/CBC was assigned CVE-2024-53845, with a CVSS v4.0 vector indicating high confidentiality impact (`VC:H`).

## **2. Description**

The Advanced Encryption Standard (AES) is a widely adopted symmetric block cipher used to protect sensitive information. AES operates in various modes, each with distinct characteristics and security properties. Cipher Block Chaining (CBC) is one such mode that provides confidentiality by ensuring that identical plaintext blocks encrypt to different ciphertext blocks. This is achieved by XORing each plaintext block with the ciphertext of the preceding block before encryption. For the first block, an Initialization Vector (IV) is used in place of a previous ciphertext block.

The security of AES-CBC heavily relies on the proper management of this IV. The IV must be unique and unpredictable for each encryption operation performed with the same key. Reusing an IV with the same key for different messages, or using predictable IVs, undermines the confidentiality guarantees of CBC mode, leading to a vulnerability commonly referred to as "IV reuse" or "aes-cbc-iv-reuse". This report details this vulnerability specifically within the context of Golang-based infrastructure.

## **3. Technical Description (for security professionals)**

In AES-CBC mode, the encryption process for a plaintext P divided into blocks P1,P2,…,Pn using a key K and an IV is as follows:

Its math Equation | Need to fix 

`C1=EK(P1⊕IV)`

`Ci=EK(Pi⊕Ci−1) for i>1`

Where EK is the AES encryption function with key K, and Ci is the i-th ciphertext block. Decryption is the reverse:

`P1=DK(C1)⊕IV`

`Pi=DK(Ci)⊕Ci−1 for i>1`

The IV's role is to introduce randomness for the first block's encryption. For AES, the block size, and thus the IV size, is 128 bits (16 bytes). The IV need not be secret and is often prepended to the ciphertext.However, NIST SP 800-38A mandates that for CBC mode, the IV must be unpredictable.

IV Reuse Vulnerability:

If the same (Key, IV) pair is used to encrypt two different plaintexts, P and P′, their respective first ciphertext blocks C1 and C1′ are:

`C1=EK(P1⊕IV)`

`C1′=EK(P1′⊕IV)`

If P1=P1′ (i.e., the first plaintext blocks are identical), then C1=C1′. This leaks the information that the two messages start with the same block of data. An attacker observing multiple ciphertexts can identify messages that share a common prefix. This is a direct violation of semantic security, which requires that an attacker learns no information about the plaintext from the ciphertext, other than possibly its length.

If an attacker knows P1 for a given C1 (and the reused IV), they can compute P1⊕IV. If they then observe C1′ from another message encrypted with the same key and IV, they can test guesses for P1′.

Predictable IVs:

If an IV is predictable (e.g., a simple counter, or derived from the previous ciphertext block in an insecure manner), an attacker might be able to mount a chosen-plaintext attack. If an attacker can predict the IVnext that will be used to encrypt a plaintext Pnext and can influence Pnext, they can potentially verify guesses about other plaintexts encrypted with the same key.5 This was the basis of the BEAST attack against TLS/SSL, which exploited predictable IVs in CBC mode.7 The core issue is that if an attacker can make the term Pi⊕Ci−1 (where C0=IV) equal to a known value for which they have the ciphertext, they can confirm their guess about Pi.

For example, if an attacker knows Cj=EK(Pj⊕Cj−1) and can predict the IVnew that will be used for a new message, they can submit a crafted plaintext Pcrafted=Pj⊕Cj−1⊕IVnew. The system will then compute EK(Pcrafted⊕IVnew)=EK((Pj⊕Cj−1⊕IVnew)⊕IVnew)=EK(Pj⊕Cj−1)=Cj. If the resulting ciphertext matches Cj, the attacker confirms their guess about Pj⊕Cj−1.

The fundamental security requirement for CBC IVs is unpredictability at the time of encryption. Randomly generating the IV for each encryption using a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) satisfies both uniqueness and unpredictability requirements.

## **4. Common Mistakes That Cause This Vulnerability in Golang**

The AES-CBC IV reuse vulnerability in Golang applications typically arises from developers misunderstanding or misapplying the requirements for IV generation and management. Golang's `crypto/cipher` package provides the necessary tools for implementing AES-CBC, but it places the responsibility of correct IV handling on the developer.

Common mistakes include:

1. **Using a Static/Hardcoded IV:** Developers might define a constant byte slice as the IV and use it for all encryption operations. This is a direct reuse of the (Key, IV) pair for every message.
    - *Example:* `var staticIV =byte("0123456789abcdef")` used repeatedly with `cipher.NewCBCEncrypter(block, staticIV)`.
    - This often occurs due to a desire for simplicity or a misunderstanding that the IV needs to be secret or complex to generate, rather than simply unique and random per encryption. The fact that such code "works" (encrypts and decrypts) can mask the underlying security flaw.
2. **Generating an IV Once and Reusing It:** An IV might be generated correctly using `crypto/rand` at application startup or when an object is initialized, but then stored and reused for multiple encryption calls.
    - *Example:* An IV stored in a struct field and reused across method calls that perform encryption.
    - This can be particularly problematic in long-running services or concurrent applications where the same IV instance might be used by multiple goroutines.
3. **Using Predictable IVs:** Instead of random IVs, developers might use sequential IVs (counters) or derive IVs in a predictable manner. While counters can be acceptable for nonce-based modes like CTR or GCM if managed carefully, they are insecure for CBC mode IVs which require unpredictability.
    - The BEAST attack demonstrated the risks of predictable IVs in CBC mode.
        
        
4. **Incorrectly Sourcing Randomness:** Using non-cryptographically secure random number generators (e.g., `math/rand` instead of `crypto/rand`) to generate IVs. `math/rand` is not suitable for security-sensitive operations as its output can be predictable.
5. **Reusing Cipher Objects:** Reusing a `cipher.BlockMode` object (which has been initialized with an IV) for multiple separate encryption operations without re-initializing it with a new, unique IV. The `cipher.BlockMode` interface itself is stateful with respect to the chaining operation but expects a fresh IV for each distinct message encryption context.
6. **Ignoring IVs in Third-Party Libraries or Examples:** Developers might use cryptographic libraries or follow online examples that incorrectly handle IVs, or where the example omits crucial details about IV management for brevity.

The low-level nature of Golang's `crypto/cipher` package means developers have significant control, which also means more opportunities for error if cryptographic best practices are not strictly followed. The lack of built-in warnings for IV misuse in the standard library further exacerbates this, as functionally correct code may still harbor serious security flaws.

## **5. Exploitation Goals**

An attacker exploiting an AES-CBC IV reuse vulnerability primarily aims to compromise the **confidentiality** of the encrypted data. Specific goals include:

1. **Identifying Identical Plaintexts:** If the same plaintext is encrypted multiple times with the same (Key, IV) pair, the resulting ciphertexts will be identical. This allows an attacker to identify when the same message has been sent or the same data has been stored, even without knowing the content.
2. **Detecting Common Prefixes:** If two different plaintexts share one or more initial blocks, and they are encrypted with the same (Key, IV) pair, their corresponding ciphertexts will also share identical initial blocks. This can leak significant information. For example:
    - Identifying file types with known headers (e.g., "PK" for ZIP files, "%PDF" for PDF files).
    - Recognizing structured data where initial fields are often the same (e.g., session tokens like `"session_id:"`, API keys like `"sk_live_..."`).
    - Determining if different encrypted records in a database share common leading information.
3. **Partial Plaintext Recovery (Information Leakage):** By observing patterns and commonalities across multiple ciphertexts generated with a reused IV, an attacker can infer partial information about the plaintexts. For instance, if an attacker knows that a message is either "APPROVE" or "DENIED" (padded to a block), and they have an example ciphertext for "APPROVE" (with the reused IV), they can determine if other messages are also "APPROVE".
4. **Full Plaintext Recovery (with Predictable IVs and Chosen Plaintext):** In scenarios where the IV is predictable and the attacker can submit chosen plaintexts for encryption (a chosen-plaintext attack or CPA), they may be able to decrypt targeted ciphertext blocks. This is a more advanced attack but can lead to complete plaintext recovery for affected blocks. The BEAST attack is a practical example of this against TLS.
5. **Facilitating Other Attacks:** Information gleaned from IV reuse might be used as a stepping stone for other attacks. For example, identifying the format or type of encrypted data could help an attacker focus subsequent cryptanalysis efforts or exploit other vulnerabilities related to how that data is processed.

It's important to note that IV reuse in CBC mode does not directly allow an attacker to recover the encryption key. However, the leakage of plaintext information can be severe enough to render the encryption ineffective for its intended purpose of confidentiality.

## **6. Affected Components or Files**

The AES-CBC IV reuse vulnerability can manifest in various components and files within a Golang infrastructure where AES-CBC encryption is employed. Developers must be vigilant wherever the `crypto/cipher` package's CBC mode functions are used.

Key areas include:

1. **Data-at-Rest Encryption:**
    - **Database Encryption:** Golang applications encrypting sensitive fields in databases (e.g., Personally Identifiable Information (PII), financial data, API keys, tokens) before storing them. If a static IV or improperly managed IV is used for encrypting multiple rows or records, this vulnerability can occur.
    - **File Encryption:** Systems that encrypt files for storage (e.g., configuration files with secrets, user-uploaded documents, backups). Reusing an IV for encrypting different files or different versions of the same file with the same key is vulnerable.
    - **Application Logs:** If sensitive data within logs is encrypted using AES-CBC.
2. **Data-in-Transit Encryption:**
    - **Custom Network Protocols:** Golang services communicating over custom network protocols where AES-CBC is used to encrypt message payloads between client and server or between microservices.
    - **API Data Encryption:** APIs that encrypt parts of request or response payloads, especially if they are not relying solely on TLS for channel security but implement an additional layer of application-level encryption.
    - **Message Queues:** Applications that encrypt messages before publishing them to a message queue (e.g., Kafka, RabbitMQ) and decrypt them upon consumption.
3. **Specific Golang Code Locations:**
    - Any Go files (`.go`) that import `crypto/aes` and `crypto/cipher`.
    - Functions or methods that call `cipher.NewCBCEncrypter(block, iv)`. The focus of review should be on how `iv` is generated and managed for each call.
    - Helper functions or utility packages designed for encryption/decryption tasks within the application. These are common places where a flawed IV management strategy might be centralized.
    - Initialization code (e.g., `init()` functions, struct constructors) where an IV might be generated once and stored for later reuse.
    - Code handling concurrent operations (goroutines) where shared IV buffers or cipher objects might be unsafely accessed, leading to unintentional IV reuse.
4. **Configuration Management:**
    - Systems where encryption keys are managed, as the vulnerability is about the (Key, IV) *pair*. While key management is distinct, the context of key usage often involves IV generation. If configuration systems also suggest or provide IVs, they could be a source of static IVs.

The pervasiveness of this issue depends on developer practices. Since Go's standard library provides the building blocks but not an opinionated, high-level "do-everything-securely" AES-CBC API, the onus is on the developer to implement IV handling correctly. This means any part of a Golang system performing AES-CBC encryption is potentially susceptible if not carefully implemented and reviewed.

## **7. Vulnerable Code Snippet (Golang)**

The following Golang code snippet demonstrates the AES-CBC IV reuse vulnerability. It uses a static, hardcoded Initialization Vector for every encryption operation.

```go
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// WARNING: This key is for demonstration purposes only.
// In a real application, keys must be securely managed and protected.
var key =byte("a very secret key 12345678901234") // 32 bytes for AES-256

// WARNING: staticIV is a hardcoded IV. Reusing this IV for multiple
// encryptions with the same key is a SEVERE VULNERABILITY.
var staticIV =byte("0123456789abcdef") // 16 bytes, AES block size

// EncryptStaticIV demonstrates vulnerable AES-CBC encryption due to IV reuse.
func EncryptStaticIV(plaintextbyte) (byte, error) {
	block, err := aes.NewCipher(key)
	if err!= nil {
		return nil, err
	}

	// Plaintext must be padded to a multiple of the block size for CBC mode.
	// For simplicity, this example assumes plaintext is already padded
	// or its length is a multiple of aes.BlockSize.
	// In a real scenario, apply PKCS#7 padding or similar.
	if len(plaintext)%aes.BlockSize!= 0 {
		// This is a simplification. Proper padding should be applied.
		// For this demo, we'll ensure input is block-aligned.
		// If not, an error or padding logic would be here.
		// To make the PoC work easily, we expect pre-padded input.
		// Example: Pad with zeros or a specific padding scheme.
		// For this example, we will make a copy and pad with a simple scheme if needed.
		padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
		if padding!= aes.BlockSize { // Only pad if not already a multiple
			padtext := bytes.Repeat(byte{byte(padding)}, padding)
			plaintext = append(plaintext, padtext...)
		}
	}

	ciphertext := make(byte, len(plaintext))

	// The vulnerability: staticIV is reused for every encryption.
	mode := cipher.NewCBCEncrypter(block, staticIV)
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

func main() {
	// Ensure plaintexts are multiples of aes.BlockSize (16) for this simplified example
	pt1 :=byte("This is message 1, common") // 26 bytes. Padded to 32.
	pt2 :=byte("This is message 2, common") // 26 bytes. Padded to 32.
	pt3 :=byte("Different content for msg 3") // 27 bytes. Padded to 32.

	// For demonstration, explicitly create block-aligned plaintexts
	// In a real scenario, a proper padding function would handle this.
	makePadded := func(ptbyte, blockSize int)byte {
		padding := blockSize - (len(pt) % blockSize)
		if padding == blockSize { // Already a multiple or empty
			if len(pt) == 0 { // Handle empty string case if needed
				return bytes.Repeat(byte{byte(blockSize)}, blockSize)
			}
			return pt // No padding needed if len(pt) % blockSize == 0 and len(pt) > 0
		}
		padtext := bytes.Repeat(byte{byte(padding)}, padding)
		return append(pt, padtext...)
	}

	paddedPt1 := makePadded(pt1, aes.BlockSize)
	paddedPt2 := makePadded(pt2, aes.BlockSize)
	paddedPt3 := makePadded(pt3, aes.BlockSize)

	fmt.Printf("Original pt1: \"%s\" (len %d), Padded pt1: %x (len %d)\n", pt1, len(pt1), paddedPt1, len(paddedPt1))
	fmt.Printf("Original pt2: \"%s\" (len %d), Padded pt2: %x (len %d)\n", pt2, len(pt2), paddedPt2, len(paddedPt2))

	c1, err := EncryptStaticIV(paddedPt1)
	if err!= nil {
		fmt.Printf("Error encrypting pt1: %v\n", err)
		return
	}
	c2, err := EncryptStaticIV(paddedPt2)
	if err!= nil {
		fmt.Printf("Error encrypting pt2: %v\n", err)
		return
	}
	// Encrypting pt1 again with the same static IV
	c3, err := EncryptStaticIV(paddedPt1)
	if err!= nil {
		fmt.Printf("Error encrypting pt1 again: %v\n", err)
		return
	}
	c4, err := EncryptStaticIV(paddedPt3)
	if err!= nil {
		fmt.Printf("Error encrypting pt3: %v\n", err)
		return
	}

	fmt.Printf("Ciphertext 1 (pt1): %x\n", c1)
	fmt.Printf("Ciphertext 2 (pt2): %x\n", c2)
	fmt.Printf("Ciphertext 3 (pt1 again): %x\n", c3)
	fmt.Printf("Ciphertext 4 (pt3): %x\n", c4)

	// Demonstration of consequences:
	if bytes.Equal(c1, c3) {
		fmt.Println("\n c1 and c3 are identical: Same plaintext + same static IV = same ciphertext.")
	}

	// Check if first blocks are identical if plaintexts share a prefix
	// pt1 and pt2 share "This is message " which is 16 bytes (one block)
	if len(c1) >= aes.BlockSize && len(c2) >= aes.BlockSize && bytes.Equal(c1, c2) {
		fmt.Println(" First blocks of c1 and c2 are identical: Plaintexts share a common first block and IV is reused.")
	} else if len(c1) >= aes.BlockSize && len(c2) >= aes.BlockSize {
		fmt.Printf("First block c1: %x\n", c1)
		fmt.Printf("First block c2: %x\n", c2)
		fmt.Println("First blocks of c1 and c2 are NOT identical. Check plaintext prefixes and padding alignment.")
	}
}
```

**Explanation of Vulnerability:**

1. **Static IV:** The `staticIV` variable is defined globally with a fixed value.
2. **Reused in `EncryptStaticIV`:** Inside the `EncryptStaticIV` function, `cipher.NewCBCEncrypter(block, staticIV)` is called. This means every time `EncryptStaticIV` is invoked with the same `key`, it uses the *exact same* `staticIV`.
3. **Consequences (as shown in `main`):**
    - If the same plaintext (`paddedPt1`) is encrypted twice (resulting in `c1` and `c3`), the ciphertexts are identical. This directly leaks that the same data was encrypted.

    - If two different plaintexts (`paddedPt1` and `paddedPt2`) share an identical first block (e.g., "This is message "), their respective ciphertexts (`c1` and `c2`) will also have identical first blocks. This leaks that the messages start with the same content.
        

This code might appear to function correctly because it successfully encrypts and can decrypt data (if a corresponding decryption function using the same static IV is implemented). However, it critically fails to provide semantic security due to IV reuse. Real-world CBC implementations also require careful padding handling (e.g., PKCS#7) for plaintexts not a multiple of the block size. The example simplifies this by assuming block-aligned input or applying a basic padding for demonstration, but improper padding can lead to separate vulnerabilities like padding oracle attacks. The core issue highlighted here is the IV reuse itself. Several CVEs have been assigned for vulnerabilities stemming from fixed IV usage in various products.

## **8. Detection Steps**

Detecting AES-CBC IV reuse in Golang infrastructure requires a combination of manual and automated techniques:

1. **Manual Code Review:**
    - **Target:** Identify all usages of `crypto/cipher.NewCBCEncrypter` and `crypto/cipher.NewCBCDecrypter`.
        
    - **IV Source Inspection:** For each call to `NewCBCEncrypter`, trace the origin of the `iv` argument.
        - Look for hardcoded IVs: byte slices defined as constants or global variables (e.g., `var myIV =byte{...}`).
        - Check for IVs generated once (e.g., in an `init()` function, struct constructor, or on first use) and then stored in a global variable or struct field for repeated use.
        - Scrutinize IV generation logic: Is it derived from predictable sources like counters, timestamps, or non-cryptographic PRNGs (e.g., `math/rand`)? For CBC mode, IVs must be unpredictable.
            
    - **Correct Pattern:** Verify that a new, random IV is generated using `crypto/rand.Reader` (typically via `io.ReadFull`) for *every individual encryption operation*. The IV should be unique per message encrypted with the same key.
        
    - **Concurrency:** In concurrent Golang applications (using goroutines), pay special attention to how IVs are handled. Ensure that goroutines do not inadvertently share or reuse IV buffers before they are re-randomized, which could lead to race conditions resulting in IV reuse.
2. **Static Analysis Security Testing (SAST):**
    - Utilize SAST tools that include checks for cryptographic misconfigurations. For Golang, `gosec` is a common tool. While `gosec` has rules against weak algorithms (e.g., G501-G505 for DES, SHA1) and insecure block cipher modes like ECB (G404), its ability to detect all nuanced forms of IV reuse in CBC might be limited.
        
    - More advanced SAST tools, or those with customizable rules (e.g., Semgrep), might be better suited. For instance, Datadog offers a `kotlin-security/no-iv-reuse` rule for Kotlin , and SonarSource has `rspec-6432` ("Cipher Block Chaining IVs should be unpredictable") for Kotlin. Similar specific checks are needed for Golang.
        
    - Effective SAST tools should perform data flow analysis to determine if an IV value remains constant or is derived from a non-random/predictable source across multiple encryption contexts. However, detecting subtle IV reuse, especially those arising from complex state management or concurrency issues in Go, can be challenging for SAST. The low-level nature of Go's `crypto/cipher` API allows for many ways to manage IVs, not all of which are easily flagged by generic rules. This underscores the continued importance of manual review by knowledgeable personnel. Organizations might consider developing custom SAST rules tailored to their specific Go codebase and IV management patterns.
3. **Dynamic Analysis / Cryptographic Testing:**
    - In controlled test environments, intercept encrypted data.
    - Encrypt known plaintexts multiple times. If IVs are prepended to ciphertexts (a common practice), check if these IVs are unique for each encryption. If IVs are not prepended, check if the full ciphertexts are identical when the same plaintext is encrypted repeatedly.
    - Encrypt different plaintexts that share known common prefixes. Observe if the resulting ciphertexts (or their initial blocks, if IVs are not prepended and reused) also share common prefixes.
4. **Logging and Monitoring (Cautionary):**
    - During development or debugging phases *only*, temporarily logging IV values (in a secure, controlled manner) could help identify reuse patterns. **IVs should never be logged in production environments** due to potential information leakage.

Effective detection often requires a defense-in-depth approach, combining automated scanning with expert human review, particularly for a subtle cryptographic flaw like IV reuse.

## **9. Proof of Concept (PoC)**

The following Proof of Concept uses the vulnerable `EncryptStaticIV` function defined in Section 7 to demonstrate the consequences of AES-CBC IV reuse in Golang.

```go

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// --- Assume EncryptStaticIV function and staticIV, key variables ---
// --- are defined as in Section 7's Vulnerable Code Snippet.    ---

// WARNING: This key is for demonstration purposes only.
var key =byte("a very secret key 12345678901234") // 32 bytes for AES-256
var staticIV =byte("0123456789abcdef")         // 16 bytes, AES block size

func EncryptStaticIV(plaintextbyte) (byte, error) {
	block, err := aes.NewCipher(key)
	if err!= nil {
		return nil, err
	}
	// Simplified padding for PoC: ensure input is block-aligned or pad simply
	if len(plaintext)%aes.BlockSize!= 0 {
		padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
		padtext := bytes.Repeat(byte{byte(padding)}, padding)
		plaintext = append(plaintext, padtext...)
	}
	ciphertext := make(byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, staticIV) // Reuses staticIV
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}
// --- End of assumed definitions ---

// makePadded is a helper to ensure plaintexts are block-aligned for the PoC.
// In real code, use a standard padding scheme like PKCS#7.
func makePadded(ptbyte, blockSize int)byte {
	padding := blockSize - (len(pt) % blockSize)
	if padding == blockSize && len(pt)!= 0 { // Already a multiple and not empty
		return pt
	}
	if len(pt) == 0 { // Handle empty string case if needed by padding to full block
	    return bytes.Repeat(byte{byte(blockSize)}, blockSize)
	}
	padtext := bytes.Repeat(byte{byte(padding)}, padding)
	return append(pt, padtext...)
}

func demonstratePoC() {
	fmt.Println("--- Proof of Concept for AES-CBC IV Reuse ---")

	// Scenario 1: Identical Plaintext, Reused IV -> Identical Ciphertext
	fmt.Println("\nScenario 1: Encrypting the same plaintext twice with static IV...")
	ptA_original :=byte("This is a secret message.")
	ptA := makePadded(ptA_original, aes.BlockSize) // Ensure block alignment

	c_A1, errA1 := EncryptStaticIV(ptA)
	if errA1!= nil {
		fmt.Printf("PoC Scenario 1 Error (A1): %v\n", errA1)
		return
	}
	c_A2, errA2 := EncryptStaticIV(ptA)
	if errA2!= nil {
		fmt.Printf("PoC Scenario 1 Error (A2): %v\n", errA2)
		return
	}

	fmt.Printf("Plaintext A (padded): %x\n", ptA)
	fmt.Printf("Ciphertext A1: %x\n", c_A1)
	fmt.Printf("Ciphertext A2: %x\n", c_A2)

	if bytes.Equal(c_A1, c_A2) {
		fmt.Println("PoC1 SUCCESS: Reused IV with the same plaintext yields identical ciphertext.")
		fmt.Println("   Leakage: An attacker can identify that the same message was sent/stored.")
	} else {
		fmt.Println("PoC1 FAILED: Ciphertexts are different (unexpected for static IV).")
	}

	// Scenario 2: Different Plaintexts with Common Prefix, Reused IV -> Common Ciphertext Prefix
	fmt.Println("\nScenario 2: Encrypting two different plaintexts sharing a common first block with static IV...")
	// First block (16 bytes): "COMMON_PREFIX_AA"
	// Second block (16 bytes): "UNIQUE_SUFFIX_X" or "UNIQUE_SUFFIX_Y"
	ptX_original :=byte("COMMON_PREFIX_AAUNIQUE_SUFFIX_X") // 32 bytes
	ptY_original :=byte("COMMON_PREFIX_AAUNIQUE_SUFFIX_Y") // 32 bytes

    // These are already block aligned (32 bytes), so makePadded won't change them.
	ptX := makePadded(ptX_original, aes.BlockSize)
	ptY := makePadded(ptY_original, aes.BlockSize)

	cX, errX := EncryptStaticIV(ptX)
	if errX!= nil {
		fmt.Printf("PoC Scenario 2 Error (X): %v\n", errX)
		return
	}
	cY, errY := EncryptStaticIV(ptY)
	if errY!= nil {
		fmt.Printf("PoC Scenario 2 Error (Y): %v\n", errY)
		return
	}

	fmt.Printf("Plaintext X: %s (%x)\n", ptX_original, ptX)
	fmt.Printf("Plaintext Y: %s (%x)\n", ptY_original, ptY)
	fmt.Printf("Ciphertext X: %x\n", cX)
	fmt.Printf("Ciphertext Y: %x\n", cY)

	if len(cX) >= aes.BlockSize && len(cY) >= aes.BlockSize && bytes.Equal(cX, cY) {
		fmt.Println("PoC2 SUCCESS: Reused IV with plaintexts sharing the first block yields identical first ciphertext block.")
		fmt.Println("   Leakage: An attacker can identify that messages share a common prefix.")
		fmt.Printf("   Identical First Block: %x\n", cX)
	} else {
		fmt.Println("PoC2 FAILED: First ciphertext blocks are different (unexpected for static IV and common plaintext prefix).")
		if len(cX) >= aes.BlockSize { fmt.Printf("   First block cX: %x\n", cX) }
		if len(cY) >= aes.BlockSizetf("   First block cY: %x\n", cY) }
	}
	fmt.Println("\n--- End of PoC ---")
}

func main() {
	demonstratePoC()
}
```

**Running this PoC with the vulnerable `EncryptStaticIV` function will demonstrate:**

1. **Identical Ciphertexts:** `c_A1` and `c_A2` will be identical because both the plaintext (`ptA`) and the IV (`staticIV`) are the same for both encryption operations. This directly shows that encrypting the same data twice yields the same ciphertext, a clear information leak.
    
2. **Common Ciphertext Prefix:** `cX` and `cY` will be identical because the first blocks of `ptX` and `ptY` are the same ("COMMON_PREFIX_AA") and the same `staticIV` is used. This leaks that the two different messages start with the same 16 bytes of data.

The simplicity of this PoC (comparing byte slices) should not detract from the severity of the underlying cryptographic weakness. It clearly shows the loss of semantic security. A more complex PoC would be required to demonstrate attacks against predictable (but not static) IVs, typically involving an interactive setup where an attacker submits crafted plaintexts to an encryption oracle. The PoC above focuses on the more direct and easily demonstrable static IV reuse.

## **10. Risk Classification**

The reuse of Initialization Vectors (IVs) in AES-CBC mode presents a significant risk to the confidentiality of encrypted data.

- **Likelihood:** Medium to High
    - The mistake of reusing IVs is relatively easy for developers to make, especially if they are not deeply familiar with cryptographic best practices or if code reviews do not specifically scrutinize IV management. Golang's `crypto/cipher` package, being somewhat low-level, provides flexibility but also opportunity for such errors if not used with care. The lack of built-in compiler or runtime warnings for IV misuse further increases this likelihood if not caught by SAST or thorough manual reviews.
        
- **Impact:** High
    - Successful exploitation leads to a breach of confidentiality. Attackers can deduce information about the plaintext, such as identifying identical messages, common prefixes, or, in some scenarios with predictable IVs, potentially recovering parts of the plaintext.
        
- **Overall Risk:** High
    - Given the potential for high confidentiality impact and the moderate to high likelihood of occurrence in implementations lacking rigorous cryptographic oversight, the overall risk is classified as High.

**Vulnerability Classification Details:**

| **Aspect** | **Details** |
| --- | --- |
| **CWE ID(s)** | **CWE-323: Reusing a Nonce, Key Pair in Encryption** **6**: This is the most direct classification, as IV reuse with the same key is precisely what occurs. <br> **CWE-329: Generation of Predictable IV with CBC Mode** : Applies if IVs are generated predictably (e.g., counters), rather than being truly random and unpredictable. <br> **CWE-327: Use of a Broken or Risky Cryptographic Algorithm**: While AES-CBC itself is not broken if used correctly, its implementation with IV reuse constitutes a broken or risky usage of the algorithm. <br> **CWE-1204: Generation of Weak Initialization Vector (IV)** : A reused or predictable IV is a form of weak IV. |
| **Example CVSS v3.1 Score / Vector** | **7.5 (High🟠)** / `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (as detailed in Section 1). This reflects a network-exploitable vulnerability with low complexity, requiring no privileges or user interaction, leading to high confidentiality impact. |
| **OWASP Top 10 2021** | **A02:2021 – Cryptographic Failures**. This category explicitly includes scenarios where "initialization vectors [are] ignored, reused, or not generated sufficiently secure for the cryptographic mode of operation." |

This classification underscores the criticality of addressing IV reuse vulnerabilities promptly.

## **11. Fix & Patch Guidance (Golang specific)**

The primary remediation for AES-CBC IV reuse in Golang is to ensure that a **unique and unpredictable (cryptographically random) Initialization Vector is generated for every encryption operation performed with the same key.**

**Golang Implementation Steps:**

1. **Generate a Random IV:** For each message to be encrypted, generate a new 16-byte IV (since `aes.BlockSize` is 16 bytes **9**) using a cryptographically secure pseudo-random number generator (CSPRNG). In Golang, this is `crypto/rand.Reader`.
    
    ```go
    
    import (
        "crypto/aes"
        "crypto/rand"
        "io"
    )
    
    iv := make(byte, aes.BlockSize)
    if _, err := io.ReadFull(rand.Reader, iv); err!= nil {
        // Handle error: failed to generate IV
        return nil, fmt.Errorf("failed to generate secure IV: %w", err)
    }
    ```
    
    This practice is recommended by Golang's own crypto examples  and general cryptographic best practices.
    
2. **Use the New IV for Encryption:** Pass this newly generated IV to `cipher.NewCBCEncrypter`.
3. **Transmit/Store the IV with the Ciphertext:** The IV is not a secret and must be available for decryption. A common and secure practice is to prepend the IV to the ciphertext.
    
    ```go
    
    ciphertext := make(byte, aes.BlockSize+len(paddedPlaintext))
    copy(ciphertext, iv) // Prepend IV
    //... then encrypt into ciphertext
    ```
    
4. **Use the IV for Decryption:** When decrypting, extract the IV from the prepended portion of the ciphertext and use it with `cipher.NewCBCDecrypter`.
    
    ```go
    iv := ciphertext
    encryptedData := ciphertext
    //... then decrypt encryptedData
    ```
    

**Corrected Golang Code Snippet (Illustrative):**

```go

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Key should be securely managed and not hardcoded in production.
// var key =byte("a very secret key 12345678901234") // AES-256 key (32 bytes)

// EncryptCorrectIV demonstrates secure AES-CBC encryption with unique, random IVs.
func EncryptCorrectIV(plaintextbyte, keybyte) (byte, error) {
	block, err := aes.NewCipher(key)
	if err!= nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Apply PKCS#7 padding.
	paddingSize := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padding := bytes.Repeat(byte{byte(paddingSize)}, paddingSize)
	paddedPlaintext := append(plaintext, padding...)

	// Allocate space for IV + ciphertext.
	ciphertext := make(byte, aes.BlockSize+len(paddedPlaintext))

	// Generate a random IV.
	iv := ciphertext
	if _, err := io.ReadFull(rand.Reader, iv); err!= nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Create CBC encrypter.
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext) // Encrypt after the IV.

	return ciphertext, nil
}

// DecryptCorrectIV demonstrates secure AES-CBC decryption.
func DecryptCorrectIV(ciphertextbyte, keybyte) (byte, error) {
	block, err := aes.NewCipher(key)
	if err!= nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short (missing IV)")
	}

	// Extract the IV from the beginning of the ciphertext.
	iv := ciphertext
	encryptedData := ciphertext

	if len(encryptedData)%aes.BlockSize!= 0 {
		return nil, fmt.Errorf("encrypted data is not a multiple of the block size")
	}

	// Create CBC decrypter.
	mode := cipher.NewCBCDecrypter(block, iv)
	decryptedData := make(byte, len(encryptedData))
	mode.CryptBlocks(decryptedData, encryptedData)

	// Remove PKCS#7 padding.
	if len(decryptedData) == 0 {
		return nil, fmt.Errorf("decrypted data is empty after CryptBlocks")
	}
	paddingSize := int(decryptedData)
	if paddingSize > len(decryptedData) |
| paddingSize > aes.BlockSize |
| paddingSize <= 0 {
		// Invalid padding size. This could indicate tampering or a different padding scheme.
		// For robustness, an application might treat this as a decryption error.
		return nil, fmt.Errorf("invalid padding size: %d", paddingSize)
	}
	// Verify padding bytes for more robustness (optional but good practice)
	for i := 0; i < paddingSize; i++ {
		if decryptedData!= byte(paddingSize) {
			return nil, fmt.Errorf("invalid padding bytes")
		}
	}

	return decryptedData, nil
}

func main_fix_example() {
	secretKey :=byte("thisisa32bytestrongpasswordkey!") // AES-256
	plaintext :=byte("This is a super secret message.")

	fmt.Printf("Original Plaintext: %s\n", plaintext)

	encrypted, err := EncryptCorrectIV(plaintext, secretKey)
	if err!= nil {
		panic(fmt.Sprintf("Encryption failed: %v", err))
	}
	fmt.Printf("Encrypted (IV+Ciphertext): %x\n", encrypted)

	// Encrypting the same plaintext again should yield a different ciphertext
	// because a new random IV will be generated.
	encrypted2, err2 := EncryptCorrectIV(plaintext, secretKey)
	if err2!= nil {
		panic(fmt.Sprintf("Second encryption failed: %v", err2))
	}
	fmt.Printf("Encrypted Again (IV+Ciphertext): %x\n", encrypted2)
	if bytes.Equal(encrypted, encrypted2) {
		fmt.Println("ERROR: Encrypting same plaintext twice resulted in same ciphertext despite fix attempt!")
	} else {
		fmt.Println("SUCCESS: Encrypting same plaintext twice resulted in different ciphertexts (due to random IVs).")
	}

	decrypted, err := DecryptCorrectIV(encrypted, secretKey)
	if err!= nil {
		panic(fmt.Sprintf("Decryption failed: %v", err))
	}
	fmt.Printf("Decrypted Plaintext: %s\n", decrypted)

	if!bytes.Equal(plaintext, decrypted) {
		fmt.Println("ERROR: Decrypted text does not match original plaintext!")
	} else {
		fmt.Println("SUCCESS: Decryption matches original plaintext.")
	}
}
```

**Additional Guidance:**

- **Key Rotation:** While generating unique IVs is the direct fix, implementing a key rotation policy is a good defense-in-depth strategy. It limits the amount of data encrypted with a single key, reducing the impact window if any cryptographic weakness (including an unforeseen IV collision, though highly improbable with 16-byte random IVs if keys are not overused) were to be exploited. Golang's `crypto/cipher` examples note never to use more than 232 random nonces with a given key due to repeat risks, although for 128-bit IVs, the birthday bound for collision is much higher (264). The primary fix remains per-encryption unique IVs.
    
- **Avoid Custom IV Schemes:** For CBC mode, generating IVs randomly using a CSPRNG is the most straightforward and secure approach. Avoid deriving IVs from the key or using deterministic schemes unless designed by cryptographic experts and thoroughly vetted, as these are prone to error.
    
- **Padding:** Ensure correct and secure padding (e.g., PKCS#7) is applied before encryption and removed after decryption. While separate from IV reuse, improper padding handling can lead to padding oracle attacks.

## **12. Scope and Impact**

The AES-CBC IV reuse vulnerability has a potentially broad scope within Golang infrastructure, affecting any system component that employs this encryption mode without adhering to strict IV management practices. The impact is primarily on the **confidentiality** of the protected data.

**Scope:**

- **Affected Golang Systems:** Any Golang application, microservice, or library that performs AES-CBC encryption is susceptible if it fails to generate unique, unpredictable IVs for each encryption operation using the same key.
- **Data States:**
    - **Data at Rest:** Encrypted databases, files, backups, and configurations. If IVs are reused for different records or files, their confidentiality is weakened.
    - **Data in Transit:** Encrypted communication between services, API request/response payloads, or messages in queues. Reused IVs can expose patterns or content in these communications.
- **Common Implementation Points:** Vulnerabilities often occur in custom encryption utilities, data access layers that handle field-level encryption, or direct usage of `crypto/cipher.NewCBCEncrypter` where IVs are mishandled.

**Impact:**

1. **Confidentiality Compromise:** This is the most direct impact.
    - **Leakage of Identical Message Prefixes:** Attackers can determine if different encrypted messages start with the same sequence of plaintext blocks. This can reveal structural information about the data, such as fixed headers or common fields.
        
    - **Distinguishing Known Plaintexts:** If an attacker has a set of possible plaintexts and can observe their ciphertexts (encrypted with a reused IV), they can identify which ciphertext corresponds to which known plaintext, or if an unknown ciphertext matches one of the known plaintexts.
        
    - **Potential for Plaintext Recovery:** In chosen-plaintext attack scenarios where IVs are predictable (not just static), attackers may be able to recover portions or even entire blocks of the plaintext.
        
    - The "silent failure" nature of this vulnerability is particularly insidious: encryption and decryption operations may appear to function correctly, masking the ongoing leakage of information until actively exploited or discovered through audit.
        
2. **Erosion of Trust:** Cryptographic failures, especially those leading to data exposure, severely undermine the trust users and dependent systems place in the application's security.
3. **Compliance Violations:** The compromise of sensitive data (e.g., PII, financial records, health information) due to weak encryption practices can lead to violations of data protection regulations such as GDPR, HIPAA, PCI DSS, potentially resulting in significant fines and legal repercussions.
4. **Reputational Damage:** Public disclosure of such a vulnerability and any ensuing data breach can cause substantial harm to an organization's reputation and brand image.
5. **Compounding Risk:** Information leakage from IV reuse can exacerbate other security weaknesses. For example, if encrypted data is inadvertently exposed through another vulnerability (e.g., misconfigured access controls on cloud storage), the IV reuse flaw makes it easier for an attacker to analyze and potentially decrypt that exposed data.

While IV reuse in CBC mode does not directly impact data integrity (the ability to detect modifications) or availability, CBC mode itself lacks inherent integrity protection and is malleable. This is a related but distinct weakness often addressed by using authenticated encryption modes. The primary and severe consequence of IV reuse is the loss of confidentiality.

## **13. Remediation Recommendation**

Addressing the AES-CBC IV reuse vulnerability requires both immediate tactical fixes and strategic long-term improvements to cryptographic practices within Golang applications.

**Immediate Actions:**

1. **Audit and Patch Existing AES-CBC Implementations:**
    - Thoroughly review all Golang code that uses `crypto/cipher.NewCBCEncrypter`.
    - Ensure that for every encryption operation, a new, unique, and cryptographically random IV (16 bytes for AES) is generated using `crypto/rand.Reader` via `io.ReadFull`, as detailed in Section 11 (Fix & Patch Guidance).
        
    - Verify that this IV is correctly prepended to the ciphertext or otherwise securely associated with it for use during decryption.

**Long-Term Strategic Recommendations:**

1. **Migrate to Authenticated Encryption (AEAD) Modes:**
    - The strongest recommendation is to migrate away from AES-CBC towards an AEAD cipher mode. AEAD modes like AES-GCM (Galois/Counter Mode) or ChaCha20-Poly1305 provide confidentiality, integrity, and authenticity in a single, integrated primitive. This mitigates risks like ciphertext malleability (inherent in CBC) and simplifies secure implementation.
        
    - Golang's `crypto/cipher` package provides `NewGCM` for AES-GCM.
        
    - **Crucial Note on GCM Nonces:** When migrating to AES-GCM, it is imperative to understand that GCM nonces have strict uniqueness requirements. A GCM nonce **must never be reused with the same key**. Reusing a GCM nonce is catastrophic, generally leading to loss of confidentiality and authenticity. Common practice is to use a 96-bit (12-byte) random nonce for each encryption. Deterministic nonces (e.g., counters) can be used if their uniqueness is absolutely guaranteed across all encryptions with a given key, but this requires careful state management. The consequences of GCM nonce reuse are far more severe than CBC IV reuse.

        
2. **Developer Training and Awareness:**
    - Conduct regular training sessions for Golang developers on secure coding practices, with a specific focus on cryptography. This should cover:
        - Correct IV/nonce generation and management for different cipher modes (CBC, CTR, GCM).
        - The importance of using CSPRNGs (`crypto/rand`).
        - The benefits and correct usage of AEAD ciphers.
        - Understanding common cryptographic pitfalls.
            
3. **Integrate SAST and Cryptographic Linting:**
    - Incorporate SAST tools into the CI/CD pipeline that are configured with rules to detect cryptographic misconfigurations, including IV/nonce misuse.
        
    - Consider custom SAST rules or linters tailored to project-specific cryptographic patterns if generic rules are insufficient.
4. **Regular Cryptographic Reviews:**
    - Periodically conduct expert reviews of critical cryptographic code and implementations. This is especially important for low-level cryptographic operations.
5. **Standardize Cryptographic Utilities:**
    - If custom cryptographic functions are necessary, centralize them into well-vetted internal libraries that enforce best practices by design. This reduces the likelihood of developers independently making mistakes.
    - Always prefer using functionalities from standard, well-vetted libraries like Go's `crypto/*` packages, but ensure they are used correctly according to their security documentation and cryptographic principles.


By implementing these recommendations, organizations can significantly reduce the risk of AES-CBC IV reuse and other cryptographic vulnerabilities in their Golang infrastructure, moving towards more robust and secure data protection. The migration to AEAD ciphers should be prioritized as it addresses a broader class of cryptographic weaknesses beyond just IV handling.

## **14. Summary**

The reuse of Initialization Vectors (IVs) in AES-CBC encryption mode within Golang applications represents a significant cryptographic vulnerability (aes-cbc-iv-reuse). This issue arises when the fundamental requirement of using a unique and unpredictable IV for each encryption operation under the same key is violated. Such mishandling, often stemming from the use of static/hardcoded IVs, IVs generated once and reused, or predictable IV generation schemes, directly undermines the confidentiality guarantees of AES-CBC.

The core problem is that IV reuse allows an attacker who can observe multiple ciphertexts to infer information about the corresponding plaintexts. This can range from identifying identical messages or common message prefixes to, in more advanced scenarios involving predictable IVs and chosen plaintexts, potentially recovering plaintext blocks. The Golang `crypto/cipher` package provides the necessary primitives for AES-CBC but places the onus of correct IV management (generation via `crypto/rand` and unique usage per encryption) squarely on the developer.

Key findings indicate that this vulnerability often occurs due to developer oversight or misunderstanding of cryptographic principles, where functionally "working" code can harbor these subtle but severe security flaws. Detection requires a combination of meticulous manual code review, targeted static analysis, and potentially dynamic cryptographic testing.

The immediate remediation is to audit all AES-CBC encryption implementations in Golang codebases and ensure that a cryptographically random IV is generated using `crypto/rand.Reader` for *every* encryption operation and prepended to the ciphertext. However, a more robust and strongly recommended long-term strategy is to migrate from AES-CBC to Authenticated Encryption with Associated Data (AEAD) ciphers, such as AES-GCM. AEAD modes provide integrated confidentiality, integrity, and authenticity, offering superior security and reducing the likelihood of implementation errors, provided their own nonce requirements (strict uniqueness for GCM) are met.

Vigilance in cryptographic implementations, continuous developer education on secure coding practices, and the integration of proactive security measures like SAST tools and regular expert reviews are imperative to protect sensitive data and maintain the integrity of Golang-based systems.

## **15. References**

**NIST Standards and Publications:**

- National Institute of Standards and Technology (NIST). (2001). *Special Publication 800-38A: Recommendation for Block Cipher Modes of Operation – Methods and Techniques*.
- National Institute of Standards and Technology (NIST). (2010). *Special Publication 800-38A Addendum: Recommendation for Block Cipher Modes of Operation: Three Variants of Ciphertext Stealing for CBC Mode*.
- NIST. (2021). *Initial Public Comments on SP 800-38A Review*.

**OWASP Resources:**

- OWASP Foundation. (2021). *OWASP Top 10:2021 A02:2021 – Cryptographic Failures*.
- OWASP Foundation. *Developer Guide: Cryptographic Practices*.
- OWASP Foundation. *Go Secure Coding Practices Guide*.

**Common Weakness Enumeration (CWE):**

- MITRE. *CWE-323: Reusing a Nonce, Key Pair in Encryption*.
- MITRE. *CWE-329: Generation of Predictable IV with CBC Mode*.
- MITRE. *CWE-327: Use of a Broken or Risky Cryptographic Algorithm*.
- MITRE. *CWE-1204: Generation of Weak Initialization Vector (IV)*.

**Golang Documentation:**

- Golang Packages. `crypto/cipher` - Example Usage.
- Golang Packages. `crypto/cipher` - Package Documentation.
- Golang Packages. `crypto/aes` - Package Documentation.

**Technical Articles and Discussions:**

- Haikel Fazzani. (Undated). *Understanding AES Encryption Modes: AES-GCM, AES-CBC, AES-CTR*.
- Texas Instruments. (2019). *AESCBC.h AESCBC Driver*.
- Wikipedia. *Initialization vector*.
- Baeldung. (2024). *Encryption With Initialization Vector (IV) in Java*. (Principles apply broadly).
- SecureFlag. (2023). *Reused IV-Key Pair*.
- Crypto Stack Exchange. (2021). *Does reusing IV in AES-CBC weaken it?*
- Crypto Stack Exchange. (2013). *Reusing keys with AES-CBC*.
- Reddit r/crypto. (2017). *Is reusing an AES key for encryption subject to any attacks?*
- Kiteworks. (Undated). *What Is AES-256 Encryption and How Does It Work?*
- Stackered. (2023). *IV Mishandling - Common pitfalls in symmetric encryption*.
- Stack Overflow. (2024). *Is it safe to use the same IV for AES encryption?*
- Reddit r/golang. (2024). *Encrypting with AES*.
- Seald.io. (2023). *3 common mistakes when implementing encryption*.
- Crypto Stack Exchange. (2018). *Is using the same IV in AES similar to not using an IV in the first place?*
- Asecuritysite.com (Bill Buchanan). (Undated). *Golang and Reusing IVs (AES GCM)*. (Discusses GCM IV reuse but principles of IV importance are relevant).
- Reddit r/golang. (2023). *What is the best practice for managing encryption keys in Go?*
- Datadog Documentation. *Static Analysis Rules: kotlin-security/no-iv-reuse*.
- GitHub Issues (pysaml2). (2017). *AESCipher reuses IVs*.
- Stack Overflow. (2019). *Initialization Vector best practices (symmetric cryptography)*.
- Stack Overflow. (2011). *How to pick an appropriate IV (Initialization Vector) for AES-CTR-NoPadding*. (CTR focused, but discusses IV generation principles).
- NVD NIST. (2024). *CVE-2024-53845 Detail*.
- SonarSource Rules. *Cipher Block Chaining IVs should be unpredictable*.
- BoostSecurity Docs. *Scanner Rules: gosec*.
- GitHub Issues (influxdata/telegraf). (2023). *Linter: gosec, Rule: G505 - Import blocklist: crypto/sha1*.
- Crypto Stack Exchange. (2013). *IV security clarification*.                                                                                                               
