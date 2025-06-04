# Report on Golang Vulnerabilities: Broken Password Hashing

## Vulnerability Title

Broken Password Hashing (Missing Salt or Insufficient Computational Effort)

## Severity Rating

High🟠

The vulnerability of broken password hashing, specifically the absence of a unique salt or the use of computationally weak hashing parameters, is classified with a high severity rating. This assessment is based on the profound impact such flaws have on the confidentiality of sensitive user data and the potential for widespread compromise. For instance, vulnerabilities related to "Use of Password Hash With Insufficient Computational Effort" (CWE-916) have been assigned a CVSS Base Score of 7.7, indicating high severity, with a direct impact on confidentiality.

The consistent high severity assigned to related Common Vulnerabilities and Exposures (CVEs) underscores the critical nature of this flaw. Compromised user credentials, even in their hashed form, can directly lead to unauthorized access to accounts. This initial breach can then serve as a gateway for more severe security incidents, including broader data breaches, identity theft, and unauthorized lateral movement within a system. While the direct act of cracking a password hash may not immediately affect the integrity or availability of a system, the subsequent exploitation of the recovered plaintext passwords invariably poses significant risks to these security pillars.

## Description

Password hashing is a fundamental cryptographic technique employed to safeguard user credentials. Instead of storing plaintext passwords, which would be immediately exposed upon a database compromise, systems transform them into fixed-length strings of characters known as hashes. This transformation is designed to be a one-way function, meaning it is computationally infeasible to reverse the hash to obtain the original plaintext password. The primary objective of this process is to ensure that even if an attacker gains access to a database containing password hashes, they cannot easily retrieve the original passwords, thereby protecting user accounts.

The "Broken Password Hashing" vulnerability emerges when this essential security mechanism is flawed. This typically occurs in two primary scenarios: either a unique random string (salt) is entirely absent from the hashing process, or the hashing parameters are configured with insufficient computational effort. When a salt is missing, identical passwords result in identical hashes, making them susceptible to precomputed attacks. When computational effort is too low, the hashing process is too fast, allowing attackers to rapidly guess passwords through brute-force methods. Both scenarios significantly weaken the security posture of user authentication, making it considerably easier for malicious actors to "crack" the hashes and gain unauthorized access to user accounts.

## Technical Description (for security pros)

Cryptographic hash functions are mathematical algorithms designed to produce a fixed-size output (hash) from any input data. For password storage, these functions must exhibit several crucial properties: pre-image resistance (difficulty in finding the input from a given hash), second pre-image resistance (difficulty in finding a different input that produces the same hash as a given input), and collision resistance (difficulty in finding two different inputs that produce the same hash). Beyond these general cryptographic properties, password hashing demands an additional characteristic: computational expense. This intentional slowness is vital to render brute-force attacks economically and practically infeasible.

Historically, and unfortunately still in some applications, general-purpose hashing algorithms like MD5, SHA-1, or even SHA-256 have been misused for password storage. These algorithms were primarily designed for speed and efficiency in data integrity checks, such as verifying file downloads. Their inherent speed, however, becomes a critical weakness when applied to password hashing. Modern attackers, leveraging powerful hardware like Graphics Processing Units (GPUs), Application-Specific Integrated Circuits (ASICs), or Field-Programmable Gate Arrays (FPGAs), can compute billions of hashes per second against fast algorithms. MD5, in particular, is highly susceptible to hash collisions, where distinct inputs yield identical hash values, making it easier for attackers to reverse-engineer passwords. SHA-1 also has documented collision vulnerabilities. Furthermore, these general-purpose algorithms do not inherently include salting, leaving them vulnerable to "rainbow table attacks." A rainbow table is a precomputed database of common passwords and their corresponding hashes. Without unique salts, a single rainbow table can effectively crack a multitude of passwords simultaneously. Unlike modern password-specific algorithms, these functions are not memory-hard, meaning they do not require significant memory during computation, which further enhances their efficiency for attackers with specialized hardware.

The critical role of unique, cryptographically secure salts cannot be overstated. A salt is a unique, randomly generated string that is concatenated with each password *before* it is hashed. The primary purpose of a salt is to ensure that even identical plaintext passwords produce distinct hash values when stored. This crucial step thwarts rainbow table attacks, as an attacker cannot precompute hashes for common passwords and then quickly find matches in a stolen database. Instead, each hash must be cracked individually, significantly increasing the attacker's computational burden. Salts do not need to be kept secret, but their uniqueness and cryptographic randomness are paramount.

Beyond salting, the importance of computational effort, achieved through iterations, memory-hardness, and parallelism, is central to secure password hashing. Modern password hashing algorithms such as bcrypt, scrypt, and Argon2 are specifically designed to be intentionally slow. This "slowness" is achieved through "key stretching," where the hashing function is applied many times, thereby increasing the "time cost" of computing a single hash. A higher cost factor dramatically increases the time and computational resources required for brute-force attacks, making them prohibitively expensive for attackers.

Furthermore, algorithms like scrypt and Argon2 are "memory-hard," meaning they demand a significant amount of memory during computation. This property is particularly effective in thwarting attackers who rely on specialized hardware (ASICs, GPUs) that often possess limited on-chip memory, thereby making parallel attacks less efficient. Argon2 also incorporates a parallelism parameter, enabling the algorithm to utilize multiple CPU cores or threads, which further compounds the computational burden for attackers.

The continuous evolution from fast, general-purpose hash functions to slow, memory-hard, and adaptive algorithms like Argon2, scrypt, and bcrypt  reflects an ongoing "arms race" in cybersecurity. As computing power, particularly that of GPUs, continues to advance, the "cost" parameters of these adaptive algorithms must be periodically increased to maintain the same level of security against brute-force attacks. This dynamic requires a proactive update strategy, acknowledging that a "secure" configuration today may become insufficient in a few years without adjustment.

## Common Mistakes That Cause This

Several common errors contribute to broken password hashing implementations in Golang applications:

A frequent mistake is the use of insecure or general-purpose hashing algorithms for password storage. Developers may inadvertently employ algorithms like MD5, SHA-1, or even SHA-256 without proper stretching, unaware of their inherent susceptibility to brute-force and rainbow table attacks when used in this context. These algorithms, while suitable for other cryptographic purposes like data integrity, are fundamentally too fast for password storage.

Another critical error is the failure to implement unique salts for each password. Omitting a unique, cryptographically random salt for every stored password allows attackers to exploit precomputed rainbow tables, enabling them to crack multiple passwords simultaneously if a database is compromised.

Even when adaptive algorithms like bcrypt, scrypt, or Argon2 are used, developers often set insufficient work factors. This can manifest as low iteration counts, inadequate memory allocation, or insufficient parallelism. For example, relying solely on `bcrypt.DefaultCost` without considering its long-term adequacy, or setting low N, r, p parameters for scrypt/Argon2, renders the hashing vulnerable to brute-force attacks by attackers with substantial computational resources.

Performing password hashing on the client-side (e.g., in the browser) is an anti-pattern that provides no additional security. A sophisticated attacker can intercept or modify client-side code, rendering this measure useless. More critically, client-side hashing prevents the server from enforcing the necessary computational work factor, making the system susceptible to offline cracking or replay attacks.

A lack of regular updates to hashing parameters as hardware capabilities advance is a significant oversight. Failing to periodically review and increase the work factors (cost, iterations, memory) of hashing algorithms means that systems become progressively more vulnerable over time as computing power improves.

Finally, inadvertently logging sensitive information, such as plaintext passwords or even password hashes, in application logs can expose them to attackers if the logs themselves are compromised.

Many of these mistakes stem from a "false sense of security." Developers might believe their implementation is secure because they are "hashing" passwords, or using an algorithm labeled "cryptographic," or even because they are performing hashing on the client-side. This leads to common anti-patterns that are counterproductive to actual security. The underlying issue is often a fundamental misunderstanding of cryptographic principles as they apply to password storage, where the goal is to deter offline attacks rather than merely obfuscate or secure transmission.

## Exploitation Goals

The primary objective for an attacker exploiting broken password hashing is to recover the plaintext password from the stolen hash. This is typically achieved through various offline password cracking techniques, including brute-force attacks, dictionary attacks, and rainbow table attacks. Attackers utilize specialized tools such as John the Ripper or Hashcat to systematically try combinations, employ pre-compiled lists of common words, or leverage precomputed hash tables. Weak hashing significantly accelerates this cracking process, making it feasible to recover a large number of passwords in a short timeframe.

Once plaintext passwords are recovered, attackers can launch "credential stuffing" attacks. This involves using the stolen username and password combinations to attempt logins on other online services, exploiting the common user behavior of reusing credentials across multiple platforms. Given the widespread practice of password reuse , this attack vector is highly effective and can lead to a significant "multiplier effect" for the attacker. A single successful crack of a weakly hashed password can unlock numerous other accounts across different services, dramatically amplifying the impact of the initial breach.

Beyond credential stuffing, compromised credentials grant attackers initial unauthorized access to systems. From this foothold, they can move laterally within the network, escalate their privileges, and establish persistence for long-term access. This access can then facilitate broader data breaches, leading to the exfiltration of sensitive information or enabling identity theft.

In specific scenarios, such as systems that rely on password hashes directly for authentication (e.g., Windows NTLM hashes), attackers may perform "Pass-the-Hash" (PtH) attacks. This technique involves stealing the password hash from memory and "passing" it to authenticate to other systems without ever needing to crack the plaintext password. This poses a significant threat, even if the underlying hashing algorithm is considered strong, as it bypasses the need for plaintext recovery.

## Affected Components or Files

The vulnerability of broken password hashing is not confined to a single isolated component but rather permeates the entire data flow related to user credentials. The primary affected components include:

- **Authentication and User Registration Modules:** Any code responsible for creating new user accounts or verifying login credentials directly interacts with the password hashing logic. This includes functions for user signup, login, and password reset.
- **User Profile Management Services:** Features that allow users to change their passwords will also utilize the underlying hashing mechanism to process and store the new credentials securely.
- **Database Schemas and Data Storage Layers:** The database tables, typically `users` or similar, are where the hashed passwords and their associated salts are stored. The structure of these tables must accommodate both the hash and the unique salt for each user.
- **Configuration Files:** Files that define the chosen hashing algorithm, the method for salt generation, and critical work factor parameters (e.g., cost, iterations, memory allocation) are directly affected. Incorrect or outdated configurations in these files can lead to the vulnerability.
- **System Password Files (e.g., `/etc/shadow` on Linux):** While not exclusively Go-specific, the concept of storing hashed passwords in restricted system files  applies to how Go applications might manage their password data or integrate with underlying operating system authentication mechanisms.
- **Application Logs:** If sensitive data, such as plaintext passwords or even password hashes, are inadvertently written to application logs, these log files become compromised components that can expose credentials to attackers.

The vulnerability represents a systemic issue, highlighting a dependency across the entire credential management data flow. A weakness in one part, such as a flawed hashing function, can be exacerbated by insecure handling of related data (like salts or plaintext passwords) or improper processing (e.g., client-side hashing). This interconnectedness necessitates a holistic security review of the entire authentication and credential management pipeline, rather than focusing solely on isolated hashing functions.

## Vulnerable Code Snippet

The following conceptual Golang example illustrates how password hashing might be implemented without a proper salt or with a weak, fast algorithm, leading to the described vulnerabilities.

```go
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	// "crypto/md5" // Example of a very weak hash, often imported for non-security uses
)

// --- VULNERABLE EXAMPLE 1: Using SHA-256 without salt or iterations (fast hash for passwords) ---
// This function is fast and not designed for password hashing, making it vulnerable to brute-force
// and rainbow table attacks if no unique salt is used.
func insecureHashPasswordSHA256(password string) string {
	hasher := sha256.New()
	hasher.Write(byte(password)) // No salt added
	return hex.EncodeToString(hasher.Sum(nil))
}

// --- VULNERABLE EXAMPLE 2: Storing plaintext (conceptual, as actual Go code would be database interaction) ---
// This is a conceptual representation of storing plaintext passwords, which is highly insecure.
// In a real application, this would involve directly inserting the password string into a database.
func storePlaintextPasswordInsecurely(username, password string) {
	fmt.Printf("WARNING: Storing plaintext password for user '%s': '%s'\n", username, password)
	// In a real app, this would be db.Exec("INSERT INTO users (username, password) VALUES (?,?)", username, password)
	// This is fundamentally broken and should NEVER be done.
}

func main() {
	// Example of insecure SHA-256 usage
	password := "mysecretpassword"
	insecureHashedPass := insecureHashPasswordSHA256(password)
	fmt.Printf("Insecure SHA-256 Hashed Password (no salt): %s\n", insecureHashedPass)
	// This hash is easily crackable with rainbow tables or brute-force if common.

	// Conceptual plaintext storage (highly insecure)
	storePlaintextPasswordInsecurely("testuser", "plaintext123")
}
```

**Explanation of Vulnerability:**

The `insecureHashPasswordSHA256` function demonstrates the use of a general-purpose cryptographic hash function (SHA-256) without incorporating a unique salt or sufficient iterations (key stretching). While SHA-256 is cryptographically strong for data integrity verification, its inherent speed makes it highly unsuitable for password hashing. Without a unique salt, identical plaintext passwords will produce identical hash values, rendering the system vulnerable to precomputed rainbow table attacks. The absence of iterations means an attacker can perform brute-force attacks very quickly, as the computational cost per guess is minimal.

The `storePlaintextPasswordInsecurely` function illustrates the most fundamental and severe password storage flaw: storing passwords directly in plaintext. This approach allows for immediate and complete compromise of user credentials upon a database breach, as the passwords are directly readable. This practice should never be implemented in any production system.

This vulnerability often remains "invisible" to an untrained eye. A function named `hashPassword` might superficially appear secure. However, the true security posture lies in the subtle details of its implementation, such as the explicit inclusion of a cryptographically random salt and the configuration of computationally expensive parameters (iterations, memory cost, parallelism). Without these crucial elements, even a function that performs a "hash" is fundamentally insecure for password storage, underscoring that security flaws in cryptography are often nuanced and require a deep understanding of underlying principles.

## Detection Steps

Detecting broken password hashing requires a multi-faceted approach, combining automated tools with thorough manual analysis and real-world testing.

**Utilizing Static Application Security Testing (SAST) Tools for Go:**
SAST tools are designed to analyze Go source code and binaries for security vulnerabilities.

- Tools such as GoSec, SonarQube, CodeQL, and GolangCI-Lint (when configured with relevant security linters) can identify common insecure cryptographic practices and weak hashing implementations.
- `govulncheck` is a specialized tool for Go that scans code and binaries against the Go vulnerability database. While it primarily identifies known vulnerabilities in dependencies, it is crucial for flagging if a project uses a version of a library with known insecure hashing.

**Manual Code Review Checklist:**
A meticulous manual code review is indispensable for uncovering subtle flaws that automated tools might miss. The review should focus on cryptographic primitives and the entire password storage logic:

- Verify that passwords are *never* stored in plaintext. This is the most critical and fundamental check.
- Ensure that only algorithms specifically designed for password hashing are used. These include Argon2id, scrypt, bcrypt, and PBKDF2. Fast, general-purpose hashes like MD5, SHA-1, or SHA-256 without proper stretching must be avoided.
- Confirm the presence and proper generation of a unique, cryptographically random salt for *each* password. The salt should be generated using a secure random number generator (e.g., Go's `crypto/rand`).
- Validate that sufficient work factors (iterations, memory cost, parallelism) are configured for the chosen hashing algorithm. These parameters should not be hardcoded at low values that could be easily overcome by modern hardware.
- Verify that hashing is performed *server-side*, not client-side. Client-side hashing offers no real security benefit and can introduce new vulnerabilities.
- Ensure sensitive information, especially plaintext passwords or password hashes, is not inadvertently logged in application logs or other persistent storage.

**Penetration Testing Techniques:**
Penetration testing provides a real-world assessment of the vulnerability's exploitability.

- If password hashes can be exfiltrated (e.g., through a simulated SQL injection or a compromised database backup), penetration testers can attempt to crack them offline using specialized tools like Hashcat or John the Ripper. The speed at which these tools can crack the hashes directly indicates the weakness of the hashing implementation.
- Testers may also attempt "pass-the-hash" attacks, if applicable to the system's authentication mechanisms, to determine if stolen hashes can be directly used to gain authentication without plaintext recovery.

A comprehensive security posture necessitates a layered defense in detection. No single detection method is foolproof. SAST tools provide efficient automated checks but may not identify complex logical flaws or custom weak implementations. Manual code reviews are crucial for a deep understanding of the implementation and for catching subtle anti-patterns. Penetration testing validates the real-world exploitability and effectiveness of defensive measures. Combining these approaches offers the most robust means of identifying and addressing broken password hashing vulnerabilities.

## Fix & Patch Guidance

Addressing broken password hashing requires a multi-pronged approach focused on adopting modern, robust cryptographic practices.

**1. Adopt Strong, Adaptive Hashing Algorithms:**
Transition away from insecure or general-purpose hashing algorithms (like MD5, SHA-1, or SHA-256 without stretching) to algorithms specifically designed for secure password storage. The recommended algorithms are:

- **Argon2id:** This is the winner of the Password Hashing Competition and is highly recommended due to its memory-hardness and configurability.
    - **Go Implementation:** Use `golang.org/x/crypto/argon2`.
    - **Recommended Parameters:** Configure with sufficient memory, iterations, and parallelism. OWASP recommends a minimum of 19 MiB memory, 2 iterations, and 1 degree of parallelism. For Go, a common configuration might be `memory: 64*1024` (64 MB), `iterations: 3`, `parallelism: 1`, `saltLength: 16`, `keyLength: 32`. The `TimeCost` should ideally be `>= 3` for Argon2i, and `>= 10` if affordable.
- **scrypt:** Another memory-hard algorithm resistant to brute-force attacks.
    - **Go Implementation:** Use `golang.org/x/crypto/scrypt`.
    - **Recommended Parameters:** Minimum CPU/memory cost parameter of `2^17`, a minimum block size of 8 (1024 bytes), and a parallelization parameter of 1. An example configuration in Go is `N: 16384`, `r: 8`, `p: 1`.
- **bcrypt:** A widely used and well-tested adaptive hashing algorithm.
    - **Go Implementation:** Use `golang.org/x/crypto/bcrypt`.
    - **Recommended Parameters:** Use a work factor (cost) of 10 or more. `bcrypt.DefaultCost` is 10. This cost parameter doubles the number of encryption iterations with each increase.
- **PBKDF2:** If FIPS-140 compliance is required, use PBKDF2 with a work factor of 600,000 or more, and set with an internal hash function of HMAC-SHA-256.

**2. Implement Unique, Cryptographically Secure Salts:**
For every password stored, generate and use a unique, cryptographically random salt. This salt must be combined with the password *before* hashing.

- **Go Implementation:** Use `crypto/rand` to generate these salts to ensure their cryptographic strength. The salt does not need to be secret but must be unique for each user and stored alongside the hashed password.

**3. Configure Sufficient Work Factors and Periodically Review:**
The "cost" parameters (iterations, memory, parallelism) are crucial for making brute-force attacks computationally expensive.

- **Regular Updates:** As computing power advances, periodically review and *increase* these work factors to maintain the desired level of security. This is an ongoing process, not a one-time fix.

**4. Ensure Server-Side Hashing:**
Password hashing must always occur on the server-side. Client-side hashing provides a false sense of security and can undermine the system's ability to enforce proper work factors and protect against replay attacks.

**5. Implement Secure Password Verification:**
When verifying a user's login, retrieve the stored hash and its associated salt. Hash the user-provided password using the retrieved salt and the *same* hashing algorithm and parameters used during registration. Then, compare the newly computed hash with the stored hash using a constant-time comparison function to prevent timing attacks.

**6. Avoid Logging Sensitive Information:**
Ensure that plaintext passwords or password hashes are never written to application logs, debug outputs, or other insecure storage locations.

**7. Update Dependencies:**
Keep your Go version and all third-party dependencies up to date. This ensures that you receive the latest security patches and performance improvements, which can address known vulnerabilities in cryptographic libraries.

## Scope and Impact

The scope of the "Broken Password Hashing" vulnerability extends across any application or system that relies on password-based authentication, particularly those implemented in Golang. This includes web applications, API services, peer-to-peer (P2P) network nodes, and any other software where user accounts are managed.

The impact of this vulnerability is primarily on the **confidentiality** of user credentials. If an attacker successfully compromises a database containing weakly hashed passwords, they can recover plaintext passwords through offline cracking techniques. This directly exposes sensitive user information.

Beyond confidentiality, the impact quickly escalates due to the pervasive issue of password reuse. Recovered plaintext passwords enable **credential stuffing attacks**, where attackers use these compromised credentials to gain unauthorized access to other services where users have reused the same password. This creates a cascading effect, amplifying the initial breach across multiple platforms and potentially leading to widespread **identity theft**.

Furthermore, successful exploitation can lead to **unauthorized access and lateral movement** within the compromised system or network. Once an attacker gains initial access through cracked credentials, they can explore the system, escalate privileges, and establish persistence, leading to deeper compromises and potentially the exfiltration of other sensitive data. While the vulnerability itself doesn't directly cause a denial-of-service (DoS) or integrity loss of the hashing mechanism, the subsequent actions of an attacker with compromised credentials can indirectly lead to service disruption or data manipulation.

## Remediation Recommendation

To effectively remediate broken password hashing vulnerabilities in Golang applications, a comprehensive strategy is required:

1. **Migrate to Strong Password Hashing Algorithms:** Immediately replace any usage of insecure or fast hashing algorithms (e.g., MD5, SHA-1, SHA-256 without proper stretching) with modern, adaptive, and memory-hard password hashing functions. Prioritize Argon2id, scrypt, or bcrypt.
    - For **Argon2id**, utilize the `golang.org/x/crypto/argon2` package and configure parameters (memory, iterations, parallelism) according to the latest OWASP recommendations and RFC9106, ensuring sufficient computational and memory cost.
    - For **scrypt**, use the `golang.org/x/crypto/scrypt` package, setting high values for the N (cost factor), r (block size), and p (parallelization factor) parameters.
    - For **bcrypt**, employ the `golang.org/x/crypto/bcrypt` package, configuring a work factor (cost) of at least 10, and ideally higher, based on current hardware capabilities and performance tolerance.
2. **Ensure Unique Salt Generation and Storage:** Implement a mechanism to generate a unique, cryptographically random salt for each user's password using Go's `crypto/rand` package. This salt must be concatenated with the password before hashing and stored alongside the resulting hash in the database.
3. **Regularly Review and Increase Work Factors:** Establish a process for periodically reviewing and increasing the computational cost parameters (iterations, memory, parallelism) of the chosen hashing algorithm. This is crucial to keep pace with advancements in computing power and maintain the security margin against brute-force attacks.
4. **Enforce Server-Side Hashing:** All password hashing operations must occur exclusively on the server-side. Remove any client-side hashing logic, as it provides no security benefits and can introduce exploitable weaknesses.
5. **Implement Secure Password Verification:** When authenticating users, retrieve the stored hash and salt from the database. Hash the user-provided password with the retrieved salt and the *exact same* algorithm and parameters used during registration. Compare the newly generated hash to the stored hash using a constant-time comparison function to prevent timing attacks.
6. **Secure Logging Practices:** Configure logging to explicitly exclude plaintext passwords or password hashes. Sensitive information should never be written to logs.
7. **Maintain Software and Dependencies:** Regularly update the Go runtime to its latest stable version and ensure all third-party cryptographic libraries and dependencies are kept up-to-date to benefit from security patches and improvements. Utilize tools like `govulncheck` to scan for known vulnerabilities in dependencies.

## Summary

Broken password hashing, characterized by the absence of unique salts or the use of insufficient computational effort, represents a critical vulnerability in Golang applications. This flaw allows attackers to efficiently crack password hashes, leading to unauthorized account access, credential stuffing attacks, and potentially broader data breaches. The issue stems from misapplying fast, general-purpose hashing algorithms for password storage, failing to use unique salts, or setting inadequate work factors. Effective remediation necessitates migrating to robust, adaptive, and memory-hard algorithms like Argon2id, scrypt, or bcrypt, coupled with the consistent use of cryptographically secure, unique salts and sufficiently high computational parameters. Regular review and adjustment of these parameters are essential to counter evolving attacker capabilities. Adhering to server-side hashing and secure logging practices further strengthens the overall security posture, safeguarding user credentials against compromise.