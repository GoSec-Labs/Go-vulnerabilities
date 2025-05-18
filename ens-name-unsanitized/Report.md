# **ENS Name Resolution Not Sanitized (ens-name-unsanitized) in Golang Applications: A Technical Vulnerability Analysis**

## **1. Vulnerability Title**

ENS Name Resolution Not Sanitized (ens-name-unsanitized) in Golang Applications

## **2. Severity Rating**

The "ENS Name Resolution Not Sanitized" vulnerability in Golang applications is assessed as having a **High🟠 to Critical🔴** severity. Utilizing the Common Vulnerability Scoring System (CVSS) v3.1, a representative vector could be CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N, yielding a score of **8.1 (High🟠)**.

**CVSS Vector Justification:**

- **Attack Vector (AV): Network (N)** – The vulnerability is typically exploited when a user interacts with a malicious ENS name through a network-connected application (e.g., a web-based dApp, a wallet connecting to a node).
- **Attack Complexity (AC): Low (L)** – Once an attacker has registered a deceptive homoglyph ENS name, the technical complexity to induce a vulnerable Golang application to resolve this name is low, primarily relying on the user inputting or interacting with the crafted name.
- **Privileges Required (PR): None (N)** – The attacker does not require any special privileges on the targeted system or application to exploit this vulnerability. The exploit leverages the application's standard ENS name resolution functionality.
- **User Interaction (UI): Required (R)** – Successful exploitation typically necessitates user interaction, such as the user typing, pasting, or clicking on a link containing the malicious ENS name, which the vulnerable Golang application then attempts to resolve.
- **Scope (S): Unchanged (U)** – The vulnerability's direct impact is generally confined to the security scope of the application processing the ENS name. While the consequences can be severe (e.g., misdirected funds), the exploit does not inherently grant the attacker control over other system components beyond the immediate transaction or interaction.
- **Confidentiality (C): High (H)** – If an ENS name is intended to resolve to a resource containing sensitive information (e.g., a private content hash) and is instead resolved to an attacker-controlled resource that mimics it, confidentiality can be breached. Moreover, misdirected interactions can lead to the exposure of transaction details or user intentions to an adversary.
- **Integrity (I): High (H)** – The primary impact often involves a loss of integrity. Resolving to a malicious address can lead to users signing transactions that interact with unintended smart contracts or send assets to an attacker, thereby corrupting the integrity of the user's intended actions and asset control.
- **Availability (A): None (N) / Low (L)** – While specific transactions can be prevented or misdirected, the overall availability of the ENS system or the application is not typically the primary target. However, repeated resolution failures or errors due to malformed or unhandled names could contribute to a degraded user experience or minor availability issues in specific application functions.

The severity of this vulnerability is significantly amplified within the Web3 ecosystem. Unlike traditional web vulnerabilities where recovery mechanisms might exist, actions on a blockchain, such as fund transfers or smart contract interactions initiated due to mis-resolved ENS names, are often irreversible. This potential for direct and permanent financial loss, coupled with the relative ease of crafting visually deceptive homoglyphs, contributes to the high-risk profile. The reliance on user interaction (UI:R) is a factor, but the low technical complexity (AC:L) for an attacker to prepare and deploy a homoglyph attack makes this a potent threat.

**Table 1: CVSS 3.1 Metrics for ens-name-unsanitized**

| **Metric** | **Value** | **Justification** |
| --- | --- | --- |
| Attack Vector | Network | Exploitation occurs via network interaction with the vulnerable application. |
| Attack Complexity | Low | Crafting homoglyphs and presenting them to a vulnerable application is not technically complex for a knowledgeable attacker. |
| Privileges Required | None | No special privileges are needed on the target system. |
| User Interaction | Required | User typically needs to input or click on the malicious ENS name. |
| Scope | Unchanged | The exploit primarily affects the application's interaction with the blockchain, not necessarily escalating privileges on the host system itself. |
| Confidentiality Impact | High | Potential exposure of intended transaction details or misdirection to sites/contracts that could steal information. |
| Integrity Impact | High | High risk of misdirected funds, interaction with malicious contracts, or alteration of intended blockchain state changes. |
| Availability Impact | None | Primarily impacts specific transactions/interactions rather than general service availability, though repeated errors could degrade user experience. |
| **Overall CVSS 3.1 Score** | **8.1** | **High** |

## **3. Description**

The "ENS Name Resolution Not Sanitized" vulnerability affects Golang applications that interact with the Ethereum Name Service (ENS) by failing to properly sanitize and normalize user-supplied ENS names prior to their resolution. ENS is a decentralized system built on the Ethereum blockchain that maps human-readable names, such as `vitalik.eth`, to machine-readable identifiers like Ethereum addresses, content hashes (e.g., for IPFS or Swarm), and other metadata. Its primary goal is to enhance user experience by simplifying interactions with complex blockchain addresses.

This vulnerability arises from the complexities of handling Unicode characters in ENS names. Attackers can exploit this by crafting "homographic" ENS names. A homograph attack involves using characters (homoglyphs) from different Unicode scripts that are visually indistinguishable or very similar to characters in a legitimate ENS name. For example, a Cyrillic 'а' can look identical to a Latin 'a'. If a Golang application does not rigorously normalize these inputs according to established standards (specifically ENSIP-15, which builds upon UTS #46), it may interpret a visually deceptive name as a distinct entity from the legitimate one.

The core of the problem is the potential for a single visual representation of an ENS name to correspond to multiple distinct canonical byte sequences if proper normalization is not enforced. An attacker can register a homoglyph of a legitimate ENS name and point it to a malicious address or contract. When a user inputs this homoglyph name into a vulnerable Golang application, the application, due to the lack of sanitization, may resolve it to the attacker’s malicious entity instead of the intended legitimate one.

Successful exploitation can lead to severe consequences, including the misdirection of cryptocurrency or NFTs to attacker-controlled addresses, users unknowingly interacting with malicious smart contracts (e.g., fake DeFi platforms or phishing contracts designed to steal assets or approvals), or being led to counterfeit decentralized websites. This fundamentally undermines the trust and usability that ENS aims to provide, as the human-readable names, intended for simplification, become a vector for deception. The impact in the Web3 space is often more direct and irreversible than in traditional web phishing scenarios, given the nature of blockchain transactions.

The vulnerability is not necessarily a flaw in the ENS protocol itself, but rather in the implementation practices within Golang applications that fail to adhere to the necessary Unicode normalization and validation procedures before processing ENS names for on-chain resolution.

## **4. Technical Description (for security pros)**

A thorough understanding of the "ENS Name Resolution Not Sanitized" vulnerability requires a detailed examination of the ENS resolution process, the relevant Unicode normalization standards, and the precise mechanism through which Golang applications can falter.

**ENS Resolution Process Deep Dive**

The resolution of an ENS name is a multi-step process orchestrated through smart contracts on the Ethereum blockchain:

1. **ENS Registry Interaction:** All ENS lookups begin at the central ENS Registry contract. This contract maintains records of all registered names and their corresponding resolvers. An application seeking to resolve a name first queries the registry using the `resolver(bytes32 node)` function, providing the namehash (or `node`) of the ENS name. The registry, if the name is registered and has a resolver set, returns the address of the resolver contract responsible for that specific name.
2. **Resolver Contract Interaction:** Once the resolver's address is obtained, the application interacts directly with this resolver contract. Resolvers are smart contracts that implement a standard interface (defined in various ENS Improvement Proposals, or ENSIPs) for returning different types of records associated with a name. Common functions queried on a resolver include:
    - `addr(bytes32 node)`: Returns the primary Ethereum address associated with the name.

    - `addr(bytes32 node, uint coinType)`: Returns an address for a different blockchain, specified by `coinType` (SLIP-44).
        
    - `contenthash(bytes32 node)`: Returns a content hash, typically for decentralized storage systems like IPFS or Swarm, allowing ENS names to point to websites or other content.
        
    - `text(bytes32 node, string key)`: Returns arbitrary key-value text records, often used for metadata like avatar URLs, email addresses, or social media handles.

    - `ABI(bytes32 node, uint256 contentTypes)`: Returns the ABI definition for a contract associated with the name.
        
    - `pubkey(bytes32 node)`: Returns the public key associated with the name.
        
3. **Interface Support Check:** Applications can verify if a resolver supports a specific record type or ENSIP by calling `supportsInterface(bytes4 interfaceID)` on the resolver contract. This ensures compatibility before attempting to query for a particular record.

**Namehashing (ENSIP-1)**

Central to ENS is the `namehash` algorithm, defined in ENSIP-1. This algorithm converts a human-readable ENS name into a unique 32-byte fixed-length hash, referred to as a `node`. This node is the actual identifier used for lookups within the ENS contracts. The algorithm is recursive and processes names from right to left (TLD to label):

- `namehash('') = 0x0000...0000` (32 zero bytes for the root node)
- `namehash(label + '.' + domain) = keccak256(namehash(domain) ++ keccak256(label))`

Where `++` denotes concatenation. For example, `namehash('vitalik.eth')` is computed as `keccak256(namehash('eth') ++ keccak256('vitalik'))`. It is critical that the labels are in their canonical, normalized form *before* `keccak256(label)` is applied. Any variation in the byte representation of a label due to improper or missing normalization will result in a completely different `labelhash` and, consequently, a different final `namehash`. Golang implementations like `jgimeno/go-namehash`  or the internal hashing in `wealdtech/go-ens` perform this.

**Unicode Normalization Standards for ENS**

Handling Unicode in ENS names securely requires adherence to specific normalization standards:

1. **UTS #46 (Unicode IDNA Compatibility Processing):** This Unicode Technical Standard defines a compatibility processing mechanism for Internationalized Domain Names (IDNs), aiming to bridge differences between IDNA2003 and IDNA2008. Key steps in UTS #46 include:
    - **Mapping:** Characters are mapped according to predefined rules. Statuses include `valid`, `ignored` (removed), `mapped` (replaced by another character or sequence, e.g., case-folding), `disallowed`, or `deviation` (treatment depends on transitional processing, which is now deprecated).
        
    - **Normalization:** The string is normalized to Unicode Normalization Form C (NFC), ensuring a canonical representation for characters that can be encoded in multiple ways.
        
    - **Validation:** Labels are checked against validity criteria, such as rules for hyphens, Bidi (bidirectional text) properties, and joiner characters (e.g., Zero Width Joiner ZWJ, Zero Width Non-Joiner ZWNJ).
    The Golang standard library `golang.org/x/net/idna` provides an implementation of UTS #46.

        
2. **ENSIP-15 (ENS Name Normalization Standard):** While UTS #46 provides a base, it was found insufficient for the unique security requirements of ENS, particularly concerning the vast range of Unicode characters (including emojis and newer scripts) and sophisticated homoglyph attacks. ENSIP-15 defines a stricter, canonical normalization process specifically for ENS names. It aims to ensure that every ENS name has a single, unambiguous normalized form. Key aspects include:
    - Building upon existing Unicode standards but adding ENS-specific rules.
    - Comprehensive handling of "confusables": characters or sequences that can be visually mistaken for others, including whole-script confusables (where an entire name might look like a Latin name but be composed of, e.g., Cyrillic characters).
    - Strict rules for disallowed characters and sequences.
    - Standardized handling of emoji sequences, including validation of ZWJ sequences and variation selectors (e.g., `U+FE0F`).
    - Providing extensive validation test suites to ensure compliant implementations.
    The reference JavaScript implementation is `adraffy/ens-normalize.js`, and its Golang counterpart is `adraffy/go-ens-normalize`.

**The Vulnerability Mechanism in Golang**

The vulnerability manifests when a Golang application performs ENS name resolution without correctly applying the ENSIP-15 normalization process to the input name before it is hashed and used in contract interactions.

- **Insufficient Normalization:** Relying solely on basic string operations (like `strings.ToLower()`) or even just the `golang.org/x/net/idna` package (UTS #46) is inadequate. While `idna.ToUnicode` might handle some IDNA compatibility aspects, it does not enforce the full set of ENSIP-15 rules, especially regarding advanced confusable detection and specific character validation crucial for ENS security.
    
- **Consequences of Improper Normalization:** If an unnormalized or improperly normalized ENS name (e.g., `pаypal.eth` with a Cyrillic 'а') is processed, its byte representation will differ from the legitimate name (`paypal.eth` with a Latin 'a'). This leads to:
    - A different `labelhash` for the affected label(s).
    - A different final `namehash` for the entire domain.
    - Consequently, the ENS registry and resolver contracts will be queried for a node that is distinct from the legitimate one. If an attacker has registered this homographic variant, the application will resolve to the attacker's specified address or resource.
- **Ecosystem Inconsistencies:** As highlighted in , if different components of the Web3 ecosystem (wallets, dApps, libraries, block explorers) implement normalization inconsistently, the same visual input string can lead to different resolution outcomes, causing user confusion and creating exploitable scenarios. A Golang application might resolve a name one way, while the user's wallet resolves it another, leading to discrepancies and potential attacks.
    

The core technical failure is the omission of, or incorrect implementation of, the ENSIP-15 standard as a mandatory pre-processing step before any ENS name is used in a security-sensitive context like on-chain resolution. This is not necessarily a flaw in the ENS contracts themselves, but a client-side implementation error in the Golang application.

**Table 2: Comparison of Normalization Standards (UTS #46 vs. ENSIP-15)**

| **Feature** | **UTS #46 (via golang.org/x/net/idna)** | **ENSIP-15 (via adraffy/go-ens-normalize)** | **Importance for ENS Security** |
| --- | --- | --- | --- |
| **Base Normalization** | IDNA2008 compatibility processing, NFC. | Builds upon Unicode standards, specifies NFC. | Foundational for consistent representation. |
| **Case Folding** | Typically maps to lowercase. | Enforces lowercase.  | Ensures case-insensitivity. |
| **Confusable Handling** | Basic, may not cover all visually similar characters across scripts. | Extensive validation for whole-script and individual character confusables; aims to prevent registration or ensure distinct normalization. | Critical for preventing homograph attacks. |
| **Emoji Handling** | No specific detailed rules for emoji sequences. | Validates emoji sequences, including ZWJ and variation selectors.| Important as emojis become more common in names; prevents ambiguity and spoofing with emoji variants. |
| **Disallowed Characters** | Defines disallowed characters based on IDNA rules. | Maintains a comprehensive list of disallowed characters and sequences, often stricter than base IDNA. | Reduces attack surface by eliminating problematic characters. |
| **ContextJ/Joiner Rules** | `CheckJoiners` option for ZWJ/ZWNJ validation per RFC 5892.  | Includes rules for joiners, often as part of broader validation.  | Prevents misuse of invisible characters that can alter namehashes. |
| **Primary Goal** | IDN compatibility for DNS.  | Canonical and secure representation for ENS names on the blockchain.  | UTS #46 is a general standard; ENSIP-15 is domain-specific and tailored to the security needs of ENS, making it indispensable for secure ENS resolution. |

**Table 3: ENS Name Processing Pipeline (Secure vs. Vulnerable)**

| **Step No.** | **Action** | **Responsible Component** | **Security Consideration (Vulnerable Path - No ENSIP-15)** | **Security Implementation (Secure Path - With ENSIP-15)** |
| --- | --- | --- | --- | --- |
| 1 | User Input / External Data Reception | User / Frontend / API | Raw ENS name (e.g., `аррle.eth`) is received. | Raw ENS name (e.g., `аррle.eth`) is received. |
| 2 | Pre-Resolution Processing (Golang) | Golang Backend | **MISSING/INCORRECT:** No ENSIP-15 normalization. May do basic lowercase or rely on `golang.org/x/net/idna` only. | **CORRECT:** Input string is passed to `ensip15.Normalize()`. Output is canonical ENS name string, or an error if invalid/confusable. |
| 3 | Namehashing | Golang Backend / Library | `namehash` is computed on the potentially incorrect byte sequence from step 2. Results in `node_homoglyph`. | `namehash` is computed on the canonical byte sequence from `ensip15.Normalize()`. Results in `node_canonical`. Or, process stops if normalization failed. |
| 4 | ENS Registry Query | Golang Backend / Library | Queries registry with `resolver(node_homoglyph)`. May return attacker's resolver. | Queries registry with `resolver(node_canonical)`. Returns legitimate resolver or error. |
| 5 | ENS Resolver Query | Golang Backend / Library | Queries attacker's resolver with `addr(node_homoglyph)`. Returns attacker's address. | Queries legitimate resolver with `addr(node_canonical)`. Returns legitimate address or error. |
| 6 | Application Action | Golang Backend / Frontend | Application uses attacker's address for transaction/display, deceiving the user. | Application uses legitimate address or handles error appropriately. |

## **5. Common Mistakes That Cause This**

The failure to correctly sanitize and normalize ENS names in Golang applications often stems from a series of common mistakes made by developers:

1. **Ignorance or Underestimation of Normalization Standards:** Many developers may not be fully aware of the stringent normalization requirements outlined in ENSIP-15  and its foundation in UTS #46.  They might treat ENS names as simple alphanumeric strings, overlooking the complexities introduced by Unicode and the potential for homograph attacks. This underestimation of Unicode's complexity in a security-critical domain like blockchain name resolution is a primary factor. Developers accustomed to traditional ASCII-based DNS may not immediately recognize the need for such rigorous pre-processing before an ENS name can be safely used.
2. **Over-reliance on Basic String Operations:** A frequent error is the use of generic Golang string manipulation functions, such as `strings.ToLower()`, for what is mistakenly believed to be sufficient "normalization." While case-folding is a part of the process, it is far from comprehensive. ENSIP-15 and UTS #46 detail much more intricate rules, including specific Unicode character mappings, validation of character sequences (like emojis and joiners), and the handling of confusable characters, all of which are missed by simple string operations.
3. **Assuming Library Sufficiency or Implicit Handling:** Developers might incorrectly assume that the Ethereum client libraries they use (e.g., `go-ethereum` or higher-level ENS libraries like `wealdtech/go-ens`) automatically handle all necessary ENSIP-15 normalization internally before resolution. Unless explicitly documented and verified, this assumption can be dangerous, as these libraries might expect already-normalized input or perform only partial normalization. The lack of clear, prominent warnings in commonly used libraries about the critical need for pre-normalization can lead developers into this pitfall.
4. **Trusting Client-Side Normalization:** A classic security mistake is to rely solely on normalization performed on the client-side (e.g., in a JavaScript frontend) without re-validating and re-normalizing the ENS name in the Golang backend. The backend, which ultimately interacts with the Ethereum blockchain, must independently ensure the canonical form of the ENS name. Any input from the client must be treated as untrusted.
5. **Incomplete or Incorrect Custom Implementations:** Some developers might attempt to implement parts of the normalization logic themselves. Given the complexity of Unicode standards and ENS-specific rules, such custom implementations are highly prone to errors and omissions, leading to incomplete or incorrect normalization.
6. **Insufficient Testing with Diverse Inputs:** Applications are often tested with common, simple Latin-based ENS names (e.g., `myname.eth`), where basic normalization might appear to work. The vulnerability often surfaces only when the system is exposed to names containing characters from different scripts, homoglyphs, emojis, or other Unicode features that require specific handling according to ENSIP-15. This "it works with common names" fallacy can mask underlying normalization deficiencies.
7. **Misunderstanding Namehash Sensitivity:** A fundamental misunderstanding can be not recognizing that the `namehash` algorithm is extremely sensitive to the exact byte sequence of the input labels. Even a minute difference in the pre-hashed label, resulting from improper normalization, will lead to a completely different node, which is the basis of the exploit.

These mistakes collectively contribute to a scenario where applications process ENS names in a non-canonical or ambiguous manner, creating an attack surface for homograph attacks and other resolution inconsistencies.

## **6. Exploitation Goals**

Attackers exploiting the "ENS Name Resolution Not Sanitized" vulnerability in Golang applications have several malicious objectives, primarily centered around deceiving users or systems into interacting with unintended blockchain entities. These goals often lead to direct financial or reputational damage.

1. **Asset Theft (Cryptocurrency and NFTs):** The most direct goal is to trick users into sending valuable digital assets, such as ETH, ERC-20 tokens, or Non-Fungible Tokens (NFTs), to an address controlled by the attacker. This is achieved by registering a homoglyph of a legitimate ENS name and associating it with the attacker's wallet address. A vulnerable Golang application, failing to normalize the user's input, resolves the deceptive name to the attacker's address, leading the user to authorize a transaction to the wrong recipient. Due to the typically irreversible nature of blockchain transactions, such losses are often permanent.
2. **Malicious Smart Contract Interaction:** Attackers can point a homoglyph ENS name to a malicious smart contract they have deployed. This contract might be designed to:
    - Mimic the interface of a legitimate DeFi protocol, tricking users into depositing funds which are then stolen.
    - Request broad token approvals (e.g., `approve` function for ERC-20 tokens), allowing the attacker's contract to subsequently drain approved tokens from the user's wallet.
    - Execute other harmful functions that compromise the user's assets or on-chain state.
3. **Phishing and Credential Theft:** By resolving a homoglyph ENS name to an attacker-controlled content hash (e.g., an IPFS hash), users can be redirected to a phishing website. This site might perfectly replicate a legitimate decentralized application (dApp) interface, aiming to steal private keys, seed phrases, or other sensitive credentials when the user attempts to "connect their wallet" or sign a message.
4. **Reputation Damage and Impersonation:** An attacker can register homoglyphs of prominent individuals, projects, or dApps to spread misinformation, conduct scams under their guise, or otherwise damage their reputation within the Web3 community.
5. **Exploiting Application-Specific Logic:** If a Golang application uses ENS names for internal logic beyond simple address resolution—such as for access control, identity verification, or routing decisions—resolving a name to an attacker-controlled but visually similar identity could bypass security mechanisms or trigger unintended privileged operations.
6. **Causing Confusion and Undermining Trust:** A broader goal, particularly with widespread exploitation, is to erode user trust in the ENS system itself and in the applications that utilize it. If users cannot reliably depend on human-readable names, one of the key usability advantages of ENS is negated. Attackers might leverage the trust users place in the `.eth` suffix or familiar names, turning this trust into an attack vector.
7. **Denial of Service or Unintended Behavior:** In some cases, providing a malformed or ambiguously normalizable ENS name to a vulnerable application might lead to unexpected errors, crashes, or denial of service if the application's resolution logic or error handling is not robust.

Sophisticated attackers may proactively register clusters of homoglyphs related to high-value targets, anticipating that some applications or users will fall prey to resolution errors. The core of these exploitation goals is to manipulate the trust layer that ENS provides, turning a feature designed for convenience into a vector for deception and harm.

## **7. Affected Components or Files**

The "ENS Name Resolution Not Sanitized" vulnerability primarily impacts Golang applications and libraries that process or resolve ENS names without adhering to the ENSIP-15 normalization standard. The ripple effects can touch various parts of the ENS interaction lifecycle.

1. **Golang Backend Services and dApps:**
    - Any server-side Golang application, microservice, or decentralized application backend that accepts ENS names as input (e.g., from user interfaces, API calls, configuration files, or other services) and subsequently uses these names for on-chain resolution or identity verification is directly affected if it lacks proper ENSIP-15 normalization. This is the primary locus of the vulnerability.
2. **Golang ENS Client Libraries:**
    - Third-party Golang libraries designed to simplify ENS interactions, such as `wealdtech/go-ens` , can be a point of vulnerability if they either do not internally perform ENSIP-15 normalization or do not clearly mandate pre-normalized input from the calling application. If such a library's resolution functions (e.g., `ens.Resolve()`) process raw string inputs, the onus of normalization falls on the application developer, and omission leads to vulnerability.

    - Core Ethereum libraries like `ethereum/go-ethereum` , when used for direct interaction with ENS smart contracts (e.g., calling `resolver.addr(node)` on a contract binding), require the application to correctly prepare the `node` (namehash). This preparation must include ENSIP-15 normalization of the original name before hashing.
        
3. **User Interface (UI) Components (Indirectly):**
    - While the normalization vulnerability itself resides in the Golang backend, UIs that accept ENS names can exacerbate the problem if they do not provide any visual cues or warnings for potentially confusable names (e.g., highlighting mixed scripts or unusual characters). A robust UI might perform preliminary normalization for display purposes, but the authoritative normalization must occur in the backend.
4. **Databases and Configuration Files:**
    - If Golang applications store ENS names in databases or read them from configuration files, these stored names are effectively inputs. If these names were stored in a non-normalized or ambiguously normalized state, and the application later retrieves and resolves them without proper ENSIP-15 processing, the vulnerability can be triggered.
5. **Smart Contracts (ENS Registry and Resolvers - Indirectly):**
    - The ENS smart contracts themselves (Registry, Resolvers) are not inherently vulnerable in this context. They correctly process valid namehashes presented to them. The issue is that the vulnerable Golang application, due to lack of normalization, computes and sends an *incorrect* namehash (derived from the homoglyph) to these contracts. The contracts then correctly resolve this (attacker's) namehash.
6. **Golang Code Performing Programmatic ENS Operations:**
    - Systems that programmatically generate or manipulate ENS names (e.g., for creating subdomains based on user data, batch registrations, or analytics) must ensure every label component is ENSIP-15 normalized before constructing the full name and deriving its namehash. Failure to do so can introduce vulnerabilities or resolution inconsistencies.

The vulnerability essentially impacts the critical juncture in a Golang application where an external ENS name string is converted into a canonical form suitable for secure on-chain lookup. The entire chain of trust, from user input to blockchain interaction, is compromised if this normalization step is flawed or missing.

**Table 4: Vulnerability Points in Golang ENS Interaction Flow**

| **Flow Step** | **Potential Mistake in Golang Application** | **Affected Golang Code Pattern Example (Conceptual)** |
| --- | --- | --- |
| 1. ENS Name Input Reception | Trusting input from user, API, or database without marking it for normalization. | `userInput := r.URL.Query().Get("ens_name")` |
| 2. Pre-Resolution Processing | No ENSIP-15 normalization; using basic `strings.ToLower()`; or incorrectly using `idna.ToUnicode()` alone. | `processedName := strings.ToLower(userInput)` |
| 3. ENS Library Call (e.g., Resolve) | Passing the unnormalized/improperly processed name to a library function like `ens.Resolve()`. | `addr, err := ens.Resolve(ethClient, processedName)` |
| 4. Manual Namehashing | Calculating `namehash` on an unnormalized or improperly normalized name. | `node := ens.Namehash(processedName)` |
| 5. Direct ENS Contract Interaction | Using the incorrect `node` from step 4 to call ENS Registry or Resolver contract methods. | `resolverAddr, err := ensRegistry.Resolver(nil, node)` <br> `ethAddr, err := resolverContract.Addr(nil, node)` |
| 6. Storing/Logging ENS Names | Storing or logging the raw, unnormalized input which might be used later for resolution. | `db.SaveENSQuery(userInput, resolvedAddress)` |

## **8. Vulnerable Code Snippet**

The following Golang code snippet illustrates the vulnerability. It demonstrates resolving an ENS name using the `wealdtech/go-ens` library without first applying ENSIP-15 normalization. This omission makes the application susceptible to resolving homoglyph names to attacker-controlled addresses.

```Go

package main

import (
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/ethclient"
	ens "github.com/wealdtech/go-ens/v3" // A common library for ENS interactions

	// The ENSIP-15 normalization library is crucial but MISSING in this vulnerable example.
	// To fix, one would typically import and use:
	// ensip15 "github.com/adraffy/go-ens-normalize/ensip15"
)

// resolveENSVulnerable attempts to resolve an ENS name to an Ethereum address.
// This function is vulnerable because it does not perform ENSIP-15 normalization
// on the input 'name' before resolution.
func resolveENSVulnerable(client *ethclient.Client, name string) (string, error) {
	// VULNERABILITY: The 'name' parameter, which could be user-supplied and contain
	// homoglyphs or characters requiring specific ENSIP-15 normalization,
	// is passed directly to ens.Resolve().
	//
	// A secure implementation would first normalize the name:
	// normalizedName, err := ensip15.Normalize(name)
	// if err!= nil {
	//     return "", fmt.Errorf("ENS name '%s' is invalid or not normalizable: %w", name, err)
	// }
	// address, err := ens.Resolve(client, normalizedName)

	log.Printf("Attempting to resolve (vulnerable): %s\n", name)
	address, err := ens.Resolve(client, name) // Directly using potentially unnormalized input
	if err!= nil {
		// If 'name' is a homoglyph registered by an attacker, this might still "succeed"
		// by resolving to the attacker's address, or it might fail if the name is
		// malformed in a way the library rejects (but not necessarily due to homoglyphs).
		return "", fmt.Errorf("failed to resolve ENS name '%s': %w", name, err)
	}
	return address.Hex(), nil
}

func main() {
	// Replace with your actual Infura Project ID or Ethereum node URL
	infuraURL := "https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID"
	client, err := ethclient.Dial(infuraURL)
	if err!= nil {
		log.Fatalf("Failed to connect to Ethereum client: %v", err)
	}

	// Scenario: Attacker has registered "аррle.eth" (using Cyrillic 'а' and 'р')
	// pointing to their malicious address.
	// The legitimate name is "apple.eth" (all Latin characters).
	homoglyphName := "аррle.eth" // Contains Cyrillic 'а' (U+0430) and 'р' (U+0440)
	legitimateName := "apple.eth"

	fmt.Printf("Resolving legitimate name: %s\n", legitimateName)
	legitAddr, err := resolveENSVulnerable(client, legitimateName)
	if err!= nil {
		log.Printf("Error resolving legitimate name '%s': %v\n", legitimateName, err)
	} else {
		fmt.Printf("Resolved address for legitimate '%s': %s\n", legitimateName, legitAddr)
	}

	fmt.Printf("\nResolving homoglyph name: %s\n", homoglyphName)
	attackerAddr, err := resolveENSVulnerable(client, homoglyphName)
	if err!= nil {
		// This error might occur if the homoglyph isn't registered, or if the library
		// has some basic validation that coincidentally catches this homoglyph.
		// However, a sophisticated homoglyph might pass basic checks.
		log.Printf("Error resolving homoglyph name '%s': %v\n", homoglyphName, err)
		log.Println("This could mean the homoglyph is not registered, or the library performed some basic validation. A successful exploit would resolve to an attacker's address.")
	} else {
		// If the homoglyph "аррle.eth" is registered by an attacker and points to their address,
		// this line will print the attacker's Ethereum address.
		fmt.Printf("VULNERABLE RESOLUTION: Resolved address for homoglyph '%s': %s\n", homoglyphName, attackerAddr)
		fmt.Println("WARNING: This address may belong to an attacker if the homoglyph was successfully resolved!")
	}

	// Example of a name that might cause issues if not ENSIP-15 normalized due to specific Unicode rules:
	// (This is a conceptual example; real-world problematic names would leverage subtle ENSIP-15 rules
	// regarding invisible characters, disallowed sequences, or complex emoji rules).
	// For instance, a name with a disallowed zero-width joiner or an unnormalized emoji sequence.
	// Let's use a name with a character that might be mapped or disallowed by ENSIP-15.
	// U+00AD (SOFT HYPHEN) is often problematic or ignored/mapped in normalization.
	complexName := "my\u00ADname.eth"
	fmt.Printf("\nResolving complex name: %s (contains U+00AD)\n", complexName)
	complexAddr, err := resolveENSVulnerable(client, complexName)
	if err!= nil {
		log.Printf("Error resolving complex name '%s': %v\n", complexName, err)
	} else {
		fmt.Printf("Resolved address for complex name '%s': %s\n", complexName, complexAddr)
		fmt.Println("Note: The resolution of this name might differ significantly with proper ENSIP-15 normalization.")
	}
}
```

**Explanation of Vulnerability in the Snippet:**

The function `resolveENSVulnerable` directly passes the input `name` to `ens.Resolve(client, name)`. It omits the critical step of normalizing the `name` string using an ENSIP-15 compliant library, such as `adraffy/go-ens-normalize`.

If `homoglyphName` (e.g., `"аррle.eth"`) is provided:

- Without ENSIP-15 normalization, the `ens.Resolve` function (or the underlying `namehash` process) will operate on the byte sequence of the Cyrillic-containing string.
- If an attacker has registered this specific homoglyph sequence on ENS and pointed it to their address, the function will "successfully" resolve to the attacker's address.
- The application (and potentially the user) would be deceived into believing they have resolved the legitimate "apple.eth".

A secure version of `resolveENSVulnerable` would first call `normalizedName, err := ensip15.Normalize(name)`. If `err` is `nil`, it would then use `normalizedName` in the `ens.Resolve` call. The `ensip15.Normalize` function would handle case-folding, map or disallow confusable characters, validate emoji sequences, and apply other ENS-specific rules, ensuring that the name used for on-chain resolution is in its single, canonical form as per ENSIP-15. This would either lead to the resolution of the true intended name or an error if the input is invalid or represents an unacceptable confusable.

The vulnerability lies in this omission, making the resolution process susceptible to manipulation through visually deceptive but technically distinct ENS names. The simplicity of the vulnerable call (`ens.Resolve(client, name)`) can mislead developers into assuming inherent safety if they are not deeply familiar with Unicode normalization complexities and ENSIP-15 requirements.

## **9. Detection Steps**

Detecting the "ENS Name Resolution Not Sanitized" vulnerability in Golang applications requires a combination of manual and automated techniques, focusing on how user-supplied or externally sourced ENS names are processed before on-chain resolution.

1. **Manual Code Review:**
    - **Identify Input Sources:** Pinpoint all locations in the Golang codebase where ENS names are received as input. This includes API request parameters, user interface form submissions, values read from configuration files or databases, and data received from other services.
    - **Trace Data Flow:** Follow the data flow of these ENS name strings from their point of entry to where they are used in ENS resolution functions (e.g., `ens.Resolve()` from `wealdtech/go-ens` ) or in `namehash` calculations for direct smart contract interactions.
    - **Verify Normalization:** Critically, check if an explicit call to an ENSIP-15 compliant normalization function, such as `ensip15.Normalize()` from the `adraffy/go-ens-normalize` library , is performed on the ENS name string *before* it's passed to any resolution or hashing function. The absence of this step is a strong indicator of vulnerability.
        
    - **Audit Library Usage:** Review the documentation of any third-party Golang ENS libraries being used. Determine if they perform ENSIP-15 normalization internally by default or if they expect pre-normalized input. Check library versions for known normalization-related vulnerabilities.
    - **Check for Naive Sanitization:** Look for attempts at manual or incomplete normalization, such as using only `strings.ToLower()` or basic character stripping, which are insufficient to prevent homograph attacks.
        
2. **Static Application Security Testing (SAST):**
    - **Custom Rules:** If the SAST tool supports custom rules, develop signatures to detect patterns where ENS resolution functions are called with tainted input (data originating from an untrusted source) that has not passed through a known ENSIP-15 normalization routine.
    - **Taint Analysis:** Configure SAST tools to trace the flow of ENS name strings. Define ENS resolution functions as sensitive sinks and ENSIP-15 normalization functions as sanitizers. An untrusted input reaching a sink without passing through a sanitizer should be flagged. However, generic SAST tools might struggle to differentiate between a compliant ENSIP-15 normalizer and a non-compliant one without specific Web3-aware rules.
    - **Dependency Scanning:** Integrate tools that check for outdated or known-vulnerable ENS or Ethereum client libraries.
3. **Dynamic Application Security Testing (DAST) / Fuzzing:**
    - **Test Case Generation:** Create a comprehensive test suite of ENS names, including:
        - Known homoglyphs of legitimate and popular ENS names (e.g., replacing Latin characters with visually similar Cyrillic, Greek, or other script characters).
        - Names containing mixed scripts.
        - Names with various emoji sequences (valid and invalid under ENSIP-15).
        - Strings with leading/trailing whitespace, control characters, or characters disallowed by ENSIP-15.
        - Strings that have different canonical forms under basic Unicode normalization versus ENSIP-15.
    - **Automated Input:** Feed these test names into the application's input vectors that accept ENS names.
    - **Monitor Resolution Outcomes:** Observe the resolved addresses or resources. Compare these against the expected resolutions for the legitimate counterparts of any homoglyphs.
    - **Reference Resolver Comparison:** A robust dynamic test involves comparing the application's resolution result for a given input against the result from a trusted, ENSIP-15 compliant reference resolver (e.g., using `adraffy/go-ens-normalize` in a test harness). Discrepancies indicate a potential normalization vulnerability.
        
    - The research paper  mentions the design of a tool specifically for "detecting application-level discrepancies in domain normalization process," indicating the feasibility and importance of such dynamic checks.
        
4. **Dependency and Library Verification:**
    - Actively verify that any Golang libraries used for ENS interaction are explicitly ENSIP-15 compliant. Check their documentation and release notes for statements regarding normalization and ENSIP-15 support.
    - Prioritize libraries that have a strong focus on security and adherence to ENS standards.

Effective detection requires a nuanced understanding that the vulnerability often lies in the *omission* of the correct, complex normalization step rather than a simple "bad function" call. The context of ENS and the specifics of ENSIP-15 are crucial for accurate detection.

## **10. Proof of Concept (PoC)**

This Proof of Concept demonstrates how a Golang application lacking ENSIP-15 normalization can be exploited by resolving a homoglyph ENS name to an attacker's Ethereum address.

Objective:

To show that a vulnerable Golang application will resolve a visually deceptive ENS name (homoglyph) to an attacker-controlled address, whereas a correctly implemented application would either reject the name or resolve it to the legitimate address (or a non-attacker-controlled canonical form).

**Setup:**

1. **Attacker's Actions:**
    - Identify a legitimate target ENS name, e.g., `wallet.eth`.
    - Create a homoglyph version, e.g., `waӏӏet.eth` (where 'ӏ' is the Cyrillic Palochka, U+04CF, visually similar to Latin 'l').
    - Register this homoglyph ENS name (`waӏӏet.eth`) on the Ethereum Name Service, pointing it to an Ethereum address controlled by the attacker (e.g., `0xAttackerAddress...`).
2. **Legitimate Setup:**
    - The legitimate ENS name `wallet.eth` is registered and points to a known, legitimate Ethereum address (e.g., `0xLegitimateAddress...`).
3. Vulnerable Golang Application:
    
    A simple Golang command-line tool or web service endpoint that:
    
    - Accepts an ENS name string as input.
    - Uses a library like `github.com/wealdtech/go-ens/v3` to resolve the ENS name.
    - Critically, **does not** perform ENSIP-15 normalization on the input string before passing it to the resolution function.
    - Outputs the resolved Ethereum address.

**Exploitation Steps:**

1. The attacker (or a victim tricked by the attacker) provides the homoglyph ENS name `waӏӏet.eth` as input to the vulnerable Golang application.
2. The Golang application receives the string `"waӏӏet.eth"`.
3. The application directly calls its ENS resolution function, for example:
`address, err := ens.Resolve(ethClient, "waӏӏet.eth")`
4. Because no ENSIP-15 normalization is performed by the application on the input string:
    - The `ens.Resolve` function (assuming it doesn't perform full ENSIP-15 normalization itself, which is common for libraries expecting normalized input or performing basic normalization only) will proceed to calculate the namehash based on the byte representation of `"waӏӏet.eth"` (with Cyrillic Palochkas).
    - This namehash will be different from the namehash of the legitimate `"wallet.eth"` (with Latin 'l's).
5. The ENS system, when queried with the namehash corresponding to `"waӏӏet.eth"`, will correctly find the record registered by the attacker.
6. The resolution function returns the attacker's Ethereum address (`0xAttackerAddress...`).
7. The vulnerable Golang application now holds the attacker's address, potentially believing it to be the address for the legitimate "wallet.eth" due to visual similarity. It might then display this address to the user or use it in a subsequent transaction.

**Verification & Expected Outcomes:**

- Vulnerable Application Output (when input is waӏӏet.eth):
    
    Resolved waӏӏet.eth to: 0xAttackerAddress...
    
- **Secure Application Behavior (with ENSIP-15 Normalization for `waӏӏet.eth`):**
    - **Outcome 1 (Rejection):** The `ensip15.Normalize("waӏӏet.eth")` function might return an error, identifying it as an invalid or confusable name according to ENSIP-15 rules (e.g., due to mixed scripts or specific confusable characters). The application would then report an error: `Error: ENS name 'waӏӏet.eth' is invalid/confusable.`
    - **Outcome 2 (Normalization to Legitimate):** Less likely for distinct homoglyphs that an attacker registers, but if ENSIP-15 normalized `waӏӏet.eth` to the canonical `wallet.eth`, then it would resolve to `0xLegitimateAddress...`. However, ENSIP-15 aims to prevent such direct equivalences for security.
    - **Outcome 3 (Normalization to a Different Valid Form):** If `waӏӏet.eth` normalized to another valid but distinct canonical form (not the attacker's registration and not the legitimate one), it would resolve accordingly or fail if that form isn't registered.
- Control Case (Input wallet.eth to Vulnerable App):
    
    Resolved wallet.eth to: 0xLegitimateAddress... (This should work correctly, masking the vulnerability if only tested with simple names).
    

**Conceptual Golang PoC Code:**

```Go

package main

import (
	"fmt"
	"log"
	// ENSIP-15 normalizer - crucial for secure implementation, intentionally omitted for PoC
	// ensip15 "github.com/adraffy/go-ens-normalize/ensip15"
	"github.com/ethereum/go-ethereum/ethclient"
	ens "github.com/wealdtech/go-ens/v3"
)

// main simulates the vulnerable application logic
func main() {
	// Setup Ethereum client (replace with actual connection)
	client, err := ethclient.Dial("https://mainnet.infura.io/v3/YOUR_INFURA_KEY")
	if err!= nil {
		log.Fatalf("Failed to connect to Ethereum client: %v", err)
	}

	// --- Attacker Setup (Conceptual - attacker does this on ENS) ---
	// Attacker registers "waӏӏet.eth" (Cyrillic Palochka 'ӏ' for 'l')
	// and points it to "0xAttackerAddress"
	attackerAddress := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // Placeholder
	homoglyphName := "waӏӏet.eth" // User input: visually deceptive name

	// --- Legitimate Setup (Conceptual - legitimate user does this on ENS) ---
	// Legitimate "wallet.eth" points to "0xLegitimateAddress"
	legitimateAddress := "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" // Placeholder
	legitimateName := "wallet.eth"

	// --- Vulnerable Application Logic ---
	fmt.Printf("Attempting to resolve user input: '%s'\n", homoglyphName)

	// VULNERABLE STEP: Direct resolution without ENSIP-15 normalization
	// In a real exploit, the application would receive homoglyphName from an external source.
	resolvedAddress, err := ens.Resolve(client, homoglyphName)
	if err!= nil {
		// This branch might be hit if the homoglyph isn't actually registered by an attacker,
		// or if the library performs some very basic validation that catches it.
		// A sophisticated homoglyph might bypass basic checks.
		fmt.Printf("Failed to resolve '%s'. Error: %v\n", homoglyphName, err)
		fmt.Println("This could mean the homoglyph is not registered or the library performed some basic validation.")
		fmt.Println("A successful exploit would resolve to an attacker's address if they registered this homoglyph.")
	} else {
		fmt.Printf("VULNERABLE RESOLUTION for '%s': %s\n", homoglyphName, resolvedAddress.Hex())
		if resolvedAddress.Hex() == attackerAddress {
			fmt.Println("SUCCESSFUL EXPLOIT: Resolved to attacker's address!")
		} else {
			fmt.Println("Resolved to an unexpected address. Further investigation needed.")
		}
	}

	// --- For Comparison: Resolving the legitimate name (should work as expected) ---
	fmt.Printf("\nAttempting to resolve legitimate name: '%s'\n", legitimateName)
	legitResolvedAddress, legitErr := ens.Resolve(client, legitimateName)
	if legitErr!= nil {
		fmt.Printf("Failed to resolve legitimate '%s'. Error: %v\n", legitimateName, legitErr)
	} else {
		fmt.Printf("Resolution for legitimate '%s': %s\n", legitimateName, legitResolvedAddress.Hex())
		// This should print 0xLegitimateAddress...
	}

	// --- Secure Application Logic (Conceptual - how it should be) ---
	// fmt.Printf("\nAttempting secure resolution for user input: '%s'\n", homoglyphName)
	// normalizedName, normErr := ensip15.Normalize(homoglyphName)
	// if normErr!= nil {
	//     fmt.Printf("ENSIP-15 Normalization Error for '%s': %v. Name rejected.\n", homoglyphName, normErr)
	// } else {
	//     fmt.Printf("Normalized name: '%s'\n", normalizedName)
	//     secureResolvedAddress, resolveErr := ens.Resolve(client, normalizedName)
	//     if resolveErr!= nil {
	//         fmt.Printf("Secure resolution failed for normalized '%s': %v\n", normalizedName, resolveErr)
	//     } else {
	//         fmt.Printf("Secure resolution for normalized '%s': %s\n", normalizedName, secureResolvedAddress.Hex())
	//         // This should ideally resolve to the legitimate address if normalization maps the homoglyph
	//         // to the canonical form, OR normalization should have failed if it's a disallowed confusable.
	//     }
	// }
}
```

This PoC highlights the critical difference in outcome when ENSIP-15 normalization is omitted. The success of the exploit depends on the attacker successfully registering the homoglyph and the vulnerable application's failure to differentiate it from the legitimate name during its flawed resolution process. A subtle aspect is that the application might *appear* to function correctly with common Latin names, masking the vulnerability until a specifically crafted homoglyph input is processed.

## **11. Risk Classification**

The "ENS Name Resolution Not Sanitized" vulnerability in Golang applications presents a significant risk within the Web3 ecosystem. Its classification considers both the likelihood of exploitation and the potential impact.

- **Likelihood: Medium to High**
    - The ease with which visually confusable homoglyph domain names can be crafted and registered on ENS contributes to the likelihood. Attackers are aware of homograph attack techniques.
        
    - The prevalence of the vulnerability depends on how widely Golang developers are aware of and correctly implement the stringent ENSIP-15 normalization standard. Given that research indicates significant inconsistencies in ENS normalization across dApps and wallets , it suggests that many applications may be vulnerable.
        
    - User input is a common vector, and users can be tricked via phishing links or by manually typing a visually similar name.
- **Impact: High to Critical**
    - **Financial Loss:** Direct and often irreversible loss of cryptocurrency and NFTs if users are tricked into sending assets to an attacker's address resolved from a homoglyph name.
        
    - **Smart Contract Exploits:** Users might unknowingly interact with malicious smart contracts, leading to theft of assets, unauthorized approvals, or other detrimental on-chain actions.
    - **Phishing and Identity Theft:** Redirection to counterfeit dApps or websites can lead to the theft of private keys, seed phrases, or other sensitive credentials.
    - **Reputational Damage:** Projects whose ENS names are successfully spoofed, or applications found to be vulnerable, can suffer significant reputational harm and loss of user trust.
    - **Systemic Risk to ENS Trust:** Widespread exploitation of this vulnerability could undermine user confidence in the reliability and security of the entire Ethereum Name Service as a user-friendly layer for blockchain interactions.
        
- **Overall Risk: High**
    - Considering the potential for severe, direct financial impact and the moderate to high likelihood due to the subtlety of homograph attacks and potential developer oversight regarding complex Unicode normalization, the overall risk is classified as High.

**Relevant Common Weakness Enumerations (CWEs):**

- **CWE-20: Improper Input Validation:** This is the most direct CWE. The vulnerability arises because the application fails to properly validate and sanitize the input ENS name according to the specific, strict rules required by the ENS protocol (ENSIP-15) before using it for resolution. The input (ENS name) is not transformed into its correct and safe canonical form.

- **CWE-116: Improper Encoding or Escaping of Output:** While the primary issue is input validation, if a vulnerable application resolves a homoglyph to a malicious address and then displays that address alongside the *visually perceived legitimate name* without any warning or indication of potential confusability, it contributes to the deception. This could be seen as improper output handling in the context of user trust.

The risk is systemic within the Web3 space because ENS is a foundational component intended to improve usability. If this usability layer itself becomes a vector for sophisticated attacks due to inconsistent or missing normalization, it poses a threat to the broader adoption and secure use of decentralized applications. Furthermore, the issue is not solely about malicious attackers; inconsistent normalization across different ecosystem tools could lead to accidental misdirection of funds or interactions even with non-maliciously registered but ambiguously normalizable names.

## **12. Fix & Patch Guidance**

Addressing the "ENS Name Resolution Not Sanitized" vulnerability in Golang applications requires a primary focus on implementing correct ENSIP-15 normalization for all ENS names before they are used in any resolution or hashing process.

**Primary Fix: Implement ENSIP-15 Normalization**

The most critical step is to ensure that any user-supplied or externally sourced ENS name is passed through an ENSIP-15 compliant normalization process before being used.

1. **Use a Compliant Library:** Integrate a Golang library that specifically implements the ENSIP-15 standard. The recommended library for this is `adraffy/go-ens-normalize`. This library is designed to be a Golang port of the reference JavaScript implementation for ENSIP-15.
2. Apply Normalization Before Resolution/Hashing:
    
    Modify code to call the normalization function (e.g., ensip15.Normalize(name)) on any ENS name string before it is passed to:
    
    - ENS resolution functions (e.g., `ens.Resolve()` from libraries like `wealdtech/go-ens`).
    - The `namehash` algorithm if performing manual contract interactions.

**Corrected Code Snippet Example (from Section 8):**

```Go

package main

import (
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/ethclient"
	ensip15 "github.com/adraffy/go-ens-normalize/ensip15" // Import the ENSIP-15 normalization library
	ens "github.com/wealdtech/go-ens/v3"
)

// resolveENSSecure attempts to resolve an ENS name to an Ethereum address securely.
func resolveENSSecure(client *ethclient.Client, name string) (string, error) {
	log.Printf("Attempting to securely resolve: %s\n", name)

	// Step 1: Normalize the input ENS name using ENSIP-15
	normalizedName, err := ensip15.Normalize(name)
	if err!= nil {
		// The name is invalid according to ENSIP-15 (e.g., contains disallowed characters,
		// is a confusable, etc.)
		return "", fmt.Errorf("ENS name '%s' is invalid or not normalizable by ENSIP-15: %w", name, err)
	}
	log.Printf("ENSIP-15 Normalized name: %s\n", normalizedName)

	// Step 2: Use the normalized name for resolution
	address, err := ens.Resolve(client, normalizedName)
	if err!= nil {
		return "", fmt.Errorf("failed to resolve normalized ENS name '%s': %w", normalizedName, err)
	}
	return address.Hex(), nil
}

func main() {
	infuraURL := "https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID" // Replace with your actual Infura Project ID
	client, err := ethclient.Dial(infuraURL)
	if err!= nil {
		log.Fatalf("Failed to connect to Ethereum client: %v", err)
	}

	homoglyphName := "аррle.eth" // Contains Cyrillic 'а' and 'р'
	legitimateName := "apple.eth"

	fmt.Printf("Securely resolving legitimate name: %s\n", legitimateName)
	legitAddr, err := resolveENSSecure(client, legitimateName)
	if err!= nil {
		log.Printf("Error securely resolving legitimate name '%s': %v\n", legitimateName, err)
	} else {
		fmt.Printf("Securely resolved address for legitimate '%s': %s\n", legitimateName, legitAddr)
	}

	fmt.Printf("\nSecurely resolving homoglyph name: %s\n", homoglyphName)
	// This should now either fail normalization or normalize to a form that does not
	// resolve to an attacker's address (if the homoglyph itself is disallowed or mapped differently).
	attackerAddr, err := resolveENSSecure(client, homoglyphName)
	if err!= nil {
		log.Printf("Secure resolution for homoglyph name '%s' correctly resulted in an error: %v\n", homoglyphName, err)
	} else {
		// This case should ideally not happen if the homoglyph is problematic and ENSIP-15 catches it.
		// If it does resolve, it means ENSIP-15 considered it valid and distinct, or it normalized
		// to a registered name. The key is that it's now consistently processed.
		log.Printf("SECURE RESOLUTION for homoglyph '%s' (normalized to '%s'): %s\n", homoglyphName, func()string{n, _ := ensip15.Normalize(homoglyphName); return n}(), attackerAddr)
		log.Println("INFO: This resolution used the ENSIP-15 normalized name. Verify if this address is expected for the normalized form.")
	}
}
```

**Further Patch and Guidance Recommendations:**

1. **Library Updates:** Keep Golang Ethereum client libraries (e.g., `go-ethereum`) and any higher-level ENS interaction libraries continuously updated to their latest stable versions. Monitor their release notes for security patches, especially those related to name processing or ENSIP compliance.
2. **Additional Input Validation:**
    - **Mixed Script Detection:** Consider implementing checks to detect or warn about ENS names containing characters from multiple scripts (e.g., Latin and Cyrillic), as these are common in homograph attacks. ENSIP-15 itself has rules regarding whole-script confusables.
    - **Visual Confusable Display:** In user interfaces, if a name passes ENSIP-15 normalization but is known to contain visually confusable characters, consider displaying a warning or rendering the name in Punycode to alert the user. This is a defense-in-depth measure.
3. **Defense in Depth for Critical Operations:**
    - **Address Confirmation:** For transactions involving significant value or critical permissions, after resolving an ENS name (even a normalized one), display the full resolved address to the user and require explicit confirmation before proceeding with the transaction.
    - **Primary Name Reverse Lookup Verification:** When displaying an ENS name for a given address (reverse resolution), always perform a forward resolution of the obtained name to ensure it resolves back to the original address. If it doesn't match, display the raw address to prevent impersonation.
        
4. **Developer Education and Awareness:**
    - Train developers on the intricacies of Unicode, IDN, UTS #46, and specifically ENSIP-15 when working with ENS names.
    - Emphasize that ENS name processing is a security-sensitive operation and not just simple string handling.
5. **Security Audits and Testing:**
    - Regularly audit Golang code that handles ENS names.
    - Include test cases with a wide variety of homoglyphs, confusable characters, and malformed Unicode sequences in the testing suite for ENS resolution logic.

By implementing these fixes, particularly the mandatory use of ENSIP-15 normalization, Golang applications can significantly reduce their susceptibility to ENS name sanitization vulnerabilities and protect their users from associated attacks. Library maintainers also play a role by ensuring their libraries either enforce ENSIP-15 internally or very clearly document the requirement for pre-normalized inputs.

## **13. Scope and Impact**

The "ENS Name Resolution Not Sanitized" vulnerability in Golang applications has a broad scope and potentially severe impact, extending beyond individual applications to affect user trust in the wider ENS ecosystem.

**Scope:**

1. **Vulnerable Golang Applications:** Any Golang application that accepts or processes ENS names from external sources (users, APIs, databases, configuration files) and uses them for on-chain resolution without proper ENSIP-15 normalization is within the scope. This includes:
    - Decentralized Applications (dApps) backends.
    - Cryptocurrency wallets with ENS resolution features.
    - Blockchain explorers or analytics platforms.
    - Backend services interacting with smart contracts based on ENS names.
    - Any tool or script written in Golang that automates ENS interactions.
    Research indicates that a significant percentage of existing dApps and wallets may have inconsistencies in their normalization practices, suggesting a potentially wide attack surface.

2. **Users of Vulnerable Applications:** End-users who interact with these vulnerable Golang applications are directly at risk. They might input an ENS name expecting a legitimate resolution but are instead deceived due to a homograph attack.
3. **ENS Ecosystem Integrity:** The trustworthiness of the Ethereum Name Service as a whole can be impacted. ENS aims to simplify user interaction with the blockchain by providing human-readable names. If these names become a common vector for fraud due to inconsistent or insecure client-side implementations, user confidence in the entire system erodes.
4. **Cross-Chain Implications (Potential):** As ENS features evolve to support multi-chain addressing (e.g., resolving an ENS name to an address on a Layer 2 network or another blockchain), Golang applications handling these resolutions must apply correct, context-aware normalization. Failure to do so could extend the scope of this vulnerability to interactions beyond the Ethereum mainnet.

**Impact:**

The impact of this vulnerability is amplified by the nature of blockchain technology, particularly the common irreversibility of transactions.

1. **Direct Financial Loss:** This is the most critical impact. Users can be tricked into:
    - Sending cryptocurrencies (ETH, ERC-20s) to an attacker's address.
    - Transferring valuable NFTs to an attacker.
    These losses are typically non-recoverable.
2. **Compromise through Malicious Contract Interaction:** Users might unknowingly authorize transactions with malicious smart contracts disguised by homoglyph ENS names. This could lead to:
    - Theft of all approved tokens from their wallet.
    - Participation in fraudulent schemes.
    - Other unintended and harmful on-chain actions.
3. **Phishing and Identity Theft:** Resolution to attacker-controlled content hashes can lead users to phishing websites that mimic legitimate dApps, designed to steal private keys, seed phrases, or other sensitive login credentials.
4. **Reputational Damage:**
    - For legitimate projects or individuals whose ENS names are spoofed.
    - For developers or companies whose Golang applications are found to be vulnerable, leading to a loss of user trust and credibility.
5. **Loss of User Trust in ENS and Web3 Applications:** If users frequently encounter issues with ENS name resolution or fall victim to homograph attacks, their overall trust in using ENS and interacting with Web3 applications will diminish. This can hinder adoption and growth of the ecosystem.
6. **Operational Issues and Service Disruption:** Inconsistent name resolution due to improper normalization can lead to application errors, inability to locate correct on-chain resources, or failed transactions, even without malicious intent. This can disrupt the normal operation of dApps and services relying on ENS.

The statement from that ENS homoglyph attacks are "more severe" than their DNS counterparts and that their effects are "almost always unrecoverable" underscores the gravity of this vulnerability in the blockchain context. The potential for direct, irreversible loss of valuable digital assets makes robust ENS name sanitization a critical security requirement for Golang applications.

## **14. Remediation Recommendation**

A multi-layered approach is recommended to remediate and mitigate the "ENS Name Resolution Not Sanitized" vulnerability in Golang applications. This involves actions for developers building these applications, maintainers of relevant libraries, and end-users.

**For Golang Application Developers:**

1. **Prioritize ENSIP-15 Normalization:**
    - **Action:** Mandate the use of an ENSIP-15 compliant normalization library for *all* ENS names received from any external source (user input, API, database, config files) *before* these names are used for on-chain resolution (e.g., with `ens.Resolve()`) or for generating a `namehash`.
    - **Implementation:** Integrate a library such as `adraffy/go-ens-normalize`. Ensure that the output of the normalization function is used for subsequent ENS operations, and that any errors returned by the normalizer (indicating an invalid or non-normalizable name) are handled appropriately (e.g., by rejecting the input).

2. **Keep Dependencies Updated:**
    - **Action:** Regularly update Golang itself, the Ethereum client library (e.g., `go-ethereum`), and any third-party ENS-specific libraries to their latest stable and secure versions.
    - **Reasoning:** Library updates may contain patches for security vulnerabilities, including improvements in handling Unicode or stricter adherence to ENSIP standards.
3. **Robust Input Validation and Sanitization:**
    - **Action:** Beyond ENSIP-15 normalization, treat all externally sourced ENS names as untrusted input. Implement additional validation checks as appropriate for the application's context.
    - **Example:** While ENSIP-15 handles confusables, an application might choose to additionally warn users or apply stricter policies for names containing mixed scripts if such names are not expected in its typical use case.
4. **Adhere to Secure Coding Practices:**
    - **Action:** Follow general secure coding guidelines for Golang development. This includes proper error handling, secure management of any credentials used by the application itself, and avoiding common pitfalls in concurrent programming if ENS resolution is done in goroutines.
        
5. **Enhance User Interface (UI) and User Experience (UX) for Security:**
    - **Action:** If the Golang application has a user-facing component, design the UI to help users identify potentially deceptive ENS names.
    - **Implementation:** Consider displaying the fully normalized version of an ENS name alongside the user's input, or rendering potentially confusable characters in a distinct way (e.g., using Punycode for highly suspicious names, or highlighting mixed-script names). Refer to ENS design guidelines for best practices in displaying names and resolved addresses. Always show the full resolved address for user confirmation before critical transactions.
        
6. **Thorough and Diverse Testing:**
    - **Action:** Develop a comprehensive test suite that includes a wide array of potentially problematic ENS names: known homoglyphs, names with mixed scripts, various emoji sequences, names with invisible or special Unicode characters, and strings that are invalid under ENSIP-15.
    - **Verification:** Ensure the application correctly rejects invalid/non-normalizable names and consistently resolves valid (and correctly normalized) names to their expected addresses.

**For Maintainers of Golang ENS Libraries:**

1. **Internalize ENSIP-15 Compliance:** Strive to make ENSIP-15 normalization an internal, default, and non-bypassable step within core resolution functions.
2. **Clear Documentation:** If a library expects pre-normalized input, this requirement must be very clearly and prominently documented, along with recommendations for compliant external normalization libraries. The security implications of providing unnormalized input should be highlighted.

**For End-Users:**

1. **Vigilance with ENS Names:** Be cautious when typing, pasting, or clicking on ENS names, especially if they appear in unsolicited messages or unfamiliar contexts. Double-check for subtle visual differences.
2. **Use Trusted Applications:** Prefer well-audited and reputable wallets and dApps that have a strong track record on security and are known to follow ENS best practices.
3. **Verify Resolved Addresses:** Before confirming any critical transaction (e.g., sending funds, interacting with a contract), always verify that the resolved Ethereum address displayed by the application matches the intended recipient's address. If in doubt, use a trusted block explorer to independently verify the ENS name and its associated address.
4. **Report Suspicious Names:** If a potentially malicious or deceptive ENS name is encountered, report it to relevant platforms or community channels if such mechanisms exist.

A community-wide commitment, encompassing standards bodies (ENSIP authors), library maintainers, application developers, and educated users, is essential for effectively mitigating the risks associated with ENS name resolution and ensuring the trustworthiness of the ENS ecosystem. The primary technical responsibility for preventing this specific vulnerability in Golang applications, however, lies with the application developers to correctly implement ENSIP-15 normalization.

## **15. Summary**

The "ENS Name Resolution Not Sanitized" vulnerability (ens-name-unsanitized) in Golang applications represents a critical security flaw where the failure to properly normalize Ethereum Name Service (ENS) names according to the ENSIP-15 standard can lead to homograph attacks and inconsistent name resolution. This primarily stems from developers underestimating the complexities of Unicode normalization in the context of ENS or making incorrect assumptions about the capabilities of standard libraries. Golang applications that directly use user-supplied or externally sourced ENS names for on-chain resolution without first passing them through an ENSIP-15 compliant normalization process are susceptible.

The core risk involves attackers registering ENS names that are visually indistinguishable (homoglyphs) from legitimate names. Due to the lack of proper sanitization, a vulnerable Golang application may resolve such a deceptive name to an attacker-controlled Ethereum address or resource. This can result in severe consequences, including the irreversible loss of cryptocurrency and NFTs, unauthorized interaction with malicious smart contracts, and successful phishing attacks, thereby undermining user trust in both the application and the broader ENS ecosystem. The impact is particularly acute in Web3 due to the direct financial implications and the immutability of blockchain transactions.

Detection of this vulnerability requires careful code review to ensure ENSIP-15 normalization is applied before resolution, supplemented by static analysis with custom rules, and dynamic testing using a diverse set of potentially problematic ENS names. The most effective remediation strategy for Golang developers is the consistent use of a dedicated ENSIP-15 compliant normalization library, such as `adraffy/go-ens-normalize`, for every ENS name before it is processed for resolution or hashing. This proactive and explicit normalization is crucial; developers should not assume that underlying ENS client libraries will perform this critical step by default.

Ultimately, securing ENS interactions is a shared responsibility. While Golang developers must implement robust normalization, library maintainers should aim for secure-by-default designs, and users should exercise caution. Addressing this vulnerability is vital for maintaining the integrity and user-friendliness that ENS aims to bring to the Ethereum ecosystem.
