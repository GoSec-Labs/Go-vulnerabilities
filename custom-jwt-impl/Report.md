# **Security Vulnerabilities in Custom JWT Implementations: A Comprehensive Analysis**

## **Severity Rating**

Variable (Typically High🟠 to Critical🔴 for many common JWT flaws)

The severity of vulnerabilities associated with JSON Web Tokens (JWTs) can vary significantly, contingent upon the specific flaw, its exploitability, and the context of the application. However, many prevalent issues, such as the acceptance of tokens with the `none` algorithm or the compromise of signing keys, frequently lead to impacts classified as High🟠 or Critical🔴. The potential for attackers to forge tokens, impersonate users, or escalate privileges underscores the severe consequences these vulnerabilities can entail.

## **Description**

JSON Web Tokens (JWTs) are an open standard (RFC 7519) that define a compact and self-contained method for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs are commonly used for authentication, authorization, and information exchange. A JWT consists of three parts separated by dots (`.`): a Header, a Payload, and a Signature. The Header typically identifies the algorithm used to sign the token. The Payload contains claims, which are statements about an entity (typically the user) and additional data. The Signature is used to verify that the sender of the JWT is who it says it is and to ensure that the message wasn't changed along the way. JWTs are often favored for their stateless nature, which can reduce the need for server-side session storage.

While JWTs are a standardized format, the process of implementing JWT generation, validation, and handling – particularly in "custom" scenarios where developers might deviate from secure library defaults or implement parts of the logic themselves – can introduce severe security vulnerabilities. The inherent flexibility of the JWT specification can be a double-edged sword if not managed with a strong understanding of security implications.

Common categories of vulnerabilities in custom JWT implementations include:

- **Signature-based attacks**: Exploiting weaknesses in how token signatures are generated or verified.
- **Algorithm manipulation**: Tricking the server into using a weaker or unintended algorithm for signature verification.
- **Improper claim validation**: Failing to correctly validate the claims contained within the JWT payload.
- **Key management flaws**: Weaknesses in how cryptographic keys are generated, stored, or managed.
- **Insecure token handling**: Mishandling tokens during storage or transmission.

The impact of these vulnerabilities is generally severe, potentially leading to unauthorized access to systems, privilege escalation, session hijacking, and sensitive data breaches.

A significant challenge in JWT security revolves around the concept of statelessness. While JWTs are often adopted for their stateless design to reduce server-side session storage, critical security functionalities like immediate token revocation upon logout or security incident often necessitate reintroducing server-side state, for example, through token blacklists or denylists. This creates a fundamental tension: striving for true statelessness with JWTs can compromise the ability to enforce robust security measures that require immediate invalidation capabilities, such as those discussed in OAuth standards or needed for prompt session termination. This paradox implies that the perceived primary benefit of statelessness may not be fully achievable if a strong security posture is paramount.

## **Technical Description (for security pros)**

A thorough understanding of JWT internals is crucial for identifying and mitigating vulnerabilities in custom implementations.

### **JWT Structure Deep Dive**

A JWT is composed of three Base64Url-encoded parts: Header, Payload, and Signature, concatenated with periods.

- **Header**: The header typically consists of two parts: the token type (`typ`), which is JWT, and the signing algorithm (`alg`) used, such as HMAC SHA256 (HS256) or RSA (RS256). The `alg` parameter is particularly critical as its manipulation is central to several attack vectors. Other header parameters like `kid` (Key ID), `jwk` (JSON Web Key), or `jku` (JWK Set URL) can also be present and, if improperly handled, can be exploited. For instance, the `kid` parameter, if used to dynamically fetch keys, might be vulnerable to path traversal or injection attacks if its value is not sanitized.
- **Payload**: The payload contains the claims, which are statements about an entity (e.g., a user) and additional metadata. Claims are categorized into:
    - **Registered Claims**: These are a set of predefined claims that are not mandatory but recommended for providing a set of useful, interoperable claims. Examples include `iss` (issuer), `exp` (expiration time), `sub` (subject), `aud` (audience), `nbf` (not before), and `iat` (issued at).
        
    - **Public Claims**: These are claims that can be defined at will by those using JWTs. However, to avoid collisions, they should be defined in the IANA JSON Web Token Claims registry or be named using a collision-resistant namespace.
    - **Private Claims**: These are custom claims created to share information between parties that agree on using them.
    It is important to remember that the payload is Base64Url encoded, not encrypted by default, meaning its contents are easily readable by anyone who intercepts the token.

- **Signature**: The signature is used to verify the integrity of the token (i.e., that the claims have not been tampered with) and, in the case of tokens signed with a private key, to verify the authenticity of the sender. It is calculated by signing the Base64Url-encoded header and payload using the algorithm specified in the header and a secret or private key.

### **Signature Vulnerabilities**

The security of a JWT heavily relies on the integrity of its signature. Flaws in signature generation or verification can lead to token forgery.

- **`alg:none` Attack**: The JWT specification allows for an "unsecured JWT" where the `alg` header parameter is set to `none`. This indicates that the token is not signed.If a server is configured to accept tokens with `alg:none`, an attacker can forge tokens with arbitrary claims by simply setting the `alg` header to `none` (or case variations like `None`, `nOne` ) and omitting the signature part. While many modern libraries, such as `golang-jwt/jwt`, attempt to mitigate this by requiring explicit unsafe flags to accept `none` tokens (e.g., `jwt.UnsafeAllowNoneSignatureType`), custom implementations or misconfigured libraries might still be vulnerable.
- **Algorithm Confusion (Type Confusion)**: This attack exploits servers that are flexible in the algorithms they accept. An attacker can modify the `alg` header of a token originally signed with an asymmetric algorithm (e.g., RS256, which uses a private key for signing and a public key for verification) to a symmetric algorithm (e.g., HS256, which uses a shared secret for both). If the server's verification logic then improperly uses the public key (intended for RS256 verification) as the secret key for HS256 verification, the signature will validate. This allows the attacker to forge tokens signed with the publicly known RSA public key.
- **Signature Stripping**: This is functionally similar to the `alg:none` attack. If the server's JWT parsing logic decodes the header and payload but fails to check for the presence or validity of the signature component itself, an attacker can simply remove the signature part from the token and submit a modified, unsigned token.
- **Weak Secret Keys (for HMAC-based algorithms)**: If symmetric algorithms like HS256, HS384, or HS512 are used, the security of the token depends entirely on the secrecy and strength of the shared secret key. If this key is weak, guessable, or hardcoded and subsequently leaked, attackers can brute-force it using tools like Hashcat and then sign their own malicious tokens.
- **Key ID (`kid`) Parameter Injection/Path Traversal**: The `kid` header parameter is sometimes used to indicate which key should be used to verify the token, often by looking up the key in a database or loading it from a file system. If the value of the `kid` parameter, which is attacker-controllable, is used insecurely in such lookups, it can lead to vulnerabilities. For example, if `kid` is used to construct a file path, path traversal sequences (`../../`) could allow an attacker to specify an arbitrary file on the server as the verification key. If the server uses an HMAC algorithm and the attacker can point `kid` to a predictable, empty, or attacker-controlled file (e.g., `/dev/null` which might be treated as an empty key), they could forge valid tokens. Similarly, if `kid` is used in a database query, it could be vulnerable to SQL injection.
- **JWK/JKU Header Injection**: The `jwk` (JSON Web Key) and `jku` (JWK Set URL) header parameters allow a token to embed or point to the key that should be used for its verification. If a server is misconfigured to trust these headers implicitly, an attacker can craft a token, sign it with their own key, and then include their public key in the `jwk` header or host it at a URL specified in the `jku` header. The server might then fetch and use the attacker's key for verification, validating the malicious token.

### **Improper Claim Validation**

Even if the signature is correctly verified, failure to properly validate the claims within the JWT payload can lead to serious security issues.

- **Expiration (`exp`) and Not Before (`nbf`) Claims**: The `exp` claim defines the expiration time after which the JWT MUST NOT be accepted for processing. The `nbf` claim defines the time before which the JWT MUST NOT be accepted. Failure to validate these claims can allow attackers to replay expired tokens or use tokens that are not yet active. Server-side time synchronization is critical, and a small leeway might be configured to account for clock skew between servers, but this should be minimal.
- **Audience (`aud`) Claim**: The `aud` claim identifies the recipients that the JWT is intended for. If an application accepts a JWT without verifying that it is an intended audience, an attacker might be able to use a token issued for a different application or service (potentially with lower security) to gain unauthorized access.
- **Issuer (`iss`) Claim**: The `iss` claim identifies the principal that issued the JWT. Validating this claim ensures that the token was issued by a trusted authority. Accepting tokens from untrusted issuers can compromise the system.
- **Subject (`sub`) Claim**: The `sub` claim identifies the principal that is the subject of the JWT. While not always a direct validation point for the token's validity itself, improper handling or trust in the `sub` claim without proper authorization checks can lead to users accessing resources or data they are not permitted to.
- **Custom Claims**: Applications often use custom private claims for their specific logic (e.g., user roles, permissions). These claims must be rigorously validated according to the application's business rules. Failure to do so can lead to logic flaws and security bypasses.

### **Token Leakage and Storage**

How tokens are stored and transmitted significantly impacts their security.

- **Client-Side Storage**: Storing JWTs in browser `localStorage` or `sessionStorage` makes them accessible to JavaScript. If the application is vulnerable to Cross-Site Scripting (XSS), an attacker can steal these tokens. Storing JWTs in `HttpOnly` cookies is generally a more secure alternative as it prevents JavaScript access.
    
- **Transmission Security**: JWTs, especially if they contain sensitive information in their claims (even if not directly PII, then session identifiers or roles), must always be transmitted over encrypted channels (HTTPS) to prevent eavesdropping and interception.
    
### **Table: JWT Signing Algorithms - Security Considerations**

| **Algorithm** | **Type** | **Key Type(s) Required** | **Common Use Cases** | **Security Considerations/Known Weaknesses** |
| --- | --- | --- | --- | --- |
| HS256 | Symmetric | Shared Secret (`byte`) | Server-to-server auth, single-app auth | Vulnerable to brute-force if key is weak or leaked. Secret must be shared securely. |
| HS384 | Symmetric | Shared Secret (`byte`) | Similar to HS256, higher security margin | Same as HS256; requires longer keys. |
| HS512 | Symmetric | Shared Secret (`byte`) | Similar to HS256, highest security margin (HMAC) | Same as HS256; requires longest keys for HMAC. |
| RS256 | Asymmetric | RSA Private Key (signing), RSA Public Key (verifying) | Third-party auth, distributed systems | Susceptible to algorithm confusion if public key used as HMAC secret. Private key compromise allows forgery. |
| RS384 | Asymmetric | RSA Private Key (signing), RSA Public Key (verifying) | Similar to RS256, higher security margin | Same as RS256. |
| RS512 | Asymmetric | RSA Private Key (signing), RSA Public Key (verifying) | Similar to RS256, highest security margin (RSA) | Same as RS256. |
| ES256 | Asymmetric | ECDSA Private Key (signing), ECDSA Public Key (verifying) | Mobile auth, resource-constrained environments | Susceptible to algorithm confusion. Private key compromise allows forgery. Some older Go versions had `crypto/elliptic` issues. |
| ES384 | Asymmetric | ECDSA Private Key (signing), ECDSA Public Key (verifying) | Similar to ES256, higher security margin | Same as ES256. |
| ES512 | Asymmetric | ECDSA Private Key (signing), ECDSA Public Key (verifying) | Similar to ES256, highest security margin (ECDSA) | Same as ES256. |
| PS256 | Asymmetric | RSA Private Key (signing), RSA Public Key (verifying) | Enhanced security over RS256 (probabilistic) | Similar RSA concerns, but generally stronger against certain attacks than PKCS#1 v1.5 padding used in RS variants. |
| PS384 | Asymmetric | RSA Private Key (signing), RSA Public Key (verifying) | Similar to PS256, higher security margin | Same as PS256. |
| PS512 | Asymmetric | RSA Private Key (signing), RSA Public Key (verifying) | Similar to PS256, highest security margin (PSS) | Same as PS256. |
| EdDSA | Asymmetric | Ed25519 Private Key (signing), Ed25519 Public Key (verifying) | Modern, high-performance, secure signing | Private key compromise allows forgery. Considered strong and less prone to implementation errors than ECDSA. |
| none | Unsecured | N/A | Debugging ONLY (SHOULD NOT be used in production) | Bypasses signature verification entirely. Allows arbitrary token forgery. |

*References for table content: 

The flexibility inherent in the JWT standard (RFC 7519), such as the client-specified `alg` header and optional nature of many claims, is a significant factor contributing to vulnerabilities. If this flexibility is not carefully constrained by secure library defaults or diligent developer implementation, it creates avenues for attack. For example, the `alg:none` attack is a direct consequence of the specification allowing unsecured tokens. While modern libraries like `golang-jwt/jwt` have evolved to make such insecure options harder to use by mistake (e.g., by requiring `UnsafeAllowNoneSignatureType` for `alg:none`), the underlying potential for misuse remains if developers are unaware or libraries are used incorrectly. This illustrates a direct pathway: the design of the standard allows for potentially insecure configurations, which, if not handled robustly by libraries or developers, leads to exploitable vulnerabilities. The onus is therefore on both the library maintainers to provide secure defaults and on developers to use these libraries correctly.

Furthermore, the `kid` (Key ID) header parameter, intended for key management, can transform into a versatile attack vector if its value, controllable by an attacker through a tampered token, is not handled with extreme care by the backend system. If the `kid` value is directly used to construct a file path for retrieving a key, an attacker could employ path traversal techniques (e.g., `../../../../../etc/passwd`) to attempt to load arbitrary files as keys. Should the `kid` value be incorporated into a SQL query to fetch a key from a database, it becomes a potential SQL injection point if not properly parameterized or sanitized. Similarly, if the `kid` value is used as part of a shell command executed by the server to retrieve or manage keys, it could open a door for command injection vulnerabilities. This demonstrates how a seemingly innocuous metadata field within the JWT can become a critical injection point, not directly into the JWT processing itself, but into the backend systems that the JWT processing logic interacts with based on the token's content.

## **Common Mistakes That Cause This**

Vulnerabilities in custom JWT implementations often stem from a set of recurring mistakes:

- **Not Validating the `alg` Header or Trusting it Blindly**: A frequent error is for the server to use the `alg` value from the token's header to determine how to verify the signature, without validating if this algorithm is expected or secure. This is the root cause of algorithm confusion attacks.
    
- **Using Hardcoded or Weak Secret Keys**: Embedding secret keys directly in source code, configuration files without proper protection, or using default, weak, or easily guessable keys for HMAC-based algorithms makes them susceptible to discovery and brute-forcing.
    
- **Allowing `alg:none` in Production Environments**: Failing to explicitly reject tokens that specify `none` as the algorithm in the `alg` header. This effectively bypasses signature verification entirely.
    
- **Missing or Incomplete Signature Verification**: Developers might use library functions that only decode the JWT payload without cryptographically verifying the signature (e.g., using a `decode()` function instead of a `verify()` function, as noted in  for Node.js, or using `ParseUnverified` in Golang's `golang-jwt/jwt` library ).

    
- **Improper Claim Validation**:
    - Failing to check standard time-based claims like `exp` (expiration time) and `nbf` (not before time), allowing for replay of old tokens or use of tokens not yet valid.

    - Neglecting to validate the `aud` (audience) claim, potentially allowing a token issued for one service to be accepted by another.
        
    - Not verifying the `iss` (issuer) claim, which could lead to accepting tokens from untrusted sources.
        
    - Insufficient validation of custom claims that are critical for application-specific authorization logic.
        
- **Insecure Storage of Tokens on the Client-Side**: Storing JWTs in `localStorage` or `sessionStorage` makes them vulnerable to XSS attacks. `HttpOnly` cookies are generally a safer alternative for web applications.

    
- **Transmitting Tokens Over Unencrypted HTTP**: Sending JWTs over plain HTTP allows them to be intercepted in transit. HTTPS must be enforced for all communications involving JWTs.
    
- **Lack of a Token Revocation Mechanism**: Once a JWT is issued, it is valid until its expiration time. Without a revocation mechanism (e.g., a server-side blacklist or denylist), there's no way to invalidate a compromised or logged-out user's token before it naturally expires.
    
- **Including Sensitive Data Directly in the JWT Payload**: Since JWT payloads are typically only Base64Url encoded and not encrypted, storing highly sensitive information (like passwords, PII beyond a user ID) directly in the claims makes it easily accessible if the token is intercepted.
    
- **Incorrectly Implementing Refresh Token Logic**: Refresh tokens, if used, must be handled securely. Flaws in their issuance, storage, validation, or revocation can undermine the security benefits they are intended to provide, potentially leading to long-term unauthorized access.
    
- **Ignoring Library Security Notices and Best Practices**: Failing to keep JWT libraries updated to patched versions or not adhering to the security recommendations provided by library maintainers can expose applications to known vulnerabilities.
    
- **Using `kid` Parameter Insecurely**: If the `kid` (Key ID) header parameter is used to select a verification key, and its value is incorporated into file paths or database queries without proper sanitization, it can lead to path traversal or SQL injection vulnerabilities.

A critical aspect of JWT security is that a single mistake can often lead to a complete compromise of the authentication mechanism. For example, if a secret key used for an HMAC-based algorithm is hardcoded and discovered, an attacker can forge any token with arbitrary claims. In such a scenario, other security measures like strong claim validation (e.g., for `exp` or `aud`) become ineffective against an attacker who can craft a perfectly valid-looking token. Similarly, if an application fails to validate the `alg` header and can be tricked into accepting `alg:none` , the signature check is bypassed, and the attacker has full control over the token's payload. This demonstrates that JWT security relies on a chain of correct implementations; the failure of a foundational element like key secrecy or algorithm enforcement can render other controls moot.

## **Exploitation Goals**

Attackers exploit JWT vulnerabilities to achieve various malicious objectives:

- **Authentication Bypass**: The most common goal is to gain unauthorized access to protected resources, APIs, or application functionalities by forging or tampering with JWTs to impersonate a legitimate user or bypass login mechanisms entirely.

    
- **Privilege Escalation**: Attackers aim to elevate their privileges within an application. This is often achieved by modifying claims in the JWT payload, such as an `isAdmin` flag from `false` to `true`, or changing a `role` claim to a more privileged one.

    
- **Impersonation / Session Hijacking**: By stealing or forging a JWT, an attacker can impersonate another user, effectively hijacking their session and gaining access to their data and functionalities.

    
- **Unauthorized Data Access/Modification**: Gaining access to or altering data that the attacker is not authorized for. This can be a direct result of impersonation or privilege escalation, allowing the attacker to read sensitive information or manipulate application data.

    
- **Information Disclosure**: If JWTs inadvertently contain sensitive information in their claims (which are only Base64 encoded), interception of the token can lead to the disclosure of this data.
    
- **Denial of Service (DoS)**: While less common as a direct result of JWT claim manipulation, exploiting vulnerabilities in the token parsing or validation logic, or flooding the system with malformed or computationally expensive tokens, could potentially lead to a denial of service.
- **Command or SQL Injection (via `kid` or other claims)**: If the application insecurely uses JWT claim values (particularly the `kid` header) as input to backend system commands or database queries, an attacker's goal might be to execute arbitrary commands or SQL on the server.


While bypassing authentication to gain access is a primary objective, the exploitation often extends to manipulating the application's state and logic by forging specific claim values. JWTs are not merely gatekeepers; they carry data that influences application behavior. Thus, attackers may target claims representing user identifiers, transaction details, or other business-logic parameters to perform more subtle attacks than simply gaining administrative privileges. For instance, modifying a `user_id` claim in a financial transaction context or altering a quantity in an e-commerce application could be an attacker's goal, achievable once signature verification is compromised.

## **Affected Components or Files**

Vulnerabilities in custom JWT implementations can manifest in various parts of an application and its infrastructure:

- **Authentication Middleware/Modules**: Code responsible for receiving, parsing, validating JWTs, and establishing the authenticated user's context or session. In Go applications, this often involves custom middleware or handlers interacting with JWT libraries.

- **API Gateway / Reverse Proxy**: If JWT validation is offloaded to these infrastructure components, their configuration and the logic they apply become critical.
- **Token Issuance Service/Endpoint**: The component that generates and signs JWTs. Vulnerabilities here, such as using weak keys, signing with `alg:none` by default, or including excessive/sensitive claims, are fundamental.
- **Client-Side Code (e.g., JavaScript)**: Code responsible for storing JWTs (e.g., in `localStorage`, `sessionStorage`, or cookies) and including them in requests to the server. Insecure storage can lead to token theft via XSS.
    
- **JWT Libraries**: The specific third-party library used for JWT operations (e.g., `golang-jwt/jwt` for Go applications ) and its version. Vulnerabilities can exist within the library itself or arise from its misuse.
    
- **Configuration Files or Environment Variables**: Locations where secret keys, issuer details, audience restrictions, and other JWT-related settings are stored. Improper protection of these can lead to key leakage.
    
- **Databases or Key Stores**: If the `kid` parameter is used to dynamically fetch verification keys, the security of these backend storage systems and the access mechanism is crucial.
- **Any Service Consuming JWTs**: In a microservices architecture, multiple services might consume and validate JWTs. A flaw in a shared validation library or inconsistent validation practices can create widespread vulnerabilities.

The "custom" nature of these implementations means that developers might be creating their own cryptographic routines, validation logic, or key handling mechanisms, or significantly deviating from the secure default usage of established libraries. This departure from battle-tested patterns increases the likelihood of introducing vulnerabilities at any stage where the token is created, transmitted, stored, parsed, or validated. Consequently, the scope of potentially affected components becomes broader than if a standard, securely configured library were used consistently.**1** Every component that interacts with the JWT in a custom manner becomes a potential point of failure.

## **Vulnerable Code Snippet(s)**

The following Go snippets illustrate common vulnerabilities. These examples often use `github.com/golang-jwt/jwt/v5` for context, but the underlying principles apply to other libraries or purely custom implementations.

- Golang: Accepting alg:none (Conceptual)
    
    While golang-jwt/jwt/v5 makes it difficult to accidentally accept alg:none by requiring the jwt.UnsafeAllowNoneSignatureType constant as the key 18, a custom implementation or a less secure library might be vulnerable:
    
    ```Go
    
    // Conceptual example if a library or custom code didn't protect against 'none'
    import (
        "fmt"
        "github.com/golang-jwt/jwt/v5" // Assuming a scenario where its protection is bypassed or not used
    )
    
    // Maliciously crafted token string with alg:none
    // header: {"alg":"none","typ":"JWT"} payload: {"user":"admin","iat":1516239022}
    tokenString := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJpYXQiOjE1MTYyMzkwMjJ9."
    
    // Vulnerable parsing logic (hypothetical)
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // BAD: If the logic here incorrectly handles 'none' or if a library defaults to allowing it without a specific key.
        // For golang-jwt/jwt/v5, to actually (and unsafely) allow 'none', the keyFunc would need to return jwt.UnsafeAllowNoneSignatureType
        // if token.Method.Alg() == jwt.SigningMethodNone.Alg() {
        //     return jwt.UnsafeAllowNoneSignatureType, nil // This is how golang-jwt/jwt handles it, but allowing 'none' is the vulnerability itself.
        // }
        // This example assumes a flawed check or a different library.
        if token.Method.Alg() == "none" {
             // If the library doesn't require a special key for 'none' and proceeds, it's vulnerable.
            return nil, nil // Incorrectly returning nil key for 'none' might be accepted by a flawed verifier.
        }
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    })
    
    if err == nil && token.Valid { // Or if token.Valid is not checked or logic is flawed
        fmt.Println("Token accepted with alg:none! Claims:", token.Claims)
        // Attacker gains access with forged claims.
    } else if err!= nil {
        fmt.Println("Error parsing token:", err)
    } else if!token.Valid {
        fmt.Println("Token is invalid")
    }
    ``
    
    *Explanation*: This snippet demonstrates the core of the `alg:none` vulnerability. If the server accepts a token where the `alg` header is `none`, no signature verification is performed. An attacker can then submit a token with arbitrary claims. The `golang-jwt/jwt/v5` library specifically requires `jwt.UnsafeAllowNoneSignatureType` as the key when `alg:none` is encountered to prevent accidental acceptance, but explicitly using this is still a deliberate act of accepting an unsigned token.**18**
    
- **Golang: Missing Signature Verification (`ParseUnverified`)**
    
    ```Go
    
    import (
        "fmt"
        "log"
        "github.com/golang-jwt/jwt/v5"
    )
    
    type MyCustomClaims struct {
        Foo string `json:"foo"`
        jwt.RegisteredClaims
    }
    
    func decodeJwtUnverified(tokenString string) {
        // BAD: JWT is only decoded without signature verification [30]
        // This function should ONLY be used if the token's signature has been verified elsewhere.
        token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &MyCustomClaims{})
        if err!= nil {
            log.Printf("Error parsing unverified: %v", err)
            return
        }
    
        if claims, ok := token.Claims.(*MyCustomClaims); ok {
            fmt.Printf("Foo claim: %s (Token NOT VERIFIED)\n", claims.Foo)
            // Using claims from 'token' is dangerous as they could be tampered with.
        } else {
            log.Printf("Cannot cast claims")
        }
    }
    ```
    
    *Explanation*: The `ParseUnverified` method from `golang-jwt/jwt/v5` explicitly bypasses signature verification. Using claims extracted from a token parsed this way is highly insecure if the token comes from an untrusted source, as the payload could have been tampered with by an attacker.
    
- **Golang: Hardcoded Secret Key**
    
    ```Go
    
    import (
        "fmt"
        "time"
        "github.com/golang-jwt/jwt/v5"
    )
    
    // BAD: Hardcoded secret key [28, 29]
    var jwtKey =byte("my_super_secret_and_very_weak_key_123")
    
    func generateTokenWithHardcodedKey(userID string) (string, error) {
        claims := jwt.MapClaims{
            "user_id": userID,
            "exp":     time.Now().Add(time.Hour * 1).Unix(),
        }
        token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
        tokenString, err := token.SignedString(jwtKey)
        if err!= nil {
            return "", fmt.Errorf("failed to sign token: %w", err)
        }
        return tokenString, nil
    }
    ```
    
    *Explanation*: Hardcoding the JWT secret key directly within the source code is a critical vulnerability. If the source code is compromised, leaked, or accessed by an unauthorized party, the attacker gains the ability to forge any valid token, impersonating any user and accessing any protected resources.**28** This is a common mistake highlighted in various security guidelines.**17**
    
- **Golang: Improper Claim Validation (Missing Issuer/Audience Check)**
    
    ```Go
    
    import (
        "fmt"
        "github.com/golang-jwt/jwt/v5"
    )
    
    // Assume jwtKey is loaded securely
    var jwtKey =byte("securely-loaded-secret")
    
    func parseTokenNoIssAudCheck(tokenString string) (jwt.MapClaims, error) {
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            // Basic algorithm check
            if _, ok := token.Method.(*jwt.SigningMethodHMAC);!ok {
                return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
            }
            return jwtKey, nil
        })
    
        if err!= nil {
            return nil, err
        }
    
        if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
            // BAD: Only checks signature and standard time-based claims (exp, nbf, iat via token.Valid).
            // Missing explicit validation of 'iss' (issuer) and 'aud' (audience) claims.[9, 20, 24]
            // An attacker could use a validly signed token from a different issuer or intended for a different audience.
            // For example:
            // if claims["iss"]!= "my-trusted-issuer" { return nil, fmt.Errorf("invalid issuer") }
            // if claims["aud"]!= "my-specific-audience" { return nil, fmt.Errorf("invalid audience") }
            return claims, nil
        }
        return nil, fmt.Errorf("invalid token or claims")
    }
    ```
    
    *Explanation*: Even if a token's signature is valid and standard time-based claims (`exp`, `nbf`, `iat`) are checked by the library (often bundled into a `token.Valid` check), failing to explicitly validate the `iss` (issuer) and `aud` (audience) claims is a vulnerability. An attacker could potentially use a legitimately signed token from a different (perhaps less secure) issuer or a token intended for a different service/audience to gain unauthorized access. The `golang-jwt/jwt/v5` library provides parser options such as `WithIssuer` and `WithAudience` to enforce these checks during parsing.
    
- **Golang: Algorithm Confusion (Conceptual - if `alg` not enforced by library options)**
    
    ```Go
    
    import (
        "crypto/rsa"
        "fmt"
        "github.com/golang-jwt/jwt/v5"
        // Assume rsaPublicKey is loaded securely, e.g., from a PEM file
    )
    
    var rsaPublicKey *rsa.PublicKey // Assume this is loaded with the server's public RSA key
    
    func vulnerableParseWithAlgorithmConfusion(tokenString string) (jwt.MapClaims, error) {
        // Attacker crafts a token with header {"alg":"HS256"} but it was expected to be RS256.
        // The attacker signs this HS256 token using the server's RSA Public Key as the HMAC secret.
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            // VULNERABLE LOGIC: Server attempts to handle based on alg header without strict enforcement.
            // This specific Keyfunc is flawed because it might return the RSA public key for HS256 verification.
            alg := token.Header["alg"]
            fmt.Printf("Token alg header: %v\n", alg)
    
            if alg == jwt.SigningMethodHS256.Alg() {
                // BAD: If an attacker sends alg:HS256, server uses RSA Public Key as HMAC secret.
                // This is the core of the algorithm confusion attack.
                // The key material must match the algorithm.
                fmt.Println("Attempting to verify HS256 with RSA Public Key (VULNERABLE)")
                return rsaPublicKey, nil // Using RSA public key for HS256 verification
            } else if alg == jwt.SigningMethodRS256.Alg() {
                // Correct for RS256
                return rsaPublicKey, nil
            }
            return nil, fmt.Errorf("unexpected signing method: %v", alg)
        })
    
        if err!= nil {
            return nil, fmt.Errorf("token parsing/validation error: %w", err)
        }
    
        if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
            fmt.Println("Token validated (potentially insecurely). Claims:", claims)
            return claims, nil
        }
        return nil, fmt.Errorf("invalid token or claims after parsing")
    }
    ```
    
    *Explanation*: This conceptual snippet illustrates how algorithm confusion could occur if the application's `Keyfunc` dynamically (and insecurely) provides keys based on the `alg` header from the token, without the server strictly enforcing an expected algorithm. If an attacker sends a token with `alg: HS256` and the server code mistakenly provides the RSA public key as the secret for HS256 verification, the signature will validate if the attacker also signed the token using the RSA public key as the HMAC secret. This bypasses the asymmetric cryptography protection. The `golang-jwt/jwt/v5` library's `WithValidMethods` parser option is the correct way to prevent this by restricting allowed algorithms server-side.
    

Many of these vulnerable code examples arise not necessarily from flaws within the JWT standard itself, but from the incorrect, insecure, or incomplete use of JWT libraries. Common patterns include invoking library functions that bypass security checks (like `ParseUnverified` ), failing to provide a comprehensive `Keyfunc` that correctly validates algorithms against expected server configurations , or neglecting to utilize built-in library options for validating critical claims such as `iss` (issuer) and `aud` (audience). For instance, the `jsonwebtoken` library in Node.js has distinct `decode()` and `verify()` functions; using `decode()` alone skips signature verification and is a known pitfall. This underscores that developer awareness and adherence to secure usage patterns for JWT libraries are as critical as the inherent security features of the libraries themselves.

## **Detection Steps**

Identifying vulnerabilities in custom JWT implementations requires a combination of manual review, automated tooling, and dynamic testing.

- **Manual Code Review**:
    - **Signature Verification Logic**: Scrutinize the code responsible for JWT parsing and signature validation. Confirm that the signature is always cryptographically verified using a strong, expected algorithm. Ensure the application does not blindly trust the `alg` header from the token; the server must enforce the algorithm(s) it expects. In Go applications using `golang-jwt/jwt`, this means verifying that `Parse` or `ParseWithClaims` is used, coupled with a `Keyfunc` that correctly validates the algorithm against a server-defined allowlist. The use of `ParseUnverified` should be a major red flag if the token source is untrusted.
        
    - **Algorithm Handling**: Specifically look for how the `alg` header is processed. The application must explicitly reject tokens with `alg: none` (or its variants) unless in a very specific, understood, and secured non-production context. Verify defenses against algorithm confusion attacks, ensuring the key material matches the algorithm being verified.
        
    - **Key Management**: Search for hardcoded secret keys or private keys within the codebase or insecurely stored configuration files. Review how keys are loaded and managed. If the `kid` parameter is used, inspect its handling for path traversal or injection vulnerabilities if it influences file or database lookups. Similarly, check `jku` and `jwk` handling for vulnerabilities if these headers are processed.

        
    - **Claim Validation**: Ensure all critical standard claims (`exp`, `nbf`, `iat`, `iss`, `aud`) are validated server-side after signature verification. Confirm that any custom claims essential for business logic and authorization are also rigorously validated.

        
    - **Error Handling**: Examine how JWT parsing and validation errors are handled. Ensure that error messages are generic and do not leak sensitive information about the validation process or internal system state.
    - **Token Transmission & Storage**: Verify that tokens are always transmitted over HTTPS. For web applications, check if tokens are stored securely on the client-side (e.g., `HttpOnly`, `Secure` cookies are generally preferred over `localStorage` to mitigate XSS-based token theft ).
        
- **Automated Security Testing**:
    - **SAST (Static Application Security Testing)**: Employ SAST tools to scan the codebase for common JWT implementation pitfalls. Tools like Semgrep can be configured with rules to detect hardcoded secrets, allowance of `alg:none`, or missing signature verification (as shown for Node.js in , principles apply to Go). CodeQL also offers queries for Go, such as detecting missing JWT signature checks. Datadog Static Analysis provides rules for issues like `alg:none` (even if shown for Kotlin, the pattern is relevant ) and hardcoded secrets.
        
    - **DAST (Dynamic Application Security Testing)**: Utilize DAST tools or specialized JWT testing tools (e.g., Burp Suite extensions like "JSON Web Tokens" or custom scripts) to send malformed or maliciously crafted JWTs to application endpoints. This can effectively test for vulnerabilities like `alg:none` acceptance, algorithm confusion, signature stripping, and susceptibility to claim manipulation. Burp Suite is mentioned as a tool for such dynamic testing.
        
    - **Dependency Scanning**: Use tools like Snyk to scan project dependencies, including the JWT library itself, for any known vulnerabilities. Outdated libraries can contain patched security flaws.
        
- **Penetration Testing**: Engage experienced security professionals to conduct targeted penetration tests against the JWT implementation. Testers can simulate sophisticated attacks and identify vulnerabilities that automated tools might miss.
- **Log Review**: Implement comprehensive logging for JWT issuance, validation successes, and failures. Regularly review these logs for suspicious patterns, such as a high volume of validation errors, attempts to use invalid algorithms, or expired tokens, which could indicate reconnaissance or active attacks.

Effective detection of JWT vulnerabilities necessitates a multi-layered strategy. Manual code review is essential for understanding the intended logic and identifying custom flaws, SAST tools help find known insecure patterns in the codebase , DAST tools test the runtime behavior of the application against various attack vectors, and dependency scanning ensures the underlying libraries are not compromised. Given the complexity and variety of potential JWT attacks, relying on a single detection method is often insufficient.

## **Proof of Concept (PoC)**

The following PoCs illustrate how theoretical JWT vulnerabilities can be exploited.

- **`alg:none` Attack**:
    1. **Obtain a valid JWT**: An attacker first gets hold of any JWT issued by the target application (e.g., by normally logging in if it's an authentication token).
    2. **Decode Header and Payload**: The attacker Base64Url-decodes the header and payload sections of the token.
    3. **Modify Algorithm and Claims**: The `alg` field in the decoded header JSON is changed to `none` (or case variations like `None`, `NONE` to potentially bypass weak filters ). Desired claims in the payload are modified (e.g., changing `{"isAdmin": false}` to `{"isAdmin": true}`).

    4. **Re-encode**: The modified header and payload are Base64Url-encoded.
    5. **Construct Forged Token**: The new token is formed as: `base64UrlEncodedHeader + "." + base64UrlEncodedPayload + "."` (note the critical trailing dot, indicating an empty signature part ).
        
    6. **Submit Token**: The attacker sends this forged token to the server. If the server is vulnerable (i.e., it accepts tokens with `alg:none` without proper checks), it will process the token and its malicious claims as valid.
- **Algorithm Confusion (e.g., RS256 to HS256)**:
    1. **Obtain Server's RSA Public Key**: The attacker needs the server's public RSA key. This might be exposed via a `/jwks.json` endpoint, a `/.well-known/` path, embedded in client-side code, or leaked through other means.

    2. **Obtain a Valid RS256 JWT**: The attacker acquires a legitimate token signed with RS256 by the server.
    3. **Decode and Modify**: The header and payload are Base64Url-decoded. The `alg` field in the header is changed from `RS256` to `HS256`. The payload claims are modified as desired by the attacker.
        
    4. **Sign with Public Key as HMAC Secret**: The modified header and payload (Base64Url-encoded) are concatenated with a dot. This string is then signed using the HMAC-SHA256 algorithm, where the *server's RSA public key* is used as the HMAC secret key.
    5. **Submit Forged Token**: The attacker sends this newly crafted token (with `alg:HS256` in the header and a signature generated using the RSA public key as the HMAC secret) to the server. If the server's verification logic is flawed and it uses the RSA public key to verify an HS256 signature, the token will be accepted.
- **Weak Secret Brute-Force (for HS256/HS384/HS512)**:
    1. **Obtain a Valid HMAC-signed JWT**: The attacker captures a token signed with an HMAC algorithm (e.g., HS256).
    2. **Prepare for Brute-Force**: The attacker separates the token into its three parts: `encodedHeader.encodedPayload.signature`.
    3. **Attempt Brute-Force**: Using a tool like Hashcat  and a dictionary of common passwords or potential secret keys (a wordlist), the attacker iterates through the list. For each potential secret key:
    a. The HMAC-SHA256 (or the corresponding algorithm) signature is computed for the string `encodedHeader + "." + encodedPayload` using the current wordlist entry as the key.
    b. The computed signature is compared against the `signature` part of the captured JWT.
        
    4. **Key Found**: If a match is found, the attacker has successfully discovered the secret key.
    5. **Forge Tokens**: With the compromised secret key, the attacker can now forge any JWT with arbitrary claims and a valid signature, which the server will accept.
- **Improper Expiration Check Bypass (Conceptual)**:
    1. **Obtain an Expired JWT**: An attacker gets an old, expired JWT.
    2. **Resubmit Token**: The attacker simply resends this expired token to a protected endpoint.
    3. **Exploit**: If the server-side validation logic fails to correctly check the `exp` (expiration) claim, or if the check is flawed (e.g., due to incorrect time zone handling, excessive leeway, or simply missing validation), the server might accept the expired token as valid, granting unauthorized access. This relies entirely on a server-side validation defect.

These Proof of Concept scenarios effectively bridge the gap between theoretical vulnerability descriptions and tangible attack methodologies. For instance, understanding that an attacker can leverage a publicly accessible component—the RSA public key—in an unintended manner to forge HS256 tokens during an algorithm confusion attack  makes the risk far more concrete for developers and system architects than a purely abstract explanation of cryptographic weaknesses. Such demonstrations are vital for underscoring the real-world exploitability of these JWT flaws.

## **Risk Classification**

Custom JWT implementations, due to their flexibility and the potential for subtle errors, often introduce vulnerabilities that carry a **High to Critical** risk. This assessment is based on the likelihood of exploitation and the potential impact.

- **Factors Influencing Risk**:
    - **Likelihood**: The ease with which a vulnerability can be exploited. For instance, an `alg:none` vulnerability or a hardcoded, leaked secret key generally presents a higher likelihood of exploitation than a more complex algorithm confusion attack that might require specific server configurations or additional information (like a public key).
    - **Impact**: The consequences of successful exploitation. For JWTs, this is typically severe, often leading to complete authentication bypass, unauthorized data access or modification, and privilege escalation.

The following table outlines common JWT vulnerabilities and their general risk profiles:

**Table 1: Common JWT Vulnerabilities and Risk Profile**

| **Vulnerability Type** | **Brief Description** | **Typical Impact (C, I, A)** | **Typical Likelihood** | **Example Exploitation Goal** | **OWASP Top 10 2021 Category** |
| --- | --- | --- | --- | --- | --- |
| `alg:none` Attack | Server accepts tokens with `alg` header set to `none`, bypassing signature verification. | High (C,I), Low (A) | Medium-High | Authentication bypass, privilege escalation | A07-Identification and Authentication Failures, A05-Security Misconfiguration |
| Algorithm Confusion | Attacker tricks server into using a weaker algorithm (e.g., HS256 with public key as secret) for verification. | High (C,I), Low (A) | Medium | Authentication bypass, privilege escalation | A07-Identification and Authentication Failures, A02-Cryptographic Failures |
| Weak/Hardcoded Secret Key | HMAC secret key is weak, guessable, or embedded in client-side code/public repository, allowing forgery. | Critical (C,I), Low (A) | High (if leaked) | Full token forgery, impersonation, privilege escalation | A02-Cryptographic Failures, A05-Security Misconfiguration |
| Signature Stripping/Missing Verify | Server decodes token without verifying the signature, or accepts tokens with missing signatures. | High (C,I), Low (A) | Medium | Authentication bypass, claim tampering | A07-Identification and Authentication Failures |
| Improper `exp`/`nbf` Validation | Server fails to check or incorrectly checks token expiration or not-before times. | Medium (C,I), Low (A) | Medium | Replay of expired tokens, use of prematurely active tokens | A07-Identification and Authentication Failures, A01-Broken Access Control |
| Improper `aud`/`iss` Validation | Server fails to validate the intended audience or trusted issuer of the token. | Medium-High (C,I), Low (A) | Medium | Token replay across services/issuers, unauthorized access | A07-Identification and Authentication Failures, A01-Broken Access Control |
| `kid`/`jwk`/`jku` Injection | Attacker manipulates key identifier/source headers to cause server to use a malicious key or insecure resource. | High-Critical (C,I), Low (A) | Low-Medium | Token forgery, command/SQL injection via `kid`  | A02-Cryptographic Failures, A03-Injection (if `kid` leads to it), A05-Security Misconfiguration |
| Sensitive Data Exposure in Payload | Unencrypted sensitive information (beyond basic identifiers) is stored in easily decodable JWT payload. | Medium (C), Low (I,A) | High (if present) | Information disclosure | A02-Cryptographic Failures (Sensitive Data Exposure is now part of this), A04-Insecure Design |
| Token Leakage (XSS/Client Storage) | Tokens stored insecurely on client (e.g., localStorage) are stolen via XSS or other client-side attacks. | High (C,I), Low (A) | Medium | Session hijacking, impersonation | A07-Identification and Authentication Failures, A03-Injection (XSS leading to token theft) |
| Lack of Revocation | Inability to invalidate active tokens before their expiry, e.g., on logout or account compromise. | Medium-High (C,I), Low (A) | High (if needed) | Continued unauthorized access with compromised/stale tokens | A07-Identification and Authentication Failures, A04-Insecure Design |

(C=Confidentiality, I=Integrity, A=Availability)

Snippet References for table content: 2

The risk associated with JWT vulnerabilities is significantly amplified by the level of trust applications often place in successfully validated tokens. These tokens frequently act as the "keys to the kingdom," granting access to critical functionalities and data. If the JWT validation process itself is flawed—due to issues like algorithm confusion, a compromised signing key, or acceptance of unsigned tokens—the entire security model of the application can collapse.This leads to a disproportionately high impact because an attacker who can forge a JWT can often bypass numerous other security controls, as the application inherently trusts any token that appears to be valid. This implicit trust is why JWT vulnerabilities are frequently assigned High or Critical severity ratings.

## **Fix & Patch Guidance**

Remediating vulnerabilities in custom JWT implementations requires a multi-faceted approach, focusing on secure library usage, robust validation logic, and sound key management practices.

- **Use Strong, Standard Libraries Correctly**:
    - Employ well-vetted and actively maintained JWT libraries for your programming language, such as `golang-jwt/jwt/v5` for Go applications.

        
    - Crucially, **always verify token signatures**. When using libraries like `golang-jwt/jwt`, this means utilizing functions such as `Parse` or `ParseWithClaims`. Avoid functions that parse without verification (e.g., `ParseUnverified` in `golang-jwt/jwt`) for tokens from untrusted sources. The `Keyfunc` provided to parsing functions must be correctly implemented to validate the algorithm and provide the correct key.

- **Algorithm Security**:
    - **Enforce Specific, Strong Algorithms**: The server must explicitly define and enforce the exact signing algorithm(s) it accepts. Do not allow the client to dictate the algorithm via the `alg` header. Reject any token with an unexpected `alg` value. For `golang-jwt/jwt/v5`, the `WithValidMethods` parser option is the recommended way to achieve this, providing a list of acceptable signing method strings.
    
        
    - **Disable `alg:none`**: Explicitly reject tokens where the `alg` header is set to `none` or its case variations. This algorithm offers no security. The `golang-jwt/jwt/v5` library makes accidental use of `none` more difficult by requiring `jwt.UnsafeAllowNoneSignatureType` to be returned by the `Keyfunc` if `none` is to be (unsafely) processed. This constant should not be used in production for verifying incoming tokens.
        
    - **Algorithm Preference**: Prefer asymmetric algorithms (e.g., RS256, ES256, EdDSA) over symmetric ones (e.g., HS256) if tokens need to be verified by multiple parties without sharing a common secret, or when the token issuer and verifier are distinct entities. Asymmetric algorithms allow the private key to be kept secure by the issuer, while the public key can be safely distributed for verification.

- **Key Management**:
    - **Use Strong, Randomly Generated Keys**: For HMAC algorithms, secret keys must possess sufficient entropy to resist brute-force attacks. For asymmetric algorithms, ensure appropriate key lengths and generation procedures.
    - **Never Hardcode Keys**: Cryptographic keys must never be embedded directly in source code. Store them securely using environment variables, secure configuration files external to the application deployment, or dedicated secret management systems such as HashiCorp Vault or AWS Secrets Manager.

    - **Protect Private Keys**: For asymmetric algorithms (RSA, ECDSA, EdDSA), the private signing key is paramount and must be stringently protected against unauthorized access.
    - **Regularly Rotate Keys**: Implement a policy and procedure for periodic key rotation. This limits the time window an attacker has if a key is compromised.
        
    - **Secure `kid`, `jku`, `jwk` Handling**: If these header parameters are used for dynamic key retrieval, their values (which can be attacker-controlled) must be strictly validated. For `jku`, whitelist trusted URLs from which keys can be fetched. For `kid`, if used to look up keys, ensure the lookup mechanism is not vulnerable to injection attacks (e.g., path traversal if `kid` influences a file path, or SQL injection if it's used in a database query).
        
- **Claim Validation**:
    - **Validate All Standard Claims**: After successful signature verification, rigorously validate all relevant standard claims. This includes `exp` (expiration time), `nbf` (not before time), `iat` (issued at time), `iss` (issuer), and `aud` (audience). Libraries often provide built-in mechanisms or options for these checks. For example, `golang-jwt/jwt/v5` has parser options like `WithIssuer()`, `WithAudience()`, `WithExpirationRequired()`, etc. , and a standalone `Validator` type.

        
    - **Implement Custom Claim Validation**: Any application-specific custom claims that are critical for business logic or authorization decisions must be validated according to those rules. In Go, if using custom claim structs with `golang-jwt/jwt`, this can often be achieved by implementing the `Valid() error` method on the claims struct.
        
    - **Use Leeway for Time-Based Claims Cautiously**: To account for minor clock skew between the issuing server and the verifying server, a small leeway (e.g., a few seconds or minutes) can be configured for time-based claims like `exp` and `nbf`. However, this leeway should be kept as short as practically possible to minimize the window for potential misuse.

        
- **Token Handling**:
    - **HTTPS Everywhere**: Mandate the use of HTTPS (TLS) for all communication channels that transmit JWTs to protect them from interception and tampering in transit.
        
    - **Secure Client-Side Storage**: If tokens must be stored on the client-side in web applications, prefer `HttpOnly`, `Secure`, and `SameSite` cookies over `localStorage` or `sessionStorage`. `HttpOnly` cookies are not accessible via JavaScript, mitigating the risk of token theft through XSS attacks.
        
    - **Token Revocation**: For applications requiring the ability to immediately invalidate tokens (e.g., upon user logout, password change, or suspected account compromise), implement a robust revocation strategy. This might involve maintaining a server-side denylist of invalidated token identifiers or using short-lived access tokens paired with a secure refresh token mechanism that allows for checks against a revocation list during refresh.

        
    - **Short Token Expiration**: Access tokens should have short expiration times (e.g., 5-60 minutes). For longer user sessions, use refresh tokens, which are typically longer-lived but are only used to obtain new access tokens and can be more easily revoked or managed.

        
- **Error Handling**: Implement generic error messages for token validation failures. Specific error details might leak information about the validation process that could aid an attacker. Log detailed errors server-side for debugging.
- **Table: `golang-jwt/jwt/v5` Key Security Features & Best Practices**

| **Feature/Function** | **Purpose** | **Secure Usage Recommendation** | **Common Pitfall if Misused** |
| --- | --- | --- | --- |
| `Parse` / `ParseWithClaims` | Parses and verifies JWT, populating claims. | Always use with a `Keyfunc` that validates the `alg` header against an expected list and returns the correct key. Ensure `token.Valid` is true and `err` is `nil`. | Providing a `Keyfunc` that doesn't check `alg`, returns wrong key type, or accepts `alg:none` insecurely. Not checking `token.Valid`. |
| `ParserOption`: `WithValidMethods(string)` | Restricts allowed signing algorithms during parsing. | Always use this option to specify a list of expected strong algorithms (e.g., `string{"RS256", "ES256"}`). | Not using this option, allowing the token's `alg` header to dictate verification, leading to algorithm confusion or `alg:none`. |
| `ParserOption`: `WithIssuer(string)` | Validates the `iss` (issuer) claim. | Use if tokens are expected from a specific issuer. | Not validating `iss`, allowing tokens from untrusted issuers. |
| `ParserOption`: `WithAudience(string)` | Validates the `aud` (audience) claim. | Use if tokens are intended for a specific audience/service. | Not validating `aud`, allowing token replay across different services. |
| `ParserOption`: `WithLeeway(time.Duration)` | Allows for clock skew for `exp`, `nbf`, `iat` claims. | Use a small, reasonable duration (e.g., 1-2 minutes) if clock skew is a known issue. | Setting too large a leeway, effectively extending token validity or premature usability. |
| `ParserOption`: `WithExpirationRequired()` | Requires the `exp` claim to be present. | Generally recommended to ensure tokens have a defined lifetime. | Not requiring `exp`, potentially allowing non-expiring tokens if not set. |
| `ParserOption`: `WithIssuedAt()` | Validates the `iat` (issued at) claim is not in the future (with leeway). | Useful for rejecting tokens that claim to be issued in the future. | Not validating `iat` might allow acceptance of oddly timestamped tokens. |
| `UnsafeAllowNoneSignatureType` | Constant used as a key with `Keyfunc` to explicitly allow `alg:none`. | **Never use for verifying untrusted tokens in production.** Intended for specific scenarios where unsecured tokens are understood and accepted (rare). | Using this to accept `alg:none` from external sources, completely bypassing signature security. |
| `Claims` interface (`Valid() error` method) | Allows custom validation logic for claim structs. | Implement this method on custom claim types to validate application-specific claims after standard validation. | Not implementing custom validation for critical business logic claims, or implementing it incorrectly. |
| `Keyfunc` (callback function for `Parse`) | Provides the key for signature verification and validates the token's algorithm. | Must check `token.Method` against a list of server-approved algorithms. Must return the correct key type for the validated algorithm. Must explicitly handle or reject `alg:none`. | Returning a key without checking `alg`, returning public key for HMAC, or insecurely handling `alg:none`. |

*Snippet References for table content:*

Securing JWT implementations fundamentally relies on a defense-in-depth strategy. No single protective measure is sufficient on its own. A robust approach combines the correct and secure use of well-vetted libraries, strict server-side enforcement of algorithms, comprehensive validation of all claims (standard and custom), diligent key management practices, secure transmission protocols (HTTPS), and careful consideration of the token's entire lifecycle, including issuance, storage, expiration, and revocation mechanisms. The wide array of potential vulnerabilities discussed underscores that a failure in any one of these areas, such as weak key management, can undermine the security provided by strengths in other areas, like the choice of a strong cryptographic algorithm.

## **Scope and Impact**

Vulnerabilities within custom JWT implementations can have far-reaching consequences, often leading to widespread system compromise. If an attacker gains the ability to forge or manipulate JWTs, they can potentially bypass authentication and authorization mechanisms entirely. This could grant them access to any resource or the ability to perform any action that any legitimate user, including administrators, is permitted to do.

The impact of such vulnerabilities can be assessed across the Confidentiality, Integrity, and Availability (CIA) triad:

- **Confidentiality**: Successful exploitation can lead to unauthorized access to sensitive data. This includes user PII, financial information, proprietary business data, or any other data managed by the application and protected by JWT-based access controls. If sensitive data is inadvertently included in JWT claims, token interception can also directly lead to confidentiality breaches.
    
- **Integrity**: Attackers may be able to modify or delete data without authorization. This can occur by impersonating users with data modification privileges or by exploiting flaws that allow them to alter application state through manipulated JWT claims. Forged tokens can be used to execute unauthorized transactions or operations, severely compromising data integrity.
    
- **Availability**: While less direct, JWT vulnerabilities can contribute to availability issues. For example, if an attacker can forge tokens to exhaust resources, or if the exploitation of a JWT flaw leads to system instability or crashes, the availability of the service can be impacted.

The **Business Impact** of compromised JWT implementations can be severe and multifaceted:

- **Reputational Damage**: Security breaches erode customer trust and can severely damage the organization's reputation.
- **Financial Loss**: Direct financial losses can occur from fraudulent transactions, theft of funds or digital assets, and the costs associated with incident response, remediation, and recovery.
- **Loss of Customer Trust**: Customers are less likely to use services they perceive as insecure, leading to customer churn.
- **Legal and Regulatory Penalties**: Depending on the nature of the data compromised and the applicable regulations (e.g., GDPR, CCPA, HIPAA), organizations can face significant fines and legal repercussions.


In systems employing microservices architectures where JWTs are often used for inter-service authentication and authorization, a vulnerability in the token generation or validation process can have **system-wide implications**. A compromised token might grant access not just to one service, but potentially to multiple services within the ecosystem, magnifying the scope of the breach.

Ultimately, a compromised JWT system does more than just affect a single user account or a specific piece of data; it can fundamentally undermine the entire trust model of the application or platform. JWTs are frequently central to how systems verify identity and enforce access controls. If attackers can forge these "digital passports" at will, as described by the capabilities gained from vulnerabilities like algorithm confusion or key compromise , it becomes exceedingly difficult for the system to distinguish legitimate operations from malicious ones. This erosion of trust can have catastrophic consequences for the application's credibility and viability.

## **Remediation Recommendation**

A comprehensive strategy is required to remediate and prevent vulnerabilities in custom JWT implementations. This involves adhering to security best practices throughout the token lifecycle.

- **Adopt and Correctly Use Secure JWT Libraries**:
    - Utilize well-maintained, reputable JWT libraries appropriate for the development language (e.g., `golang-jwt/jwt/v5` for Go ). Avoid implementing cryptographic functions or complex parsing logic manually, as this is highly error-prone.
        
    - Follow the library's security guidelines diligently. For instance, always use functions that verify signatures (e.g., `Parse` or `ParseWithClaims` in `golang-jwt/jwt/v5`) and never use unverified parsing functions (like `ParseUnverified`) for tokens from untrusted sources.
- **Strict Algorithm Enforcement**:
    - On the server-side, explicitly define and enforce the exact signing algorithm(s) that will be accepted. This should be a non-negotiable configuration.
    - Reject any token that specifies an unexpected `alg` value in its header. Most critically, **explicitly reject tokens with `alg` set to `none`** or its case variations.
        
    - When using libraries like `golang-jwt/jwt/v5`, leverage options such as `WithValidMethods` to provide an allowlist of acceptable algorithms during parsing.
        
- **Robust Key Management Strategy**:
    - **Generate Strong Keys**: Use cryptographically secure random number generators to create keys of appropriate length and entropy for the chosen algorithm.
    - **Secure Key Storage**: Never hardcode keys in source code or commit them to version control. Store keys securely using environment variables, dedicated secret management systems (e.g., HashiCorp Vault, Azure Key Vault, AWS Secrets Manager), or hardware security modules (HSMs).
        
    - **Key Rotation**: Implement and enforce a key rotation policy to limit the impact of a potential key compromise. Old keys should be invalidated after a new key is active.
        
    - **Protect Private Keys**: For asymmetric algorithms, ensure private keys are stored with strict access controls. Public keys can be distributed more widely for verification.
- **Comprehensive Claim Validation**:
    - After signature verification, **always validate standard claims**: `exp` (expiration time), `nbf` (not before time), `iat` (issued at), `iss` (issuer), and `aud` (audience) against expected server-side values.

    - Validate any **custom claims** that are critical to application logic or authorization decisions according to defined business rules.
        
    - Use minimal, necessary leeway for time-based claims (`exp`, `nbf`, `iat`) to account for clock skew, but keep this window very short.
- **Secure Token Handling Practices**:
    - **HTTPS Exclusively**: Transmit JWTs only over HTTPS (TLS) encrypted channels to prevent interception.
        
    - **Secure Client-Side Storage**: For web applications, prefer storing JWTs in `HttpOnly`, `Secure`, and `SameSite` cookies to protect against XSS and CSRF attacks. Avoid `localStorage` or `sessionStorage` for sensitive tokens.
        
    - **Short Access Token Lifespans**: Configure access tokens to have short expiration times (e.g., 5-60 minutes).
    - **Implement Refresh Tokens Securely**: For longer user sessions, use a refresh token mechanism. Refresh tokens should be long-lived, securely stored (ideally `HttpOnly` cookie or secure backend storage), and used only to obtain new, short-lived access tokens. Implement robust validation and revocation for refresh tokens.
        
    - **Token Revocation**: Implement a mechanism to revoke tokens before their natural expiration if needed (e.g., upon user logout, password change, privilege change, or suspected compromise). This typically involves a server-side denylist or a more sophisticated revocation checking system.
    
- **Input Validation for Claims Used in Backend Operations**:
    - If any JWT claims (especially those like `kid` that might be used to retrieve keys or other resources) are used as input to other backend functions (e.g., file system operations, database queries, shell commands), these claim values **must be treated as untrusted user input** and be rigorously validated and sanitized to prevent injection attacks (e.g., path traversal, SQL injection, command injection).
        
- **Regular Security Audits and Penetration Testing**:
    - Periodically conduct thorough security reviews, code audits, and penetration tests specifically targeting the JWT implementation and its integration within the application.
        
- **Developer Training**:
    - Educate developers on JWT security best practices, common vulnerabilities, and secure usage of JWT libraries.
        
- **Monitoring and Logging**:
    - Implement detailed and structured logging for token issuance, validation attempts (both successful and failed), and any errors encountered.
    - Monitor these logs for anomalies, such as high rates of invalid token errors, attempts to use unexpected algorithms, or frequent validation failures for specific users or IP addresses, which could indicate ongoing attacks or reconnaissance.

A proactive security posture is indispensable for JWT implementations. Remediation should not be viewed as a one-time fix for individual bugs but as the adoption of a security-first mindset throughout the entire lifecycle of JWT usage. This encompasses secure-by-design principles, meticulous selection and utilization of libraries, unwavering server-side validation, robust key management protocols, continuous monitoring for threats, and ongoing developer education. The diverse range of potential vulnerabilities and the comprehensive advice from various authoritative sources clearly indicate that a holistic and layered security approach is necessary. This is particularly true for "custom" JWT implementations, which, by their nature, may deviate from established secure defaults and thus require more rigorous scrutiny and adherence to these comprehensive security engineering principles.

## **Summary**

Custom implementations of JSON Web Tokens, while offering flexibility, are fraught with potential security vulnerabilities if not designed and managed with extreme care. The core of JWT security lies in the unforgeable nature of its signature and the reliable validation of its claims. However, common pitfalls can undermine these protections entirely.

The most impactful vulnerabilities frequently stem from:

- **Algorithm Manipulation**: Such as the `alg:none` attack, where signature verification is bypassed, or algorithm confusion attacks, where an attacker tricks the server into using an insecure verification method (e.g., using an RSA public key as an HMAC secret).
- **Weak or Compromised Keys**: Hardcoded, weak, or leaked secret/private keys allow attackers to forge any token they wish.
- **Improper Claim Validation**: Failure to validate critical claims like `exp` (expiration), `aud` (audience), and `iss` (issuer) can lead to token replay, cross-service attacks, or acceptance of tokens from untrusted sources.
- **Insecure Token Storage and Transmission**: Storing tokens in XSS-vulnerable `localStorage` or transmitting them over HTTP exposes them to theft and interception.

Remediation strategies must be comprehensive, emphasizing:

- **Strict Server-Side Algorithm Enforcement**: Never trust the `alg` header from the client; enforce a specific, strong algorithm.
- **Secure Key Management**: Use strong, randomly generated keys stored securely outside the codebase and implement regular key rotation.
- **Thorough Claim Validation**: Validate all standard and custom claims relevant to the application's security model.
- **Secure Token Handling**: Enforce HTTPS, use `HttpOnly` cookies for web client storage, implement short access token lifespans with a robust refresh token mechanism, and establish a token revocation strategy.
- **Correct Use of Well-Vetted Libraries**: Leverage established JWT libraries and adhere strictly to their security guidelines, avoiding manual implementation of cryptographic primitives.

While JWTs offer benefits such as statelessness, this advantage can be diminished when robust security measures like token revocation are required, often necessitating a return to some form of server-side state management. The "custom" aspect of JWT implementations tends to magnify standard risks because it implies a potential deviation from secure defaults provided by libraries, a re-implementation of security-critical logic, or an oversight of established best practices.**1** This increases the likelihood of introducing vulnerabilities that could have been prevented by consistently applying the secure defaults and recommended usage patterns of mature JWT libraries. Therefore, continuous vigilance, developer education, and rigorous testing are paramount in maintaining a secure JWT-based authentication and authorization system.

## **References**

- RFC 7519: JSON Web Token (JWT)

- OWASP JWT Cheat Sheet (and related OWASP resources)

- `golang-jwt/jwt` library documentation and security guidelines
    
- PortSwigger Web Security Academy: JWTs
    
- Semgrep Blog: Common JWT Mistakes

    
- PentesterLab Blog: JWT Algorithm Confusion & Vulnerabilities
    
    
- RedfoxSec Blog: JWT Deep Dive into Algorithm Confusion
    