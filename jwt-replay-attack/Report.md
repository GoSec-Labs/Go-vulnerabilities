# **JWT Replay Attacks in Golang Applications (Alternate Name: jwt-replay-attack)**

## **1. Vulnerability Title**

JWT Replay Attacks in Golang Applications (Alternate Name: jwt-replay-attack)

## **2. Severity Rating**

The severity of JWT replay attacks is typically classified as **High🟠** to **Critical🔴**. The precise CVSS (Common Vulnerability Scoring System) score is contingent upon the specific impact of a successful replay within the context of the affected Golang application. Factors influencing this include the level of privileges granted by the replayed token and the nature of unauthorized actions an attacker can perform, such as unauthorized data access, privilege escalation, or manipulation of financial transactions. For instance, if a replayed token facilitates unauthorized administrative actions or financial fraud, the severity would escalate to Critical. A CVSS v3.1 base score often falls within the 7.0-9.8 range. The high end of this range is justified when considering that replay attacks can lead to complete authentication bypass.

The significant potential for damage is a key contributor to this high severity. The core of the issue lies not in a cryptographic failure of the JWT itself—a replayed token often retains its cryptographic validity—but in a logical flaw within the application's token validation and state management policies. The server mistakenly trusts a token that, while correctly signed, is no longer appropriate for the current request due to prior use or changed context. This oversight allows an attacker to inherit all privileges associated with the original token.

Furthermore, the likelihood of this vulnerability emerging in Golang applications can be influenced by common development practices. The absence of built-in, stateful replay prevention mechanisms in many standard JWT libraries necessitates that developers implement such crucial security features (e.g., `jti` stores or nonce tracking) themselves. This decentralization of a critical security control increases the probability of implementation errors or omissions, thereby elevating the overall risk score associated with JWT replay attacks.

An illustrative CVSS v3.1 vector for a common JWT replay attack scenario might be: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N.

- **Attack Vector (AV): Network (N)** – The token is captured and replayed over the network.
- **Attack Complexity (AC): Low (L)** – Once a token is intercepted, replaying it often requires minimal technical skill or resources.
- **Privileges Required (PR): None (N)** – If the token is sniffed or leaked, the attacker requires no prior privileges.
- **User Interaction (UI): None (N)** – No user interaction is typically needed for the attacker to replay the token.
- **Scope (S): Unchanged (U)** – Typically, the exploit impacts resources within the same security scope as the compromised token. (This could be 'Changed' (C) if the replayed token allows pivoting to other systems/scopes).
- **Confidentiality (C): High (H)** – If the token grants access to sensitive data.
- **Integrity (I): High (H)** – If the token allows data modification or unauthorized actions.
- **Availability (A): None (N) / Low (L)** – Direct impact on availability might be less common but possible if replay leads to resource exhaustion or account lockout.

This scoring underscores the potential for significant harm, particularly regarding confidentiality and integrity breaches.

## **3. Description**

A JSON Web Token (JWT) replay attack is a security vulnerability where an adversary intercepts a valid JWT and subsequently re-submits this token to a server or service to impersonate the legitimate user or gain unauthorized access to protected resources or functionalities. This type of attack is particularly pertinent to Golang applications that leverage JWTs for session management or API authentication if these applications fail to implement robust mechanisms to verify the uniqueness and timeliness of each token. The fundamental problem is the server's acceptance of a previously issued, cryptographically valid token as currently authentic without adequate contextual validation or historical tracking of token usage.

The vulnerability does not typically involve breaking the JWT's cryptographic signature; rather, it exploits weaknesses in the server-side logic that processes the token. A replayed token, if untampered, will pass signature validation. The attack succeeds because the server fails to ascertain whether *this specific, valid token* has been used before or if its use is still appropriate within the intended operational lifecycle (e.g., it has not expired and has not been revoked). This distinction is critical: the signature confirms the token's authenticity and integrity at its point of issuance, not its validity for the current, specific request.

The prevalence of Golang in building high-performance APIs and microservices, where JWTs are a favored authentication method due to their perceived statelessness, contributes to a growing attack surface for such vulnerabilities. If developers are not consistently aware of and addressing the nuances of secure JWT handling—particularly the need for stateful checks like `jti` (JWT ID) blacklisting or nonce tracking—replay vulnerabilities can easily manifest.

## **4. Technical Description**

JSON Web Tokens (JWTs) are structured into three parts: the Header, Payload, and Signature, delimited by periods. The Header typically specifies the algorithm (`alg`) used for signing (e.g., HS256, RS256) and the token type (`typ`, usually "JWT"). The Payload contains claims, which are statements about an entity (typically the user) and additional metadata. Standard claims include `iss` (issuer), `aud` (audience), `sub` (subject), `exp` (expiration time), `nbf` (not before), `iat` (issued at), and `jti` (JWT ID). It is crucial to remember that the payload is Base64URL encoded and not encrypted by default, meaning its contents are easily readable. The Signature is used to verify that the sender of the JWT is who it says it is and to ensure that the message wasn't changed along the way.

In a typical authentication flow, a user authenticates (e.g., with credentials), and the server, upon successful authentication, issues a JWT. The client application then stores this JWT (e.g., in localStorage, sessionStorage, or an HTTP-only cookie) and includes it in the `Authorization` header (commonly as `Bearer <token>`) of subsequent requests to protected API endpoints.

A JWT replay attack unfolds as follows:

1. **Interception:** An attacker obtains a valid JWT. This can occur through various means:
    - Man-in-the-Middle (MitM) attacks if data transmission is not secured with TLS (though this is less common for the token itself if HTTPS is enforced).
    - Cross-Site Scripting (XSS) vulnerabilities that allow an attacker to steal tokens from client-side storage.
        
    - Compromise of the client device or insecure storage of the token on the client-side.
    - Leakage through server-side logs if JWTs are inadvertently logged without redaction.
    - Physical access, shoulder surfing, or social engineering.
2. **Re-transmission (Replay):** The attacker re-sends the captured JWT to a protected API endpoint. This is often accomplished using tools such as `curl`, Postman, Burp Suite, or custom scripts. Some tools like `jwt_tool` are also noted for JWT manipulation and potential replay scenarios.
    
3. **Server-Side Validation Flaw:** The Golang server receives the replayed token. It successfully validates the cryptographic signature because the token itself has not been tampered with. However, the vulnerability lies in the server's subsequent failure to perform adequate checks:
    - **Expiration (`exp`):** The server might not check the `exp` claim, or the token might have an excessively long or no expiration time.
    - **Uniqueness (`jti` or Nonce):** The server does not validate a `jti` (JWT ID) claim or a nonce against a server-side store of already processed or revoked identifiers. This is the core of the replay vulnerability.
4. **Successful Exploitation:** The server, having confirmed the signature and potentially other basic claims (like `iss` or `aud` if configured), erroneously processes the replayed request as if it were a new, legitimate request from the original user. This grants the attacker unauthorized access or allows them to perform actions with the privileges associated with the replayed token.

While JWTs are often lauded for enabling stateless authentication architectures, robust replay prevention mechanisms, such as `jti` blacklisting or server-side nonce tracking, inherently introduce a stateful component to the validation process. The attack's success hinges on the server's inability to differentiate between the first legitimate use of a token and subsequent illegitimate reuses, as the cryptographic signature remains identical and valid in both instances. The attack surface for JWT interception in Golang applications can be diverse, including insecure WebSocket communications if tokens are passed improperly, or through logging mechanisms that inadvertently capture sensitive token data if not configured for redaction. Furthermore, Golang's efficiency in handling concurrent requests could, paradoxically, make a vulnerable endpoint more susceptible to rapid, automated replay attacks if rate-limiting is not robustly implemented alongside anti-replay measures.

## **5. Common Mistakes That Cause This**

Several common mistakes in the implementation and configuration of JWT-based authentication in Golang applications can lead to replay attack vulnerabilities:

1. **Missing or Improper `exp` (Expiration Time) Claim Validation:**
    - **Failure to Set `exp`:** Generating JWTs without an `exp` claim, making them effectively non-expiring unless the server has a default lifespan for tokens it issues.
        
    - **Excessively Long Expiration Times:** Setting `exp` values that are too far in the future (e.g., days, months, or years) significantly widens the window of opportunity for a captured token to be replayed.
        
    - **Lack of Server-Side `exp` Validation:** The server-side Golang code must actively check the `exp` claim against the current time. Relying on the client to stop using an expired token is insecure. This validation should account for potential clock skew between servers, typically by allowing a small leeway (e.g., a few seconds or minutes).
        
    - **Library Misuse (e.g., `golang-jwt/jwt`):** In libraries like `github.com/golang-jwt/jwt/v5`, default parsing functions such as `ParseWithClaims` might not enforce expiration checking unless specific options like `jwt.WithExpirationRequired()` are explicitly used. Developers might overlook this, assuming expiration is checked by default. Furthermore, as highlighted by CVE-2024-51744, complex error handling scenarios (e.g., a token being both expired and having an invalid signature) can lead to vulnerabilities if developers only check for `jwt.ErrTokenExpired` and ignore other critical errors like `jwt.ErrTokenSignatureInvalid`.

        
2. **Lack of `jti` (JWT ID) or Nonce Implementation and Validation:**
    - **Omitting Uniqueness Claims:** Failing to include a unique identifier like the `jti` claim (a standard JWT claim for providing a unique ID for the token) or a custom nonce in the JWT payload during generation.
        
    - **No Server-Side Tracking:** The Golang server-side logic must:
        - Extract the `jti` or nonce from the incoming token.
        - Maintain a persistent and shared store (e.g., Redis, a database, or a distributed cache) of `jti`s/nonces that have already been processed or explicitly revoked.
        - Atomically check if the received `jti`/nonce is present in this store. If it is, the token must be rejected as a replay. This store must also handle the eviction of `jti`s for tokens that have naturally expired to prevent unbounded growth.
            
3. **No Effective Token Revocation Mechanism:**
    - **Relying Solely on `exp`:** Depending entirely on the `exp` claim for token invalidation is insufficient. If a token is compromised or a user session needs to be terminated prematurely (e.g., user logs out, password change, suspected account takeover), there must be a way to invalidate the token immediately, regardless of its expiration time.
        
    - **Absence of Blacklists:** Golang applications often lack a server-side blacklist for compromised `jti`s or other token-specific identifiers that would allow for immediate revocation.
4. **Issuing Long-Lived Access Tokens Without Robust Refresh Token Strategy:**
    - Providing access tokens with excessively long lifespans (e.g., hours or days) directly increases the risk and impact of replay attacks if the token is stolen. While refresh tokens can manage longer user sessions, the access tokens themselves should remain short-lived.
        
5. **Misunderstanding JWT Statelessness vs. Security Needs:**
    - A fundamental misunderstanding is that the "stateless" nature of JWTs (meaning the server doesn't need to store session data for basic validation) implies no server-side state is *ever* needed. For robust security features like replay prevention (`jti` tracking) or revocation, some form of server-side state is unavoidable.
        
6. **Insecure Handling of Refresh Tokens:**
    - If refresh tokens are used to obtain new access tokens, they too must be protected against replay. This can involve one-time use refresh tokens, refresh token rotation, or their own `jti` tracking and revocation mechanisms.
        
7. **Ignoring Security Best Practices from Libraries and RFCs:**
    - Not adhering to the guidelines in RFC 7519 (the JWT standard)  or the specific documentation of Golang JWT libraries regarding secure validation. For instance, `golang-jwt/jwt/v5` introduced `ParserOption`s and a `ClaimsValidator` interface for more granular control over validation, which developers might not fully utilize.
        
A common thread in these mistakes is often an incomplete understanding of the division of responsibility between the JWT library and the application code. While a library might parse a token and verify its signature, the onus is typically on the Golang application to implement the logic for checking expiration (if not enforced by the library by default or via options), `jti` uniqueness against a store, and revocation status. The ease of use of some Golang JWT libraries for basic token generation and parsing can sometimes mask the underlying complexity of achieving a truly secure implementation, leading developers to overlook these critical validation steps.

## **6. Exploitation Goals**

Attackers who successfully execute a JWT replay attack aim to achieve one or more of the following objectives, leveraging the privileges associated with the replayed token:

- **Unauthorized Access to Resources and Data:** The most direct goal is to gain access to protected API endpoints, user-specific data, or system functionalities that the legitimate token holder is authorized to access. This could include viewing sensitive information, configuration details, or other proprietary data.

- **Session Hijacking and Impersonation:** By replaying a valid session token, an attacker can effectively take over a legitimate user's authenticated session. This allows the attacker to perform actions within the application as if they were that user, potentially viewing their data, changing settings, or interacting with other users.
    
- **Privilege Escalation:** While a replay attack itself doesn't typically escalate privileges beyond what the token originally granted, if an attacker can intercept and replay a token belonging to an administrative or higher-privileged user, they effectively gain those elevated privileges. In some poorly designed systems, replaying a token multiple times or in a specific sequence might inadvertently lead to an escalated state.
- **Data Exfiltration:** Once unauthorized access is achieved, a common goal is to steal or exfiltrate sensitive data. This could be personal identifiable information (PII), financial records, intellectual property, or any other data the compromised session has access to.
- **Unauthorized Operations and Transactions:** Attackers may aim to execute state-changing operations. This includes modifying data, posting unauthorized content, deleting information, or initiating transactions (e.g., financial transfers, service subscriptions) on behalf of the impersonated user. The lack of `jti` or nonce validation is particularly exploitable for goals involving repeated actions, such as voting multiple times or claiming a reward repeatedly, if the action is not inherently idempotent and relies solely on token validity for authorization.

- **Bypassing Usage Quotas or Rate Limiting:** If application controls like rate limits or usage quotas are tied to the issuance of new tokens rather than tracking unique user activity over time, replaying an existing token might allow an attacker to bypass these controls for certain actions.
- **Denial of Service (DoS):** In some scenarios, replaying tokens could lead to DoS. For example, if replaying a token triggers a resource-intensive operation on the server, repeated replays could exhaust server resources. Alternatively, if a token is associated with a unique, consumable resource (e.g., a one-time voucher), replaying the token to consume this resource multiple times could deny the legitimate user access to it or lead to an inconsistent application state.

The fundamental aim is to abuse the legitimate permissions conferred by the JWT. The attacker is not breaking the token's cryptography but rather exploiting the server's failure to ensure that the token is being used legitimately in the current context. In systems where JWTs gate access to critical, state-altering functions, particularly in Golang applications within financial or data-sensitive domains, the impact of achieving these exploitation goals can be exceptionally severe.

## **7. Affected Components or Files**

JWT replay vulnerabilities primarily manifest in the server-side Golang application code that handles JWT-based authentication and authorization. Specific components and files commonly affected include:

- **Golang Application Code:**
    - **Authentication Middleware:** These are often custom-written pieces of code (e.g., in files like `middleware/auth.go`, `auth/jwt.go`) responsible for intercepting incoming HTTP/WebSocket requests, extracting the JWT from headers (e.g., `Authorization: Bearer <token>`) or cookies, and invoking validation logic. Flaws here, such as missing `jti` checks or improper `exp` validation, are common sources of the vulnerability.
    - **JWT Utility Functions/Packages:** If the application uses custom utility functions or internal packages for generating and validating JWTs (e.g., `pkg/jwtutils/token.go`), errors in this shared code can affect multiple parts of the application.
    - **API Endpoint Handlers:** Individual HTTP handlers (e.g., in `handlers/user_api.go`, `controllers/resource_controller.go`) that process requests after the initial JWT validation might perform insufficient secondary checks or rely on inadequately validated claims. If replay prevention is not centralized in middleware, each handler becomes a potential point of failure.
- **JWT Libraries (Misuse or Misconfiguration):**
    - The vulnerability typically lies in how Golang JWT libraries are *used*, rather than flaws in the libraries themselves (though library vulnerabilities can occur, e.g., CVE-2024-51744 for `golang-jwt/jwt` related to error handling ).
        
    - For `github.com/golang-jwt/jwt/v5`: Code segments where parser options like `jwt.WithExpirationRequired()` are omitted, or where the `ClaimsValidator` interface isn't used for custom `jti` validation, are key areas.
        
    - Legacy applications might still use the deprecated `github.com/dgrijalva/jwt-go` library, which has its own historical issues and usage patterns that could lead to vulnerabilities if not handled correctly.
        
- **Configuration Files/Environment Variables:**
    - Files (e.g., `config.yaml`, `app.env`) or environment variables that store JWT secret keys, define token expiration policies (`ACCESS_TOKEN_LIFETIME`), specify token issuers (`JWT_ISSUER`), or audiences (`JWT_AUDIENCE`). If these configurations lead to the issuance of overly permissive tokens (e.g., extremely long expiry) or inadvertently disable security checks (e.g., a debug flag that bypasses `jti` validation), they become affected components.
- **Server-Side State Stores (for Replay Prevention):**
    - If the application attempts replay prevention using `jti`s or nonces, the code that interacts with the chosen state store (e.g., Redis, PostgreSQL, an in-memory map like `sync.Map`) is critical. Bugs in the logic for adding `jti`s to the store, checking for their existence, or expiring/pruning old `jti`s can undermine the entire replay protection mechanism. For example, a race condition in updating the `jti` store could allow a token to be replayed.

The most critical points of failure are often within the custom Golang middleware or handler functions that orchestrate the use of JWT libraries. These libraries provide the cryptographic tools and claim parsing capabilities, but the application code is responsible for defining and enforcing the security policy, including which claims are mandatory (like `exp` and `jti` for replay protection), how they are validated against server-side state, and how errors are handled. Poorly documented or overly complex JWT validation logic in these custom Golang components can also lead to vulnerabilities, as developers might inadvertently bypass or weaken security checks during code maintenance or when adding new features. In larger Golang projects, especially those with a microservice architecture, ensuring consistent and correct JWT handling across all services is a significant challenge; a vulnerability fixed in one service might persist in another if not addressed systematically.

## **8. Vulnerable Code Snippet (Golang)**

The following Golang code snippets, using the `github.com/golang-jwt/jwt/v5` library, illustrate common ways JWT replay vulnerabilities can manifest.

**Snippet 1: Missing `exp` (Expiration) and `jti` (JWT ID) Validation**

This example demonstrates a handler that only verifies the JWT signature, making it vulnerable to indefinite replay if the token itself lacks an expiration and to multiple replays even if it had an expiration but no `jti` check.

```Go

package main

import (
    "fmt"
    "net/http"
    "time" // Only used for IssuedAt in this vulnerable example

    "github.com/golang-jwt/jwt/v5"
)

var mySigningKeySnippet1 =byte("averyweaksecret!")

// AppClaims defines the structure of our custom claims.
type AppClaimsSnippet1 struct {
    Username string `json:"username"`
    IsAdmin  bool   `json:"is_admin"`
    jwt.RegisteredClaims
}

// generateBasicVulnerableToken creates a token without 'exp' and 'jti' for demonstration.
func generateBasicVulnerableToken(username string, isAdmin bool) (string, error) {
    claims := AppClaimsSnippet1{
        Username: username,
        IsAdmin:  isAdmin,
        RegisteredClaims: jwt.RegisteredClaims{
            // No ExpiresAt claim is set.
            // No ID (jti) claim is set.
            IssuedAt: jwt.NewNumericDate(time.Now()),
            Issuer:   "vulnerable-app",
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(mySigningKeySnippet1)
}

// handleProtectedResourceBasic is a vulnerable HTTP handler.
// It only checks the token's signature. It does not validate expiration
// (and the token generated by generateBasicVulnerableToken doesn't have one)
// nor does it check for a JTI to prevent replay.
func handleProtectedResourceBasic(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    if len(authHeader) < 7 |
| authHeader[:7]!= "Bearer " {
        http.Error(w, "Missing or malformed token", http.StatusUnauthorized)
        return
    }
    tokenString := authHeader[7:]

    token, err := jwt.ParseWithClaims(tokenString, &AppClaimsSnippet1{}, func(token *jwt.Token) (interface{}, error) {
        // Basic validation: ensure the signing method is as expected.
        if _, ok := token.Method.(*jwt.SigningMethodHMAC);!ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return mySigningKeySnippet1, nil
    }) // MISTAKE: No jwt.WithExpirationRequired() or other options for 'exp' or 'jti' validation.

    if claims, ok := token.Claims.(*AppClaimsSnippet1); ok && token.Valid {
        // CRITICAL FLAW: token.Valid here primarily confirms the signature is correct.
        // Since no 'exp' was set in the token and no server-side check for 'exp' is enforced
        // via options, this token, once issued, can be replayed indefinitely.
        // Similarly, no 'jti' was set or checked, allowing multiple replays.
        fmt.Fprintf(w, "Vulnerable Access Granted to %s! Admin: %v.", claims.Username, claims.IsAdmin)
    } else {
        // This error might catch signature issues or malformed tokens, but not replay.
        http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
    }
}

func main_snippet1() { // Renamed to avoid conflict
    // Example token generation (in a real app, this would be from a login endpoint)
    // vulnerableToken, _ := generateBasicVulnerableToken("attacker", true)
    // fmt.Printf("Attacker's re-playable token: %s\n", vulnerableToken)

    http.HandleFunc("/vulnerable-resource", handleProtectedResourceBasic)
    fmt.Println("Starting vulnerable server on :8080...")
    // http.ListenAndServe(":8080", nil) // Do not run in production
}
```

In this snippet, the `handleProtectedResourceBasic` function parses the JWT. The `token.Valid` check primarily ensures the signature is correct. However, because the token generated by `generateBasicVulnerableToken` does not include an `ExpiresAt` claim, and `ParseWithClaims` is not called with `jwt.WithExpirationRequired()`, the token will not be rejected due to expiration. More critically, there is no mechanism to check for a `jti` or nonce, meaning this token can be replayed by an attacker indefinitely.

**Snippet 2: `exp` Validation Present, but No `jti`/Nonce Check for Replay Prevention**

This example shows a handler that correctly uses `jwt.WithExpirationRequired()` to ensure tokens are not expired, but still fails to prevent replay attacks within the token's validity window because it does not check for token uniqueness using a `jti`.

```Go

package main

import (
    "fmt"
    "net/http"
    "sync" // For a naive in-memory JTI store example - NOT PRODUCTION READY
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid" // For generating unique JTI values
)

var mySecureSigningKeySnippet2 =byte("slightlylessweaksecret")

// For demonstration purposes only. In a real application, use a persistent,
// distributed, and time-aware store like Redis or a database for JTIs.
var usedJTIsStore sync.Map

// SecureAppClaimsSnippet2 defines claims including standard registered claims.
type SecureAppClaimsSnippet2 struct {
    Username string `json:"username"`
    jwt.RegisteredClaims
}

// generateReplayableTokenWithExpiryAndJTI creates a token with 'exp' and 'jti'.
func generateReplayableTokenWithExpiryAndJTI(username string) (string, error) {
    jti := uuid.NewString() // Generate a unique JTI
    claims := SecureAppClaimsSnippet2{
        Username: username,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Minute)), // Token expires in 1 minute
            ID:        jti,                                                 // JTI is set
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            Issuer:    "semi-secure-app",
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(mySecureSigningKeySnippet2)
}

// handleProtectedResourceWithExpiryButNoJTIValidation is vulnerable to replay within the token's lifetime.
func handleProtectedResourceWithExpiryButNoJTIValidation(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    if len(authHeader) < 7 |
| authHeader[:7]!= "Bearer " {
        http.Error(w, "Missing or malformed token", http.StatusUnauthorized)
        return
    }
    tokenString := authHeader[7:]

    token, err := jwt.ParseWithClaims(tokenString, &SecureAppClaimsSnippet2{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC);!ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return mySecureSigningKeySnippet2, nil
    }, jwt.WithExpirationRequired()) // CORRECT: 'exp' claim IS checked by the library due to this option.

    if err!= nil {
        // This will catch expired tokens, signature errors, etc.
        http.Error(w, fmt.Sprintf("Token parsing or expiration error: %v", err), http.StatusUnauthorized)
        return
    }

    if claims, ok := token.Claims.(*SecureAppClaimsSnippet2); ok && token.Valid {
        // PROBLEM: Signature is valid, and token is not expired.
        // HOWEVER, the JTI (claims.ID) is NOT checked against a store of used JTIs.
        // Therefore, this token can be replayed multiple times until it expires (in 1 minute).
        
        // To fix, one would need to implement JTI checking:
        // if claims.ID == "" {
        //    http.Error(w, "JTI claim missing", http.StatusForbidden)
        //    return
        // }
        // if _, loaded := usedJTIsStore.LoadOrStore(claims.ID, true); loaded {
        //    http.Error(w, "Token has already been used (replay)", http.StatusForbidden)
        //    return
        // }
        // // Schedule JTI cleanup after token expiration (simplified)
        // time.AfterFunc(time.Until(claims.ExpiresAt.Time), func() {
        //    usedJTIsStore.Delete(claims.ID)
        // })

        fmt.Fprintf(w, "Semi-Secure Access Granted to %s! Token JTI: %s. Resource accessed.", claims.Username, claims.ID)
    } else {
        // This case might be redundant if 'err!= nil' already caught validation issues.
        // token.Valid might be false for reasons other than those producing an error from ParseWithClaims directly.
        http.Error(w, "Invalid token (claims assertion or general validity failed)", http.StatusUnauthorized)
    }
}

func main_snippet2() { // Renamed to avoid conflict
    // Example token generation
    // replayableToken, _ := generateReplayableTokenWithExpiryAndJTI("attacker")
    // fmt.Printf("Attacker's token (replayable for 1 min): %s\n", replayableToken)

    http.HandleFunc("/semi-secure-resource", handleProtectedResourceWithExpiryButNoJTIValidation)
    fmt.Println("Starting semi-secure (but still replayable) server on :8081...")
    // http.ListenAndServe(":8081", nil) // Do not run in production
}
```

In this second snippet, `jwt.WithExpirationRequired()` ensures that the `exp` claim is present and validated. However, the application still fails to check the uniqueness of the `ID` (JTI) claim. An attacker who intercepts this token can replay it multiple times within its 1-minute validity window. The commented-out section illustrates the conceptual logic for a JTI check using a `sync.Map` (which itself is not a complete production solution without persistence and robust eviction).

These examples highlight that `token.Valid` from JWT libraries often confirms cryptographic validity and standard time-based claims (if options are used correctly), but does not inherently prevent replay attacks. The application logic must explicitly implement checks for token uniqueness (e.g., via `jti` or nonces) and manage their state. The lack of built-in, "secure-by-default" stateful replay prevention in many Golang web frameworks or JWT libraries places the onus of implementing this critical security feature on developers, thereby increasing the likelihood of such omissions or errors.

## **9. Detection Steps**

Identifying JWT replay vulnerabilities in Golang applications requires a combination of manual code review, penetration testing, and log analysis.

- **Manual Code Review (Golang Specific):** This is the most crucial step for detecting logical flaws in JWT handling.
    - **JWT Generation Logic:**
        - Verify that an `exp` (expiration time) claim is always set during token generation.
        - Ensure the `exp` values are reasonably short (e.g., minutes for access tokens, longer for refresh tokens if used).
        - Check if a unique `jti` (JWT ID) claim or a nonce is being generated and included in the token payload.
    - **JWT Validation Middleware/Handlers:**
        - **Signature Verification:** Confirm that the token's signature is always cryptographically verified using the correct algorithm and key before any claims are trusted.
        - **`exp` Claim Validation:** Ensure the `exp` claim is explicitly checked on the server-side. For `github.com/golang-jwt/jwt/v5`, verify that `ParseWithClaims` is used with the `jwt.WithExpirationRequired()` option, or that equivalent custom validation logic is in place. Pay attention to error handling to ensure expiration errors are correctly processed.
            
        - **`jti`/Nonce Validation:** This is paramount for replay prevention.
            - Confirm that the `jti` or nonce claim is extracted from the token.
            - Verify that this unique identifier is checked against a server-side store (e.g., Redis, database, distributed cache) of already processed or revoked tokens.
            - Ensure that if a `jti`/nonce is found in the store (indicating a replay), the request is rejected.
            - Examine the logic for managing this store: How are `jti`s/nonces added? How and when are they evicted (e.g., after the corresponding token's `exp` time to prevent the store from growing indefinitely)? Is the store access atomic and concurrency-safe?
        - **Revocation Check:** If a token revocation mechanism (e.g., a blacklist) is intended, verify that it's consulted during validation.
        - **Error Handling:** Scrutinize error handling paths to ensure that validation failures (expired token, replayed token, invalid signature) correctly lead to request rejection and do not inadvertently allow processing.
- **Penetration Testing:**
    - **Token Interception:** Capture legitimate JWTs during normal application usage using a proxy tool like Burp Suite or OWASP ZAP.
    - **Basic Replay:** Re-submit the intercepted JWT to the protected endpoint(s) using tools like Burp Repeater, `curl`, or custom scripts. Observe if the server accepts and processes the replayed token.
    - **Replay After Expiration:** Attempt to replay a token after its `exp` time has passed. The server should reject it.
    - **Replay After Logout/Revocation:** If the application has a logout feature that is supposed to invalidate the JWT, test replaying the token after logout.
    - **Multiple Replays:** Send the same valid (unexpired) token multiple times to an endpoint that should only process a unique request once (e.g., claiming a one-time reward). Success indicates a lack of `jti`/nonce checking.
    - Specialized JWT tools like `jwt_tool` can be used for dissecting and manipulating tokens, which can aid in crafting replay scenarios. Burp Scanner also has capabilities to detect some JWT vulnerabilities.

        
- **Log Analysis:**
    - If `jti` claims or other unique request identifiers are logged by the Golang application, monitor server logs for multiple requests bearing the same `jti` but originating from different IP addresses, user agents, or occurring at suspicious intervals.
    - Look for access patterns that suggest the reuse of tokens that should have been invalidated (e.g., access with a token long after a user's typical session activity has ceased).
- **Automated Security Scanning:**
    - While generic SAST (Static Application Security Testing) and DAST (Dynamic Application Security Testing) tools may not always have deep, context-aware checks for JWT replay logic, specialized API security testing tools are more likely to identify such issues.

A key aspect of detection is understanding the application's expected stateful behavior concerning tokens. A simple stateless check of a JWT (signature, `exp`) will not reveal a replay vulnerability. Detection methods must consider the history of token usage, which implies checking against some form of server-maintained state (e.g., the `jti` store). In complex Golang microservice architectures, effective detection may necessitate distributed tracing and centralized logging capabilities. This allows for tracking token usage across service boundaries and identifying anomalous replay patterns that might be missed if services are monitored in isolation. Logging JWT claims like `jti`, `sub`, `iss`, and `aud`, along with correlation IDs from tracing systems, can provide invaluable data for security analysts.

## **10. Proof of Concept (PoC)**

This Proof of Concept demonstrates how a JWT replay attack can be performed against a vulnerable Golang HTTP server. The server will have an endpoint protected by JWT authentication but will lack proper `jti` (JWT ID) validation, making it susceptible to replays within the token's expiration window.

**1. Setup: Vulnerable Golang Server**

The following Golang code sets up an HTTP server with two endpoints:

- `/login`: Issues a JWT upon dummy authentication.
- `/resource`: A protected resource that requires a valid JWT. This endpoint will check the token's signature and expiration but will not check for `jti` uniqueness.

```Go

package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "strings"
    "sync"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
)

var jwtKey =byte("my_vulnerable_secret_key")

// In-memory store for used JTIs - for PoC only, NOT production-safe
// var usedJTIs = make(map[string]bool)
// var jtiMutex = &sync.Mutex{}

type Claims struct {
    Username string `json:"username"`
    jwt.RegisteredClaims
}

// Login handler: issues a JWT
func login(w http.ResponseWriter, r *http.Request) {
    // Dummy authentication
    username := "testuser"
    expirationTime := time.Now().Add(1 * time.Minute) // Token valid for 1 minute
    jti := uuid.NewString()

    claims := &Claims{
        Username: username,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(expirationTime),
            ID:        jti,
            Issuer:    "poc-app",
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err!= nil {
        http.Error(w, "Failed to create token", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"token": tokenString, "jti": jti})
    log.Printf("Issued token for %s with JTI: %s, ExpiresAt: %s\n", username, jti, expirationTime)
}

// Protected resource handler
func resource(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        http.Error(w, "Authorization header required", http.StatusUnauthorized)
        return
    }

    tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
    if tokenStr == authHeader { // No "Bearer " prefix
        http.Error(w, "Malformed token", http.StatusUnauthorized)
        return
    }

    claims := &Claims{}
    token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC);!ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return jwtKey, nil
    }, jwt.WithExpirationRequired()) // Enforces 'exp' claim validation

    if err!= nil {
        if err == jwt.ErrTokenExpired {
            http.Error(w, "Token has expired", http.StatusUnauthorized)
        } else {
            http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
        }
        return
    }

    if!token.Valid {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    // VULNERABILITY: No JTI check against a store of used JTIs.
    // A real fix would involve:
    // jtiMutex.Lock()
    // if _, found := usedJTIs; found {
    //    jtiMutex.Unlock()
    //    http.Error(w, "Token replayed", http.StatusForbidden)
    //    return
    // }
    // usedJTIs = true
    // jtiMutex.Unlock()
    // // Schedule JTI cleanup after token expiration
    // time.AfterFunc(time.Until(claims.ExpiresAt.Time), func() {
    //    jtiMutex.Lock()
    //    delete(usedJTIs, claims.ID)
    //    jtiMutex.Unlock()
    //    log.Printf("Cleaned up JTI: %s", claims.ID)
    // })

    log.Printf("Access granted to /resource for user: %s with JTI: %s\n", claims.Username, claims.ID)
    fmt.Fprintf(w, "Welcome %s, you have accessed the protected resource with JTI: %s!", claims.Username, claims.ID)
}

func main() {
    http.HandleFunc("/login", login)
    http.HandleFunc("/resource", resource)

    log.Println("Starting server on :8080...")
    if err := http.ListenAndServe(":8080", nil); err!= nil {
        log.Fatal(err)
    }
}
```

**2. Step 1: Obtain a Valid JWT**

- Start the Golang server.
- Send a GET request to the `/login` endpoint (e.g., using `curl` or Postman):
`curl http://localhost:8080/login`
- The server will respond with a JSON object containing the JWT and its JTI:
    
    ```JSON
    
    {"jti":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3R1c2VyIiwiZXhwIjoxNzA0MDY3MjAwLCJqdGkiOiJ4eHh4eHh4LXh4eHgteHh4eC14eHh4LXh4eHh4eHh4eHh4eCIsImlzcyI6InBvYy1hcHAifQ.YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"}
    ```
    
- Copy the `token` value. Let's call this `CAPTURED_TOKEN`. Note its `jti`.

**3. Step 2: Replay the JWT to Access the Protected Resource (First time)**

- Send a GET request to the `/resource` endpoint, including the `CAPTURED_TOKEN` in the Authorization header:
`curl -H "Authorization: Bearer <CAPTURED_TOKEN>" http://localhost:8080/resource`
- **Expected Outcome:** The server should grant access because the token's signature is valid and it has not yet expired. The response will be:
`Welcome testuser, you have accessed the protected resource with JTI: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx!`
- Server log will show: `Access granted to /resource for user: testuser with JTI: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

**4. Step 3: Replay the SAME JWT Again (Demonstrating Replay)**

- Within the 1-minute validity window of the token, send the *exact same* GET request to `/resource` with the *same* `CAPTURED_TOKEN`:
`curl -H "Authorization: Bearer <CAPTURED_TOKEN>" http://localhost:8080/resource`
- **Vulnerable Outcome:** The server **again grants access**. The response will be identical to the previous one:
`Welcome testuser, you have accessed the protected resource with JTI: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx!`
- Server log will show another entry: `Access granted to /resource for user: testuser with JTI: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

This demonstrates the JWT replay attack. The same token (with the same JTI) was accepted multiple times because the server only checked for signature validity and expiration, not for the uniqueness of the JTI for each request. A non-vulnerable server implementing JTI checking would have rejected the second request with a "Token replayed" error.

This PoC highlights how a seemingly minor omission in server-side validation logic in a Golang application can lead to a significant security vulnerability. The ease with which standard tools like `curl` (or a simple Go `net/http` client program) can be used to execute this attack underscores its practicality. The impact is particularly clear if the `/resource` endpoint were, for example, a "claim daily bonus" function; replaying the token would allow claiming the bonus multiple times.

## **11. Risk Classification**

JWT replay attacks in Golang applications can be classified using standard vulnerability frameworks, which helps in understanding their nature and prioritizing remediation efforts.

- **CWE (Common Weakness Enumeration):**
    - **CWE-294: Authentication Bypass by Capture-replay:** This is a direct classification. The attacker captures a valid token and replays it to bypass the authentication process for subsequent requests, effectively acting as the legitimate user.

    - **CWE-384: Session Fixation:** While not a classic session fixation scenario, replaying a JWT can lead to prolonged unauthorized access that mimics the characteristics of a fixed session, especially if the token has a long lifespan or if revocation mechanisms are absent. The attacker is essentially "fixing" their access using the replayed token.

    - **CWE-287: Improper Authentication:** The server fails to properly authenticate the true origin of the request when a replayed token is presented. It authenticates the token itself (based on signature) but not the legitimacy of its current use.
        
    - **CWE-613: Insufficient Session Expiration:** This is a contributing factor if tokens lack an expiration (`exp` claim), have excessively long expiration times, or if server-side validation of expiration is flawed. This extends the window during which a captured token can be successfully replayed.
        
- **OWASP API Security Top 10 (2023):**
    - **API2:2023 - Broken Authentication:** Replaying a token is a fundamental break in the authentication mechanism. The server incorrectly assumes the bearer of a cryptographically valid but previously used token is the legitimate, currently authenticated user for that specific request.
        
    - **API5:2023 - Broken Function Level Authorization:** If a replayed token is used to access functions or perform actions that should be restricted (e.g., an action that should only be performed once per session or per unique token instance), this constitutes a failure in function-level authorization. The system fails to enforce that a specific token instance can only authorize an action once.
- **OWASP Web Top 10 (2021):**
    - **A01:2021 - Broken Access Control:** Successful replay of a JWT often leads to unauthorized access to data or functionalities, which is a core aspect of broken access control.
        
    - **A07:2021 - Identification and Authentication Failures:** This category broadly covers weaknesses in confirming user identity and managing sessions. JWT replay falls squarely into this, as the system fails to correctly identify and authenticate the actual entity making the request when a token is replayed.

The mapping to multiple CWEs and OWASP categories underscores that JWT replay is not a singular, isolated flaw. It intersects with fundamental principles of secure authentication, session management, and access control. The specific risk classification may also be influenced by the context of the Golang application. For instance, in a financial application, the integrity aspects (CWE-287, API5 leading to unauthorized transactions) might be prioritized, whereas for an information portal, confidentiality breaches (API2 leading to unauthorized data access) might be the primary concern. The core vulnerability—accepting a replayed token—remains the same, but its manifestation and the most pertinent risk classifications can vary based on the application's function and the data it processes.

## **12. Fix & Patch Guidance**

Addressing JWT replay vulnerabilities in Golang applications requires a multi-layered approach, focusing on robust server-side validation of token timeliness, uniqueness, and overall lifecycle management. The following guidance details essential fixes and patches:

1. **Implement and Strictly Enforce `exp` (Expiration Time) Claim:**
    - **Generation:** Always include an `exp` claim in every JWT generated. This claim defines the exact time after which the token MUST NOT be accepted.
        
    - **Short Lifespans:** Configure short, reasonable expiration times for access tokens (e.g., 5-60 minutes, depending on security requirements and user experience trade-offs). Longer-lived tokens significantly increase the replay attack window.
        
    - **Server-Side Validation (Golang):**
        - When using `github.com/golang-jwt/jwt/v5`, always employ the `jwt.WithExpirationRequired()` parser option during token validation with `ParseWithClaims`. This ensures the library actively checks the `exp` claim.
            
        - Alternatively, or as an additional check, manually verify the `exp` claim against the current server time. Account for potential minor clock skew between servers by allowing a small leeway (e.g., a few seconds to a minute).
            
        - Properly handle errors returned by the JWT library. For instance, CVE-2024-51744 highlighted that not checking all returned errors from `ParseWithClaims` in `golang-jwt/jwt` could lead to accepting invalid tokens if, for example, only `jwt.ErrTokenExpired` was checked while ignoring an embedded `jwt.ErrTokenSignatureInvalid`.
            
2. **Implement `jti` (JWT ID) Claim for Uniqueness / Nonce Strategy:**
    - **Generation:** Include a unique `jti` claim (e.g., a Version 4 UUID) in each JWT payload upon issuance. This `jti` serves as a unique identifier for that specific token instance.
        
    - **Server-Side Validation (Golang):**
        - Upon receiving a JWT, extract the `jti` claim (e.g., `claims.RegisteredClaims.ID` if using `jwt.RegisteredClaims` with `golang-jwt/jwt/v5`).
        - Maintain a server-side, persistent, and shared store (e.g., Redis, a database table, or a distributed cache) of `jti` values that have already been processed or explicitly revoked.
        - Before accepting the JWT as valid (even if its signature and `exp` are valid), check if its `jti` is present in this store.
        - If the `jti` is found in the store, the token is a replay and **must be rejected** (e.g., with an HTTP 401 or 403 status).
        - If the `jti` is not found, add it to the store and then process the request. The `jti` should be stored at least until the token's original `exp` time to prevent the store from growing indefinitely. Ensure this check-and-set operation is atomic to prevent race conditions in concurrent environments.

            
3. **Implement a Robust Token Revocation Mechanism (Blacklisting):**
    - Maintain a server-side blacklist of `jti`s (or other unique token identifiers) that have been explicitly revoked. This is crucial for scenarios like user logout, password change, or suspected token compromise.
        
    - During token validation, after signature and `exp` checks, consult this blacklist. If the token's `jti` is on the blacklist, reject the token.
    - Revoked `jti`s should ideally be kept on the blacklist until their original `exp` time.
4. **Utilize Refresh Tokens for Managing Longer User Sessions:**
    - Issue short-lived access tokens and, if longer sessions are required, provide longer-lived refresh tokens. Refresh tokens are used solely to obtain new access tokens and should be stored securely by the client (e.g., in an HTTP-only, secure cookie).
        
    - Refresh tokens themselves must be protected against replay (e.g., by being strictly one-time use, having their own `jti` tracking, or through refresh token rotation).
5. **Enforce HTTPS (TLS) for All Communications:**
    - Always transmit JWTs over HTTPS to protect them from interception during transit. This is a fundamental prerequisite for JWT security.

        
6. **Golang Library-Specific Considerations (`golang-jwt/jwt/v5`):**
    - Make full use of `ParserOption`s provided by the library, such as `jwt.WithExpirationRequired()`, `jwt.WithAudience()`, `jwt.WithIssuer()`, to enforce validation of standard claims.

    - For custom validation logic, such as `jti` checking against a store, implement the `ClaimsValidator` interface in your custom claims struct. The `Validate()` method will be called automatically by the parser.
        
7. **Consider Sender-Constrained Tokens:**
    - For higher security requirements, explore mechanisms like Demonstration of Proof-of-Possession (DPoP) which cryptographically bind the token to the specific client that requested it, making stolen tokens much harder for an attacker to replay from a different client.

Effective replay prevention is a defense-in-depth strategy. Relying on a single mechanism, such as short expiration times alone, is often insufficient. A combination of short-lived access tokens, rigorous `jti`/nonce validation against a server-side store, and robust revocation capabilities provides a more comprehensive defense. For Golang applications, the choice and implementation of the `jti`/nonce store (e.g., in-memory for single instances with careful eviction, Redis for distributed systems, or a database) is a critical design decision that impacts performance, scalability, and complexity. This store must be designed to handle concurrent access safely and efficiently.

## **13. Scope and Impact**

**Scope:**

The vulnerability of JWT replay attacks affects any Golang application or service that utilizes JWTs for authentication, authorization, or session management if adequate replay prevention mechanisms are not implemented. This includes:

- **Web Applications and APIs:** Client-facing applications where JWTs are issued to browsers or mobile clients.
- **Microservices Architectures:** Internal service-to-service communication where JWTs are used to assert identity and permissions between Golang microservices.
- **Stateless Services:** Applications designed to be stateless that rely on JWTs to carry session information.

The vulnerability is not inherent to the Go language itself or to standard JWT libraries, but rather to the application-level logic (or lack thereof) in validating the uniqueness and timeliness of tokens.

**Impact:**

A successful JWT replay attack can have severe consequences, commensurate with the privileges granted by the replayed token:

- **Unauthorized Access and Impersonation:** The most direct impact is that an attacker can gain the same level of access as the legitimate user whose token was replayed. This allows the attacker to impersonate the user and perform any actions the user is authorized to perform.
    
- **Data Breach (Loss of Confidentiality):** If the replayed token grants access to sensitive information (e.g., personal user data, financial records, proprietary business information), the attacker can exfiltrate this data.
- **Data Tampering (Loss of Integrity):** If the token permits write operations, the attacker can modify, corrupt, or delete data, leading to data integrity issues. This could involve altering user profiles, changing application settings, or manipulating transactional records.
- **Unauthorized Actions and Financial Loss:** Attackers can execute functions or initiate transactions (e.g., financial transfers, purchases, administrative changes) that the legitimate user is authorized for. This can lead to direct financial loss, fraud, or disruption of business processes.
    
- **Privilege Escalation:** While replay doesn't inherently grant new privileges, if an attacker captures a token belonging to an administrator or a user with elevated permissions, replaying that token effectively escalates the attacker's privileges to that level for the duration of the token's validity (or until detected).
- **Denial of Service (DoS):**
    - Replaying tokens that trigger resource-intensive operations could potentially overload server resources.
    - If a token is intended for a one-time action (e.g., redeeming a voucher, casting a unique vote), replaying it could lead to an inconsistent state, effectively denying the service to the legitimate user or corrupting application logic.
- **Reputational Damage:** Security incidents resulting from JWT replay attacks can severely damage an organization's reputation and erode user trust.
- **Compliance Violations:** For applications handling sensitive data or operating in regulated industries (e.g., finance, healthcare), a JWT replay attack leading to unauthorized access or data breach can result in non-compliance with standards like PCI DSS, HIPAA, GDPR, potentially leading to significant fines and legal liabilities.

The impact is not necessarily confined to the specific Golang service that initially accepts the replayed token. In a microservices environment, if the compromised identity or privileges are propagated to downstream services, the blast radius of the attack can expand significantly. Therefore, the configuration and validation logic for JWTs are critical across all components of a distributed system.

## **14. Remediation Recommendation**

To effectively remediate JWT replay vulnerabilities in Golang applications, a comprehensive, server-centric defense-in-depth strategy is essential. The core principle is to ensure that each JWT is not only cryptographically valid but also unique for its intended use and within its valid timeframe.

1. **Prioritize Robust Server-Side Validation:**
    - All critical validation logic for JWTs, including signature verification, expiration checking, `jti`/nonce uniqueness, and revocation status, **must** be performed on the server-side within the Golang application. Client-side checks are unreliable for security enforcement as they can be bypassed.
2. **Implement a Multi-Layered Anti-Replay Strategy:**
    - **Short-Lived Access Tokens:** Generate access tokens with short expiration times (e.g., 5-60 minutes). This minimizes the window during which a compromised token can be replayed.
        
    - **`jti` (JWT ID) Claim for Uniqueness:**
        - **Generation:** Ensure every JWT contains a unique `jti` claim (e.g., a UUID).

        - **Server-Side Tracking:** Maintain a server-side store (e.g., Redis, database with appropriate indexing, or a distributed cache for multi-instance Golang deployments) of all `jti`s from valid, non-expired tokens that have been processed.
        - **Validation:** Upon receiving a JWT, after verifying its signature and `exp` claim, check if its `jti` is already present in the store. If it is, the token is a replay and must be rejected. If not, add the `jti` to the store (with an expiration time mirroring the token's `exp` to allow for automatic pruning) before processing the request. This check-and-add operation must be atomic.
    - **Refresh Token Mechanism:** For longer user sessions, implement a secure refresh token mechanism. Refresh tokens are typically longer-lived but are used only to obtain new, short-lived access tokens. They should be stored securely (e.g., HTTP-only cookies) and ideally be one-time use or have their own rotation and revocation strategy.

    - **Server-Side Token Revocation (Blacklisting):** Implement a mechanism to explicitly revoke tokens (via their `jti`) before their natural expiration. This is crucial for scenarios like user logout, password changes, or suspected security incidents. The validation process must check against this revocation list.
        
3. **Golang-Specific Implementation Details:**
    - **Leverage `golang-jwt/jwt/v5` Securely:**
        - When parsing tokens with `jwt.ParseWithClaims`, consistently use parser options such as `jwt.WithExpirationRequired()` to enforce `exp` claim validation. Also, use options like `jwt.WithAudience()` and `jwt.WithIssuer()` if these claims are relevant to your application's security model.
            
        - For custom validation logic, particularly `jti` uniqueness checks against a store, implement the `ClaimsValidator` interface on your custom claims struct. The library will then invoke your `Validate()` method during parsing.

        - Be meticulous with error handling returned by the JWT library. As demonstrated by CVE-2024-51744, failing to check for all relevant error types (e.g., prioritizing `ErrTokenSignatureInvalid` over just `ErrTokenExpired` when both might be present) can lead to vulnerabilities.
            
    - **Concurrency-Safe `jti` Store:** If implementing an in-memory `jti` store in Golang (suitable only for single-instance deployments or testing), use concurrency-safe structures like `sync.Map` or protect access with mutexes. For production and distributed systems, prefer external stores like Redis or a database.
4. **General Security Best Practices:**
    - **Enforce HTTPS (TLS):** All communication channels transmitting JWTs must use HTTPS to protect tokens from interception in transit.
        
    - **Regular Code Audits and Security Reviews:** Periodically review Golang code responsible for JWT generation, validation, and `jti` store management.
    - **Developer Training:** Educate Golang developers on the nuances of JWT security, common pitfalls (like those listed in Section 5), and best practices for replay prevention.
        
    - **Consider Sender-Constrained Tokens:** For applications requiring higher security, evaluate the use of sender-constrained tokens (e.g., DPoP with OAuth 2.0) that bind the token to the client, making replay by a different attacker difficult even if the token is stolen.
        
5. **Monitoring, Logging, and Alerting:**
    - Implement comprehensive logging of authentication events, including `jti` values, successful validations, and rejected attempts (especially those due to replay detection or expiration).
    - Set up monitoring and alerting for suspicious patterns, such as repeated attempts to use the same `jti`, a surge in expired token errors, or validation failures from unexpected sources.

Remediation requires a shift in perspective for Golang developers: JWTs should not be treated as "fire-and-forget" credentials. While they facilitate stateless architectures in some respects, ensuring security against replay attacks necessitates careful server-side lifecycle management and, critically, some form of stateful tracking (like `jti` stores). Golang's strengths in concurrency and performance should be leveraged to implement these stateful checks (e.g., `jti` stores, revocation services) efficiently, ensuring that security measures do not unduly become performance bottlenecks.

## **15. Summary**

JWT replay attacks represent a significant threat to Golang applications that utilize JSON Web Tokens for authentication and authorization. This vulnerability arises not from a flaw in the JWT standard itself or its cryptography, but from deficiencies in the server-side implementation of token validation logic. Specifically, attacks are successful when applications fail to adequately verify a token's uniqueness for each request (e.g., by not using or improperly validating `jti` claims or nonces) and its continued timeliness (beyond simple expiration checks, including revocation status).

The primary causes in Golang applications often stem from common mistakes such as neglecting to implement server-side `jti`/nonce tracking, setting excessively long token expiration times without robust revocation, or misunderstanding the shared responsibility between JWT libraries and application code for comprehensive validation. While libraries like `github.com/golang-jwt/jwt/v5` provide the tools for parsing and cryptographic verification, the onus is on the developer to implement the stateful logic required for replay prevention.

The impact of a successful JWT replay attack can be severe, ranging from unauthorized access to sensitive data and user impersonation to privilege escalation and fraudulent transactions, ultimately leading to financial loss and reputational damage.

Effective remediation requires a defense-in-depth approach. Key strategies include issuing short-lived access tokens, mandating the use of unique `jti` claims (or nonces) that are validated against a server-side store of used tokens, implementing robust refresh token mechanisms, and establishing effective token revocation capabilities (e.g., blacklisting). Golang developers must ensure their JWT validation logic is thorough, explicitly checking all relevant claims and leveraging library features correctly, such as parser options for expiration and custom validators for `jti` uniqueness. The evolution of JWT libraries and security best practices, as seen with `golang-jwt/jwt/v5` and discussions around error handling, underscores the need for continuous learning and adaptation to maintain secure JWT implementations.

In essence, while JWTs offer advantages in modern application architectures, their secure use in Golang, as in any environment, demands diligent implementation of server-side controls to prevent attackers from reusing valid tokens for malicious purposes.

## **16. References**

- RFC 7519: JSON Web Token (JWT).
    
- OWASP API Security Top 10 (2023).
    
- OWASP Cheat Sheet Series (General Principles).
    
- `github.com/golang-jwt/jwt/v5` library documentation and discussions.
    
- Cloudflare. (n.d.). *JWT Validation*. API Shield.
    
- MojoAuth. (2024). *Understanding JWT Issued At (iat) Claim: A Comprehensive Guide*.
    
- Sophos. (2025). *JSON Web Tokens Explained*.

- AspiaInfoTech. (2024). *JSON Web Tokens (JWT) Attacks And How To Prevent Them*.
    
- NordVPN. (2024). *What is a replay attack and how to prevent it?*

    
- F5 Labs. (2020). *JWT: A How Not to Guide*.
    
- Stack Overflow. (2020). *Preventing JWT replay attacks against the client side*.

    
- Stack Overflow. (2016). *Can I prevent a replay attack of my signed JWTs?*
    
- Oligo Security. (2025). *OWASP Top 10: Cheat Sheet of Cheat Sheets*.
    
- Permify. (2024). *Implementing JWT Authentication In Go*.
    
- Gist - andreyvit. (2023). *Example simple JWT implementation for Go*.
    
- Okta. (2024). *okta-jwt-verifier-golang*. GitHub.
    
- `golang-jwt/jwt` GitHub Repository.
    
- Reddit r/golang. (2024). *Authentication in go*.
    
- SuperTokens. (2024). *Revoke Access Using a JWT Blacklist*.
    
- PortSwigger. (n.d.). *JWT attacks | Web Security Academy*.
    
- LoginRadius. (2025). *Complete Guide to JSON Web Token (JWT) and How It Works*.
    
- Okta Developer. (2024). *Elevate Access Token Security by Demonstrating Proof-of-Possession*.
    
- FOSSA. (2024). *Understanding CVSS: The Common Vulnerability Scoring System*.
    
- Strobes Security. (2024). *CVSS Score: A Comprehensive Guide to Vulnerability Scoring*.
    
- The Green Report. (2025). *JWT Token Security Testing: Building a Custom Fuzzer for Authorization Header Attacks*.
    
- DEV Community - Leapcell. (2025). *JWT in Action: Secure Authentication & Authorization in Go*.

- SuperTokens. (2024). *What is JWT? Understand JSON Web Tokens*.
    
- Reddit r/node. (2024). *JWT auth best practices*.
    
- CVE-2024-51744. National Vulnerability Database.
    
- Linode. (2024). *The Dangers of the Never-Expiring JWT*.
    
- MojoAuth. (2024). *Understanding JWT Expiration Time claim (exp)*.
    
- Turing Secure. (n.d.). *Session Token Does Not Expire (CWE-613)*.
    
- Cyprox. (n.d.). *Vulnerabilities - JWT Expiration Time (CWE-613)*.

- Common Weakness Enumeration (CWE). MITRE. (e.g., CWE-287, CWE-294, CWE-384, CWE-613).
