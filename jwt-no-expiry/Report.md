# **Golang Vulnerability Report: Improper JWT Expiration (jwt-no-expiry)**

## **1. Vulnerability Title**

JWT Not Expiring Properly (jwt-no-expiry) in Golang Applications

## **2. Severity Rating**

**Medium🟡 to High🟠**

The severity of the "JWT not expiring properly" vulnerability is context-dependent, ranging from Medium to High. This variability is influenced by factors such as the sensitivity of the resources protected by the JSON Web Token (JWT) and the likelihood of the token being compromised. A non-expiring token that grants access to low-impact, publicly readable data would pose a lower risk than one controlling access to sensitive financial transactions, personally identifiable information (PII), or administrative functions.

The Common Weakness Enumeration (CWE) entry CWE-613 ("Insufficient Session Expiration"), which closely aligns with this vulnerability, is often rated as High. For instance, CVE-2025-2559, related to Keycloak's caching of JWTs with excessively long expiration times leading to a Denial of Service (DoS), has a CVSS 3.1 score of 4.9 (Medium). Conversely, vulnerabilities involving fundamental flaws in JWT handling, such as hard-coded JWTs (e.g., CVE-2025-20188), can receive Critical ratings (9.8), underscoring the potential severity when token security is compromised.

The absence of expiration, or improper handling thereof, significantly increases the attack window if a token is stolen or leaked. This risk is further compounded if other JWT security best practices, such as secure token storage on the client-side (e.g., HttpOnly cookies) and consistent use of HTTPS for transmission, are neglected. If a token is more likely to be compromised due to these other failings, a non-expiring nature makes that compromise far more damaging.

The following table provides an illustrative CVSS v3.1 vector analysis for a scenario where a non-expiring JWT grants significant access:

| **CVSS Metric** | **Assessed Value for jwt-no-expiry (Illustrative)** | **Justification** |
| --- | --- | --- |
| Attack Vector (AV) | Network (N) | JWTs are typically used over networks. |
| Attack Complexity (AC) | Low (L) | If a token is compromised, using it is straightforward. Discovery of the vulnerability might depend on code review or observing token behavior. |
| Privileges Required (PR) | None (N) | An attacker needs to obtain a token (e.g., through theft, leakage) but doesn't need prior privileges on the system itself to use an already issued, non-expiring token. |
| User Interaction (UI) | None (N) | No user interaction is typically required to exploit a stolen, non-expiring token. |
| Scope (S) | Unchanged (U) | Typically, the exploit impacts resources within the same security authority. |
| Confidentiality (C) | High (H) | If the token grants access to sensitive data. |
| Integrity (I) | High (H) | If the token allows modification of sensitive data or system state. |
| Availability (A) | Low (L) / Medium (M) | May not directly cause unavailability unless combined with other issues (e.g., resource exhaustion from processing many old tokens, or DoS if missing expiry leads to panics in certain library versions). |
| **Illustrative Base Score:** | **7.0 - 8.8 (High)** | Depending on C/I/A impacts. |

This illustrative scoring suggests a High severity, particularly when sensitive data or critical functionalities are protected by the JWT.

## **3. Description**

The "JWT not expiring properly" vulnerability, colloquially termed "jwt-no-expiry," arises when JSON Web Tokens are issued without a correctly configured and enforced expiration time, or when server-side validation logic fails to adequately check or interpret the standard `exp` (expiration time) claim. Consequently, a JWT that should have become invalid after a certain period remains usable indefinitely. This allows an attacker, or any holder of such a token (even if legitimately obtained initially but subsequently compromised or leaked), to maintain unauthorized access to protected resources or functionalities long after the intended access window has closed.

This vulnerability typically manifests in one of two ways:

1. **Token Generation Flaw:** The application logic responsible for creating JWTs either omits the `exp` claim entirely, uses a non-standard claim for expiration , or sets the `exp` claim to an effectively infinite or excessively long duration.

2. **Token Validation Flaw:** The server-side application logic responsible for parsing and validating incoming JWTs does not check the `exp` claim, or checks it incorrectly, thereby accepting tokens that have, according to their `exp` claim, already expired. This can also occur if error handling during token validation is flawed, masking expiration errors.

JWTs are widely adopted for their stateless nature, meaning the server does not need to store session state for each client. This statelessness relies on the assumption that tokens are self-contained and have a limited lifespan, after which they are inherently untrusted. Non-expiring tokens break this fundamental security assumption. While statelessness is a benefit, the absence of a finite validity period for the token turns this feature into a significant liability, as the primary mechanism for automatically revoking access (i.e., time-based expiration) is nullified. The vulnerability is classified under CWE-613: Insufficient Session Expiration.

## **4. Technical Description**

The core of this vulnerability lies in the improper handling of the `exp` (Expiration Time) claim defined in RFC 7519, "JSON Web Token (JWT)". According to RFC 7519, the `exp` claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing. Its value MUST be a number containing a NumericDate value (a JSON number representing seconds since 1970-01-01T00:00:00Z UTC, ignoring leap seconds).

In Golang applications, JWTs are commonly handled by libraries such as `github.com/golang-jwt/jwt` (versions v4, v5, etc., which is a community-maintained fork of the now-archived `github.com/dgrijalva/jwt-go`). The vulnerability can arise from several technical missteps related to these libraries:

1. Omission or Misconfiguration of exp during Generation:
    
    If the exp claim is not included when the token is created, or if a non-standard claim like ttl is used instead, most JWT parsing libraries will not recognize an expiration time, effectively treating the token as non-expiring.
    
2. Lack of Server-Side exp Validation by Default:
    
    A critical aspect, particularly with github.com/golang-jwt/jwt/v5, is that the ParseWithClaims function does not validate the exp claim by default. Developers must explicitly use the jwt.WithExpirationRequired() parser option to enforce this check.16 Without this option, a token will be considered valid if its signature is correct, even if the exp claim is in the past or missing. This "less secure by default" behavior is a frequent source of the vulnerability if developers are unaware or overlook this requirement.
    
3. Incorrect Manual Validation Logic:
    
    If developers attempt to manually validate the exp claim after parsing (perhaps because they are not using WithExpirationRequired() or are using an older library version), their logic can be flawed. For example, checking if claims.ExpiresAt < time.Now().Unix() can be problematic if claims.ExpiresAt is a zero value (the default for int64 if the claim is not present in the token or not parsed into the struct field), as 0 will always be less than the current Unix timestamp, leading to incorrect validation outcomes.
    
4. Complex Error Handling and Masking:
    
    As highlighted by CVE-2024-51744 for golang-jwt, unclear documentation or complex error wrapping can lead to developers improperly checking returned errors.10 If a token is both expired and has an invalid signature, ParseWithClaims might return multiple error types. If the application code only checks for jwt.ErrTokenExpired (e.g., using errors.Is) and considers the token invalid solely on that basis, it might inadvertently ignore a concurrent jwt.ErrTokenSignatureInvalid error. While this specific CVE is about combined errors potentially leading to invalid tokens being accepted if error checking is too narrow, it underscores how mishandling errors from parsing functions can subvert validation logic, including for expiration.
    
5. Pointer vs. Value Semantics in Custom Claims (DoS Risk):
    
    A subtle Golang-specific issue was identified in golang-jwt/jwt/v4 where embedding *jwt.RegisteredClaims (a pointer) in a custom claims struct, rather than jwt.RegisteredClaims (a value), could lead to a nil pointer if the JWT being parsed did not contain any standard registered claims (like ExpiresAt). If the Valid() method was subsequently called on this nil embedded pointer, it would cause a panic and a Denial of Service (DoS).8 This is a direct consequence of a token potentially missing an ExpiresAt claim (or other standard claims) leading to a crash, linking the absence or improper handling of expiration data to service unavailability.
    

While other claims like `iat` (Issued At) and `nbf` (Not Before) are part of the token lifecycle and should also be validated, the `exp` claim is paramount for preventing indefinite token validity.

## **5. Common Mistakes That Cause This**

Several common mistakes by developers can lead to the "JWT not expiring properly" vulnerability in Golang applications. These often stem from misunderstandings of JWT standards, library defaults, or insufficient attention to security details during implementation.

1. Omitting the exp Claim During Token Generation:
    
    The most straightforward mistake is simply not including the exp claim when the JWT is created. Developers might set other claims like iat (Issued At) but forget to define a finite lifespan for the token.
    
2. Using Non-Standard Claims for Expiration:
    
    Instead of the RFC 7519 standard exp claim, developers might use custom or non-standard claims like ttl (time-to-live) to specify the intended duration.9 JWT parsing libraries, unless specifically configured to understand these custom claims for expiration, will ignore them, treating the token as if it has no expiration.
    
3. Incorrectly Setting the exp Claim Value:
    
    The exp claim must be a NumericDate (Unix timestamp in seconds). Mistakes include:
    
    - Setting it to a zero value.
    - Accidentally setting it to a date very far in the future due to calculation errors.
    - Using an incorrect format (e.g., milliseconds instead of seconds, or a relative duration instead of an absolute timestamp).
4. Server-Side: Failing to Validate the exp Claim:
    
    Even if the exp claim is correctly set during generation, the server consuming the JWT might not validate it. This is a critical omission in the validation logic.
    
5. Relying Solely on Client-Side Expiration Checks:
    
    Any checks performed on the client-side can be bypassed by an attacker. Expiration validation MUST occur on the server.
    
6. Misunderstanding Golang JWT Library Defaults:
    
    As discussed previously, a significant cause in Golang is the assumption that JWT libraries, like github.com/golang-jwt/jwt/v5, validate the exp claim by default when parsing. Functions like ParseWithClaims require explicit options (e.g., jwt.WithExpirationRequired()) to enforce this validation.16 Without such options, the token might be considered structurally valid and have a verified signature, yet its expiration status is ignored by the parser itself. A developer might then incorrectly assume the token's exp claim was validated by the library.
    
7. Flawed Manual Expiration Checks:
    
    If developers opt for manual validation of the exp claim after parsing (instead of using library-provided mechanisms), their logic can be faulty. A common error is not correctly handling cases where ExpiresAt might be zero (if the claim was absent or not parsed correctly), leading to incorrect comparisons with the current time.17 For example, if claims.ExpiresAt!= 0 && claims.ExpiresAt < time.Now().Unix() is a more robust manual check than simply claims.ExpiresAt < time.Now().Unix().
    
8. Improper Error Handling from JWT Parsing Functions:
    
    JWT parsing functions can return various errors. If the application code does not meticulously check for and correctly interpret these errors, it might mask an expiration validation failure or other critical validation issues.10 For instance, broadly catching all errors as generic "invalid token" without specific handling for jwt.ErrTokenExpired means the application doesn't act appropriately on expiration. Conversely, as seen in CVE-2024-51744, only checking for ErrTokenExpired and ignoring other co-occurring errors like ErrTokenSignatureInvalid can also lead to accepting an invalid token.
    

The following table summarizes these common mistakes:

| **Mistake Category** | **Specific Error** | **Golang Context/Example** | **Consequence** |
| --- | --- | --- | --- |
| Token Generation | Omitting `exp` claim | `jwt.MapClaims{"user_id": 123}` (no `exp`) | Token never expires. |
| Token Generation | Using non-standard expiration claim | `jwt.MapClaims{"ttl": 3600}` instead of `exp` | `exp` is not recognized; token treated as non-expiring. |
| Token Generation | Incorrect `exp` value | Setting `exp` to `0` or a malformed timestamp. | Token may be treated as non-expiring or immediately expired, depending on validation logic. |
| Token Validation | No server-side `exp` check | Relying on client-side checks or assuming library default. | Expired tokens accepted by server. |
| Library Usage (Validation) | `golang-jwt/jwt/v5`: `ParseWithClaims` without `WithExpirationRequired()` | `jwt.ParseWithClaims(tokenString, &claims, keyFunc)` | `exp` claim is not validated by the parser by default.|
| Library Usage (Validation) | Flawed manual `exp` check | `if claims.RegisteredClaims.ExpiresAt.Unix() < time.Now().Unix()` without checking if `ExpiresAt` is non-nil/non-zero. | Incorrectly validates tokens, especially if `exp` is missing or zero. |
| Error Handling | Ignoring or misinterpreting parsing errors | `if err!= nil { /* generic error */ }` without specific check for `jwt.ErrTokenExpired` or other validation errors. | Expiration failures might be masked or misattributed. |

Addressing these common mistakes requires careful attention during both JWT generation and validation phases, thorough understanding of the JWT libraries being used, and robust error handling.

## **6. Exploitation Goals**

The primary goals of exploiting a "JWT not expiring properly" vulnerability revolve around illegitimately extending access to protected resources and services. Attackers aim to:

1. Session Hijacking / Unauthorized Persistent Access:
    
    The most direct goal is to reuse a compromised or stolen JWT indefinitely. If a token does not expire, an attacker who obtains it (e.g., through malware, XSS, insecure logging, or a data breach) can impersonate the legitimate user for an unlimited period, maintaining access to their account and associated resources long after the legitimate session should have ended.2
    
2. Privilege Escalation (if the token has high privileges):
    
    If the non-expiring token belongs to an administrative user or an account with elevated privileges, the attacker gains long-term administrative control over the system or application.19 This can lead to complete system compromise.
    
3. Bypassing Re-authentication Mechanisms:
    
    Systems often require users to re-authenticate after a certain period of inactivity or session duration. A non-expiring token allows an attacker (or even a legitimate user whose token was compromised unknowingly) to bypass these re-authentication prompts, maintaining access without needing to provide credentials again.
    
4. Maximizing the Utility of Stolen Tokens:
    
    The value of a stolen token to an attacker is directly proportional to its validity period. A non-expiring token is maximally valuable because it provides a persistent backdoor. This is particularly dangerous as the initial token theft might be a one-time event, but its consequences become ongoing due to the lack of expiration.12
    

The "jwt-no-expiry" vulnerability often acts as an **amplifier** for other security weaknesses. For instance:

- If an XSS vulnerability allows an attacker to steal a JWT from a user's browser, a non-expiring token means the attacker can use that token for days, weeks, or even longer, instead of just a few minutes or hours.
- If tokens are inadvertently logged in an insecure manner, a non-expiring token found in old logs could still be active.

Furthermore, this vulnerability facilitates **stealth and persistence**. Once an attacker has a non-expiring token, they may not need to perform further actions that could trigger intrusion detection systems (e.g., repeated failed login attempts, exploiting other vulnerabilities to regain access). They can silently maintain their foothold using the compromised token as long as the server continues to accept it.

## **7. Affected Components or Files**

The "JWT not expiring properly" vulnerability primarily affects components involved in the lifecycle of JSON Web Tokens within Golang applications. These include:

1. **Golang JWT Libraries:**
    - **`github.com/golang-jwt/jwt` (versions v4, v5, etc.):** This is the current de facto standard JWT library for Golang. Specific functions like `ParseWithClaims` are central to validation, and their usage (e.g., with or without options like `WithExpirationRequired()`) is critical. Different versions may have different default behaviors or specific bugs related to claim validation (e.g., the DoS issue in v4 if `ExpiresAt` was missing from a token and a pointer to `RegisteredClaims` was used , or error handling nuances in CVE-2024-51744 ).
        
    - **`github.com/dgrijalva/jwt-go` (archived):** The predecessor to `golang-jwt/jwt`. Applications still using this older, unmaintained library are at risk not only from this vulnerability if improperly used but also from other known and unfixed security issues. Code using this library for parsing would need careful review of its expiration handling.

2. **Authentication Middleware:**
    - Any custom-written or third-party middleware in Golang web frameworks (e.g., Gin, Echo, Fiber, standard `net/http`) that is responsible for intercepting requests, extracting JWTs, and validating them. If this middleware does not correctly invoke library functions for expiration checking or implements flawed manual checks, it becomes a vulnerable component.
        
3. **API Endpoints and Backend Services:**
    - Any Golang backend code that directly consumes JWTs for authenticating and authorizing access to specific API endpoints or services. If validation is decentralized to individual handlers rather than centralized in middleware, each such handler is a potential point of failure.
4. **Token Generation Logic:**
    - The parts of the Golang application responsible for creating and signing JWTs. If this logic omits the `exp` claim, sets it incorrectly (e.g., using non-standard claims, zero values, or excessively far-future dates), or uses weak keys/algorithms (which, while not directly "no-expiry," weakens overall token security), it contributes to the vulnerability.

The specific files affected would be any `.go` source files containing the JWT generation or validation logic. This often includes files named `auth.go`, `middleware.go`, `jwt_handler.go`, or similar, within the application's codebase.

It is crucial to recognize that library versioning plays a significant role. Default behaviors, available options, and known bugs can differ between versions of the same library. Therefore, identifying affected components requires not just looking at the library name but also the specific version and how its API is utilized for expiration handling. Custom JWT implementations, while less common if standard libraries are available, are inherently high-risk if they do not meticulously adhere to RFC 7519 for `exp` claim processing and cryptographic best practices.

## **8. Vulnerable Code Snippet**

The following Golang code snippets illustrate common ways the "JWT not expiring properly" vulnerability can manifest. These examples primarily use the `github.com/golang-jwt/jwt/v5` library.

**Scenario 1: Token Generation Without `exp` Claim**

This snippet shows a JWT being generated without setting the standard `exp` (expiration) claim.

```Go

package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Key used for signing the token. In a real application, this should be a strong, securely managed key.
var mySigningKey =byte("mysecretkey")

func generateVulnerableToken_NoExpiry() (string, error) {
	// Create the token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set claims
	claims := token.Claims.(jwt.MapClaims)
	claims["authorized"] = true
	claims["user_id"] = "12345"
	claims["iat"] = time.Now().Unix() // IssuedAt is set
	// VULNERABILITY: 'exp' (Expiration Time) claim is NOT set.
	// claims["exp"] = time.Now().Add(time.Minute * 15).Unix() // This line would fix it

	// Sign the token
	tokenString, err := token.SignedString(mySigningKey)
	if err!= nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}
	return tokenString, nil
}

func main() {
	vulnToken, err := generateVulnerableToken_NoExpiry()
	if err!= nil {
		fmt.Println("Error generating vulnerable token:", err)
		return
	}
	fmt.Println("Vulnerable Token (No Expiry):", vulnToken)
	// This token, if used by a server not strictly validating 'exp',
	// or if the validating library doesn't check 'exp' by default,
	// could be accepted indefinitely.
}
```

In the `generateVulnerableToken_NoExpiry` function, the `exp` claim is commented out. A token generated this way lacks a defined expiration time.

**Scenario 2: Token Validation Ignoring `exp` Claim (Common Mistake with `golang-jwt/jwt/v5`)**

This snippet demonstrates parsing a JWT using `jwt.ParseWithClaims` from `golang-jwt/jwt/v5` without explicitly enabling expiration validation via `jwt.WithExpirationRequired()`.

```Go

package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Key used for signing the token.
var mySigningKey =byte("mysecretkey")

// CustomClaims structure embedding jwt.RegisteredClaims
type CustomClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// Function to simulate generating a token that *should* expire
func generateTokenWithExpiry() (string, error) {
	expirationTime := time.Now().Add(-5 * time.Minute) // Token is already expired
	claims := &CustomClaims{
		UserID: "testuser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "test-issuer",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(mySigningKey)
}

// Vulnerable validation function
func validateTokenVulnerably(tokenString string) (*CustomClaims, error) {
	claims := &CustomClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Basic validation: check signing algorithm
		if _, ok := token.Method.(*jwt.SigningMethodHMAC);!ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return mySigningKey, nil
	})
	// VULNERABILITY: jwt.WithExpirationRequired() option is MISSING in ParseWithClaims.
	// The library will not automatically validate the 'exp' claim by default.
	// See: [16]

	if err!= nil {
		// Error might be due to signature, malformed token, etc., but not necessarily 'exp' if not checked.
		// If 'exp' was in the past, 'err' would contain jwt.ErrTokenExpired *if* WithExpirationRequired was used.
		// Or if a manual check for claims.Valid() was done after successful parsing (which also checks exp).
		return nil, err
	}

	if token.Valid { // token.Valid checks signature and, if RegisteredClaims is used, standard claims like exp, nbf, iat.
		// However, the initial parsing might not have failed on 'exp' if not explicitly told to.
		// A common mistake is to assume if err == nil and token.Valid is true, all is well,
		// without ensuring 'exp' was part of the strict parsing validation.
		// If WithExpirationRequired() is not used, an expired token might pass this stage if the
		// only error returned (and thus caught above) was related to something else, or if no error
		// was returned because 'exp' wasn't a parsing failure condition.
		
		// More robust check if not using WithExpirationRequired:
		// Manually validate expiration from claims, being careful of zero values.
		// if claims.ExpiresAt == nil |
| claims.ExpiresAt.Time.IsZero() {
		//     return nil, fmt.Errorf("token has no expiration time")
		// }
		// if time.Now().Unix() > claims.ExpiresAt.Unix() {
		//     return nil, fmt.Errorf("token is expired (manual check)")
		// }
		// The above manual check itself can be flawed if claims.ExpiresAt is not populated correctly or is zero.
		// Example of a potentially flawed manual check from [17]:
		// if claims.ExpiresAt.Unix() < time.Now().Unix() { /* This is problematic if ExpiresAt is 0 or nil */ }

		return claims, nil
	}

	return nil, fmt.Errorf("token is invalid")
}

func main() {
	expiredTokenString, _ := generateTokenWithExpiry()
	fmt.Println("Generated Expired Token:", expiredTokenString)

	parsedClaims, err := validateTokenVulnerably(expiredTokenString)
	if err!= nil {
		fmt.Println("Token validation failed (as expected for expired token if properly checked):", err)
		// If WithExpirationRequired() was used, err would include jwt.ErrTokenExpired.
		// If token.Claims.Valid() is called, it would also return an error for an expired token.
		// The vulnerability lies in *not* using these checks or misinterpreting their absence.
	} else {
		// VULNERABLE OUTCOME: If this block is reached with an expired token,
		// it means expiration was not properly checked.
		fmt.Println("VULNERABLE: Token validated successfully despite being expired. UserID:", parsedClaims.UserID)
	}
}
```

In `validateTokenVulnerably`, the call to `jwt.ParseWithClaims` lacks the `jwt.WithExpirationRequired()` option. While `token.Valid` does check standard claims if `jwt.RegisteredClaims` is embedded and populated, the primary parsing step itself might not fail due to expiration without the explicit option. A developer might incorrectly assume that if `err` is `nil` after `ParseWithClaims` and `token.Valid` is true, the token is fully vetted, including its expiration, without realizing the library's default behavior regarding `exp` validation during parsing. The snippet also alludes to potentially flawed manual checks (commented out) as another path to vulnerability if library mechanisms are bypassed or misunderstood.*

These snippets illustrate how omissions in generation or reliance on library defaults without full understanding during validation can lead to JWTs being treated as non-expiring.

## **9. Detection Steps**

Detecting the "JWT not expiring properly" vulnerability in Golang applications requires a combination of static analysis, dynamic analysis, manual code review, and dependency checking.

1. **Static Analysis (SAST):**
    - **Scan Golang code for JWT generation patterns:**
        - Identify where JWTs are created (e.g., calls to `jwt.NewWithClaims`, `token.SignedString` from `github.com/golang-jwt/jwt`).
        - Verify that the `exp` claim (e.g., via `jwt.RegisteredClaims.ExpiresAt` or `jwt.MapClaims["exp"]`) is consistently populated with a valid, future, non-zero Unix timestamp.
        - Flag instances where `exp` is missing, set to a static far-future date, or uses non-standard fields (e.g., `ttl`).
    - **Scan for JWT validation patterns:**
        - Locate calls to JWT parsing functions like `jwt.ParseWithClaims`.
        - For `github.com/golang-jwt/jwt/v5`, check if the `jwt.WithExpirationRequired()` option is used.
            
        - If older versions or different libraries are used, verify that their respective mechanisms for enforcing expiration checks are correctly invoked.
        - Analyze any manual timestamp comparisons involving `claims.ExpiresAt`. Ensure they correctly handle zero or `nil` values for `ExpiresAt` and compare against the current time appropriately.
            
    - **Review error handling:** Examine the code immediately following JWT parsing calls. Ensure that errors indicating expiration (e.g., `jwt.ErrTokenExpired`) are explicitly checked for and handled, and not masked by generic error handling or by only checking for other types of errors (e.g., signature invalidity).
        
2. **Dynamic Analysis (DAST):**
    - **Token Replay After Expiry:**
        1. Authenticate to the application to obtain a JWT.
        2. Decode the JWT (the payload is typically Base64URL encoded, not encrypted) to identify its `exp` claim value and determine its intended expiration time.
        3. Wait until after this intended expiration time has passed.
        4. Attempt to use the original, now-expired JWT to access protected resources.
        5. If access is granted, the vulnerability is confirmed.
    - **Testing with Modified/Missing `exp` Claim:**
        1. If possible (e.g., during development or if token signing keys are known), generate tokens with no `exp` claim or an `exp` claim set to the past.
        2. Attempt to use these tokens to access protected resources. Successful access indicates a vulnerability.
    - **Security Testing Tools:** Employ web application scanners or API security testing tools that have capabilities to inspect JWTs. Many tools can automatically flag tokens with missing or invalid `exp` claims, or those with excessively long validity periods.
3. **Manual Code Review:**
    - **Focus Areas:** Concentrate on authentication middleware, token generation services, and any API endpoint handlers that directly parse or validate JWTs.
    - **Library Documentation:** Cross-reference the usage of JWT library functions with the official library documentation to ensure correct application of validation options and interpretation of return values/errors.
    - **RFC 7519 Compliance:** Verify that the handling of the `exp` claim aligns with the requirements of RFC 7519.
        
    - **Clock Skew:** Check if a reasonable leeway for clock skew is considered during expiration validation, as recommended by RFC 7519 and supported by options like `WithLeeway` in `golang-jwt/jwt/v5`.
        
4. **Dependency Checking:**
    - Utilize tools like `govulncheck`  to scan project dependencies for known vulnerabilities in the JWT libraries used. This can identify issues like the DoS vulnerability in `golang-jwt/jwt/v4` related to tokens missing an `ExpiresAt` claim , or error handling issues like CVE-2024-51744 in `golang-jwt`.
        
    - Regularly update dependencies to patched versions.

Effective detection often involves a multi-faceted approach. For instance, SAST might flag potentially problematic code using `ParseWithClaims` without `WithExpirationRequired()`, and DAST can then be used to confirm if an expired token is indeed accepted by the live application. Manual review is crucial for understanding nuanced logic errors, especially in custom validation routines or complex error handling paths.

## **10. Proof of Concept (PoC)**

This Proof of Concept (PoC) demonstrates the "JWT not expiring properly" vulnerability in a simplified Golang HTTP server. It will show a token being accepted even after its intended (but improperly handled) expiration.

**PoC Steps:**

1. **Setup a Golang HTTP Server:**
    - Create a simple HTTP server with one endpoint (e.g., `/protected`) that requires JWT authentication.
    - Implement a login endpoint (e.g., `/login`) that generates a JWT.
2. **Vulnerable Token Generation:**
    - The `/login` endpoint will generate a JWT. For this PoC, we will simulate two scenarios leading to non-expiring behavior:
        - **Scenario A (No `exp` claim):** Generate a token without setting the `exp` claim.
        - **Scenario B (Ignored `exp` claim during validation):** Generate a token *with* an `exp` claim set to a short future time (e.g., 5 seconds), but the `/protected` endpoint's validation logic will deliberately omit the check for this `exp` claim (e.g., by not using `jwt.WithExpirationRequired()` in `golang-jwt/jwt/v5` and not performing a correct manual check).
3. **Initial Access:**
    - Call the `/login` endpoint to receive the JWT.
    - Immediately use this token to access the `/protected` endpoint. Access should be granted.
4. **Simulate Time Passage:**
    - Wait for a period longer than the intended short expiration (e.g., 10 seconds for Scenario B). For Scenario A, any wait time demonstrates the problem.
5. **Attempt Re-access with the Same Token:**
    - After the wait, use the *exact same JWT* obtained in Step 3 to try and access the `/protected` endpoint again.
6. **Observe Outcome:**
    - **Vulnerable Outcome:** If access to `/protected` is *granted* again, the vulnerability is demonstrated. The token was accepted despite being (or intended to be) expired.
    - **Secure Outcome (for comparison):** If access is *denied* (typically with a 401 Unauthorized error), the expiration is being handled correctly.

**Illustrative Golang Code (Conceptual for Scenario B - Ignored `exp`):**

```Go

package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var mySigningKey =byte("pocsecretkey")

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// In a real app, you'd validate credentials here
	expirationTime := time.Now().Add(5 * time.Second) // Token should expire in 5 seconds
	claims := &Claims{
		Username: "testuser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(mySigningKey)
	if err!= nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, tokenString)
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	claims := &Claims{}

	// VULNERABLE VALIDATION: ParseWithClaims without WithExpirationRequired()
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC);!ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return mySigningKey, nil
	})

	// Incorrectly assumes err == nil && token.Valid is sufficient without strict 'exp' parsing.
	if err == nil && token.Valid {
		// Even if token.Valid checks 'exp' from RegisteredClaims, if ParseWithClaims was configured
		// with WithExpirationRequired(), the error would have been caught earlier and more explicitly.
		// This PoC relies on the default parsing behavior not failing on 'exp' if not told to.
		fmt.Fprintf(w, "Welcome, %s! Access to protected resource granted.", claims.Username)
	} else {
		// This error might not be jwt.ErrTokenExpired if not checked during parsing.
		log.Printf("Token validation error: %v", err)
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}
}

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/protected", protectedHandler)

	log.Println("Server starting on port 8080...")
	if err := http.ListenAndServe(":8080", nil); err!= nil {
		log.Fatal(err)
	}
}
```

**Execution of PoC:**

1. Run the Golang server.
2. **Get Token:** Send a request to `http://localhost:8080/login`. Copy the received JWT string.
3. **Initial Access:** Immediately send a GET request to `http://localhost:8080/protected` with the `Authorization: Bearer <JWT_STRING>` header.
    - *Expected:* "Welcome, testuser! Access to protected resource granted."
4. **Wait:** Wait for 10 seconds (longer than the 5-second intended expiry).
5. **Attempt Re-access:** Send the *same* GET request to `http://localhost:8080/protected` with the same JWT in the Authorization header.
    - **Vulnerable Outcome:** "Welcome, testuser! Access to protected resource granted." This demonstrates the token was accepted despite its `exp` claim being in the past because the validation logic did not strictly enforce it during parsing or subsequent checks.
    - **Secure Outcome (if `jwt.WithExpirationRequired()` was used or a correct manual check was in place):** HTTP 401 Unauthorized with a message like "Invalid or expired token."

This PoC illustrates that the absence of rigorous server-side expiration validation allows a token, which should be expired, to continue granting access, thereby confirming the "jwt-no-expiry" vulnerability.

## **11. Risk Classification**

The "JWT not expiring properly" vulnerability carries significant risk, categorized as follows:

- **CWE (Common Weakness Enumeration):**
    - **CWE-613: Insufficient Session Expiration:** This is the most direct classification. When a JWT, which often functions as a session token, does not expire or its expiration is not enforced, it leads to sessions that can be hijacked or misused indefinitely if the token is compromised.
        
    - **CWE-347: Improper Verification of Cryptographic Signature:** While not always directly linked, if the lack of expiration check is part of a broader pattern of lax validation (e.g., also allowing `alg: none` or weak signature checks), this CWE can become relevant. An attacker might try to bypass other checks if they know the token will be long-lived.
        
    - **CWE-287: Improper Authentication:** A non-expiring token can lead to a state of improper authentication over time. An initially valid authentication (represented by the JWT) is not re-validated or timed out, allowing potentially stale or compromised credentials (the token itself) to grant access indefinitely.
- **OWASP API Security Top 10 (2023):**
    - **API2:2023 - Broken Authentication:** A non-expiring token can be considered a facet of broken authentication. The system fails to properly terminate authentication status after a reasonable period, allowing a compromised token to grant access as if it were a fresh authentication.
    - **API5:2023 - Broken Function Level Authorization:** If a user's roles or permissions change, but their old, non-expiring token (issued when they had higher privileges) is still accepted, it leads to a bypass of current authorization rules.
    - **API8:2023 - Security Misconfiguration:** The failure to correctly configure JWT generation (by omitting `exp`) or validation (by not checking `exp`) is a clear security misconfiguration of the authentication mechanism.
- **Risk Rating (based on OWASP Risk Rating Methodology):**
    - **Likelihood:** Can range from **Medium to High**.
        - *Ease of Discovery:* If the vulnerability stems from common misconfigurations of popular Golang libraries (e.g., default behavior of `ParseWithClaims` in `golang-jwt/jwt/v5` not checking `exp` without specific options ), it can be relatively easy to discover through code review or by observing token behavior. Automated tools might also flag JWTs lacking `exp` claims.

        - *Ease of Exploit:* Once an attacker obtains a non-expiring token (through other means like XSS, data breaches, insecure logging), exploiting the "no-expiry" aspect is trivial – they simply keep using the token. The difficulty lies in obtaining the token initially.
    - **Impact:** Can range from **Medium to High**, and potentially **Critical**.
        - *Loss of Confidentiality/Integrity/Availability:* Depends heavily on what resources the JWT protects. If it's an admin token, the impact is high across all three. If it's for user data, confidentiality and integrity are high. Prolonged access due to no expiry amplifies the potential damage from a single token compromise.
        - *Business Impact:* Can include financial loss (if funds are controlled), reputational damage, non-compliance (e.g., with data protection regulations if PII access is prolonged), and loss of user trust.
    - **Overall Risk:** Given these factors, the overall risk is typically assessed as **Medium to High**. In scenarios where highly sensitive functions or data are protected, or where token compromise is more likely due to other weaknesses, the risk can escalate to **Critical**.

The "jwt-no-expiry" vulnerability often serves as a critical link in an attack chain. While the non-expiring token itself might be a latent issue, its true danger materializes when combined with a token leakage or theft vulnerability (e.g., XSS, insecure storage, man-in-the-middle attacks if HTTPS is not enforced). The lack of expiration dramatically increases the window of opportunity and the potential damage an attacker can inflict with a stolen token.

## **12. Fix & Patch Guidance**

Addressing the "JWT not expiring properly" vulnerability in Golang applications requires a multi-faceted approach, focusing on both correct token generation and rigorous server-side validation.

1. Always Use the Standard exp Claim for Expiration:
    
    During JWT generation, ensure the exp (Expiration Time) claim is always included and correctly formatted as per RFC 7519 (a NumericDate representing seconds since epoch).11 Avoid using non-standard claims like ttl for expiration, as these are typically ignored by standard JWT libraries.9
    
2. Set Reasonable and Short Expiration Times:
    
    Access tokens should have short lifespans, typically ranging from 5 to 15 minutes, or up to an hour depending on the application's risk profile.7 This minimizes the window during which a compromised token can be misused.
    
3. Implement Refresh Tokens for Extended Sessions:
    
    To provide a good user experience without using long-lived access tokens, implement a refresh token mechanism. Refresh tokens are longer-lived tokens that are securely stored by the client and can be exchanged for new, short-lived access tokens.7 Refresh tokens themselves must be securely handled and should also have an expiration and a revocation mechanism.
    
4. Mandatory and Correct Server-Side exp Validation:
    
    This is the most critical step for fixing the vulnerability on the consumer side.
    
    - **For `github.com/golang-jwt/jwt/v5`:** When using `jwt.ParseWithClaims` or similar parsing functions, explicitly enable expiration validation using the `jwt.WithExpirationRequired()` parser option.
        
        ```Go
        
        token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc, jwt.WithExpirationRequired())
        ```
        
    - **Correct Error Handling:** After parsing, meticulously check the returned error. Specifically test for `jwt.ErrTokenExpired` using `errors.Is(err, jwt.ErrTokenExpired)`. Differentiate this from other validation errors like `jwt.ErrTokenSignatureInvalid` or `jwt.ErrTokenNotValidYet` to ensure appropriate action is taken.
        
    - **Older Libraries/Custom Logic:** If using older versions of `dgrijalva/jwt-go` or other libraries, consult their documentation thoroughly to understand how to enforce strict expiration checking. If performing manual checks on the `exp` claim, ensure the logic correctly handles nil or zero values for `ExpiresAt` and compares Unix timestamps accurately.
        
5. Account for Clock Skew:
    
    When validating the exp (and nbf, iat) claims, allow for a small leeway (e.g., a few minutes) to account for potential clock synchronization differences between the issuing server and the validating server.14 The golang-jwt/jwt/v5 library provides the jwt.WithLeeway(duration) parser option for this purpose.24
    
    ```Go
    
    token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc, jwt.WithExpirationRequired(), jwt.WithLeeway(2*time.Minute))
    ```
    
6. Implement Token Revocation/Blacklisting (Denylist):
    
    For highly sensitive applications or immediate invalidation needs (e.g., user logout, password change, suspected compromise), implement a server-side mechanism to revoke tokens before their natural expiration. This typically involves maintaining a denylist of token identifiers (jti claim) or user session identifiers that are no longer valid.12 This introduces some statefulness but significantly enhances security.
    
7. Regularly Update JWT Libraries and Golang:
    
    Keep your JWT handling libraries and the Golang runtime updated to the latest stable versions. Updates often include security patches for known vulnerabilities.9 For example, users of dgrijalva/jwt-go should migrate to github.com/golang-jwt/jwt 15, and be aware of version-specific issues like those in golang-jwt/jwt/v4 8 or error handling clarifications in v4.5.1 for CVE-2024-51744.10
    
8. Secure Token Transmission and Storage:
    
    Always transmit JWTs over HTTPS to prevent interception. On the client-side, store tokens securely (e.g., in HttpOnly cookies for web applications) to mitigate XSS risks.7
    

The following table summarizes key remediation strategies:

| **Strategy** | **Description** | **Golang Implementation Notes (using golang-jwt/jwt/v5)** |
| --- | --- | --- |
| **Enforce `exp` Claim in Generation** | Always include a standard `exp` claim with a Unix timestamp when creating tokens. | Set `RegisteredClaims.ExpiresAt` with `jwt.NewNumericDate(time.Now().Add(duration))`. |
| **Strict Server-Side `exp` Validation** | Ensure the server explicitly validates the `exp` claim during token parsing. | Use `jwt.WithExpirationRequired()` option with `ParseWithClaims`. |
| **Correct Error Handling** | Specifically check for `jwt.ErrTokenExpired` and handle it appropriately. | `if errors.Is(err, jwt.ErrTokenExpired) {... }` |
| **Manage Token Lifespan** | Use short-lived access tokens (e.g., 5-15 mins). Implement refresh tokens for longer sessions. | Application-level logic for token issuance and refresh flow. |
| **Account for Clock Skew** | Allow a small time window (e.g., 1-2 minutes) for `exp` validation to accommodate clock differences. | Use `jwt.WithLeeway(duration)` option with `ParseWithClaims`. |
| **Consider Token Revocation** | For immediate invalidation, implement a server-side denylist for token IDs (`jti`) or user sessions. | Requires custom application logic and a persistent store for the denylist. |
| **Library Updates** | Keep `github.com/golang-jwt/jwt` and other dependencies updated. | Use `go get -u github.com/golang-jwt/jwt/v5` and monitor for security advisories. |

By implementing these measures comprehensively, developers can significantly mitigate the risks associated with improperly expiring JWTs.

## **13. Scope and Impact**

**Scope:**

The "JWT not expiring properly" vulnerability can affect any Golang application or service that utilizes JSON Web Tokens for authentication, authorization, or session management, where the expiration of these tokens is not correctly implemented or enforced. This includes:

- **Web Services and APIs:** Backend services written in Golang that issue and/or consume JWTs to protect endpoints.
- **Microservices Architectures:** Individual Golang microservices that use JWTs for inter-service communication or client authentication.
- **Single Page Applications (SPAs) Backends:** Golang backends serving SPAs that rely on JWTs for user sessions.
- **Mobile Application Backends:** Golang servers providing APIs for mobile clients authenticated via JWTs.

Essentially, any component within a Golang ecosystem that handles JWTs without rigorous expiration control is within the scope of this vulnerability.

**Impact:**

The impact of this vulnerability can be severe and multifaceted:

1. **Prolonged Unauthorized Access:** This is the most direct impact. If a JWT is compromised (e.g., through theft, leakage via XSS, insecure logging, man-in-the-middle if not using HTTPS), its non-expiring nature allows an attacker to use it indefinitely to access protected resources or impersonate the legitimate user.
    
2. **Session Hijacking:** Stolen non-expiring tokens can be used to hijack user sessions for extended periods, potentially long after the user believes their session has ended.
    
3. **Data Breach:** If the compromised token grants access to sensitive user data or confidential business information, its indefinite validity can lead to a more extensive data breach over time.
4. **Privilege Escalation:** If a non-expiring token associated with an administrative or privileged account is compromised, the attacker gains persistent high-level access, which can be used to further compromise the system, exfiltrate more data, or disrupt services.
    
5. **Bypass of Security Controls:** Expiration is a fundamental security control for time-bound access. Its absence negates this control, potentially allowing bypass of periodic re-authentication requirements.
6. **Compliance Violations:** For applications handling sensitive data (e.g., PII, financial data, health records), indefinite sessions due to non-expiring tokens can violate regulatory compliance requirements (e.g., GDPR, HIPAA, PCI DSS) which often mandate session timeouts and secure credential management.
7. **Reputational Damage:** A security incident stemming from this vulnerability can lead to significant reputational damage for the organization, eroding user trust.
8. **Denial of Service (DoS) - Indirectly:**
    - In specific library versions like `golang-jwt/jwt/v4`, parsing a token that is missing an `ExpiresAt` claim (when using a pointer to `jwt.RegisteredClaims` in the custom claims struct) could lead to a panic due to a nil pointer dereference, causing a DoS for the service processing the token.
        
    - While distinct from "no expiry," tokens with excessively long (but technically present) expiration times can lead to resource exhaustion in some systems that cache tokens until they expire, potentially causing OutOfMemoryErrors and DoS, as seen in the Keycloak vulnerability CVE-2025-2559. This illustrates a related risk of improper time-bound management of tokens.

The impact is often not immediate or obvious. A system might function correctly with non-expiring tokens until a token is actually compromised. At that point, the lack of expiration transforms a potentially limited breach into a persistent security hole, making it a "silent killer" that can be exploited over a long duration without raising immediate alarms unless robust monitoring for anomalous token usage is in place.

## **14. Remediation Recommendation**

A comprehensive remediation strategy for the "JWT not expiring properly" vulnerability in Golang applications involves proactive measures during development, rigorous validation practices, and ongoing maintenance. The following recommendations should be implemented:

1. **Audit and Enforce `exp` Claim Generation:**
    - Thoroughly review all JWT generation logic in Golang code.
    - Ensure the standard `exp` (Expiration Time) claim is *always* set for every JWT issued.
    - The `exp` value must be a Unix timestamp (seconds since epoch) representing a future point in time.
    - Implement short, reasonable lifetimes for access tokens (e.g., 5-60 minutes, depending on sensitivity).

2. **Mandate Strict Server-Side `exp` Claim Validation:**
    - All JWTs received by the server *must* undergo `exp` claim validation.
    - When using `github.com/golang-jwt/jwt/v5`, always include the `jwt.WithExpirationRequired()` option in `ParseWithClaims` calls to ensure the library validates this claim during parsing.

    - If using older libraries or custom validation, ensure the logic is robust, correctly handles missing or zero-value expiration claims, and accurately compares against the current time, accounting for potential clock skew.
3. **Implement a Refresh Token Strategy:**
    - For applications requiring user sessions longer than the short lifespan of access tokens, implement a secure refresh token mechanism.
        
    - Refresh tokens should have longer expiry times than access tokens but must be stored securely (e.g., HttpOnly, Secure cookies) and have their own lifecycle management, including revocation.
4. **Consider Token Revocation Mechanisms:**
    - For applications with high-security requirements or specific events that necessitate immediate token invalidation (e.g., user logout, password change, detected compromise), implement a server-side token revocation list (denylist). This typically involves storing the `jti` (JWT ID) of revoked tokens until their original `exp` time.
        
5. **Secure Token Transmission and Client-Side Storage:**
    - Always transmit JWTs over HTTPS to prevent interception.
    - Advise or enforce secure storage of JWTs on the client-side (e.g., HttpOnly cookies for web clients to prevent XSS access to the token; secure storage for mobile clients).
        
6. **Regularly Update Dependencies:**
    - Keep Golang JWT libraries (e.g., `github.com/golang-jwt/jwt`) and the Golang runtime itself updated to their latest stable and patched versions. This helps mitigate known vulnerabilities in these components.
        
    - Utilize tools like `govulncheck` to monitor dependencies for known security issues.
        
7. **Developer Education and Secure Coding Practices:**
    - Train developers on JWT security best practices, including the importance and correct handling of the `exp` claim, and the specific behaviors and requirements of the JWT libraries in use.
    - Emphasize the principle of "secure by default" and the dangers of relying on implicit library behaviors for security-critical functions.
8. **Incorporate into Secure Software Development Lifecycle (SSDLC):**
    - Integrate SAST (Static Application Security Testing) tools into the CI/CD pipeline to automatically scan Golang code for common JWT misconfigurations, such as missing `exp` claims or improper validation patterns.
    - Perform regular DAST (Dynamic Application Security Testing) and penetration testing to identify vulnerabilities in live environments, including testing token expiration.
    - Conduct thorough security code reviews, especially for authentication and authorization modules.

By adopting these recommendations holistically, organizations can significantly reduce the risk of "jwt-no-expiry" vulnerabilities and enhance the overall security posture of their Golang applications. The focus should be on a defense-in-depth strategy where multiple layers of security controls address different aspects of JWT handling.

## **15. Summary**

The "JWT not expiring properly" (jwt-no-expiry) vulnerability in Golang applications arises when JSON Web Tokens are issued without a correctly defined `exp` (Expiration Time) claim or when server-side logic fails to validate this claim. This oversight allows JWTs to be used indefinitely, creating a persistent security risk. If such a token is compromised, an attacker can gain prolonged unauthorized access to protected resources, potentially leading to session hijacking, data breaches, and privilege escalation.

The root causes often lie in common developer mistakes, such as omitting the `exp` claim during token generation, using non-standard claims for expiration, or misunderstanding the default behaviors of Golang JWT libraries like `github.com/golang-jwt/jwt`, which may not validate expiration by default without explicit configuration (e.g., using `WithExpirationRequired()` in v5). Flawed manual validation logic or improper error handling during token parsing can also contribute to this vulnerability.

The impact is significant, transforming a potentially short-lived token compromise into a long-term access vector. This vulnerability is classified under CWE-613 (Insufficient Session Expiration) and relates to several OWASP API Security Top 10 risks, including Broken Authentication and Security Misconfiguration.

Key remediation strategies are crucial:

1. **Generation:** Always set a standard `exp` claim with a short, reasonable lifetime during JWT creation.
2. **Validation:** Mandate strict server-side validation of the `exp` claim, utilizing library-specific options (e.g., `jwt.WithExpirationRequired()` for `golang-jwt/jwt/v5`) and correctly handling validation errors.
3. **Lifecycle Management:** Implement refresh tokens for longer user sessions and consider token revocation mechanisms for high-security scenarios.
4. **Maintenance:** Keep JWT libraries and the Golang runtime updated to patch known vulnerabilities.
5. **Awareness:** Educate developers on secure JWT handling practices and library nuances.

By meticulously ensuring that JWTs have a finite, validated lifespan, organizations can significantly mitigate this vulnerability and bolster the security of their Golang applications.

## **16. References**

- RFC 7519: JSON Web Token (JWT).
    
- CVE-2024-51744: Vulnerability in `golang-jwt` related to error handling in `ParseWithClaims`.
    
- `github.com/golang-jwt/jwt` library documentation and issues.
    
- `github.com/dgrijalva/jwt-go` library (archived).
    
- Linode Blog: "The Dangers of the Never-Expiring JWT."
    
- Stytch Blog: "How to validate a JWT."
    
- MojoAuth Blog: "Understanding JWT Expiration Time claim (exp)."

- Stack Overflow: "Time expiration issue in jwt."
    
- OWASP REST Security Cheat Sheet (mentions JWT validation).
    
- OWASP Top 10 Cheat Sheet of Cheat Sheets (mentions JWT session management).
    
- Descope Blog: "JWT Logout: Risks and Mitigations."
    
- Dev.to: "JWT in action: Secure Authentication & Authorization in Go."
    
- Goa.design Docs: "JWT Authentication."
    
- Reddit: Golang JWT Refresh Token Flow.
    
- GoFiber Docs: JWT Middleware.
    
- Cyprox.io Vulnerabilities (lists CWE-613 for JWT Expiration Time).
    
- TuringPoint Security: "Session Token Does Not Expire" (CWE-613).
    
- Acunetix Blog: "JSON Web Token Attacks And Vulnerabilities."
    
- Stack Overflow: "JWT token expired but it doesn't have expiration time."
    
- PartnerPens Hashnode: "JWT Authentication in Go."
    
- Hub.corgea.com: "Go Lang Security Best Practices."
    
- Aptori Blog: "JWT Security Best Practices Every Developer Should Know."
    
- NVD: CVE-2025-2559 (Keycloak JWT caching DoS).
    
- OWASP Risk Rating Methodology. (S_S154, S_S203, S_S211)
- OWASP API Security Top 10 - 2023. (S_S215, S_S216, S_S217, S_S275, S_S276, S_S277)