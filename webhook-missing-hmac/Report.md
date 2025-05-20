# **Missing HMAC Verification in Webhooks (webhook-missing-hmac)**

## **Severity Rating**

**Rating: High🟠**

The classification of this vulnerability as "High" severity stems from a combination of factors relating to its exploitability and potential impact. Webhook endpoints, while sometimes perceived as internal or semi-private communication channels, are fundamentally HTTP accessible URLs. If an attacker can discover or guess this URL, the absence of HMAC signature verification means there is no cryptographic mechanism to confirm the authenticity or integrity of an incoming request. An attacker merely needs to understand the expected payload structure, which can often be reverse-engineered from public documentation or observed traffic if other compromises have occurred.

The potential impact of successfully forged webhook requests can be severe. Depending on the actions triggered by the webhook, an attacker could manipulate data, execute unauthorized commands, or disrupt service availability. For instance, a webhook designed to update customer records could be used to inject malicious data, or a webhook triggering a deployment process could be exploited to deploy unauthorized code. The ease with which a forged request can be sent, coupled with the potentially significant consequences of processing such a request, underpins the "High" severity rating. This risk is often compounded because the public accessibility of the endpoint might be overlooked, leading to a false sense of security based on the "trusted" nature of the originating service. However, without cryptographic verification, this trust is unfounded.

## **Description**

This vulnerability, "Missing HMAC Verification in Webhooks," arises when an application that consumes webhooks fails to cryptographically verify that incoming messages originate from the legitimate source and have not been tampered with in transit. Webhooks are automated messages sent from one application to another when something happens; they are essentially HTTP callbacks triggered by an event in a source system, pushing data to a destination system. A Hash-based Message Authentication Code (HMAC) or a similar cryptographic signature mechanism is employed by webhook providers to ensure authenticity and integrity.

When this verification step is missing or improperly implemented, an attacker can craft and send forged webhook requests to the receiving application's endpoint. By impersonating the legitimate source, the attacker can potentially inject malicious data, trigger unauthorized actions within the receiving application, or cause other detrimental effects. The failure to implement this crucial security check means the application implicitly trusts any data sent to its webhook endpoint, rendering it vulnerable to a range of attacks that can compromise its data, functionality, and security posture.

## **Technical Description**

Webhooks are a common mechanism for enabling real-time communication between disparate software systems. Typically, when an event occurs in a source system (e.g., a code push in a version control system, a successful payment in a payment gateway), the source system makes an HTTP POST request to a pre-configured URL on a destination system, delivering a payload containing information about the event.

To secure this communication, especially since webhook endpoints are often publicly accessible, webhook providers typically sign their requests. This signature allows the receiving application to verify that the request is indeed from the expected source and that the payload has not been altered during transit. HMAC is a widely adopted standard for this purpose.

The HMAC signature generation and verification process generally involves the following steps:

1. The webhook provider (sender) and the consumer (receiver) share a secret key. This key is known only to them.
2. When an event occurs, the provider prepares the webhook payload (often a JSON body).
3. The provider computes an HMAC hash (e.g., HMAC-SHA256) of the raw request payload using the shared secret key. Some providers might include other elements like timestamps in the data to be hashed.
    
    
4. The provider sends this computed signature to the receiver, typically in an HTTP header such as `X-Hub-Signature-256` (used by GitHub and Snyk), `X-PlanetScale-Signature`, or `X-Shopify-Hmac-Sha256`. The format of this signature in the header can vary (e.g., hex-encoded, base64-encoded, prefixed with the algorithm name).

    
5. Upon receiving the webhook request, the destination application uses its copy of the shared secret key to independently compute the HMAC hash of the raw request body it received.
6. The application then compares its computed hash with the hash received in the HTTP header. This comparison **must** be performed using a constant-time algorithm (e.g., `hmac.Equal` in Go) to prevent timing attacks, which could otherwise allow an attacker to reconstruct the signature byte by byte.

    
7. If the signatures match, the webhook is considered authentic and its integrity is verified. The application can then proceed to process the payload. If they do not match, the request should be rejected.

The vulnerability, "Missing HMAC Verification in Webhooks," occurs when the receiving application omits this verification process entirely or implements it incorrectly. This could mean not checking for a signature header, not computing the local HMAC, using the wrong secret, hashing the wrong data (e.g., a parsed version of the body instead of the raw body), or using an insecure comparison method.

A common misconception can arise from the perceived nature of webhook endpoints. Developers might implicitly trust incoming webhook data, especially if the source is a well-known or "trusted" service. However, this trust is misplaced if not backed by cryptographic verification. Webhook URLs are, by their nature, accessible via HTTP/S. Attackers can discover these URLs through various means, including public documentation, application binaries, or even educated guessing. Once the URL is known, and if the expected payload structure can be inferred (often possible from API documentation), an attacker can send a POST request. Without signature verification, the receiving system has no reliable way to distinguish a legitimate request from a forged one, effectively leaving an open door for malicious inputs.

To aid developers in recognizing and correctly implementing these checks, common signature headers and their associated algorithms are often documented by service providers. The following table provides examples:

**Table 1: Common Webhook Signature Headers and Algorithms**

| **Header Name** | **Common Algorithm** | **Example Provider(s)** | **Notes** |
| --- | --- | --- | --- |
| `X-Hub-Signature-256` | HMAC-SHA256 | GitHub, Snyk  | Often prefixed with `sha256=` |
| `X-Shopify-Hmac-Sha256` | HMAC-SHA256 | Shopify  | Base64 encoded digest |
| `X-PlanetScale-Signature` | HMAC-SHA256 | PlanetScale | Hex digest |
| `X-Sphere-Engine-Signature` | HMAC-SHA256 | Sphere Engine | Hex digest |
| `X-CIO-Signature` | HMAC-SHA256 | Customer.io | Involves version and timestamp in signed content |
| `X-Hook-Signature` | HMAC-SHA256 | Generic  | Placeholder for custom or less common implementations |
| `X-Hub-Signature` | HMAC-SHA1 | GitHub (Legacy)  | Deprecated due to SHA1 weaknesses; prefer SHA-256 versions |

Understanding these technical details is paramount for security professionals tasked with auditing or designing systems that consume webhooks.

## **Common Mistakes That Cause This**

Several common errors can lead to the absence or ineffective implementation of HMAC verification for webhooks in Golang applications:

- **No Verification Attempt:** The most direct cause is the complete omission of any signature verification logic. The application receives the webhook payload and processes it based on blind trust.
- **Using Parsed/Modified Request Body for HMAC Calculation:** This is a frequent and critical error. HMAC verification must be performed on the exact, raw byte stream of the HTTP request body as it was received from the sender. Many web frameworks, including those in Go, offer convenient middleware or utilities that automatically parse incoming JSON (or other formats) into native data structures (e.g., Go structs). If developers attempt to calculate the HMAC signature based on this parsed data (e.g., by re-serializing the struct back to JSON), the resulting byte stream may not be identical to the original raw body due to subtle differences in whitespace, field ordering (for some JSON libraries if not strictly controlled), or Unicode character representation. Even minute changes will result in a different HMAC hash, causing legitimate requests to fail verification. This can lead developers to mistakenly conclude the verification logic itself is flawed and disable it, rather than addressing the core issue of using the non-raw body. The correct approach is to read and store the raw body first for signature calculation before any parsing occurs.
    
- **Incorrect Secret Handling:**
    - **Hardcoding Secrets:** Embedding the shared secret key directly within the application's source code is a severe security misstep. If the source code is compromised or becomes publicly accessible, the secret is exposed.

    - **Insecure Storage:** Storing secrets in version control systems (like Git), in plain-text configuration files alongside code, or in other easily accessible locations makes them vulnerable to theft.
        
    - **Secret Encoding Issues:** A subtle but impactful operational error can occur with the encoding of the secret itself. For example, when base64 encoding a secret for storage (e.g., in an environment variable or a Kubernetes secret), tools like `echo "mysecret" | base64` might inadvertently include a trailing newline character in the output. If the application then base64 decodes this string, the resulting secret byte array will contain this extraneous newline (`mysecret\n` instead of `mysecret`). This altered secret will produce a different HMAC hash, leading to persistent or intermittent verification failures, even if the HMAC implementation logic is otherwise correct. This highlights that secure implementation extends to precise and secure operational practices for managing secret material.
        
- **Using Insecure or Deprecated Algorithms:** Employing cryptographically weak hashing algorithms like MD5 or SHA1 for HMAC calculation is a significant vulnerability. While some older webhook implementations might still use HMAC-SHA1 (e.g., GitHub's legacy `X-Hub-Signature` header), SHA-256 (or stronger, like SHA-512) is the current standard recommendation. MD5 and SHA1 are susceptible to collision attacks, which, while not directly breaking HMAC in all scenarios, undermines the overall cryptographic strength.
    
- **Mismatched Character Encoding:** Webhook payloads can contain Unicode characters. If the server-side application does not consistently handle the payload as UTF-8 (or as specified by the provider), the byte representation of the payload used for HMAC calculation might differ from what the provider used, leading to signature mismatches.
    
- **Non-Constant-Time Comparison of Signatures:** Using simple byte-wise or string equality checks (e.g., `bytes.Compare` in Go if not used carefully, or `==` on byte slices) to compare the computed signature with the received signature can expose the application to timing attacks. In such attacks, an adversary measures the time taken for the comparison to fail for different inputs, potentially allowing them to reconstruct the valid signature byte by byte. Go's `crypto/hmac` package provides the `hmac.Equal` function, which performs a constant-time comparison and should always be used for this purpose.
    
- **Incorrect Signature Decoding:** Webhook providers often send the signature in the HTTP header in an encoded format, such as hexadecimal or base64. The receiving application must correctly decode this signature string back into its raw byte representation before comparing it with the locally computed raw HMAC digest. Failure to do so (e.g., comparing a hex string with a raw byte array) will inevitably lead to mismatches. For instance, if a provider sends a hex-encoded SHA256 signature, the Go application must use `encoding/hex.DecodeString` to convert it to `byte` before using `hmac.Equal`.
    
- **Ignoring Provider-Specific Details:** Different webhook providers may have unique requirements for signature verification. These can include specific header names, variations in how the signature is encoded (hex, base64), or specific rules about what content is included in the signature calculation (e.g., some providers might concatenate a timestamp or other metadata with the request body before hashing ). Developers must consult and adhere to the specific documentation of each webhook provider they integrate with.
    

Addressing these common mistakes is crucial for building secure webhook consumer applications in Golang.

## **Exploitation Goals**

Attackers who identify and target webhook endpoints lacking proper HMAC verification may pursue several malicious objectives:

- **Data Injection and Manipulation:** The most direct goal is often to send forged webhook payloads containing malicious or altered data. If the application processes this unvalidated data—for example, by updating database records, creating user accounts, or modifying application settings—the attacker can corrupt data integrity, introduce false information, or create unauthorized entries. The impact of this depends heavily on the nature of the data and the actions the webhook triggers.
    
- **Unauthorized Action Execution:** Many webhooks are designed to trigger specific actions or workflows within the receiving system, such as deploying new code, sending notifications, initiating financial transactions, or provisioning resources. By sending a forged webhook, an attacker can illegitimately invoke these actions, potentially leading to unauthorized code execution, service misuse, or financial fraud.
- **Denial of Service (DoS):** An attacker can flood a vulnerable webhook endpoint with a high volume of forged requests. If processing these requests consumes significant server resources (CPU, memory, network bandwidth, database connections), this can overwhelm the application, leading to a denial of service for legitimate users or other integrated services. Even if individual request processing is not intensive, a large enough volume can still cause degradation or unavailability.
    
- **Information Disclosure:** While less common as a primary goal for this specific vulnerability, it's conceivable that an attacker could craft a webhook payload that, when processed by a vulnerable or poorly error-handled application, causes it to respond with error messages or data that inadvertently reveals sensitive system information, internal configurations, or other data useful for further attacks.
- **Lateral Movement and Further System Compromise:** In more complex scenarios, a successfully forged webhook request might serve as an initial foothold or a stepping stone for more advanced attacks. If the webhook interacts with internal systems or databases, or if it can trigger processes that have broader permissions, compromising the webhook functionality could enable an attacker to move laterally within the victim's network or escalate privileges.

A critical aspect of these exploitation goals is that they often target the specific business logic implemented by the webhook. An attacker who understands what a particular webhook is intended to do (e.g., confirm a payment, update inventory, grant access to a resource) can craft payloads designed to exploit that business process for their gain. For instance, forging a "payment_successful" event could trick an e-commerce system into shipping goods without actual payment, or a forged "user_authenticated" event might grant unauthorized access. The absence of HMAC verification means the system cannot differentiate between a legitimate trigger for these business processes and a malicious one, making the business logic itself a target.

## **Affected Components or Files**

The "Missing HMAC Verification in Webhooks" vulnerability primarily affects specific parts of a Golang application responsible for handling incoming HTTP requests from external services. These include:

- **Golang HTTP Handlers:** Any Go function that implements the `http.Handler` interface or is a `http.HandlerFunc` (e.g., registered using `http.HandleFunc`) and is designated as an endpoint for receiving webhook messages. These handlers contain the core logic for processing the incoming request, including reading the body, parsing the payload, and (ideally) verifying its authenticity.
- **Webhook Integration Modules/Packages:** In larger applications, there might be dedicated Go packages or modules specifically designed to manage integrations with various third-party services that use webhooks. These modules would encapsulate the logic for receiving, verifying, and processing webhooks from providers like payment gateways, version control systems (GitHub, GitLab), CI/CD tools, communication platforms (Slack, Twilio), or other SaaS products.
- **Source Code Files:** The vulnerability resides within the Golang source code files (typically with a `.go` extension) that contain the implementations of the aforementioned HTTP handlers or integration modules. The specific file names and locations will vary depending on the application's architecture and project structure (e.g., `webhook_handlers.go`, `github_integration.go`, `payment_processor.go`).

Essentially, any piece of Go code that defines an HTTP endpoint intended to consume data pushed from another service via a webhook mechanism is potentially affected if it does not correctly implement HMAC signature verification.

## **Vulnerable Code Snippet (Golang)**

The following Golang code snippet illustrates a common scenario where a webhook handler processes an incoming request without performing any HMAC signature verification, making it vulnerable.

```Go

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// WebhookPayload represents the expected structure of the incoming webhook data.
type WebhookPayload struct {
	Event string      `json:"event"`
	Data  interface{} `json:"data"` // Using interface{} for generic data part
}

// vulnerableWebhookHandler is an HTTP handler that processes incoming webhooks
// without any signature verification.
func vulnerableWebhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method!= http.MethodPost {
		http.Error(w, "Only POST method is accepted", http.StatusMethodNotAllowed)
		return
	}

	// Read the raw request body
	body, err := ioutil.ReadAll(r.Body)
	if err!= nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close() // Ensure the body is closed

	// CRITICAL VULNERABILITY: Missing HMAC signature verification.
	// The application proceeds to parse and process the payload without
	// verifying if it came from the legitimate source or if it was tampered with.
	// An attacker can send any payload matching the expected structure to this endpoint.

	var payload WebhookPayload
	// Attempt to unmarshal the body into the WebhookPayload struct
	err = json.Unmarshal(body, &payload)
	if err!= nil {
		log.Printf("Error unmarshalling JSON payload: %v", err)
		http.Error(w, "Error processing payload: Invalid JSON", http.StatusBadRequest)
		return
	}

	// Log the received event and data (for demonstration)
	log.Printf("Received webhook event: %s, Data: %v", payload.Event, payload.Data)

	// Example of processing the event based on potentially unverified/forged data.
	// In a real application, this could involve database updates, triggering other services, etc.
	processWebhookEvent(payload)

	// Send a success response
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Webhook received and processed (vulnerably): Event '%s'\n", payload.Event)
}

// A placeholder function for event processing logic
func processWebhookEvent(payload WebhookPayload) {
	// In a real application, this function would contain logic to handle
	// different event types, interact with databases, or call other services.
	// This logic is now vulnerable to being triggered by unauthenticated requests.
	log.Printf("Processing event '%s' with data: %v", payload.Event, payload.Data)
}

func main() {
	// Register the vulnerable webhook handler for a specific path
	http.HandleFunc("/webhook-receiver", vulnerableWebhookHandler)

	port := "8080"
	log.Printf("Starting vulnerable webhook server on port %s. Endpoint: /webhook-receiver", port)
	// Start the HTTP server
	if err := http.ListenAndServe(":"+port, nil); err!= nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
```

In this vulnerable example, `vulnerableWebhookHandler` reads the request body and immediately attempts to unmarshal and process it. There is no step to:

1. Retrieve a signature from an HTTP header (e.g., `X-Hub-Signature-256`).
2. Retrieve a pre-shared secret key.
3. Compute an HMAC hash of the raw request body using the secret.
4. Compare the computed hash with the received signature in a constant-time manner.

Because these crucial verification steps are absent, any attacker who knows the endpoint URL (`/webhook-receiver`) and the expected JSON structure can send a forged request, and the application will process it as if it were legitimate.

## **Detection Steps**

Identifying whether a Golang application is vulnerable to missing HMAC verification in its webhook handlers involves several methods:

- **Manual Code Review:** This is often the most effective method for Go applications.
    1. **Identify Webhook Endpoints:** Locate all HTTP handlers in the codebase that are designed to receive webhook requests. These are typically registered with `http.HandleFunc` or through routing libraries.
    2. **Check for Signature Retrieval:** For each identified handler, examine the code to determine if it attempts to read a signature from an incoming HTTP header. Common headers include `X-Hub-Signature-256`, `X-PlanetScale-Signature`, `X-Shopify-Hmac-Sha256`, etc., depending on the webhook provider.
        
    3. **Verify HMAC Computation:** If a signature header is retrieved, check if the code then computes its own HMAC signature. This involves using a cryptographic library (like `crypto/hmac` and `crypto/sha256` in Go), a securely stored shared secret key, and crucially, the **raw request body**.

    4. **Inspect Signature Comparison:** Ensure that the locally computed signature is compared against the signature received in the header using a constant-time comparison function. In Go, this is `hmac.Equal`. Use of functions like `bytes.Equal` or direct string comparison for signatures is incorrect and insecure.
        
    5. **Confirm Raw Body Usage:** Double-check that the HMAC calculation uses the unaltered, raw bytes of the request body, *before* any parsing (e.g., JSON unmarshalling) or modification occurs. This is a common point of failure.
        
    6. **Secret Management:** Investigate how the shared secret is stored and accessed. It should not be hardcoded or stored insecurely.
- **Security Testing (Penetration Testing):**
    1. **Endpoint Discovery:** Identify all potential webhook listener URLs.
    2. **Craft Test Payloads:** Prepare HTTP POST requests with payloads that mimic legitimate webhook structures.
    3. **Test Scenarios:**
        - Send a request *without* any signature header.
        - Send a request *with* the expected signature header name but an *incorrect or random* signature value.
        - Send a request *with* the expected signature header name but an *empty* signature value.
    4. **Observe Behavior:** If the application accepts and processes any of these requests (indicated by a `2xx` HTTP status code and evidence of the action being performed), it strongly suggests that signature verification is either missing or flawed.
- **Review Webhook Provider Documentation:** For each third-party service that sends webhooks to the application, consult its official documentation. This documentation will specify the exact header name used for the signature, the hashing algorithm (e.g., HMAC-SHA256), how the signature is encoded (e.g., hex, base64), and any other specifics of their signing process.**1** Compare these documented requirements against the actual implementation in the Golang code.
- **Dynamic Analysis and Instrumentation (Advanced):** In a testing environment, one could instrument the application code to log detailed information about incoming webhook requests, including headers and the outcome of any verification attempts. Alternatively, network monitoring tools can capture traffic to webhook endpoints, which can then be analyzed for the presence and validity of signatures.
- **Static Analysis Security Testing (SAST) Tools:** Some SAST tools may be able to identify missing cryptographic checks or the use of insecure functions. However, the specificity of detecting missing HMAC verification for webhooks can vary greatly between tools and their rule sets. Custom SAST rules might be necessary for reliable detection.

A common pitfall during development that leads to this vulnerability is the "it works" fallacy. Developers often test webhook functionality by sending sample payloads using tools like `curl` or Postman. These tests typically focus on ensuring the core logic (parsing the payload, performing the action) functions correctly. Signature verification might be seen as an additional security layer to be implemented later. If the basic functionality is confirmed, the task might be considered complete, and the crucial security step of HMAC verification is overlooked or indefinitely postponed. Detection, therefore, requires not just confirming that the webhook *processes data*, but specifically verifying the *presence and correctness* of the security validation logic.

## **Proof of Concept (PoC)**

This Proof of Concept demonstrates how an attacker can exploit a vulnerable Golang webhook handler, such as the `vulnerableWebhookHandler` presented in the "Vulnerable Code Snippet" section.

- **Scenario:** The vulnerable Golang application is running and listening on `http://localhost:8080/webhook-receiver`. This endpoint expects a JSON payload for an event, for instance, a "product_updated" event from a hypothetical service "AwesomeSaaS." The legitimate "AwesomeSaaS" service would normally include a signature in an `X-Awesome-Signature-256` header, but the vulnerable handler does not check this.
- **Attacker's Prerequisites:**
    1. Knowledge of the webhook endpoint URL: `http://localhost:8080/webhook-receiver`.
    2. Knowledge of the expected JSON payload structure for a "product_updated" event (e.g., from API documentation or by observing legitimate traffic if a prior compromise allowed sniffing).
- **Steps:**
    1. **Craft Malicious Payload:** The attacker creates a JSON payload designed to trigger a desired action or inject specific data.
        
        ```JSON
        
        `{
          "event": "product_updated",
          "data": {
            "productId": "FORGED_ID_001",
            "new_price": 0.01,
            "description": "This product listing was updated by a forged webhook.",
            "status": "active_and_compromised"
          }
        }`
        
    2. **Send Forged Request:** The attacker uses a tool like `curl` to send an HTTP POST request to the vulnerable endpoint with the crafted payload. Crucially, no valid signature is provided, or if a signature header is expected by some intermediate proxy (though not by the vulnerable code itself), an arbitrary one could be sent.
        
        ```Bash
        
        curl -X POST http://localhost:8080/webhook-receiver \
        -H "Content-Type: application/json" \
        -d '{
          "event": "product_updated",
          "data": {
            "productId": "FORGED_ID_001",
            "new_price": 0.01,
            "description": "This product listing was updated by a forged webhook.",
            "status": "active_and_compromised"
          }
        }'
        ```
        
        In this command:
        
        - `X POST` specifies the HTTP method.
        - `http://localhost:8080/webhook-receiver` is the target URL.
        - `H "Content-Type: application/json"` sets the content type header.
        - `d '{...}'` provides the JSON payload.
        *(Note: No `X-Awesome-Signature-256` or any other signature header is being validated by the `vulnerableWebhookHandler`.)*
- **Expected Outcome on Vulnerable Server:**
    - The `vulnerableWebhookHandler` at `http://localhost:8080/webhook-receiver` receives the POST request.
    - Since there is no HMAC signature verification logic, the handler proceeds to read and unmarshal the JSON payload.
    - The server's log will show messages indicating receipt and processing of the event, for example:
        
        `Received webhook event: product_updated, Data: map
        Processing event 'product_updated' with data: map`
        
    - The server responds to the attacker's `curl` command with an HTTP `200 OK` status and the message: `Webhook received and processed (vulnerably): Event 'product_updated'`.
    - The application then acts upon this forged data (e.g., updates product "FORGED_ID_001" in its database with the new price and description, potentially triggering other business logic based on the "active_and_compromised" status).
- **Verification of Vulnerability:** The successful processing of the request, despite the absence of a valid signature, confirms the vulnerability. The application has accepted and acted upon unauthenticated and potentially malicious data.

This PoC highlights the simplicity of exploiting this vulnerability. Once an attacker identifies a vulnerable endpoint and understands the expected payload format, sending a malicious request requires minimal technical sophistication. No complex cryptographic operations or exploit code are needed on the attacker's part; it is a direct injection of data that bypasses an absent security control. This low barrier to exploitation is a significant factor contributing to the vulnerability's "High" severity rating.

## **Risk Classification**

The risk posed by missing HMAC verification in webhooks can be assessed using methodologies like the OWASP Risk Rating Methodology. This involves evaluating likelihood and impact factors.

- **Likelihood:**
    - **Threat Agent Factors:**
        - *Skill Level:* Low to Moderate. The attacker needs to understand HTTP, be able to craft a POST request, and discover the webhook endpoint and its expected payload structure. No advanced cryptographic skills are required for basic exploitation.
        - *Motive:* Varied. Could range from curiosity or mischief to financial gain (e.g., faking orders), data theft, service disruption, or reputational damage to the target.
        - *Opportunity:* Depends on the discoverability of the webhook endpoint. Publicly documented endpoints or those following predictable URL patterns present higher opportunity.
        - *Size:* Potentially large if the vulnerability is systemic across many applications or if a popular service's webhooks are commonly implemented insecurely.
    - **Vulnerability Factors:**
        - *Ease of Discovery:* Moderate. Finding the specific endpoint URL might require some reconnaissance, but if found, the lack of verification is itself the vulnerability.
        - *Ease of Exploit:* Easy. Once the endpoint and payload format are known, sending a forged POST request is trivial using common tools like `curl` or scripting languages.
            
            **1**
            
        - *Awareness:* Moderate to High. HMAC verification for webhooks is a known security best practice, but its omission is still a common oversight.
        - *Intrusion Detection:* Low. If the application does not specifically log or alert on signature validation failures (or the absence of expected signatures), forged requests might blend in with legitimate traffic, especially if they don't cause immediate errors.
    - **Overall Likelihood:** Can range from **Medium to High**, heavily influenced by how easily the webhook endpoint can be found and the attacker's motivation.
- **Impact:**
    - **Technical Impact:**
        - *Loss of Confidentiality:* Low to Moderate. Direct information disclosure is less common, but manipulated responses or error messages could leak data.
        - *Loss of Integrity:* High. The primary impact is the ability to inject false data or trigger unauthorized modifications to data or system state.
            
        - *Loss of Availability:* Moderate to High. Forged requests can be used to overwhelm system resources, leading to a Denial of Service (DoS).
            
            
        - *Loss of Accountability:* Moderate. Actions performed due to forged webhooks might be incorrectly attributed to the legitimate source system if logs are not detailed enough to distinguish them.
    - **Business Impact:**
        - *Financial Damage:* Can be significant if webhooks control financial transactions, order processing, or resource provisioning.
        - *Reputational Harm:* Security breaches resulting from exploited webhooks can severely damage user trust and the organization's reputation.
        - *Operational Disruption:* Forged data can disrupt normal business operations, requiring costly cleanup and recovery efforts.
        - *Legal and Compliance Penalties:* If sensitive data (e.g., PII, PHI) is compromised or manipulated, or if services are disrupted in regulated industries, significant legal and compliance repercussions can follow.
    - **Overall Impact:** Can range from **Medium to High**, critically dependent on the specific actions the webhook triggers and the sensitivity of the data it handles.

Combining a Medium/High Likelihood with a Medium/High Impact typically results in an **Overall Risk rating of High**. The OWASP API Security Top 10 project lists "Webhook Manipulation" as a key API security risk, underscoring its significance.

A conceptual CVSSv3.1 score for a typical instance of this vulnerability might be:

AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L

This translates to:

- Attack Vector (AV): Network
- Attack Complexity (AC): Low
- Privileges Required (PR): None
- User Interaction (UI): None
- Scope (S): Unchanged
- Confidentiality Impact (C): Low
- Integrity Impact (I): High
- Availability Impact (A): Low

This baseline would yield a CVSS score in the High range (e.g., 7.3 or higher), although specific impacts (C, I, A) can vary based on the webhook's function, potentially increasing the score.

## **Fix & Patch Guidance (Golang)**

To remediate the "Missing HMAC Verification in Webhooks" vulnerability in Golang applications, developers must implement a robust signature validation process for every incoming webhook request. The following steps detail how to do this correctly:

1. **Obtain and Securely Store the Shared Secret Key:**
    - Each webhook provider (e.g., GitHub, Stripe, PlanetScale) will provide a unique secret key when a webhook is configured in their system. This secret is shared between the provider and the receiving application.
        
    - **Crucially, never hardcode this secret key directly in the application's source code**.
        
    - The secret should be stored securely, for example:
        - As an environment variable (e.g., `WEBHOOK_PROVIDER_SECRET`).
        - In a dedicated secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager, Google Cloud Secret Manager, Azure Key Vault).
        - As a Kubernetes Secret if deploying in a Kubernetes environment.
    - In Go, retrieve the secret at application startup:
        
        ```Go
        
        var webhookSecretbyte
        
        func loadWebhookSecret() {
            secretStr := os.Getenv("YOUR_WEBHOOK_PROVIDER_SECRET")
            if secretStr == "" {
                log.Fatal("CRITICAL: YOUR_WEBHOOK_PROVIDER_SECRET environment variable not set.")
            }
            webhookSecret =byte(secretStr)
        }
        
        func init() {
            loadWebhookSecret()
        }
        ```
        
2. **Read the Raw Request Body:**
    - The HMAC signature is calculated based on the exact, unaltered byte stream of the HTTP request body. It is imperative to read the entire raw body *before* any parsing (e.g., JSON unmarshalling) or modification occurs.

    - The `io/ioutil.ReadAll(r.Body)` function is commonly used for this. Remember to close `r.Body` after reading.
        
        ```Go
        
        bodyBytes, err := ioutil.ReadAll(r.Body)
        if err!= nil {
            log.Printf("Error reading request body: %v", err)
            http.Error(w, "Cannot read request body", http.StatusInternalServerError)
            return
        }
        defer r.Body.Close() // Close the original body
        ```
        
    - A common pitfall is that `r.Body` (an `io.ReadCloser`) can typically only be read once. If the application needs to parse the body after verification (which is usually the case), the `bodyBytes` read for HMAC calculation should be used for unmarshalling. If the body needs to be available for further middleware or handlers as an `io.ReadCloser`, it can be "re-wrapped":
    
    However, for a single handler performing verification and processing, using `bodyBytes` directly for unmarshalling after successful verification is often simpler and sufficient.
    
        ```Go
        
        // After reading into bodyBytes and closing r.Body:
        // To make bodyBytes available for further reading as if it were r.Body:
        r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
        ```
        
3. **Retrieve the Signature from the HTTP Header:**
    - Webhook providers send the computed signature in an HTTP header. Consult the provider's documentation for the exact header name (e.g., `X-Hub-Signature-256` for GitHub, `X-Stripe-Signature` for Stripe).

        ```Go
        
        receivedSignatureHeader := r.Header.Get("X-Hub-Signature-256") // Example for GitHub
        if receivedSignatureHeader == "" {
            log.Println("Request missing X-Hub-Signature-256 header")
            http.Error(w, "Missing signature header", http.StatusUnauthorized)
            return
        }
        ```
        
4. **Parse the Received Signature String:**
    - Signatures in headers are often prefixed with the algorithm (e.g., `sha256=`) and are typically hex-encoded or base64-encoded. The prefix must be removed, and the remaining string must be decoded into a raw byte slice.
        
        ```Go
        
        // Example for "sha256=<hex_encoded_signature>"
        const expectedPrefix = "sha256="
        if!strings.HasPrefix(receivedSignatureHeader, expectedPrefix) {
            log.Printf("Invalid signature format: missing prefix '%s'", expectedPrefix)
            http.Error(w, "Invalid signature format", http.StatusUnauthorized)
            return
        }
        signatureHex := strings.TrimPrefix(receivedSignatureHeader, expectedPrefix)
        receivedSignatureBytes, err := hex.DecodeString(signatureHex)
        if err!= nil {
            log.Printf("Error decoding hex signature: %v", err)
            http.Error(w, "Invalid signature encoding", http.StatusUnauthorized)
            return
        }
        ```
        
5. **Compute the HMAC Signature Locally:**
    - Use Go's standard library `crypto/hmac` and the appropriate hash function (e.g., `crypto/sha256` for HMAC-SHA256) to compute the signature of the `bodyBytes` using the `webhookSecret`.

        ```Go
        
        mac := hmac.New(sha256.New, webhookSecret)
        mac.Write(bodyBytes) // Write the raw request body bytes
        expectedSignatureBytes := mac.Sum(nil)
        ```
        
6. **Compare Signatures Using a Constant-Time Function:**
    - Critically, use `hmac.Equal()` to compare the `receivedSignatureBytes` with your `expectedSignatureBytes`. This function performs a comparison in constant time, which helps prevent timing attacks. **Do not use `bytes.Equal()` or `==` for comparing cryptographic signatures**.
    
    
        ```Go
        
        if!hmac.Equal(receivedSignatureBytes, expectedSignatureBytes) {
            log.Println("Signature mismatch: Computed signature does not match received signature.")
            http.Error(w, "Invalid signature", http.StatusUnauthorized) // Or http.StatusBadRequest
            return
        }
        ```
        
7. **Proceed with Processing (If Signature is Valid):**
    - If `hmac.Equal` returns `true`, the signature is valid. The application can now safely unmarshal `bodyBytes` into the appropriate Go struct and process the webhook event.
        
        ```Go
        
        log.Println("Webhook signature verified successfully.")
        var payload YourWebhookPayloadStruct // Define your payload struct
        if err := json.Unmarshal(bodyBytes, &payload); err!= nil {
            log.Printf("Error unmarshalling JSON after signature verification: %v", err)
            http.Error(w, "Error processing payload", http.StatusBadRequest)
            return
        }
        //... proceed with your application logic using the verified payload...
        fmt.Fprintf(w, "Webhook processed securely.\n")
        ```
        

**Secure Code Example (Putting it all together for a GitHub-like webhook):**

```Go

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

// YourWebhookPayloadStruct defines the expected structure of the webhook payload.
type YourWebhookPayloadStruct struct {
	Event string      `json:"event"`
	Data  interface{} `json:"data"`
}

var githubWebhookSecretbyte

func init() {
	// Load secret from environment variable at startup
	secretStr := os.Getenv("GITHUB_WEBHOOK_SECRET")
	if secretStr == "" {
		log.Fatal("CRITICAL: GITHUB_WEBHOOK_SECRET environment variable not set.")
	}
	githubWebhookSecret =byte(secretStr)
}

func secureWebhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method!= http.MethodPost {
		http.Error(w, "Only POST method is accepted", http.StatusMethodNotAllowed)
		return
	}

	// 1. Read the raw request body
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err!= nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Cannot read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close() // Close original body

	// If needed for further processing by other handlers, re-wrap the body:
	// r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	// 2. Retrieve the signature from the header
	receivedSignatureHeader := r.Header.Get("X-Hub-Signature-256")
	if receivedSignatureHeader == "" {
		log.Println("Request missing X-Hub-Signature-256 header")
		http.Error(w, "Missing signature header", http.StatusUnauthorized)
		return
	}

	// 3. Parse the received signature string
	const expectedPrefix = "sha256="
	if!strings.HasPrefix(receivedSignatureHeader, expectedPrefix) {
		log.Printf("Invalid signature format: missing prefix '%s'", expectedPrefix)
		http.Error(w, "Invalid signature format", http.StatusUnauthorized)
		return
	}
	signatureHex := strings.TrimPrefix(receivedSignatureHeader, expectedPrefix)
	receivedSignatureBytes, err := hex.DecodeString(signatureHex)
	if err!= nil {
		log.Printf("Error decoding hex signature: %v", err)
		http.Error(w, "Invalid signature encoding", http.StatusUnauthorized)
		return
	}

	// 4. Compute the HMAC signature locally
	mac := hmac.New(sha256.New, githubWebhookSecret)
	mac.Write(bodyBytes) // Hash the raw request body
	expectedSignatureBytes := mac.Sum(nil)

	// 5. Compare signatures using a constant-time function
	if!hmac.Equal(receivedSignatureBytes, expectedSignatureBytes) {
		log.Println("Signature mismatch.")
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	// 6. Proceed with processing (if signature is valid)
	log.Println("Webhook signature verified successfully.")
	var payload YourWebhookPayloadStruct
	if err := json.Unmarshal(bodyBytes, &payload); err!= nil {
		log.Printf("Error unmarshalling JSON after signature verification: %v", err)
		http.Error(w, "Error processing payload", http.StatusBadRequest)
		return
	}

	log.Printf("Securely processed webhook event: %s, Data: %v", payload.Event, payload.Data)
	//... Your application-specific logic here...

	fmt.Fprintf(w, "Webhook processed securely: %s\n", payload.Event)
}

func main() {
	http.HandleFunc("/secure-webhook-endpoint", secureWebhookHandler)
	port := "8080"
	log.Printf("Starting secure webhook server on port %s. Endpoint: /secure-webhook-endpoint", port)
	if err := http.ListenAndServe(":"+port, nil); err!= nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
```

This comprehensive example provides a template for correctly implementing HMAC-SHA256 signature verification for webhooks in a Golang application. Always adapt header names, prefixes, and secret management to the specific webhook provider's requirements.

## **Scope and Impact**

The "Missing HMAC Verification in Webhooks" vulnerability has a broad scope and can lead to significant negative impacts on affected Golang applications and the organizations that rely on them.

- **Scope:**
    - The vulnerability can affect any Golang application or microservice that acts as a consumer of webhooks, regardless of whether these webhooks originate from external third-party services (like payment gateways, social media platforms, SCM systems) or internal systems within an organization's own infrastructure.
    - It is relevant to systems that depend on webhooks for a wide array of functionalities, including but not limited to:
        - Real-time data synchronization between different applications.
        - Event-driven notifications (e.g., build status, new orders, user actions).
        - Automation of CI/CD pipelines (e.g., triggering builds or deployments on code commits).
        - Integration with SaaS platforms for various business processes.
- **Impact:**
    - **Data Integrity Compromise:** This is a primary impact. Attackers can send forged webhook payloads containing false or manipulated data. If the application processes this data without validation, it can lead to an incorrect application state, corruption of databases, propagation of erroneous information to other systems, and ultimately, flawed business intelligence or decisions.
        
    - **Unauthorized Access and Actions:** Forged webhooks can be used to trigger unauthorized operations within the receiving application. This could range from creating unauthorized user accounts, modifying permissions, initiating fraudulent financial transactions (e.g., faking payment confirmations, issuing refunds), deploying malicious code, or misusing other services controlled by the webhook.
        
    - **Denial of Service (DoS):** Unprotected webhook endpoints can become targets for DoS attacks. An attacker can flood the endpoint with a large volume of bogus requests, consuming server resources such as CPU, memory, network bandwidth, and database connections. This can degrade performance or render the service entirely unavailable for legitimate traffic and users.
        
    - **Reputational Damage:** Security incidents stemming from exploited webhook vulnerabilities, especially those leading to data breaches or service disruptions, can severely erode user trust and damage the organization's reputation.
    - **System Instability:** Malformed or unexpectedly structured payloads in forged requests, if not handled robustly by the parsing and processing logic (even if basic input validation exists), might cause the webhook handler or the entire application to crash or enter an unstable state.
    - **Compliance Violations:** Depending on the nature of the data handled by the webhooks (e.g., Personal Identifiable Information (PII), Protected Health Information (PHI), payment card data) and the industry regulations applicable to the organization (e.g., GDPR, HIPAA, PCI DSS), a security breach resulting from this vulnerability could lead to significant compliance violations, fines, and legal liabilities.

A particularly insidious aspect of this vulnerability is the potentially silent nature of a breach. Unlike some attacks that cause immediate and obvious system failures or alerts, a skillfully crafted forged webhook request might inject subtle malicious data or trigger an unauthorized action that goes unnoticed for an extended period. The application might continue to appear to "work" correctly from an operational standpoint, but its data integrity or security posture is compromised. This makes auditing for such breaches and conducting incident response more challenging, as the impact can accumulate silently over time until a larger discrepancy or a more significant problem surfaces, by which point substantial damage may have already occurred.

## **Remediation Recommendation**

A multi-layered approach is recommended to effectively remediate and protect against the "Missing HMAC Verification in Webhooks" vulnerability. The primary defense is robust signature verification, supported by several other security best practices.

- **Primary: Implement Robust HMAC Signature Verification:** This is the cornerstone of remediation. For every webhook endpoint in the Golang application, meticulously implement HMAC signature verification as detailed in the "Fix & Patch Guidance" section. This includes using the raw request body, the correct shared secret, a strong hashing algorithm (typically HMAC-SHA256), and constant-time comparison for signatures.**1**
- **Defense in Depth Strategies:**
    - **Use HTTPS for Webhook URLs:** Always expose webhook endpoints over HTTPS. This encrypts the webhook data in transit, protecting it from eavesdropping and man-in-the-middle attacks that could intercept payloads or signatures. While HTTPS protects data confidentiality and integrity in transit, it does *not* prevent an attacker from sending a forged request directly to the HTTPS endpoint; hence, signature verification remains essential.
        
    - **Timestamp Validation (Replay Attack Mitigation):** If the webhook provider includes a timestamp in the request (often in a header or as part of the signed payload), validate this timestamp. Reject requests that are older than a reasonable threshold (e.g., 5 minutes). This helps mitigate replay attacks, where an attacker intercepts a valid, signed webhook and re-sends it later. Ensure server clocks are synchronized using NTP for accurate timestamp validation.
        
    - **Idempotency:** Design webhook handlers to be idempotent. This means that processing the same webhook request multiple times produces the same result and has the same side effects as processing it just once. Idempotency is crucial for gracefully handling legitimate retries from webhook providers (due to transient network issues) and can also offer some protection against simple replay attacks.
        
    - **IP Address Whitelisting (Use with Caution):** If the webhook provider publishes a stable, limited list of IP addresses from which they send webhooks, consider whitelisting these IPs at the network firewall or application level. However, this should be used as a secondary control, not the primary one, as IP addresses can change, and relying solely on IP whitelisting can be brittle and may not be feasible for all providers.
        
- **Secrets Management:**
    - Implement a robust strategy for managing shared secret keys. Use dedicated secrets management tools or platforms (e.g., HashiCorp Vault, AWS Secrets Manager, Google Cloud Secret Manager, Azure Key Vault) instead of hardcoding secrets or storing them in insecure configuration files.

    - Establish a policy for rotating webhook secrets periodically and, critically, immediately if a compromise is suspected or confirmed.

    - Ensure meticulous handling of secret encoding (e.g., when using base64) to avoid issues like trailing newlines that can invalidate HMAC calculations.
        
- **Regular Audits and Security Testing:**
    - Periodically conduct manual code reviews of webhook integration logic, specifically focusing on the correctness and completeness of signature validation.
    - Include webhook security checks (testing for missing/flawed signature verification, replay attacks, etc.) as part of regular penetration testing exercises and automated security scanning.
- **Comprehensive Logging and Monitoring:**
    - Log all incoming webhook requests, including relevant headers (especially signature headers and timestamps), the source IP address, and the request payload (or a digest of it if too large or sensitive).
    - Crucially, log the outcome of every signature validation attempt (success or failure).
    - Implement monitoring and alerting for high rates of signature validation failures. A sudden spike could indicate a misconfiguration, an issue with the provider, or an active attack attempt.
        
- **Strict Input Validation:** Even after a webhook's signature has been successfully verified (confirming its authenticity and integrity), always perform strict validation of the payload's structure and content against an expected schema. Reject any requests with unexpected fields, incorrect data types, or malformed data. This helps protect against logical flaws or unexpected data even from a legitimate source.
- **Principle of Least Privilege:** Ensure that the actions triggered by webhook processing logic operate with the minimum necessary permissions required to perform their designated tasks. This limits the potential damage if a webhook endpoint is compromised despite other defenses.

The following checklist can serve as a guide for ensuring comprehensive webhook security:

**Table 2: Webhook Security Remediation Checklist**

| **Category** | **Checkpoint** | **Status (Done/Pending)** | **Notes** |
| --- | --- | --- | --- |
| **Signature Verification** | Implement HMAC-SHA256 (or provider-specified) signature validation? |  | Use `hmac.Equal` for comparison. |
|  | Is the **raw request body** used for HMAC calculation? |  | Must be done *before* any parsing or modification of the body. |
|  | Is the correct signature header being checked (as per provider documentation)? |  | E.g., `X-Hub-Signature-256`, `X-Stripe-Signature`.**5** |
|  | Is the received signature correctly decoded (e.g., from hex/base64) before comparison? |  | .**10** |
| **Secret Management** | Is the shared secret stored securely (not hardcoded, not in VCS)? |  | Use environment variables, dedicated secrets managers.**5** |
|  | Are secrets rotated periodically and immediately on suspicion of compromise? |  | .**3** |
|  | Is the secret encoding (if any, e.g., base64) handled correctly to avoid errors like trailing newlines? |  | .**13** |
| **Transport Security** | Is HTTPS enforced for the webhook endpoint URL? |  | .**1** |
| **Replay Prevention** | Is timestamp validation implemented (if provider supports and it's feasible)? |  | Check `Webhook-Timestamp` or similar headers; reject old requests.**1** |
| **Idempotency** | Is the webhook handler designed to be idempotent? |  | Processing the same request multiple times has the same effect as once. |
| **Input Validation** | Is the payload content and structure validated against a schema *after* signature verification? |  | .**15** |
| **Logging/Monitoring** | Are signature validation attempts (success/failure) and outcomes logged? |  | .**15** |
|  | Are alerts configured for high rates of signature validation failures or unusual patterns? |  |  |
| **Least Privilege** | Do webhook-triggered actions and the handler itself operate with the minimum necessary permissions? |  | Limit potential impact if other controls fail. |

By systematically addressing these recommendations, organizations can significantly improve the security posture of their Golang applications that consume webhooks.

## **Summary**

The failure to implement HMAC signature verification in Golang webhook handlers constitutes a critical security vulnerability. This oversight allows attackers to forge webhook requests, effectively impersonating legitimate services and injecting malicious data or triggering unauthorized actions within the receiving application. The consequences can be severe, ranging from data corruption and unauthorized system modifications to denial of service and reputational damage.

Exploitation of this vulnerability is often straightforward, requiring an attacker to know the webhook endpoint URL and the expected payload structure. Without cryptographic validation, the application has no reliable means to ascertain the authenticity or integrity of incoming messages.

Effective remediation hinges on the diligent implementation of HMAC signature verification for every webhook. This involves:

1. Securely obtaining and storing the shared secret key provided by the webhook source.
2. Calculating an HMAC (commonly HMAC-SHA256) of the **raw request body**.
3. Comparing this computed signature with the signature provided in the HTTP request header using a **constant-time comparison function** (e.g., `hmac.Equal` in Go).
4. Rejecting any request where the signatures do not match or where the signature is missing or malformed.

Beyond this primary defense, a comprehensive security strategy should include defense-in-depth measures. These include enforcing HTTPS for webhook endpoints, implementing timestamp validation to mitigate replay attacks, ensuring webhook handlers are idempotent, performing strict input validation on the payload content (even after signature verification), and adhering to the principle of least privilege for actions triggered by webhooks. Robust secrets management practices are also paramount to protect the shared secret keys.

Developers and security teams working with Golang applications must prioritize the implementation of these security measures. Regular code reviews, security testing, and diligent adherence to provider-specific webhook security guidelines are essential to protect applications, data, and user trust in an increasingly interconnected digital ecosystem.

## **References**

- **5**: PlanetScale Documentation - Webhooks
- **1**: Hookdeck - Webhook Security Vulnerabilities Guide
- **2**: Hookdeck - Webhooks Security Checklist
- **6**: GitHub Docs - Validating webhook deliveries (also )
- **16**: n8n Community - Webhook HMAC hash cannot be verified
- **12**: Bubble Forum - Webhook requires HMAC-SHA256 signature
- **10**: Stack Overflow - Golang Dropbox webhook signature validation HMAC (also )
    
- **17**: Hookdeck Docs - Authentication
- **4**: Svix - Receiving Webhooks with Go (also )
    
- **13**: GitHub Issues (argo-cd) - Occasional HMAC error
- **14**: Gist - Handle Github webhooks with golang
- **9**: Snyk Docs - Webhook events and payloads
- **7**: WebhookRelay Docs - HMAC
- **11**: Sphere Engine Docs - Webhooks Security
- **3**: Astra Security Blog - API Security Risks
- **15**: SecOps Solution Blog - Webhook Security Checklist
- **18**: Reddit r/golang - Get the raw text of a request
- **19**: HTTPie Docs - Raw request body
- **20**: Go Packages - piusalfred/whatsapp/webhooks
- **8**: Customer.io Docs - Send and receive data with webhooks
- **4**: Search results for Golang code examples, common mistakes, raw request body
- **6**: GitHub Docs - Validating webhook deliveries (Processed)
- **10**: Stack Overflow - Golang Dropbox webhook signature validation HMAC (Processed)
- **5**: PlanetScale Docs - Webhooks (Processed)
- **1**: Hookdeck - Webhook Security Vulnerabilities Guide (Processed)