# Report on Golang Vulnerability: Poor Rate Limits on Mempool Fetching APIs (mempool-rate-limit-missing)

## 1. Executive Summary

This report provides a comprehensive analysis of the "Poor Rate Limits on Mempool Fetching APIs," identified as `mempool-rate-limit-missing`, a significant security vulnerability affecting Golang applications that interact with blockchain mempools. This flaw is a specific manifestation of **CWE-770: Allocation of Resources Without Limits or Throttling**. The absence of adequate rate limiting on these critical APIs allows malicious actors to launch Denial of Service (DoS) attacks by overwhelming blockchain nodes with excessive requests, leading to severe operational disruptions and compromised network stability.

The primary consequence of this vulnerability is a direct impact on the availability and performance of blockchain nodes and, by extension, the entire network. Such attacks can cause considerable transaction delays, artificially inflate network fees, and introduce instability that undermines the fundamental principles of decentralization. The ability to disrupt individual nodes through unthrottled API access challenges the inherent resilience that decentralization is designed to provide. This extends beyond typical application-level DoS, representing a systemic risk to the core operational integrity of a blockchain, where the integrity of the distributed ledger's pre-consensus state is directly attacked.

Effective mitigation strategies necessitate a multi-layered defense. This includes implementing robust rate limiting mechanisms both within the Golang application code, leveraging libraries such as `golang.org/x/time/rate` , and at the infrastructure level, utilizing external API gateways or reverse proxies like NGINX. Proactive and continuous monitoring of API usage and system resources is also essential to detect and respond to potential exploitation.

## 2. Vulnerability Title

The vulnerability under examination is formally titled: **Poor Rate Limits on Mempool Fetching APIs**. It is commonly referred to by the shorthand `mempool-rate-limit-missing`. This vulnerability is a direct instance of, and is categorized under, the broader class of weaknesses known as **CWE-770: Allocation of Resources Without Limits or Throttling**. This explicit linkage to a standardized Common Weakness Enumeration provides a recognized security context, enabling security professionals to quickly understand the fundamental nature of the problem and to leverage existing knowledge about CWE-770 for effective remediation.

## 3. Severity Rating

The overall severity of the "Poor Rate Limits on Mempool Fetching APIs" vulnerability is assessed as **High🟠**. This determination is based on an evaluation of its characteristics against standard vulnerability scoring systems, particularly the CVSS v3.1 framework, and alignment with industry recommendations.

**CVSS v3.1 Metrics (Estimated):**

- **Attack Vector (AV): Network (N)**: The vulnerability is exploitable remotely over the network, as mempool fetching APIs are typically exposed and accessible via standard network protocols.
- **Attack Complexity (AC): Low (L)**: Exploitation of this vulnerability requires simple API requests. No complex preconditions or specialized techniques are necessary to trigger the flaw.
- **Privileges Required (PR): None (N)**: An attacker does not need any form of authentication or elevated privileges to initiate requests against the vulnerable endpoints.
- **User Interaction (UI): None (N)**: The attack can be performed directly by the adversary without requiring any action or manipulation of a legitimate user.
- **Scope (S): Unchanged (U)**: The vulnerability primarily impacts the resources and availability of the target system (the blockchain node or its API service) without directly affecting components in a different security scope.
- **Confidentiality Impact (C): None (N)**: This vulnerability does not directly lead to unauthorized disclosure of sensitive information or data breaches.
- **Integrity Impact (I): None (N)**: The vulnerability does not directly result in unauthorized modification or corruption of data.
- **Availability Impact (A): High (H)**: The core impact of this vulnerability is Denial of Service (DoS). Successful exploitation can render the API unresponsive or completely unavailable, leading to a significant disruption of service. This directly results in resource exhaustion, including excessive memory and CPU consumption.

**Industry Alignment and Specific Impact:**
A related "Allocation of Resources Without Limits or Throttling" vulnerability (SNYK-GOLANG-GOLANGORGXOAUTH2JWS-8749594) was independently assessed by Snyk with a High severity rating (8.7). Furthermore, the Secure3.io severity rating system classifies vulnerabilities requiring "low effort to exploit" as "High" severity, explicitly listing impacts such as "Denial of Service (DoS)," "RPC API Crash," and "Transaction Processing Overload" as high-impact scenarios. This convergence across multiple industry sources consistently points to a "High" severity for resource exhaustion and DoS vulnerabilities, especially when they are easily exploitable over the network.

While general DoS is inherently severe, the impact on blockchain-specific metrics elevates the criticality of this vulnerability. The potential for "Transaction Processing Overload" to cause network processing nodes to exceed their parameters, leading to congestion, delays, and potential network instability , is a crucial distinction. This is not merely a generic API becoming unavailable; it is a direct disruption to a core component of a decentralized ledger. Such disruption has cascading effects on transaction finality, user experience, and the economic incentives of miners and validators, potentially leading to broader network health issues.

It is important to note a potential discrepancy between exploitability and observed exploitation. While the CVSS score indicates high exploitability due to low complexity and no privileges, the EPSS (Exploit Prediction Scoring System) for a similar Golang CWE-770 vulnerability shows a relatively low probability of exploitation in the wild (0.06%, 20th percentile). This could suggest that while the *potential* for exploitation is high, the *actual observed exploitation* for this specific class of Golang vulnerabilities might be lower, perhaps due to effective external mitigations already in place or a lack of widespread awareness. However, organizations should not become complacent based on low observed exploitation rates. The inherent ease of exploitation and high potential impact mean that proactive security measures are paramount, rather than relying solely on historical attack data. The "low effort to exploit" characteristic, which contributes to a High severity rating, would directly contradict a low EPSS if the vulnerability were widely known and actively targeted.

## 4. Vulnerability Description

Missing Rate Limiting is a fundamental security vulnerability that manifests when an application fails to enforce limits on the number of requests a user, client, or IP address can make within a specified timeframe. This oversight can lead to various forms of abuse, including brute-force attacks, API scraping, resource exhaustion, and Denial of Service (DoS).

In the context of blockchain networks, this vulnerability specifically impacts **mempools**. A mempool (short for "memory pool") serves as a critical temporary holding area for pending and unconfirmed transactions before they are selected and included in a block by miners. It is important to understand that there is no single, global mempool; rather, each node within the network maintains its own distinct mempool, which may vary slightly based on the transactions it has received and its individual processing policies. Mempool fetching APIs are interfaces that allow external clients—such as blockchain explorers, wallets, or analytics tools—to query and retrieve real-time or historical information about the state of these pending transactions.

The vulnerability, `mempool-rate-limit-missing`, arises when these mempool fetching APIs lack proper rate limiting controls. Without these controls, an attacker can flood a target blockchain node with an excessive volume of requests to these APIs. This relentless querying can quickly overwhelm the node's computational resources, including CPU, memory, and network bandwidth. The consequence is a severe degradation in performance, leading to the mempool service becoming unresponsive or entirely unavailable, and potentially causing the entire blockchain node to crash or disconnect from the network.

The absence of rate limits on mempool APIs is particularly sensitive and more severe than on typical application APIs due to the unique nature of mempools. Mempools are not merely static data repositories; they are volatile, real-time buffers of unconfirmed, often high-stakes, financial transactions. They also represent a critical pre-consensus component in the blockchain's transaction lifecycle. Unthrottled access to these APIs therefore does not just result in an application slowing down; it directly impacts the core functionality of a blockchain node—its ability to efficiently process, prioritize, and propagate transactions for eventual block inclusion. This direct threat to the liveness and integrity of a distributed ledger system by disrupting its transaction processing pipeline underscores the heightened severity of this vulnerability.

## 5. Technical Description (for Security Professionals)

To fully grasp the implications of `mempool-rate-limit-missing`, a detailed understanding of blockchain mempools and the nature of resource exhaustion vulnerabilities is essential.

**Blockchain Mempools: A Technical Overview**

A mempool functions as a node's local queue of pending and unconfirmed transactions. In a decentralized network, each node independently maintains its own mempool, which may contain a slightly different set of transactions based on its connectivity, received transactions, and local policies. When a transaction is initiated, it is broadcast across the network using a peer-to-peer (P2P) protocol. Each node that receives the transaction performs a series of validity checks—such as verifying signatures, ensuring sufficient funds, and checking against network rules—before adding it to its local mempool.

Miners play a crucial role by selecting transactions from their mempools to include in new blocks. This selection process often prioritizes transactions offering higher fees, as this incentivizes miners to include them promptly. The size and congestion of a mempool directly influence transaction processing times and the fees required for timely confirmation. For instance, Bitcoin Core nodes typically allocate 300MB of memory for their mempools and will begin rejecting new transactions below a certain fee threshold if the mempool becomes full.

**CWE-770: Allocation of Resources Without Limits or Throttling**

This Common Weakness Enumeration describes a vulnerability where a system or application allocates or consumes resources without setting proper limits or implementing throttling mechanisms. In the context of APIs, this means that requests, especially those involving user input, can consume disproportionate amounts of resources such as network bandwidth, CPU cycles, memory, and storage.

When applied to mempool fetching APIs, the absence of these limits allows a malicious actor to continuously request large volumes of mempool data or submit a flood of resource-intensive queries. This can quickly exhaust the target node's allocated memory, CPU cycles, or network capacity. Examples of exploitable resource limits include execution timeouts, maximum allocable memory, the number of file descriptors, and the number of requests permitted per client or resource.

**Attack Vectors and Mechanisms**

- **Denial of Service (DoS):** The primary objective of exploiting `mempool-rate-limit-missing` is to achieve a DoS condition. By flooding mempool fetching APIs with an overwhelming number of requests, an attacker can render the API unresponsive or completely unavailable. This prevents legitimate users and services from querying vital mempool data, monitoring transaction statuses, or even submitting new transactions, thereby disrupting normal blockchain operations.
- **Resource Exhaustion:** Direct and excessive consumption of the target node's CPU, memory, and network bandwidth is a key mechanism. Sustained high request volumes can lead to the node crashing, becoming unresponsive, or disconnecting from the network, severely impacting its ability to participate in the blockchain consensus process.
- **Asymmetric Denial of Mempool Service (ADAMS):** While ADAMS is typically described in the context of submitting crafted transactions to fill a mempool at a low cost to the attacker , unthrottled *fetching* APIs can exacerbate such attacks. An attacker can use rapid, unthrottled queries to monitor the mempool's state, observe the effectiveness of their transaction flooding, and adapt their attack strategy in real-time. This allows for more precise and cost-effective disruption, overwhelming the node's ability to process any requests, including legitimate transaction submissions.
- **Transaction Flooding Amplification:** Unthrottled mempool APIs can facilitate or amplify transaction flooding attacks. By allowing attackers to rapidly query the mempool's status, they can gauge network congestion and transaction prioritization, enabling them to fine-tune their spam transaction broadcasts to maximize disruption.

The ability of an attacker to use unthrottled mempool APIs to monitor the effectiveness of their DoS attack creates a dangerous feedback loop. Real-time insights into network congestion and transaction prioritization  enable adversaries to observe mempool growth, transaction eviction patterns, or changes in fee rates, allowing them to adapt and optimize their disruption campaigns. This means that unthrottled mempool fetching APIs not only directly cause resource exhaustion but also serve as a valuable intelligence gathering tool for attackers, leading to more precise and effective DoS campaigns, including sophisticated ADAMS attacks.

## 6. Common Mistakes That Cause This Vulnerability

The presence of the "Poor Rate Limits on Mempool Fetching APIs" vulnerability can be attributed to several common programming errors and architectural oversights:

- **Lack of Explicit Rate Limiting Implementation:** The most straightforward cause is simply neglecting to implement any form of rate limiting logic for API endpoints, particularly those that provide data or accept submissions. Developers may prioritize functionality over security, or underestimate the potential for abuse of seemingly innocuous data fetching APIs.
- **Architectural Oversights:**
    - **Sole Reliance on In-Application Rate Limiting:** While Golang's `rate` package (`golang.org/x/time/rate`) is an effective tool for implementing rate limits within an application , relying exclusively on this approach can be problematic. A critical paradox exists: if the application itself comes under extreme load from a DoS attack, its internal rate limiting logic may fail to execute effectively, leading to a complete system freeze or crash. The very mechanism designed to protect against overload can become a casualty of that overload.
    - **Failure to Implement External Rate Limiting:** Many security experts and system architects strongly advocate for handling rate limiting at a layer external to the application, such as an API Gateway, a service mesh (e.g., Istio utilizing Envoy filters), or a reverse proxy like NGINX. This architectural decision offloads the burden of traffic management from the application, providing a more robust and scalable first line of defense that can absorb and filter malicious traffic before it impacts the application's core logic.
    - **Neglect of Distributed Nature:** Rate limiting in a distributed system, such as a blockchain network with multiple nodes, presents unique challenges. Simply applying a local rate limit per node might be insufficient if attackers can distribute their requests across numerous compromised machines or IP addresses. A comprehensive solution often requires a shared, external storage mechanism (like Redis) to track request counts across the entire distributed system.
- **Insufficient Resource Controls:** Beyond just request frequency, developers may fail to define and enforce maximum limits on other resource-consuming aspects of API requests. This includes not setting limits on request payload sizes, the number of records returned per page in a response, or execution timeouts for complex queries. For mempool APIs, this could manifest as allowing queries for an unbounded number of transactions or permitting requests for very large transaction data, which can be computationally expensive to retrieve and serialize.
- **Inadequate Monitoring and Alerting:** Without robust monitoring of API usage patterns, real-time resource consumption, and error rates (specifically HTTP 429 "Too Many Requests" responses), developers and operators may not detect an ongoing DoS attack until it has already caused significant service degradation or a complete outage. The absence of `429` responses under high load is a key indicator of missing rate limits.
- **Misunderstanding of Mempool Dynamics:** A lack of deep appreciation for how mempool congestion, transaction propagation, and the economic incentives of miners operate can lead to underestimating the severe impact of unthrottled access to mempool data. This can result in a false sense of security regarding the potential for DoS attacks targeting these APIs.

## 7. Exploitation Goals

Attackers exploiting the "Poor Rate Limits on Mempool Fetching APIs" vulnerability typically pursue several objectives, ranging from direct disruption to more indirect, systemic impacts on the blockchain ecosystem:

- **Denial of Service (DoS):** The primary and most direct goal is to overwhelm the target blockchain node or its mempool API, rendering it unresponsive or completely unavailable to legitimate users and services. This prevents users from performing essential actions such as checking the status of their transactions, querying account balances, or submitting new transactions to the network.
- **Resource Exhaustion:** A direct consequence and a means to achieve DoS, attackers aim to consume excessive CPU, memory, and network bandwidth on the target node. This can lead to the node crashing, experiencing severe performance degradation, or disconnecting from the network, thereby disrupting its role in maintaining the blockchain's integrity and liveness.
- **Network Congestion:** By successfully overwhelming individual nodes, an attacker can contribute to broader network congestion. This slows down the propagation of legitimate transactions across the network and significantly increases confirmation times for all users, regardless of their transaction fees.
- **Increased Transaction Fees:** During periods of network congestion induced by a DoS attack, legitimate users are often forced to pay higher transaction fees (gas prices) to incentivize miners to include their transactions in blocks. This is because miners typically prioritize transactions with higher fees to maximize their profits, effectively turning the attack into an economic burden for users.
- **Financial Manipulation/Arbitrage (Indirect):** While mempool *fetching* APIs do not directly enable financial manipulation, an attacker with unthrottled access can rapidly query the mempool's state to gain an informational advantage. This real-time visibility can be leveraged for strategies such as frontrunning or other forms of Miner Extractable Value (MEV), where pending high-value transactions are identified, and the attacker submits their own transaction with a higher fee to ensure it is processed first. Unthrottled fetching can also be used to confirm the success and impact of a transaction flooding attack.
- **Undermining Network Liveness and Decentralization:** A successful and sustained DoS attack on mempool APIs can force blockchain validators to produce empty or underutilized blocks. This directly undermines the economic incentives of validators and can, in the long run, lead to a reduction in network participation and overall decentralization.

The exploitation of this vulnerability leads to increased transaction fees and delays. This directly impacts the economic viability and user experience of the blockchain. Furthermore, repeated disruptions erode user trust in the network's reliability and security. This is not merely a technical failure; it represents a significant economic and reputational blow to the blockchain ecosystem. The vulnerability therefore has cascading economic effects, driving up user costs and undermining the fundamental trust users place in the blockchain's ability to process transactions reliably.

## 8. Affected Components or Files

The "Poor Rate Limits on Mempool Fetching APIs" vulnerability can affect a range of components within a Golang-based blockchain ecosystem, primarily those exposing public-facing interfaces for mempool interaction.

- **Generic Golang API Endpoints:** Any Golang application or service that exposes HTTP or RPC (Remote Procedure Call) endpoints designed for querying or interacting with a blockchain node's mempool is susceptible if proper rate limiting is absent. This includes, but is not limited to, APIs for:
    - **Fetching lists of pending transactions:** For example, endpoints akin to `GET /mempool/transactions` which provide a current snapshot of transactions awaiting confirmation.
    - **Retrieving details of specific unconfirmed transactions:** APIs like `GET /mempool/transactions/:txid` that return granular information about individual transactions in the mempool.
    - **Accessing real-time mempool data streams:** Services that provide continuous updates on mempool activity, often via WebSockets, as is common for monitoring Ethereum mempools.
    - **APIs utilized by wallets, block explorers, or other decentralized applications (dApps):** These applications frequently rely on mempool data to provide users with transaction status, network congestion insights, and fee recommendations.
- **Blockchain Node Implementations (Golang-based):**
    - Specific components within blockchain node software written in Golang that manage and expose mempool data are directly vulnerable. Examples from various blockchain projects include:
        - `mempool/mempool.go` within `btcsuite/btcd` : This file defines internal mempool policies, such as `FreeTxRelayLimit` (a rate limit for zero-fee transactions) and `MaxOrphanTxs`/`MaxOrphanTxSize` (limits to prevent memory exhaustion from large orphan transactions). The vulnerability would specifically arise if these internal limits, designed for *transaction admission*, are not complemented by external rate limits on *fetching* APIs.
        - `mempool/reactor.go` in `cometbft/cometbft` : This component handles peer-to-peer communication and the reception of transactions for the mempool. While it might include internal P2P rate controls (`SendRate`, `RecvRate` ), the vulnerability would lie in the public-facing RPC fetching APIs that expose this mempool data without adequate throttling.
        - `service.IssueRawTx` and associated `mempool` packages in Avalanche's BlobVM : These illustrate the mechanisms for submitting transactions to the VM's mempool and for gossiping transactions across the network. A vulnerability would exist in any public API that allows querying this mempool without appropriate access controls or rate limits.
- **Any API Gateway or Proxy:** If an organization intends to implement rate limiting at the infrastructure layer, but the API Gateway or reverse proxy (e.g., NGINX) is misconfigured or lacks the necessary rate limiting rules for mempool APIs, it becomes an affected component.

A critical distinction must be made between internal mempool policies and external API rate limiting. Internal mempool implementations, such as those found in `btcd`'s `mempool.go`  or CometBFT's `reactor.go` , often include limits for *transaction admission* (e.g., `MaxOrphanTxSize`, `FreeTxRelayLimit`). These internal limits are designed to protect the mempool from invalid or malicious *transactions*. However, a common mistake is to secure these internal transaction processing mechanisms while overlooking the external-facing APIs that *expose* this data. The internal limits protect the mempool from *bad transactions*, but not from *excessive queries for legitimate transactions*. Therefore, developers must explicitly distinguish between internal mempool policy (focused on transaction validation and admission) and external API rate limiting (focused on controlling query volume). Securing one does not automatically secure the other.

## 9. Vulnerable Code Snippet

The vulnerability "Poor Rate Limits on Mempool Fetching APIs" stems from the absence of explicit rate limiting logic in Golang API handlers. A typical vulnerable scenario involves a standard HTTP handler that fetches mempool data without any middleware or direct code to restrict request frequency.

Consider the following conceptual Golang HTTP handler designed to fetch mempool transactions. This example simulates a resource-intensive operation that a real-world mempool API might perform, such as iterating through a large number of pending transactions, serializing complex data structures, or performing database queries.

```go
package main

import (
	"fmt"
	"net/http"
	"time"
	// In a real application, this would import blockchain-specific mempool client libraries,
	// e.g., "github.com/your-blockchain/client/mempool"
)

// getMempoolTransactions simulates a handler that fetches and processes mempool data.
// In a vulnerable state, it lacks any rate limiting.
func getMempoolTransactions(w http.ResponseWriter, r *http.Request) {
	// Simulate resource consumption for fetching and processing mempool data.
	// This loop represents CPU-intensive work, e.g., iterating through a large mempool
	// or complex data serialization for a large response.
	for i := 0; i < 1000000; i++ {
		_ = i * i // Dummy CPU-intensive operation
	}

	// Simulate returning a large dataset (e.g., all current mempool transactions).
	// In a real scenario, this would be JSON encoded mempool data.
	response := "Successfully fetched (unlimited) mempool transactions. This operation consumed significant resources."
	fmt.Fprintf(w, response)
}

func main() {
	// This endpoint is exposed without any rate limiting middleware or logic.
	http.HandleFunc("/mempool/transactions", getMempoolTransactions)
	fmt.Println("Server listening on :8080 without rate limits...")
	http.ListenAndServe(":8080", nil)
}
```

This code snippet demonstrates the core vulnerability: any client can make an arbitrary number of requests to `/mempool/transactions` without restriction, potentially exhausting the server's resources.

To illustrate the remediation, the following table provides a side-by-side comparison of the vulnerable code and a fixed version that incorporates rate limiting using Go's `golang.org/x/time/rate` package. This package implements a token bucket algorithm, a common and effective strategy for controlling request rates.

**Table 1: Vulnerable vs. Fixed Go Code Snippet**

| Aspect | Vulnerable Code | Fixed Code | Explanation |
| --- | --- | --- | --- |
| **Dependencies** | `net/http` | `net/http`, `golang.org/x/time/rate`, `time` | The `golang.org/x/time/rate` package provides the necessary rate limiting functionality. |
| **API Handler** | `go func getMempoolTransactions(w http.ResponseWriter, r *http.Request) { //... resource-intensive operations... fmt.Fprintf(w, "Fetched mempool data.") }` | `go var limiter = rate.NewLimiter(rate.Every(time.Second), 10) func rateLimitMiddleware(next http.Handler) http.Handler { return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { if!limiter.Allow() { http.Error(w, "Too many requests", http.StatusTooManyRequests) return } next.ServeHTTP(w, r) }) } func getMempoolTransactions(w http.ResponseWriter, r *http.Request) { //... resource-intensive operations... fmt.Fprintf(w, "Fetched mempool data.") }` | The `rateLimitMiddleware` checks if a request is allowed by the `limiter`. If not, it returns `429 Too Many Requests`. The `limiter` is configured to allow 10 requests per second. |
| **Server Setup** | `go func main() { http.HandleFunc("/mempool/transactions", getMempoolTransactions) http.ListenAndServe(":8080", nil) }` | `go func main() { router := http.NewServeMux() router.Handle("/mempool/transactions", rateLimitMiddleware(http.HandlerFunc(getMempoolTransactions))) http.ListenAndServe(":8080", router) }` | The `getMempoolTransactions` handler is wrapped with the `rateLimitMiddleware` before being registered with the HTTP router. This ensures all requests to this endpoint pass through the rate limiter. |
| **Key Difference** | No mechanism to control request frequency. | Enforces a limit of 10 requests per second using a token bucket algorithm. | The `limiter.Allow()` call is the critical addition that prevents resource exhaustion from excessive requests. |

This table directly illustrates the problem and solution in a concise, visual format, providing developers with a concrete, actionable example of how to implement the fix in Go. It helps readers quickly grasp the concept of rate limiting middleware and its application, particularly for those familiar with Go's `net/http` package.

## 10. Detection Steps

Detecting the "Poor Rate Limits on Mempool Fetching APIs" vulnerability requires a multi-faceted approach, combining automated tools with manual review and active testing.

- **Automated Scanners:**
    - **API Security Scanners:** Tools specifically designed for API security can analyze API definitions (e.g., OpenAPI/Swagger specifications) and observe traffic patterns to identify endpoints that lack defined rate limiting policies. These scanners often flag endpoints that appear to be publicly accessible and perform resource-intensive operations without corresponding throttling mechanisms.
    - **Static Application Security Testing (SAST):** SAST tools analyze the Golang source code without executing it. They can be configured to identify common patterns indicative of missing rate limiting logic. This includes searching for HTTP handlers or RPC service methods that interact with mempool data (e.g., functions calling `mempool.GetTransactions()`, `mempool.Size()`, `mempool.ReapMaxTxs()`, `mempool.TxsFront()`, etc., as hinted by the `btcsuite/btcd` and `cometbft` mempool packages ) but do not incorporate checks from `golang.org/x/time/rate` or similar rate limiting middleware.
    - **Dynamic Application Security Testing (DAST):** DAST tools actively test API endpoints by sending a high volume of requests, similar to an attacker. They observe server responses, response times, and error codes. The absence of `HTTP 429 Too Many Requests` responses under high load, coupled with signs of performance degradation or resource spikes, is a strong indicator of a missing rate limit.
- **Manual Code Review:**
    - A thorough manual inspection of the Golang codebase is crucial. Security architects and developers should specifically review all HTTP handlers and RPC service methods that expose or interact with blockchain mempool data. The focus should be on verifying the presence and correct application of `golang.org/x/time/rate` or any custom rate limiting logic. This also involves ensuring that any custom rate limiting implementations are robust, thread-safe, and correctly applied to all relevant endpoints.
- **Performance and Load Testing:**
    - Dedicated stress tests and load tests should be conducted on mempool fetching APIs. These tests involve simulating high concurrent request volumes from various simulated client IP addresses. During these tests, it is imperative to monitor server-side metrics such as CPU utilization, memory consumption, and network I/O. Significant and sustained spikes in resource usage without the application returning `HTTP 429` responses indicate a clear vulnerability.
- **Network Monitoring and Logging:**
    - Continuous monitoring of network traffic for unusual spikes in requests directed at mempool-related endpoints is essential. Implementing comprehensive logging for all API requests, including the source IP address, request frequency, and response times, allows for post-incident analysis and real-time detection of abuse patterns. The absence of `HTTP 429 Too Many Requests` responses when under heavy load, particularly when performance degrades, is a critical signal of a missing rate limit.
- **System Metrics Monitoring:**
    - Regularly monitoring the CPU, memory, and network utilization of blockchain nodes is a proactive measure. Unexplained spikes or sustained high resource usage could indicate an ongoing Denial of Service (DoS) attack exploiting unthrottled APIs.

A significant challenge in detecting this vulnerability is the potential for "silent failure." If rate limiting is entirely missing, the system may not explicitly return an `HTTP 429 Too Many Requests` error. Instead, it might simply slow down, become unresponsive, or even crash. This makes detection more challenging, as there is no clear "rate limit hit" signal. Consequently, monitoring for *resource exhaustion* (CPU, memory, network I/O) and *degraded performance* (increased latency, timeouts) becomes paramount, as these are the primary symptoms of such a silent failure. Detection strategies must therefore extend beyond looking for explicit rate limit errors and actively monitor overall system health and performance metrics to identify the subtle signs of resource exhaustion caused by unthrottled API access.

## 11. Proof of Concept (PoC)

A Proof of Concept (PoC) for the "Poor Rate Limits on Mempool Fetching APIs" vulnerability aims to demonstrate that an attacker can effectively exhaust node resources or render the mempool API unresponsive by sending a high volume of requests without encountering any rate limiting.

**Objective:** To show that a vulnerable Golang application's mempool fetching API can be overwhelmed, leading to Denial of Service (DoS) and resource exhaustion.

**Tools:** Standard command-line utilities such as `curl` or `ab` (ApacheBench) are sufficient. For more sophisticated, programmatic attacks, a simple script written in Golang or Python can be utilized.

**Setup:**

1. **Vulnerable Target:** A Golang application exposing a mempool fetching API (e.g., `/mempool/transactions`) must be running on a test blockchain node. This application *must not* have any rate limiting implemented for the target endpoint.
2. **Attacking Machine:** A separate machine or virtual instance from which the attack requests will be launched.

**Steps:**

1. **Baseline Measurement:** Before initiating the attack, establish a baseline. Measure the normal response time of the target API endpoint under typical, non-stressful load conditions. Simultaneously, monitor the resource utilization (CPU, memory, network I/O) of the target Golang application's process and the underlying blockchain node using system monitoring tools (e.g., `top`, `htop`, `docker stats`, or cloud provider monitoring dashboards).
2. **Attack Execution (High-Volume Requests):**
    - From the attacking machine, initiate a flood of concurrent requests to the vulnerable mempool fetching API. The goal is to send requests faster than the server can process them without rate limits.
    - **Example using `curl` (simple loop, multiple terminals for concurrency):**Bash
        
        `# Open multiple terminal windows and run this command in each
        while true; do curl -s -o /dev/null http://<target_ip>:<port>/mempool/transactions; done`
        
        - The `s` flag silences progress output, and `o /dev/null` discards the response body, focusing on the request rate.
    - **Example using `ApacheBench` (`ab`) for higher concurrency and controlled request counts:**Bash
        
        `# Send 10,000 requests with a concurrency of 100
        ab -n 10000 -c 100 http://<target_ip>:<port>/mempool/transactions`
        
    - **For more resource-intensive attacks:** If the API supports parameters that control the amount of data returned (e.g., number of transactions per page), attempt to request a very large number of records (e.g., `/api/users?size=200000` as depicted in OWASP scenarios ). Similarly, if the API processes request payloads, manipulate the payload size to maximize resource consumption.
3. **Observation of Impact:**
    - **Client-side Observations:** From the attacking machine and from other legitimate client machines attempting to access the API, observe a significant increase in response times, frequent timeouts, and eventual connection failures.
    - **Server-side Monitoring:** Continuously monitor the target Golang application's process and the underlying blockchain node's resource consumption.
        - **Expected Outcome:** A successful PoC will demonstrate significant spikes in CPU utilization, memory consumption, and potentially network I/O on the target node. This will lead to the API becoming noticeably slow, unresponsive, or the entire application/node crashing, thereby achieving a Denial of Service. Crucially, the absence of `HTTP 429 Too Many Requests` responses during the attack confirms the lack of effective rate limiting.

This PoC effectively demonstrates that a simple high-volume request attack can cause DoS. The concept of "asymmetrically low cost" for the attacker, as highlighted in discussions of Asymmetric Denial of Mempool Service (ADAMS) attacks , is highly relevant here. A straightforward, unauthenticated flood of requests is remarkably cheap for an adversary to mount, yet it can inflict significant operational costs on the victim, including resource consumption, prolonged downtime, and reputational damage. This vulnerability therefore represents a highly cost-effective attack vector for adversaries, making it a particularly attractive target for disruption campaigns against critical blockchain infrastructure.

## 12. Risk Classification

The "Poor Rate Limits on Mempool Fetching APIs" vulnerability is classified as **High Risk**. This classification is based on a comprehensive assessment of both its likelihood of exploitation and the potential impact of a successful attack.

**Likelihood: High**

The probability of this vulnerability being exploited is high due to several factors:

- **Low Attack Complexity:** Exploitation requires only simple API requests, making it accessible even to attackers with limited technical sophistication.
- **No Privileges Required:** Attackers do not need any form of authentication or elevated permissions to interact with the vulnerable endpoints.
- **Readily Available Tools:** Tools for generating high volumes of concurrent requests (e.g., `curl` loops, ApacheBench, custom scripts) are widely available and easy to use.
- **Network Accessibility:** Mempool fetching APIs are often publicly exposed to facilitate blockchain explorers, wallets, and other services, making them easily discoverable targets.

**Impact: High**

A successful exploitation of this vulnerability can lead to severe and cascading consequences across the blockchain ecosystem:

- **Availability:** The most direct and severe impact is on the availability of the target system. This results in a Denial of Service (DoS) where the API becomes unresponsive or completely unavailable, and the underlying blockchain node may crash or be forced offline. This directly prevents legitimate users from interacting with the blockchain, such as submitting new transactions or checking their status.
- **Performance:** Even without a full DoS, the node and its APIs will experience severely degraded performance, characterized by increased latency, slow response times, and frequent timeouts for all API consumers.
- **Resource Consumption:** The attack directly leads to the exhaustion of critical system resources, including CPU cycles, memory, and network bandwidth, forcing the node to operate beyond its designed capacity.
- **Financial:** The financial impact, while indirect, can be significant. This includes increased operational costs due to the need to over-provision infrastructure to absorb attack traffic, potential loss of revenue from disrupted services, and damage to the organization's reputation. Furthermore, during periods of network congestion caused by the attack, legitimate users may be forced to pay significantly higher transaction fees to ensure their transactions are confirmed, creating an economic burden for the user base.
- **Network Health:** Widespread or sustained attacks can lead to network-wide congestion, impacting the overall efficiency of transaction propagation and confirmation times across the entire blockchain. If a significant number of nodes are affected, it can reduce the effective decentralization of the network, concentrating power among the remaining robust nodes and potentially undermining the network's resilience.
- **Integrity/Confidentiality:** This specific vulnerability does not directly impact data confidentiality (unauthorized access to sensitive data) or data integrity (unauthorized modification of data). However, prolonged DoS conditions can indirectly lead to data inconsistencies or other integrity issues if nodes are forced offline or operate in a degraded state for extended periods.

To summarize the multifaceted consequences, the following table outlines the various impacts of a successful exploitation:

**Table 2: Impact Summary**

| Impact Type | Specific Consequence | Severity |
| --- | --- | --- |
| **Availability** | API Unresponsiveness / Service Downtime | Critical |
|  | Node Crashes / Disconnection from Network | Critical |
| **Performance** | Degraded API Response Times / Increased Latency | High |
|  | Transaction Processing Delays / Unconfirmed Transactions | High |
| **Resource Consumption** | High CPU / Memory / Network I/O Usage | High |
|  | Infrastructure Overload / Scaling Issues | High |
| **Financial** | Increased Operational Costs (e.g., cloud bills) | Moderate |
|  | Potential Loss of Revenue / User Trust | High |
|  | Increased Transaction Fees for Users | High |
| **Network Health** | Network Congestion / Reduced Throughput | High |
|  | Undermined Decentralization / Validator Incentives | High |

This table provides a high-level overview of the multifaceted consequences for stakeholders, helping in understanding the most critical areas affected and aiding in resource allocation for remediation. It simplifies complex impacts into an easily digestible format for both technical and non-technical audiences.

## 13. Fix & Patch Guidance

Addressing the "Poor Rate Limits on Mempool Fetching APIs" vulnerability requires a multi-layered defense strategy, combining in-application controls with external infrastructure-level protections.

- **Implement In-Application Rate Limiting (Golang):**
    - **Utilize `golang.org/x/time/rate`:** The Go standard library's `golang.org/x/time/rate` package is the recommended tool for implementing robust rate limiting within Golang applications. This package provides an implementation of the **Token Bucket Algorithm**.
        - **Token Bucket Algorithm:** This algorithm works by adding "tokens" to a virtual "bucket" at a fixed rate. Each incoming request consumes one token from the bucket. If a request arrives and the bucket is empty, the request is denied. This approach is highly effective as it allows for short bursts of traffic (up to the bucket's capacity) while maintaining a steady average request rate over time.
    - **Implementation as Middleware:** The most idiomatic way to apply rate limiting in Golang HTTP services is by implementing it as middleware. This involves wrapping your API handlers with a function that performs the rate limit check before the request reaches the core business logic. This ensures that every incoming request is subjected to the rate limit.
    - **Per-Client Rate Limiting:** To provide fair usage and robust protection against distributed attacks, implement rate limiting on a per-client basis. This typically involves identifying clients by their IP address, authenticated user ID, or API key. A common pattern involves using a `map` to store individual `rate.Limiter` instances for each client, coupled with a mechanism to periodically clean up inactive client entries to prevent memory bloat.
    - **Appropriate Response Handling:** When a request exceeds the defined rate limit, the application should return an `HTTP 429 Too Many Requests` status code. It is also best practice to include a `Retry-After` header in the response, informing the client when they can safely retry their request.
- **Implement External Rate Limiting:**
    - **API Gateways/Reverse Proxies:** Deploying an API Gateway (e.g., NGINX, Envoy via a service mesh like Istio, Cloudflare) in front of your Golang application is a critical defense layer. These tools are specifically designed to handle high volumes of incoming requests and can apply rate limits at the edge of your network, filtering malicious traffic before it even reaches your application servers. This offloads the burden from your application and provides a more robust first line of defense.
    - **Distributed Storage for State:** For highly scalable and distributed systems, especially those with multiple application instances, the state required for rate limiting (e.g., request counts per client) should be stored in an external, centralized data store like Redis or Cassandra, rather than in-memory per application instance. This ensures consistent rate limiting across all instances and prevents attackers from bypassing limits by distributing their requests across different application servers.
- **Resource Controls and Input Validation:**
    - **Execution Timeouts:** Implement strict timeouts for API requests to prevent long-running or computationally expensive operations from consuming excessive resources indefinitely.
    - **Max Allocable Memory:** Configure maximum memory limits for the Golang application process itself. This can be done at the operating system or container level (e.g., Docker memory limits).
    - **Payload and Response Size Limits:** Enforce maximum size limits on all incoming request parameters and payloads. Crucially, for mempool queries, implement limits on the maximum number of items (transactions) returned per page or per request to prevent attackers from demanding excessively large datasets that are costly to generate and transmit.
- **Table 3: Rate Limiting Algorithms Comparison**

| Algorithm | Description | Pros | Cons |
| --- | --- | --- | --- |
| **Token Bucket** | Tokens are added to a bucket at a fixed rate. Each request consumes a token. If the bucket is empty, the request is denied. | Allows for short bursts of traffic, providing flexibility. Simple to implement and understand. Good balance between strictness and flexibility. | Requires careful tuning of bucket size and refill rate. |
| **Leaky Bucket** | Requests are added to a bucket (queue) and processed at a fixed, constant rate. If the bucket overflows, new requests are dropped. | Smooths out traffic spikes, providing a consistent output rate. Useful for maintaining a steady processing load. | Can introduce latency for requests during bursts. May drop requests if bucket fills up. |
| **Fixed Window** | Tracks the number of requests within a fixed time window (e.g., 1 minute). If the limit is exceeded, further requests are denied until the next window begins. | Simple to implement and understand. Easy to reset counts at fixed intervals. | Can suffer from the "burst at the edge" problem, where clients can send double the allowed requests across two windows. |
| **Sliding Window** | A more sophisticated version of fixed window. Tracks requests over a rolling time period, either by using counters that slide over time or by storing timestamps of requests. | More accurate and smoother rate limiting than fixed window. Avoids the "burst at the edge" problem. | More complex to implement, especially for distributed systems requiring shared state. |

This table provides a comprehensive overview of common rate limiting algorithms, outlining their characteristics, advantages, and disadvantages. This context is valuable for developers and architects in choosing the most appropriate implementation strategy based on their specific application requirements, such as the need to tolerate bursts of traffic versus maintaining a strictly smooth processing rate.

## 14. Scope and Impact

The "Poor Rate Limits on Mempool Fetching APIs" vulnerability has a broad scope, affecting various components within a blockchain ecosystem, and can lead to significant operational, network, and user experience impacts.

- **Affected Systems:**
    - **Publicly Accessible RPC Nodes:** These nodes, which provide an interface for applications to interact with the blockchain, are primary targets. If their mempool fetching APIs are unthrottled, they are highly susceptible to DoS attacks.
    - **Blockchain Explorers and Analytics Platforms:** These services heavily rely on querying mempool data to provide real-time insights into network activity. If their underlying data fetching mechanisms (which might be Golang-based) are vulnerable, their services can be disrupted.
    - **Wallets and Decentralized Applications (dApps):** Many wallets and dApps depend on real-time mempool information for features like transaction status updates, fee estimations, and transaction broadcasting. A DoS on mempool APIs can severely impair their functionality.
    - **Internal Services:** Even internal services within a blockchain infrastructure, if exposed to untrusted input or if they serve as an aggregation point for mempool data without internal rate limits, can become vulnerable.
- **Operational Impact:**
    - **Service Downtime:** The most immediate and severe operational consequence is the complete unavailability of mempool services. This prevents legitimate users from checking transaction statuses, monitoring network conditions, or submitting new transactions, effectively halting critical operations.
    - **Degraded Performance:** Even if a full outage is avoided, the system will experience severe performance degradation. This manifests as slow response times, increased latency for API calls, and significant delays in processing and confirming transactions across the network.
    - **Increased Operational Costs:** Responding to and mitigating a DoS attack often incurs substantial operational costs. This includes higher cloud computing expenses due to excessive resource consumption, the need to over-provision infrastructure to absorb attack traffic, and the human cost of incident response and recovery.
- **Network Health Impact:**
    - **Network Congestion:** Overwhelmed individual nodes can lead to a cascading effect, causing network-wide congestion. This directly impacts the efficiency of transaction propagation and significantly increases confirmation times for all users on the blockchain.
    - **Reduced Decentralization:** A successful attack that takes a significant number of vulnerable nodes offline can inadvertently centralize control among the remaining robust nodes. This undermines the core principle of decentralization, making the network less resilient to future attacks and potentially compromising its censorship resistance.
    - **Undermined Validator Incentives:** DoS attacks that prevent legitimate transactions from entering the mempool or cause nodes to produce empty or underutilized blocks can directly reduce the rewards for validators. This economic disincentive can potentially discourage participation in the network, further impacting decentralization and security.
- **User Experience and Trust:**
    - **User Frustration:** Users will experience significant frustration due to prolonged transaction delays, failed transaction submissions, and unexpected increases in transaction fees.
    - **Loss of Trust:** Repeated disruptions to network availability and reliability can severely erode user confidence in the blockchain network's stability and security. This can lead to users migrating to other networks or losing faith in the underlying technology.

This vulnerability highlights a systemic risk in decentralized architectures, often referred to as the "Tragedy of the Commons." While each node maintains its own mempool , and a vulnerability might initially appear to be a local problem for that specific node, the collective health of individual nodes directly contributes to the overall network's resilience. If a sufficient number of individual nodes are vulnerable and subsequently attacked, it becomes a collective problem where the pursuit of individual (attacker's) gain leads to the degradation of a shared resource—the healthy and functional blockchain network. This demonstrates that individual node vulnerabilities, if widespread, can collectively compromise the stability and integrity of the entire network, even in the absence of a single point of failure.

## 15. Remediation Recommendation

Effective remediation of the "Poor Rate Limits on Mempool Fetching APIs" vulnerability requires a comprehensive, multi-layered approach that integrates security measures throughout the application lifecycle, encompassing both development-time and operational-time controls.

- **Immediate Action:**
    - **Implement In-Application Rate Limiting Middleware:** For all public-facing API endpoints that fetch mempool data, it is imperative to immediately integrate a robust rate limiting middleware. Leveraging Golang's `golang.org/x/time/rate` package is highly recommended due to its efficiency and native integration. Initial rate limits should be set conservatively (e.g., 5-10 requests per second per IP) and then carefully adjusted based on observed legitimate usage patterns and performance metrics. This ensures that the application can handle expected traffic while preventing abuse.
    - **Deploy External Rate Limiter:** If not already in place, configure and deploy an API Gateway or a reverse proxy (such as NGINX or Cloudflare) at the edge of your network. This external layer should be configured to enforce rate limits on all incoming requests to your Golang application's mempool fetching APIs. This acts as a crucial first line of defense, absorbing and filtering malicious traffic before it can even reach and overwhelm your application servers.
- **Best Practices for Secure API Design:**
    - **Identify Critical Endpoints:** Conduct a thorough audit to identify all API endpoints that interact with or expose mempool data, as these are inherently critical and resource-intensive. Prioritize applying granular rate limits to these specific endpoints.
    - **Define Granular Limits:** Implement rate limits that are not just global but are applied based on various identifiers. This includes tracking requests per IP address, authenticated user ID, or API key. Granular limits provide more equitable usage for legitimate clients and offer better protection against distributed attacks. For highly distributed systems, consider using a shared, external data store (like Redis) for rate limiting state to ensure consistency across multiple application instances.
    - **Set Resource Quotas:** Beyond simply limiting request frequency, enforce explicit limits on the resources consumed by each request. This includes:
        - **Maximum Response Size:** Limit the total size of data returned for mempool queries to prevent attackers from requesting excessively large datasets.
        - **Execution Timeouts:** Set strict timeouts for API requests, especially for complex queries, to prevent long-running operations from consuming excessive CPU cycles.
        - **Maximum Items per Page:** For APIs that support pagination, enforce a strict maximum number of items (e.g., transactions) that can be returned in a single request.
    - **Implement Robust Error Handling:** When a rate limit is exceeded, ensure that the API consistently returns an informative `HTTP 429 Too Many Requests` status code. Additionally, include a `Retry-After` header to advise clients on when they can safely retry their request.
    - **Input Validation:** Strictly validate all incoming parameters and payloads to prevent malicious inputs from triggering unexpected or excessive resource consumption.
- **Monitoring and Alerting:**
    - **Comprehensive Logging:** Implement detailed logging for all API requests and responses, including information about the source IP, request frequency, and whether a rate limit was hit. This data is invaluable for forensic analysis and identifying attack patterns.
    - **Real-time Monitoring:** Establish real-time monitoring and alerting for unusual traffic patterns, sudden spikes in resource utilization (CPU, memory, network I/O), and an increase in `429` errors (which indicate that rate limits are actively working). Conversely, an increase in other error codes or performance degradation without `429` errors could signal an ongoing DoS attack bypassing existing controls.
- **Regular Security Audits:** Conduct periodic security audits, penetration testing, and code reviews specifically focusing on API security, resource consumption, and rate limiting implementations. This proactive approach helps identify and address new or overlooked vulnerabilities.

Effectively mitigating this vulnerability requires a combined "shift-left" and "shift-right" security approach. "Shift-left" involves integrating security considerations early in the development lifecycle through secure coding practices, static analysis, and code reviews. "Shift-right" emphasizes continuous monitoring, robust infrastructure-level controls (like API Gateways), and dynamic testing in production environments. This holistic strategy ensures comprehensive protection throughout the application lifecycle, from design to deployment and ongoing operation.

## 16. Summary

The "Poor Rate Limits on Mempool Fetching APIs" vulnerability, identified as `mempool-rate-limit-missing`, represents a critical security flaw in Golang-based blockchain applications. This vulnerability, categorized under CWE-770 (Allocation of Resources Without Limits or Throttling), directly enables Denial of Service (DoS) and resource exhaustion attacks by allowing malicious actors to overwhelm blockchain nodes with unthrottled requests to mempool-related APIs.

The exploitation of this vulnerability is straightforward, requiring minimal attacker effort and no special privileges, making it a highly attractive target for adversaries. Its consequences are severe, impacting node availability, network stability, and overall user experience. Beyond direct service disruption, it can lead to increased transaction fees, undermine validator incentives, and ultimately compromise the decentralized nature of blockchain networks.

Remediation necessitates a robust, multi-layered defense strategy. This includes implementing in-application rate limiting using Golang's `golang.org/x/time/rate` package, deploying external API gateways or reverse proxies for edge-level protection, and enforcing comprehensive resource quotas. Continuous monitoring, detailed logging, and regular security audits are also paramount to detect and respond to potential exploitation effectively. Proactive implementation and maintenance of these controls are essential to preserving the resilience, reliability, and trustworthiness of decentralized blockchain ecosystems.

## 17. References

- https://mempool.space/docs/faq
- https://sp2025.ieee-security.org/downloads/posters/sp25posters-final7.pdf
- https://osl.com/academy/article/bitcoin-mempool-what-happens-to-unconfirmed-transactions/
- https://www.risein.com/blog/blockchains-waiting-room-mempool
- https://security.snyk.io/vuln/SNYK-GOLANG-GOLANGORGXOAUTH2JWS-8749594
- https://owasp.org/API-Security/editions/2019/en/0xa4-lack-of-resources-and-rate-limiting/
- https://docs.mobb.ai/mobb-user-docs/fixing-guides/missing-rate-limiting-fix-guide
- https://github.com/mastodon/mastodon/security/advisories/GHSA-v39f-c9jj-8w7h
- https://docs.secure3.io/features/severity-standard
- https://www.researchgate.net/publication/290249302_Empirical_Analysis_of_Denial-of-Service_Attacks_in_the_Bitcoin_Ecosystem
- https://www.reddit.com/r/golang/comments/1k5xqe5/rate_limiting_in_golang/
- https://blog.sentry.io/how-to-deal-with-api-rate-limits/
- https://github.com/btcsuite/btcd/blob/master/mempool/mempool.go
- https://app.studyraid.com/en/read/11866/377474/middleware-for-rate-limiting
- https://gobyexample.com/rate-limiting
- https://docs.mobb.ai/mobb-user-docs/fixing-guides/missing-rate-limiting-fix-guide
- https://www.geeksforgeeks.org/how-to-design-a-rate-limiter-api-learn-system-design/
- https://dev.to/vivekalhat/rate-limiting-for-begi
- https://arxiv.org/html/2312.02642v2
- https://www.usenix.org/system/files/usenixsecurity24-wang-yibo.pdf
- https://pkg.go.dev/github.com/cometbft/cometbft/mempool
- https://github.com/CardanoSolutions/ogmios/discussions/211
- https://blog.logrocket.com/rate-limiting-go-application/
- https://dev.to/neelp03/adding-api-rate-limiting-to-your-go-api-3fo8
- https://arxiv.org/html/2312.02642v2
- https://docs.tendermint.com/v0.34/tendermint-core/running-in-production.html
- https://gist.github.com/glozow/dc4e9d5c5b14ade7cdfac40f43adb18a
- https://www.usenix.org/system/files/usenixsecurity24-yaish.pdf
- https://build.avax.network/docs/virtual-machines/golang-vms/complex-golang-vm
- https://www.quicknode.com/guides/ethereum-development/transactions/how-to-access-ethereum-mempool
- https://www.getambassador.io/blog/api-throttling-best-practices
- https://www.cyfrin.io/blog/blockchain-rpc-node-guide
- https://www.quicknode.com/guides/ethereum-development/transactions/how-to-access-ethereum-mempool
- https://trustwallet.com/blog/security/ddos-attacks-in-blockchain-networks-explained
- https://ntnuopen.ntnu.no/ntnu-xmlui/bitstream/handle/11250/3140501/2091267_DoS%2BAttacks%2Bon%2BBlockchain%2BEcosystem.pdf?sequence=1&isAllowed=y
- https://docs.bitquery.io/docs/examples/mempool/mempool-api/
- https://build.avax.network/docs/virtual-machines/golang-vms/complex-golang-vm
- https://publicapi.dev/mempool-api
- https://sensu.io/blog/how-to-measure-every-api-call-in-your-go-app
- https://owasp.org/API-Security/editions/2019/en/0xa4-lack-of-resources-and-rate-limiting/
- https://security.snyk.io/vuln/SNYK-GOLANG-GOLANGORGXOAUTH2JWS-8749594
- https://docs.mobb.ai/mobb-user-docs/fixing-guides/missing-rate-limiting-fix-guide