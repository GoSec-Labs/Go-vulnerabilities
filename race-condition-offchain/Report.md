# Report on Golang Vulnerabilities: Race Condition in Off-Chain Calls (race-condition-offchain)

## Vulnerability Title: Race Condition in Off-Chain Calls (race-condition-offchain)

## Severity Rating

Race conditions, in general, are recognized as a significant source of unpredictable behavior, data corruption, system crashes, and even Denial of Service (DoS) or privilege escalation within software systems. When such conditions manifest in financial contexts, they directly lead to inconsistent results and potential financial losses. The intersection of these race conditions with blockchain reorganizations (reorgs)—inherent phenomena in decentralized networks that can be exploited for malicious purposes such as double-spending —amplifies the potential impact. The fundamental problem lies in an off-chain system acting upon a blockchain state that is subsequently invalidated, leading to a critical divergence from the canonical truth of the distributed ledger.

The interaction of Go's concurrency model with the probabilistic finality of blockchain creates a unique class of Time-of-Check-to-Time-of-Use (TOCTTOU) vulnerability. The "race" in this scenario is not confined to goroutines within the Go application but extends to the competition between the off-chain application's processing speed and the blockchain network's consensus mechanism. This dynamic interaction makes the issue a distributed system consistency problem, rather than solely a local concurrency bug. The analysis of this vulnerability through the CVSS framework reveals that while the attack complexity can be high, the potential consequences are severe and wide-ranging. This suggests that even if instances of such attacks are rare, their profound implications necessitate robust preventative and reactive measures. The designation of "Changed" scope within the CVSS assessment underscores that the effects of a successful attack ripple beyond the immediate vulnerable component, impacting the broader financial ecosystem. A double-spend, for instance, directly manipulates the perceived state of funds on the blockchain, compromising the integrity of the ledger itself, which constitutes a systemic risk.

The CVSS v3.1 score breakdown for this vulnerability is presented below:

| CVSS Metric Group | Specific Metric | Justification |
| --- | --- | --- |
| **Attack Vector (AV)** | Network (N) | The vulnerability is exploited by interacting with the blockchain network (e.g., submitting transactions that trigger reorgs) or by the off-chain service consuming data from the network. No local access to the vulnerable system is required for the initial trigger. |
| **Attack Complexity (AC)** | High (H) | Exploiting race conditions often demands precise timing and control over concurrent operations. In this context, it involves anticipating or influencing network latency and block propagation to ensure the off-chain system processes a transaction *before* a reorg invalidates it. Malicious reorganizations, such as 51% attacks, are complex to orchestrate, particularly on large blockchain networks. However, the inherent unpredictability of concurrent systems makes even seemingly simple race conditions challenging to detect and fix. |
| **Privileges Required (PR)** | None (N) | An attacker typically does not require any elevated privileges on the target Golang system or the blockchain network itself to initiate the conditions for this vulnerability. The attacker operates as a regular network participant. |
| **User Interaction (UI)** | None (N) | Direct user interaction with the victim's off-chain application is generally not required for the attack to succeed. The attack primarily involves the attacker's actions on the blockchain and the off-chain service's automated processing. |
| **Scope (S)** | Changed (C) | A successful exploitation can lead to inconsistencies that extend beyond the immediate off-chain service. For example, a double-spend can affect the integrity of funds on the blockchain itself, altering the scope of impact from the specific vulnerable component to the broader financial ecosystem. |
| **Confidentiality Impact (C)** | Low (L) to High (H) | While not a direct information leakage vulnerability, data corruption (e.g., incorrect balances, transaction histories) can indirectly expose sensitive financial positions or lead to unauthorized transfers. The severity of this impact depends on the nature of the data being processed. |
| **Integrity Impact (I)** | High (H) | The primary impact is the compromise of data integrity. Double-spending directly undermines the integrity of transactions, and an inconsistent state in the off-chain system means its records no longer accurately reflect the canonical blockchain, leading to unreliable operations. |
| **Availability Impact (A)** | Low (L) to High (H) | A successful exploitation might not always result in a complete denial of service, but an off-chain service operating on inconsistent data can become unreliable, slow, or necessitate manual intervention, thereby impacting its availability. Severe or repeated reorgs can also cause significant delays and uncertainty for users. |

Given the potential for direct financial loss through double-spending, severe data integrity compromise, and significant operational and reputational damage, this vulnerability is classified as **High** to **Critical**. The specific impact will depend on the value of assets managed by the off-chain service and the criticality of the business logic being executed.

## Description

The "Race condition in off-chain calls" (race-condition-offchain) represents a critical vulnerability that arises when a Golang application, operating off-chain, processes data or executes business logic based on information received from a blockchain. The vulnerability occurs because the blockchain's state can undergo a "reorganization" (reorg) *after* the off-chain logic has begun processing the initial information but *before* that processing is fully reconciled or considered final. This creates a time-sensitive "race window" where the off-chain system's actions become inconsistent with the true, canonical blockchain state, ultimately leading to erroneous or exploitable outcomes.

To fully grasp this vulnerability, it is essential to understand its two foundational components: race conditions in concurrent programming and blockchain reorganizations. A race condition is a phenomenon in concurrent systems where the outcome of operations depends on the unpredictable timing or interleaving of multiple processes accessing shared resources. In the context of Go, this typically involves multiple goroutines accessing shared mutable data without proper synchronization mechanisms. Such conditions can lead to non-deterministic behavior, data corruption, and various security breaches, including Denial of Service and Privilege Escalation. Their unpredictable nature makes them notoriously difficult to detect and debug.

Blockchain reorganizations, or "reorgs," are an intrinsic part of decentralized consensus mechanisms. A reorg occurs when a node discovers a new, longer chain segment that replaces the previously accepted main chain. This process effectively "rewrites" a portion of the blockchain's history. While short reorgs (typically 1-2 blocks deep) are a common occurrence due to network latency and simultaneous block mining , deeper reorgs can also happen, particularly in Proof-of-Work (PoW) chains, or be maliciously induced through attacks like a 51% attack. When a reorg takes place, blocks in the old, shorter chain are "deactivated" or become "stale," meaning their transactions are effectively reverted or are no longer considered part of the canonical history. Any off-chain system that has acted upon these stale transactions will now possess an outdated and incorrect view of the blockchain state.

The core of this vulnerability lies in the critical time gap between an off-chain Golang service observing a blockchain event (e.g., a transaction confirmation) and that event achieving sufficient "finality" on the blockchain. If the off-chain service acts on a transaction that is subsequently reorged out, its internal state—such as a database balance or a fulfilled order—becomes inconsistent with the actual, canonical blockchain. This represents a classic Time-of-Check-to-Time-of-Use (TOCTTOU) race condition. The "check" involves the off-chain service observing a transaction on the blockchain, and the "use" involves the service acting on that transaction off-chain. The vulnerability exists because the underlying truth—the canonical chain—can change within this window, invalidating the initial observation. The "shared resource" in this race condition is not merely an in-memory variable but the *perceived state of the blockchain* as interpreted by the off-chain service. The "concurrent operations" are the off-chain service's processing loop and the blockchain network's continuous consensus process, which includes the possibility of reorganizations. This highlights the challenge of maintaining consistency across distributed, asynchronously updating systems. This vulnerability also underscores that the security and reliability of decentralized applications (dApps) extend beyond just smart contract audits. The integration layer between on-chain and off-chain components constitutes a significant attack surface that demands careful design and robust handling of the blockchain's probabilistic finality. If a dApp's backend processes payments or grants access based on on-chain events without correctly handling reorgs, an attacker can exploit this gap, compromising the overall system even if the smart contract code itself is perfectly secure.

## Technical Description (for security pros)

The "race-condition-offchain" vulnerability is a specific instance of a Time-of-Check-to-Time-of-Use (TOCTTOU) vulnerability. In this scenario, the "check" phase involves an off-chain Golang service querying a blockchain node for transaction details or event logs. This typically utilizes libraries such as `go-ethereum`, employing methods like `ethclient.Dial` to connect to a client and `SubscribeFilterLogs` to listen for events , or `eth_getBlockReceipts` for retrieving transaction receipts. The "use" phase then involves the Go application updating its internal state, such as a database or an in-memory cache, or triggering downstream business processes based on this retrieved information. The critical TOCTTOU window exists because the blockchain's canonical chain can undergo a reorganization (reorg) between the completion of the "check" and the execution of the "use," thereby invalidating the initial observation.

Go's concurrency model, built around lightweight goroutines, facilitates highly performant parallel execution. However, the Go memory model, which adheres to the "happens before" principle, implies that unsynchronized concurrent reads and writes to shared memory can lead to unpredictable data corruption. In the context of off-chain services, the concept of "shared memory" extends beyond internal Go variables to encompass external resources like databases or external APIs. These external resources are updated based on blockchain events. If multiple goroutines are processing events concurrently without proper internal synchronization, or if the external state (the blockchain) changes unexpectedly, the integrity of the data becomes compromised. This clarifies that the issue is fundamentally a distributed systems consistency problem, not merely a local Go concurrency bug. Even if a Go application employs `sync.Mutex` or `channels` to protect its *internal* shared variables, it remains susceptible if it fails to account for the *external, asynchronous changes* to the blockchain's canonical state. A Go program might be internally thread-safe, but if it fetches data from an external source like a blockchain node, and that source's data changes atomically from its perspective (a reorg is an atomic change to the chain's head), the Go program's internal state can become inconsistent. The race occurs between the Go program's read/process cycle and the blockchain's consensus updates.

Blockchain reorganizations occur when a node discovers a new, longer chain that supersedes its current main chain, prompting the node to abandon the old chain and switch to the new one. This process effectively "rewrites" a segment of the blockchain's history. For instance, in a Proof-of-Work (PoW) chain, a miner might privately mine a longer chain and then broadcast it, compelling other nodes to adopt it. This can be an accidental occurrence due to network latency or a deliberate malicious act, such as a 51% attack, where an attacker controls over 50% of the network's hashing power to create a longer, private chain for double-spending purposes. Transactions included in blocks that are subsequently reorged out become "stale" and are no longer considered part of the canonical chain. An off-chain service that has already processed these stale transactions will consequently maintain an inconsistent view of the blockchain state, leading to discrepancies in its internal records. This vulnerability highlights the profound challenge of achieving strong consistency guarantees in systems that bridge probabilistic finality (blockchain) with traditional deterministic state (off-chain databases). This implies that developers must design for potential rollbacks and state reconciliation as a fundamental aspect of their architecture, not merely as an edge case. The immutability often associated with blockchain is, for off-chain systems, an *eventual* immutability, demanding a different design paradigm than typical application development where database writes are generally considered final unless explicitly modified.

A common exploitation flow, exemplified by a double-spend attack, proceeds as follows:

1. **Initial Transaction (TxA):** An attacker initiates a transaction (TxA), such as a payment to a cryptocurrency exchange, which is then included in a block (Block N) on the current canonical chain.
2. **Off-Chain Processing:** The off-chain Golang service, acting as an event listener, rapidly observes Block N and TxA. It then processes TxA, updating its internal database (e.g., crediting the attacker's account on the exchange or initiating the release of goods/services). This processing often occurs with minimal blockchain confirmations to exploit the inherent race window.
3. **Concurrent Attack Chain:** Simultaneously or shortly after TxA is confirmed, the attacker mines a private alternative chain (e.g., Block N', Block N+1', etc.) that originates from a block *prior* to Block N and *does not* include TxA, or instead includes a different transaction (TxB) that benefits the attacker. The attacker ensures this private chain ultimately becomes longer than the honest chain.
4. **Network Reorganization:** The attacker then broadcasts their longer private chain to the network. Honest nodes, adhering to the longest chain rule, reorganize their local view of the blockchain to adopt the attacker's chain. Consequently, Block N (which contained TxA) becomes stale and is effectively removed from the canonical history.
5. **Inconsistent State & Double-Spend:** The off-chain service has already acted upon TxA, which is now no longer present on the canonical chain. Without proper reorg handling, the attacker has successfully received goods or services while their original payment (TxA) has been effectively reversed on the blockchain, enabling them to spend the same funds again.

## Common Mistakes That Cause This

Several common development and architectural oversights contribute to the emergence of race conditions in off-chain calls within Golang applications. These typically stem from a misunderstanding of blockchain finality and the complexities of distributed system consistency.

### Insufficient Confirmation Depth

A prevalent mistake involves relying on transactions with zero or very few blockchain confirmations for critical off-chain business logic. Developers often prioritize transaction processing speed over the certainty of finality. While processing transactions quickly can enhance user experience, this approach leaves a substantial "race window" open for reorgs. Deeper reorganizations are possible, particularly in Proof-of-Work (PoW) chains or under malicious attacks. For example, the Tezos blockchain recommends waiting for 30 blocks for transaction finality , and Ethereum provides "safe" and "finalized" block tags to signify higher degrees of certainty. This practice is a direct consequence of misunderstanding or underestimating blockchain's probabilistic finality. Developers might treat a transaction appearing in a block as an immediate, irreversible event, akin to a traditional database commit. However, blockchain consensus mechanisms mean a block can be "orphaned" or become "stale" , effectively undoing the transaction from the canonical chain. The error lies in assuming absolute finality where only probabilistic finality exists.

### Lack of Reorg Detection and Reconciliation Logic

A significant design flaw is the failure to implement explicit mechanisms within the off-chain Go application to detect blockchain reorganizations and reconcile its internal state accordingly. This includes not storing block numbers or hashes alongside processed data, neglecting to check for hash continuity between sequential blocks, or failing to establish a robust rollback or re-indexing strategy. Many off-chain services are designed with an implicit assumption of monotonic blockchain progression. When a reorg occurs, if the system does not detect it, it will continue to operate on outdated data, leading to severe inconsistencies. Critical steps such as verifying the `parentHash` continuity of incoming blocks are frequently overlooked. This highlights a fundamental design oversight in bridging blockchain and traditional application logic. Traditional event-driven systems typically assume that once an event is processed, its effects are durable. Blockchain events, however, can be "undone" by reorgs. The mistake is applying a traditional event processing paradigm to a blockchain context without adapting to its unique consistency model, which requires the off-chain system to be capable of "undoing" its state changes.

### Improper Use of Go Concurrency Primitives

Even when reorg handling is considered, internal concurrency issues within the Go application can exacerbate the problem. Concurrent access to shared mutable data structures—such as in-memory caches, database connection pools, or shared counters—without proper synchronization mechanisms (e.g., `sync.Mutex`, `channels`, `sync/atomic` operations) can introduce internal race conditions. While these internal issues do not directly cause blockchain reorgs, they can corrupt the off-chain state, rendering reorg reconciliation efforts ineffective or leading to further unpredictable behavior. For instance, if multiple goroutines attempt to update a user's balance in a map concurrently without a mutex, the final balance could be incorrect irrespective of any blockchain reorgs. This points to a layered problem: even perfectly designed external reorg handling can be undermined by internal concurrency bugs. A system can be architecturally sound in its approach to reorg handling but still fail due to low-level programming errors. If the logic responsible for "rolling back" or "re-indexing" data after a reorg itself contains race conditions, the corrected state will remain unreliable, emphasizing that general secure coding practices for concurrency are always vital.

### Over-reliance on Real-time WebSocket Streams Without Verification

A common operational misstep is to solely trust real-time WebSocket event streams from blockchain nodes as the definitive source of truth, without independent verification against the blockchain or waiting for sufficient confirmations. While WebSockets offer low-latency updates, they often provide provisional data. A comment from a community discussion explicitly warns against relying on WebSockets for reorg-sensitive data, suggesting they are problematic if not combined with robust reconciliation mechanisms. The speed advantage of these streams can inadvertently lead to processing non-finalized data more quickly, thereby increasing the exposure to the race window. This represents an operational misjudgment where the pursuit of responsiveness overrides the fundamental need for data integrity in an eventually consistent system. WebSockets are designed for rapid data push, meaning they are likely to deliver events from blocks that are still at risk of being reorged. The error lies in treating the speed of delivery as a proxy for finality, which can lead to premature actions based on potentially invalid data.

## Exploitation Goals

Exploitation of race conditions in off-chain calls primarily targets the integrity and reliability of systems that bridge blockchain and traditional application logic. The objectives of an attacker typically fall into several categories, each with distinct consequences.

### Double-Spending

The most prevalent and financially devastating objective is double-spending. An attacker aims to spend the same cryptocurrency or digital asset twice. This is achieved by making an initial payment to a victim (e.g., an exchange, a vendor), receiving goods or services off-chain, and then causing a blockchain reorganization to reverse the original transaction on the canonical chain. The off-chain Golang service, lacking proper reorg handling, processes the initial (now stale) transaction and triggers an irreversible off-chain action, such as releasing funds or shipping products. The attacker then ensures their original payment is removed from the blockchain's history, effectively acquiring something for free. The off-chain service, in this scenario, acts as an unwitting oracle or gateway that can be manipulated to validate a fraudulent state. The attacker exploits the time delay between the off-chain system's action and the blockchain's eventual finality. If this off-chain system makes irreversible decisions based on non-finalized blockchain data, it becomes a critical vulnerability.

### Data Inconsistency and Corruption

Beyond direct financial theft, an attacker may aim to manipulate the off-chain system's internal state—including databases and caches—to reflect an incorrect or malicious view of the blockchain. This can result in erroneous user balances, invalid transaction histories, or misinformed automated business decisions. By repeatedly triggering reorgs or causing the off-chain service to process stale blocks, an attacker can desynchronize the off-chain data from the true blockchain state. While this might not involve immediate financial theft, it can cause significant operational chaos, auditing complexities, and undermine overall system reliability. This goal targets the fundamental integrity and trustworthiness of the application's data. Even if an attacker cannot directly steal funds, causing persistent data inconsistencies can degrade the service to the point of being unusable or necessitate costly and time-consuming manual reconciliation, which can be considered a form of economic denial of service or a precursor to other attacks.

### Denial of Service (DoS) / Service Disruption

Another objective is to render the off-chain service unavailable or severely degraded. This can be achieved by repeatedly triggering reorgs or race conditions that force the off-chain service into an inconsistent state, leading to crashes, errors, or requiring continuous manual intervention. If the reorg handling logic is inefficient, buggy, or non-existent, continuous reorgs (even natural ones) can overwhelm the off-chain service's processing capabilities, exhausting system resources or leading to deadlocks. This represents a non-financial but equally damaging impact, affecting user experience, increasing operational costs, and compromising overall system reliability. A poorly implemented reorg handling mechanism can effectively become a self-inflicted DoS. If the system is constantly attempting to reconcile its state or crashes due to unexpected data, it becomes unavailable for legitimate use.

### Privilege Escalation (Indirect)

While not a direct or common consequence of this specific race condition, some race conditions can be exploited for privilege escalation. In the context of off-chain calls, this could theoretically occur if the off-chain service's internal logic, when operating on inconsistent blockchain data (e.g., incorrect token ownership or staking status), inadvertently grants unauthorized access or permissions to an attacker. An attacker might manipulate a reorg to temporarily appear to possess a certain token or stake, which the off-chain service then uses to grant a privilege (e.g., access to a restricted feature, voting power). If the privilege is granted before the reorg is detected and reconciled, a window for exploitation exists. This highlights a broader potential risk stemming from the unpredictable nature of race conditions, even if less common in this specific scenario. If an off-chain service uses on-chain data for authorization (e.g., "only token holders can access this feature"), a reorg that temporarily shows an attacker as a token holder could lead to unauthorized access. The race in this instance is between the off-chain system's authorization check and the reorg event.

## Affected Components or Files

The vulnerability of race conditions in off-chain calls impacts several key components within a Golang application that interacts with blockchain networks. Understanding these affected areas is crucial for comprehensive mitigation.

### Blockchain Event Listeners/Indexers (Golang Services)

These components are the primary interface between the off-chain system and blockchain nodes, responsible for retrieving real-time or historical data. Any Go service that subscribes to blockchain events, for instance, by using `ethclient.Dial` to establish a connection and `SubscribeFilterLogs` from the `go-ethereum` library to listen for events , and then processes these events (e.g., for indexing transactions, tracking token transfers , or monitoring smart contract events), is directly exposed to this vulnerability. These services represent the *entry point* for blockchain data into the off-chain system. If they do not correctly account for the probabilistic nature of blockchain finality and the possibility of reorgs, they become the initial point of failure, propagating potentially invalid data throughout the system.

### Databases/Data Stores

Any persistent storage mechanism, such as PostgreSQL  or NoSQL databases, utilized by the off-chain service to store blockchain-derived state is susceptible. This includes critical data like user balances, transaction records, mirrored smart contract states, or any other data copied or processed from the blockchain. The database effectively functions as the "shared mutable state" that is vulnerable to the race condition. If the off-chain service updates this database based on stale blockchain data—i.e., data from a chain that is later reorged out—the database will maintain an inconsistent and potentially exploitable view of the actual blockchain state. This can lead to discrepancies that are difficult to reconcile without proper mechanisms.

### Internal Caches/Memory

In-memory caches, shared Go variables, or other temporary data structures that hold blockchain state or derived data are also vulnerable. Concurrent access to these components without proper Go synchronization primitives (e.g., `sync.Mutex`, `channels`, `atomic` operations) can significantly exacerbate the problem. These components are the immediate targets of internal Go race conditions. Even if robust external reorg handling is implemented, internal concurrency bugs can lead to corrupted state within the application's memory, rendering subsequent reconciliation efforts futile or introducing new vulnerabilities. This highlights that general secure coding practices for concurrency are paramount, even when addressing distributed system challenges.

### Business Logic Modules

Any Go modules, functions, or services that execute critical business logic based on blockchain data are directly affected. This encompasses modules responsible for financial operations (e.g., crediting or debiting accounts), asset transfers, user authentication or authorization mechanisms tied to on-chain token ownership, or any other decision-making processes that rely on the accuracy of blockchain-derived information. These modules are where the impact of the race condition becomes tangible, as they act upon the potentially inconsistent data. For example, a module that releases digital goods upon detecting a payment transaction will inadvertently release goods for a payment that is later reversed if the underlying blockchain data is reorged out. The integrity of these business operations is directly compromised when the input data from the blockchain is not definitively final.

## Vulnerable Code Snippet

While a specific vulnerable code snippet from the research material is not provided, a conceptual Go code snippet can illustrate the core problem of an off-chain service acting on unconfirmed or potentially stale blockchain data. The following example demonstrates a simplified event listener that processes a "deposit" event without adequate confirmation depth or reorg handling, leading to a potential race condition.

```go
package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/core/types"
)

// Mock database to simulate off-chain state
var userBalances = make(map[common.Address]*big.Int)
var dbMutex sync.Mutex

// Event structure (simplified)
type DepositEvent struct {
	User    common.Address
	Amount  *big.Int
	TxHash  common.Hash
	BlockNumber uint64
	BlockHash common.Hash // Crucial for reorg detection
}

func main() {
	// Connect to an Ethereum client (e.g., Infura, local node)
	// For demonstration, assume connection is successful
	client, err := ethclient.Dial("wss://mainnet.infura.io/ws/v3/YOUR_INFURA_PROJECT_ID")
	if err!= nil {
		log.Fatalf("Failed to connect to Ethereum client: %v", err)
	}

	// Example contract address (replace with actual contract)
	contractAddress := common.HexToAddress("0xYourContractAddressHere")

	query := ethereum.FilterQuery{
		Addresses:common.Address{contractAddress},
	}

	logs := make(chan types.Log)
	sub, err := client.SubscribeFilterLogs(context.Background(), query, logs)
	if err!= nil {
		log.Fatalf("Failed to subscribe to event logs: %v", err)
	}

	fmt.Println("Listening for deposit events...")

	for {
		select {
		case err := <-sub.Err():
			log.Fatalf("Subscription error: %v", err)
		case vLog := <-logs:
			// In a real application, parse the log data into DepositEvent
			deposit := DepositEvent{
				User:    common.HexToAddress("0xAttackerAddressHere"), // Simplified for example
				Amount:  big.NewInt(1000000000000000000), // 1 ETH (simplified)
				TxHash:  vLog.TxHash,
				BlockNumber: vLog.BlockNumber,
				BlockHash: vLog.BlockHash,
			}

			// --- VULNERABLE LOGIC START ---
			// Processing transaction immediately without sufficient confirmations
			// or robust reorg handling.
			fmt.Printf("Processing deposit from block %d, Tx: %s\n", deposit.BlockNumber, deposit.TxHash.Hex())

			dbMutex.Lock()
			currentBalance := userBalances[deposit.User]
			if currentBalance == nil {
				currentBalance = big.NewInt(0)
			}
			userBalances[deposit.User] = new(big.Int).Add(currentBalance, deposit.Amount)
			dbMutex.Unlock()

			fmt.Printf("User %s balance updated to: %s\n", deposit.User.Hex(), userBalances[deposit.User].String())
			// --- VULNERABLE LOGIC END ---

			// In a real double-spend scenario, an off-chain action (e.g., releasing goods)
			// would occur here based on this potentially unconfirmed deposit.
		}
	}
}
```

**Explanation of Vulnerability in Snippet:**

The vulnerability in this snippet lies in the immediate update of `userBalances` (simulating an off-chain database) upon receiving a `DepositEvent` from the WebSocket stream. The code does not:

1. **Wait for sufficient confirmations:** It processes events from the "latest" block as soon as they are received. This leaves a wide window for a blockchain reorganization to occur, invalidating the block containing the deposit.
2. **Implement reorg detection:** There is no logic to check if a previously processed block has become stale due to a reorg. If `Block N` (containing the deposit) is later replaced by `Block N'` in a reorg, the `userBalances` will remain incorrectly updated, leading to a double-spend opportunity if the attacker has already received goods/services off-chain.
3. **Handle internal concurrency race conditions:** While `dbMutex` is used for the `userBalances` map, this only protects against internal Go goroutine races. It does not protect against the external race condition caused by blockchain reorgs. If multiple off-chain services or instances of this service are running, they would also need coordinated reorg handling.

An attacker could deposit funds, trigger the off-chain system to act, and then orchestrate a reorg (e.g., via a 51% attack or by exploiting network latency) to remove their original deposit from the canonical chain. The off-chain system would have processed the deposit, but the funds on the blockchain would remain with the attacker, enabling a double-spend.

## Detection Steps

Detecting race conditions in off-chain calls requires a multi-faceted approach, combining internal Go tooling with external blockchain monitoring and rigorous testing.

### Go's Built-in Race Detector

For identifying internal Go concurrency issues that could exacerbate or introduce race conditions within the off-chain service itself, Go's built-in race detector is an invaluable tool. It can be enabled by running Go programs with the `-race` flag (e.g., `go run -race your_program.go`, `go test -race your_package`). This detector instruments memory accesses and identifies unsynchronized concurrent reads and writes to shared variables. It is highly effective at catching data races, which can lead to unpredictable behavior and data corruption. However, it is important to note that the race detector is a dynamic analysis tool; it can only detect race conditions when they are actually triggered during execution. This means that comprehensive test coverage, especially stress tests and integration tests, is crucial to exercise concurrent parts of the code and increase the likelihood of uncovering such issues. While it identifies internal Go concurrency problems, it does not directly detect the distributed race condition stemming from blockchain reorgs, as that involves external state changes.

### Blockchain Monitoring and Data Integrity Checks

To detect the distributed race condition related to blockchain reorgs, the off-chain system must actively monitor the blockchain state for inconsistencies. This involves:

1. **Verifying Block Hash Continuity:** Users of off-chain services should independently verify that each received block's `parentHash` matches the hash of the immediately preceding block. A mismatch indicates a reorg has occurred. Services like QuickNode Streams are designed to handle reorgs by monitoring block validity and position, detecting discrepancies when a new block's parent hash doesn't match the previous one.
2. **Tracking Block Numbers and Hashes:** For every transaction or event processed, the off-chain system should store the associated block number and block hash. On receiving new blocks, before processing new data, the system should check if it has previously seen a block with the same number but a different hash. If so, a reorg has occurred, and the data associated with the old block number must be reconciled.
3. **Monitoring `removed` Flag in Event Logs:** Ethereum event logs include a `removed` boolean field that indicates whether a log was removed due to a chain reorganization. Off-chain listeners should process this flag to identify and handle events that have been invalidated by a reorg.
4. **Observing Chain Tips:** For nodes that are directly connected to the blockchain, commands like `bitcoin-cli getchaintips` can reveal competing chains (`valid-fork`, `valid-headers` statuses) and their `branchlen`, indicating potential or actual reorganizations.

### Stress Testing and Simulation

Given the time-sensitive nature of race conditions, robust testing environments are essential. This includes:

- **Concurrency Testing:** Designing tests that simulate multiple concurrent requests or event processing to stress the off-chain system's handling of shared resources and external data updates.
- **Reorg Simulation:** In a controlled test environment, it is possible to simulate blockchain reorganizations (e.g., by running private chains or using tools that allow for chain manipulation) to observe how the off-chain service reacts and to confirm its ability to reconcile state correctly. This can involve using tools like GOAT for Go concurrency testing, which facilitates systematic schedule space exploration to accelerate bug occurrence.

## Proof of Concept (PoC)

A Proof of Concept (PoC) for a race condition in off-chain calls typically aims to demonstrate the feasibility of a double-spend attack or significant data inconsistency. The PoC would involve orchestrating a precise sequence of events across both the blockchain and the vulnerable off-chain Golang service.

The general steps for constructing such a PoC would include:

1. **Setup a Vulnerable Off-Chain Service:** Deploy a Golang application that acts as an event listener or indexer for a blockchain, processing transactions with insufficient confirmation depth (e.g., acting on 0-1 confirmations) and lacking robust reorg detection/reconciliation logic. This service would update an internal database or trigger an off-chain action (e.g., crediting an account, releasing a simulated good).
2. **Establish a Controlled Blockchain Environment:** For a reliable PoC, a private blockchain network (e.g., a local Geth instance for Ethereum) or a testnet where reorgs can be more easily induced or observed is preferred. This allows the attacker to control mining/staking power or simulate network latency.
3. **Attacker Account and Initial Funds:** The attacker would need an account with funds on the blockchain to initiate transactions.
4. **Execute Initial Transaction (TxA):** The attacker sends a transaction (TxA) to the victim's contract or address that the off-chain service is monitoring. This transaction should be designed to trigger an off-chain action upon minimal confirmation.
5. **Monitor Off-Chain Action:** The attacker monitors the off-chain service to confirm that it has processed TxA and performed the desired action (e.g., credited their account, released goods). This typically happens very quickly after TxA is included in a block.
6. **Induce a Reorganization:**
    - **Simulated 51% Attack:** The attacker, controlling a majority of hashing power (in PoW) or stake (in PoS) in the controlled environment, secretly mines an alternative chain that starts from a block *before* TxA's block and *does not* include TxA. This alternative chain must be made longer than the chain containing TxA. For instance, a 51% attack involves an entity controlling over 50% of the network's computational power to create a longer, private chain and reverse previously confirmed transactions.
    - **Network Latency Exploitation:** In some cases, especially on less decentralized networks or during high network congestion, an attacker might exploit network latency to create a temporary fork and then quickly build on their preferred fork, hoping the off-chain service processes the "wrong" side first.
7. **Broadcast Alternative Chain:** Once the alternative chain is longer, the attacker broadcasts it to the network. Honest nodes, following the longest chain rule, will reorganize, making the block containing TxA stale.
8. **Verify Double-Spend/Inconsistency:** The attacker verifies that the off-chain action (e.g., goods received) remains valid, while the original TxA is no longer on the canonical blockchain, allowing the attacker to spend the same funds again. Alternatively, the PoC could demonstrate internal data inconsistencies in the off-chain database without direct financial gain, showcasing data corruption.

An example PoC could involve a simulated exchange where the off-chain Go service credits a user's balance immediately upon detecting a deposit. The attacker deposits 1 ETH, the Go service credits their off-chain balance, and the attacker then quickly initiates a reorg to remove the 1 ETH deposit from the canonical chain. The attacker now has 1 ETH on-chain (as the deposit was reverted) and 1 ETH credited to their off-chain exchange balance, demonstrating a successful double-spend.

## Risk Classification

The risk associated with a race condition in off-chain calls is classified as **High** to **Critical**. This classification is derived from a comprehensive assessment of its severity, the likelihood of occurrence under certain conditions, and the profound impact it can have on both the vulnerable application and the broader blockchain ecosystem.

**Severity:** As detailed in the "Severity Rating" section, the CVSS v3.1 score points to high integrity impact, potential high confidentiality and availability impact, and a changed scope. This indicates that the vulnerability can lead to direct financial losses (e.g., double-spending), severe data corruption, and significant operational disruption. The ability to manipulate the canonical chain's perception by an off-chain service directly undermines the fundamental trust model of blockchain technology.

**Likelihood:** The likelihood of exploitation, while not trivial, is elevated by several factors:

- **Probabilistic Finality:** All blockchains, especially Proof-of-Work chains, inherently have probabilistic finality, meaning blocks can be reorged. While deep reorgs are less frequent, shallow reorgs are common.
- **Economic Incentives:** The potential for significant financial gain (e.g., double-spending valuable assets) provides strong incentives for attackers to invest in sophisticated exploitation techniques.
- **Complexity of Distributed Systems:** Correctly handling distributed consistency across an off-chain system and a blockchain is inherently complex. Common mistakes, such as insufficient confirmation depth or inadequate reorg handling, are widespread due to performance pressures or a lack of understanding of blockchain nuances.
- **Accessibility of Blockchain Data:** Off-chain services continuously consume blockchain data, creating persistent attack surfaces.

**Impact:** The impact of a successful exploitation is multifaceted:

- **Financial Loss:** Direct theft of funds through double-spending is the most immediate and severe consequence, affecting users, exchanges, and decentralized applications.
- **Data Integrity Compromise:** The off-chain system's internal state (databases, caches) becomes desynchronized from the true blockchain, leading to unreliable data, incorrect balances, and auditing nightmares.
- **Operational Disruption:** Inconsistent states can cause the off-chain service to malfunction, crash, or require extensive manual intervention, leading to service unavailability and increased operational costs.
- **Reputational Damage:** Successful attacks severely erode user trust in the application and the underlying blockchain ecosystem, impacting adoption and market value.
- **Systemic Risk:** In large-scale applications, widespread exploitation could introduce systemic risks to the broader decentralized finance (DeFi) ecosystem if the vulnerable off-chain service is a critical component.

In summary, the combination of high potential impact and a non-negligible likelihood, driven by the inherent complexities of blockchain interaction and common development pitfalls, places this vulnerability in the High to Critical risk category. Organizations operating Golang off-chain services that interact with blockchains must prioritize robust mitigation strategies to safeguard against this threat.

## Fix & Patch Guidance

Mitigating race conditions in off-chain calls requires a layered approach, addressing both the fundamental interaction with the blockchain and the internal concurrency of the Golang application.

### 1. Implement Sufficient Confirmation Depth

The most critical step is to wait for a sufficient number of blockchain confirmations before considering a transaction final and acting upon it off-chain. The ideal number of confirmations varies by blockchain network and the value of the transaction, but it should be chosen to minimize the probability of a reorg invalidating the transaction. For example, while Bitcoin often suggests 6 confirmations, other chains like Tezos recommend 30 blocks , and Ethereum offers "safe" and "finalized" block tags that signify higher degrees of immutability. This practice directly reduces the "race window" during which a reorg can occur and invalidate the transaction.

### 2. Develop Robust Reorg Detection and Reconciliation Logic

Off-chain Golang services must be designed to explicitly detect and handle blockchain reorganizations. This involves:

- **Storing Block Metadata:** For every processed transaction or event, store its associated block number and the block hash in the off-chain database.
- **Continuity Checks:** Continuously verify the hash continuity of incoming blocks. If a new block's `parentHash` does not match the hash of the previously processed block, a reorg has occurred.
- **Reconciliation Strategy:** Upon detecting a reorg, the service must:
    - Identify the divergence point: Work backward from the discrepancy to find the last matching block between the off-chain data and the canonical chain.
    - Invalidate/Rollback Stale Data: Delete or mark as invalid all off-chain data that originated from blocks on the reorged-out chain. The Safe Transaction Service, for example, marks blocks as unconfirmed until a certain depth is reached and deletes related transactions if a `blockHash` changes.
    - Re-index Canonical Data: Re-process events from the newly established canonical chain from the divergence point forward to ensure the off-chain state is consistent with the blockchain's truth. Services like QuickNode Streams can re-stream blocks to correct discrepancies.
- **Utilize `removed` Flag:** When subscribing to Ethereum event logs, monitor the `removed` boolean field, which indicates if a log was invalidated by a reorg.

### 3. Proper Use of Go Concurrency Primitives

Even with robust reorg handling, internal race conditions can undermine the system's integrity. Developers must employ Go's synchronization primitives correctly to protect shared mutable data within the application:

- **Mutexes (`sync.Mutex`, `sync.RWMutex`):** Use mutexes to protect critical sections of code where shared variables (e.g., maps, counters, database connections) are accessed and modified by multiple goroutines.
- **Channels:** Employ channels for safe communication and synchronization between goroutines, adhering to the "share memory by communicating" principle.
- **Atomic Operations (`sync/atomic`):** For simple, single-variable updates (e.g., counters), use atomic operations like `atomic.AddUint32` or `atomic.Load` to ensure atomicity without the overhead of mutexes.
- **Immutable Data Structures:** Where feasible, use immutable data structures to avoid the need for synchronization altogether.

### 4. Avoid Over-reliance on Provisional Data Streams

While WebSocket streams offer real-time updates, they often provide provisional data. Do not solely rely on these streams for critical business logic without independent verification or waiting for sufficient confirmations. Always combine real-time streams with robust reconciliation logic that queries the blockchain directly for definitive state, especially for high-value transactions.

### 5. Continuous Monitoring and Testing

Regularly run Go's race detector during development and in continuous integration pipelines. Conduct stress tests and integration tests that simulate high concurrency and potential reorg scenarios to uncover subtle timing-dependent bugs. Deploy race-enabled instances in production as "canaries" to detect issues under realistic workloads.

## Scope and Impact

The scope and impact of a race condition in off-chain calls extend significantly beyond the immediate vulnerable Golang service, affecting the entire ecosystem it interacts with.

**Scope:** The vulnerability's scope is classified as "Changed" because a successful exploitation allows an attacker to influence resources or components beyond the initial target. For instance, a double-spend attack initiated through this vulnerability directly manipulates the perceived state of funds not just within the off-chain application's database but also impacts the actual financial integrity on the blockchain itself. The attacker effectively changes the history or state of the blockchain as far as the off-chain service is concerned, leading to a divergence from the true canonical chain. This means the impact is not confined to a single application layer but permeates the trust boundary between on-chain and off-chain systems.

**Impact:** The consequences of this vulnerability are severe and multi-faceted:

- **Financial Loss:** This is the most direct and devastating impact. Double-spending allows attackers to illicitly acquire goods, services, or other assets without relinquishing their original funds on the blockchain. This can lead to substantial financial losses for exchanges, vendors, or users relying on the off-chain service. The Ethereum Classic (ETC) attack in August 2020, where approximately $5.6 million worth of ETC was double-spent during a chain reorganization, serves as a stark example of this financial impact.
- **Data Integrity Compromise:** The core integrity of the off-chain system's data is fundamentally undermined. Internal databases and caches will hold inaccurate transaction histories, incorrect user balances, or invalid records of smart contract states. This desynchronization from the canonical blockchain creates a "single source of truth" problem, making auditing, reconciliation, and reliable operation extremely challenging.
- **Operational Disruption and Increased Costs:** An off-chain service operating on inconsistent data can exhibit unpredictable behavior, suffer from crashes, or require continuous manual intervention to correct discrepancies. This leads to service unavailability, degraded user experience, and increased operational overhead for manual data reconciliation and system recovery. The longer a reorg lasts, the more expensive it becomes to handle for nodes.
- **Reputational Damage and Loss of Trust:** Successful exploitation erodes user and investor confidence in the application and the broader blockchain project. This can lead to a decline in user adoption, a drop in token value, and long-term reputational harm, as seen in past blockchain incidents.
- **Potential for Cascading Failures:** If the vulnerable off-chain service is a critical component in a larger decentralized application or ecosystem, its compromise could trigger cascading failures across interconnected services, amplifying the overall impact. This is particularly relevant in complex DeFi protocols where off-chain aggregators or indexers feed data to other applications.

In essence, the vulnerability transforms the perceived immutability and reliability of blockchain transactions into a point of failure for off-chain systems, demonstrating that the security of decentralized applications is not solely dependent on the smart contracts themselves but also on the robustness of their off-chain integration layers.

## Remediation Recommendation

Addressing the race condition in off-chain calls requires a comprehensive and architectural shift in how Golang applications interact with blockchain networks. The following recommendations outline a robust strategy for remediation:

1. **Prioritize Blockchain Finality:**
    - **Wait for Ample Confirmations:** For any critical off-chain business logic (e.g., crediting user accounts, releasing assets), wait for a sufficient number of blockchain confirmations before considering a transaction irreversible. The specific number should be determined based on the security requirements of the application, the value of the assets involved, and the reorg characteristics of the specific blockchain (e.g., 6+ for Bitcoin, 12+ for Ethereum, potentially more for smaller chains or specific use cases).
    - **Utilize Finalized Block Tags:** Where available, leverage blockchain node APIs that provide "safe" or "finalized" block tags (e.g., Ethereum's `finalized` tag) to ensure that the processed data is from a block that is highly unlikely to be reorged.
2. **Implement Comprehensive Reorganization Handling:**
    - **Persistent State Tracking:** Store the block number and block hash alongside all blockchain-derived data in the off-chain database. This metadata is crucial for detecting and reconciling reorgs.
    - **Proactive Reorg Detection:** Actively monitor for reorgs by comparing the `parentHash` of new blocks with the hash of the previously processed block. Additionally, process the `removed` flag in event logs to identify invalidated events.
    - **Atomic Rollback and Re-indexing:** Design the off-chain system with the capability to "undo" actions. Upon detecting a reorg, the system should:
        - Identify the common ancestor block.
        - Rollback all off-chain state changes that occurred on the reorged-out chain. This might involve deleting records, reverting balances, or marking transactions as invalid.
        - Re-index events and transactions from the new canonical chain, starting from the common ancestor, to rebuild the accurate off-chain state.
    - **Idempotent Processing:** Ensure that all off-chain processing logic is idempotent, meaning that processing the same event multiple times (e.g., during re-indexing) yields the same correct result without unintended side effects.
3. **Strengthen Internal Go Concurrency Management:**
    - **Protect Shared Resources:** Utilize Go's synchronization primitives (`sync.Mutex`, `sync.RWMutex`, `sync/atomic`) to protect all shared mutable data structures accessed by multiple goroutines within the off-chain service.
    - **Communicate via Channels:** Favor Go channels for communication between goroutines, adhering to the principle of "sharing memory by communicating" rather than "communicating by sharing memory". This helps prevent many common data races.
    - **Immutable Data:** Design data structures to be immutable where possible, reducing the need for explicit synchronization.
4. **Strategic Use of Data Streams:**
    - **Verify Provisional Data:** While real-time WebSocket streams are useful for low-latency updates, they should be treated as provisional. Critical actions should only be taken after verifying the data's finality through direct blockchain queries or sufficient confirmations.
    - **"Latest Block Delay" Feature:** If using services like QuickNode Streams, consider utilizing the "Latest Block Delay" feature to stream data a specified number of blocks behind the most recent one. This probabilistically reduces the likelihood of processing blocks that may not be part of the canonical chain, significantly decreasing reorg exposure.
5. **Rigorous Testing and Monitoring:**
    - **Automated Race Detection:** Integrate `go test -race` into the continuous integration/continuous deployment (CI/CD) pipeline to automatically detect internal Go race conditions.
    - **Concurrency and Reorg Simulation Tests:** Develop specific integration and stress tests that simulate high concurrency and blockchain reorgs in a controlled environment. This helps uncover timing-dependent vulnerabilities that might not appear in normal testing.
    - **Production Monitoring:** Deploy enhanced monitoring to detect anomalies in off-chain state that might indicate a reorg or race condition, such as unexpected balance changes or transaction discrepancies.

By implementing these recommendations, organizations can significantly enhance the resilience of their Golang off-chain services against race conditions stemming from blockchain reorganizations, thereby protecting financial assets, maintaining data integrity, and ensuring operational reliability.

## Summary

The "Race condition in off-chain calls" (race-condition-offchain) in Golang applications represents a critical vulnerability at the intersection of off-chain business logic and blockchain's probabilistic finality. This vulnerability arises when a Golang service processes blockchain events and updates its internal state based on data that is subsequently invalidated by a blockchain reorganization (reorg). Such a scenario creates a Time-of-Check-to-Time-of-Use (TOCTTOU) race condition, where the off-chain system acts on a perceived truth that no longer aligns with the canonical blockchain.

The core problem stems from the inherent nature of blockchain reorgs—which can be natural (due to network latency or simultaneous block mining) or malicious (e.g., 51% attacks)—that cause blocks and their contained transactions to become "stale" and removed from the canonical chain. If an off-chain Golang application does not account for this possibility by waiting for sufficient confirmations or implementing robust reorg detection and reconciliation mechanisms, it becomes susceptible to severe consequences.

Common mistakes leading to this vulnerability include processing transactions with insufficient confirmation depth, a complete absence of reorg detection and rollback logic, improper use of Go's internal concurrency primitives (like mutexes and channels), and over-reliance on real-time but provisional WebSocket data streams without independent verification.

The primary exploitation goal is financial gain through double-spending, where an attacker receives goods or services off-chain based on a transaction that is later reversed on the blockchain. Beyond direct theft, attackers may aim for data inconsistency and corruption, leading to operational chaos, or even Denial of Service (DoS) by overwhelming poorly designed reconciliation systems.

Affected components typically include blockchain event listeners/indexers, databases/data stores that mirror blockchain state, internal caches/memory within the Go application, and any business logic modules that make critical decisions based on blockchain data.

Remediation requires a multi-layered strategy. This includes waiting for ample blockchain confirmations, implementing comprehensive reorg detection (e.g., by tracking block hashes and utilizing the `removed` flag in event logs) and robust reconciliation logic (including atomic rollbacks and re-indexing), and ensuring proper use of Go's concurrency primitives (`sync.Mutex`, `channels`, `sync/atomic`) for internal shared state. Additionally, continuous testing with Go's race detector and simulating reorgs in development environments are crucial. By adopting these measures, organizations can significantly enhance the security and reliability of their Golang off-chain services, safeguarding against financial losses, data integrity compromises, and reputational damage.

## References

- url: https://www.researchgate.net/publication/390996198_Securing_Decentralized_Ecosystems_A_Comprehensive_Systematic_Review_of_Blockchain_Vulnerabilities_Attacks_and_Countermeasures_and_Mitigation_Strategies
- url: https://www.contrastsecurity.com/security-influencers/navigating-os.root-and-path-traversal-vulnerabilities-go-1.24-detection-and-protection-methods-contrast-security
- url: https://www.alchemy.com/overviews/what-is-a-reorg
- url: https://arxiv.org/pdf/2009.05413
- url: https://arxiv.org/pdf/2505.05328
- url: https://www.scmr.com/article/common-supply-chain-reorganization-approaches-gone-wrong
- url: https://docs.chainstack.com/docs/uncovering-the-power-of-ethgetblockreceipts
- url: https://www.chainguard.dev/unchained/avoid-exploit-chaining-threats-with-chainguard-images
- url: https://www.reddit.com/r/ethereum/comments/xmnnam/new_to_ethersweb3_how_to_handle_reorgs/
- url: https://ethereum-magicians.org/t/eip-8000-available-attestation-a-reorg-resilient-solution-for-ethereum/23927
- url: https://fastercapital.com/content/Blockchain-Reorganization--Blockchain-Reorganization--How-Uncle-Blocks-Influence-Stability.html
- url: https://www.kaleido.io/blockchain-blog/on-or-off-chain-business-logic
- url: https://www.quicknode.com/docs/streams/reorg-handling
- url: https://www.investopedia.com/terms/1/51-attack.asp
- url: https://learnmeabitcoin.com/technical/blockchain/chain-reorganization/
- url: https://www.quicknode.com/guides/quicknode-products/streams/building-a-blockchain-indexer-with-streams
- url: https://www.reddit.com/r/ethereum/comments/xmnnam/new_to_ethersweb3_how_to_handle_reorgs/
- url: https://www.reddit.com/r/Monero/comments/aodbku/proposal_prevent_large_reorgs_from_happening/
- url: https://github.com/ethereum/go-ethereum/blob/master/core/blockchain.go
- url: https://docs.safe.global/core-api/api-safe-transaction-service
- url: https://hacken.io/insights/blockchain-security-vulnerabilities/
- url: https://www.quicknode.com/docs/streams/reorg-handling
- url: https://www.mdpi.com/1999-5903/17/5/205
- url: https://docs.chainstack.com/docs/ethereum-logs-tutorial-series-logs-and-filters
- url: https://www.mdpi.com/1999-5903/17/5/205
- url: https://docs.safe.global/core-api/api-safe-transaction-service
- url: https://docs.safe.global/core-api/api-safe-transaction-service
- url: https://github.com/ethereum/go-ethereum/blob/master/core/blockchain_test.go
- url: https://stackoverflow.com/questions/44556664/golang-http-handler-wrapping-chaining
- url: https://www.justsecurity.org/110820/how-congress-can-stop-crypto-crash/
- url: https://www.rareskills.io/post/smart-contract-security
- url: https://www.kaleido.io/blockchain-blog/on-or-off-chain-business-logic
- url: https://hacken.io/insights/blockchain-security-vulnerabilities/
- url: https://goethereumbook.org/event-subscribe/
- url: https://www.dxtalks.com/blog/news-2/understanding-on-chain-and-off-chain-transactions-in-2025-782
- url: https://learnmeabitcoin.com/technical/blockchain/chain-reorganization/
- url: https://www.dxtalks.com/blog/news-2/understanding-on-chain-and-off-chain-transactions-in-2025-782
- url: https://www.bovill-newgate.com/americas/crypto-custody-at-a-crossroads-what-u-s-rias-need-to-know-in-2025/
- url: https://www.alchemy.com/overviews/what-is-a-reorg
- url: https://labex.io/tutorials/go-how-to-prevent-race-conditions-in-go-422424
- url: https://checkmarx.com/blog/race-conditions-can-exist-in-go/
- url: https://arxiv.org/html/2506.01885v1
- url: https://stackoverflow.com/questions/60356134/what-happens-when-multiple-blocks-are-added-at-the-same-time-to-a-blockchain
- url: https://www.imperva.com/learn/application-security/race-condition/
- url: https://portswigger.net/web-security/race-conditions
- url: https://blog.traderspost.io/article/understanding-race-conditions-in-automated-trading
- url: https://www.bugcrowd.com/blog/racing-against-time-an-introduction-to-race-conditions/
- url: https://blog.arcjet.com/security-concepts-for-developers-race-condition-attacks/
- url: https://www.geeksforgeeks.org/race-condition-vulnerability/
- url: https://blog.laisky.com/p/golang-race/
- url: https://www.reddit.com/r/golang/comments/1b8jv1z/race_conditions_and_common_mistakes/
- url: https://blog.mozilla.org/services/2014/03/12/sane-concurrency-with-go/
- url: https://2ality.com/2019/10/shared-mutable-state.html
- url: https://arxiv.org/html/2506.01885v1
- url: https://www.themoonlight.io/review/sok-concurrency-in-blockchain-a-systematic-literature-review-and-the-unveiling-of-a-misconception
- url: https://pkg.go.dev/vuln/list
- url: https://news.ycombinator.com/item?id=42043939
- url: https://go.dev/doc/articles/race_detector
- url: https://dev.to/shrsv/race-conditions-in-go-a-simple-tutorial-1e1i
- url: https://go.dev/blog/race-detector
- url: https://stackoverflow.com/questions/31792810/simple-race-condition-in-go-http-handler-is-this-really-a-race-condition
- url: https://codefinity.com/blog/Golang-10-Best-Practices
- url: https://krakensystems.co/blog/2019/golang-race-detection
- url: https://www.reddit.com/r/golang/comments/1kinezf/static_analysis_for_golang/
- url: https://stackoverflow.com/questions/52893411/what-is-meant-by-race-condition-in-go-when-using-race-flag
- url: https://github.com/staheri/goat
- url: https://ccmiller2018.co.uk/posts/go-concurrency/
- url: https://dev.to/adriandy89/concurrency-in-go-goroutines-mutexes-and-channels-40f4#:~:text=To%20prevent%20this%2C%20Golang%20provides,safe%20communication%20between%20multiple%20goroutines.
- url: https://mayallo.com/go-concurrency-mutexes-vs-channels/
- url: https://www.geeksforgeeks.org/atomic-adduint32-function-in-golang-with-examples/
- url: https://pkg.go.dev/sync/atomic