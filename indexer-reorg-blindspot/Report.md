## Vulnerability Title
Failure to detect re-orgs in indexer (short: indexer-reorg-blindspot)

## Severity Rating
High🟠. This vulnerability directly impacts data accuracy and integrity, potentially leading to financial losses, incorrect application state, and a complete breakdown of trust in the indexed data.

## Description
A Go application acting as a blockchain indexer fails to properly detect and handle blockchain reorganizations (re-orgs). This means that the indexer continues to process and store data from a "stale" or "orphaned" chain, leading to an inconsistent and inaccurate view of the blockchain's true state. Consequently, any applications or services relying on this indexer will operate on incorrect data, potentially causing financial discrepancies, failed transactions, or displaying misleading information.

## Technical Description (for security pros)
The vulnerability arises when an indexer, after initially ingesting data from a block (or a series of blocks), does not implement mechanisms to detect if those blocks have been "reorganized out" of the canonical chain. This can happen due to:

* **Insufficient Block Finality Checks:** The indexer might consider a block "final" too early, without waiting for a sufficient number of subsequent blocks to be mined on top of it, which significantly reduces the probability of a re-org.
* **Lack of Chain Head Validation:** The indexer might not regularly query the blockchain node to verify its current canonical chain's head and compare it against its own indexed chain.
* **Improper Rollback/Re-indexing Logic:** When a re-org *is* detected, the indexer fails to correctly revert its indexed state to a consistent point *before* the re-org occurred, and then re-index the correct (new) chain. This could involve simply appending new blocks without removing the old, orphaned ones.
* **Relying Solely on "Latest Block" Events:** Only subscribing to "new block" events without checking for chain history or comparing block hashes can lead to a blind spot.

The consequence is that the indexer's database or data store diverges from the actual blockchain state. Transactions that were reversed in a re-org might still appear as "confirmed" in the index, or new transactions from the canonical chain might be missed.

## Common Mistakes That Cause This
* **Over-optimizing for speed:** Prioritizing fast indexing over robust re-org detection, leading to simplified logic that doesn't account for chain instability.
* **Misunderstanding blockchain consensus:** Assuming that once a block is seen, it's permanently final, especially in chains with shorter block times or less stringent finality guarantees.
* **Inadequate blockchain node interaction:** Not querying the blockchain node for historical block data, parent hashes, or finality status indicators.
* **Complex or faulty state management:** Difficulties in designing and implementing rollback mechanisms that can revert the index to a consistent state before a re-org.
* **Lack of testing for re-org scenarios:** Not simulating re-orgs in development or testing environments to ensure the indexer behaves correctly.

## Exploitation Goals
The primary exploitation goal is **Data Inconsistency and Financial Manipulation**. An attacker aims to:
* **Double Spending (Indirectly):** By performing a double-spend attack on the blockchain (e.g., submitting a transaction and then initiating a re-org to reverse it), an attacker can cause the indexer to report the first transaction as confirmed, even if it was invalidated on-chain. This could trick applications reliant on the indexer into releasing goods/services without actual payment.
* **Information Manipulation:** Cause the indexer to show false transaction histories, account balances, or smart contract states, misleading users or other applications.
* **Denial of Service (of Accurate Data):** While not a direct crash, the indexer becomes useless if its data is unreliable, effectively denying accurate service.
* **Bypass Security Controls:** If security decisions (e.g., access control based on token balances) are made based on the indexer's data, an attacker could manipulate the chain to exploit this.

## Affected Components or Files
* **Blockchain Listener/Poller:** The component responsible for receiving new block notifications or polling the blockchain node.
* **Block Processing Logic:** The code that extracts and transforms data from blocks.
* **Database/Data Store Integrations:** The logic for writing and updating index data, which must support atomic rollbacks.
* **State Management:** Any logic that tracks the current "head" of the indexed chain and its historical context.

## Vulnerable Code Snippet
(Illustrative example - a real-world indexer would be much more complex and involve database operations)

```go
package main

import (
	"fmt"
	"strconv"
	"sync"
	"time"
)

// Simplified representation of a blockchain block
type Block struct {
	Height    int
	Hash      string
	ParentHash string
	Transactions []string
}

// InsecureIndexer only cares about the highest block height and doesn't handle re-orgs
type InsecureIndexer struct {
	mu            sync.Mutex
	lastIndexedBlock *Block
	indexedTransactions map[string]bool // Simplified: just tracking transaction IDs
}

// NewInsecureIndexer creates a new indexer
func NewInsecureIndexer() *InsecureIndexer {
	return &InsecureIndexer{
		indexedTransactions: make(map[string]bool),
	}
}

// ProcessBlock processes a new block as if it's always canonical
// THIS IS THE VULNERABLE PART: It assumes sequential, always-growing blocks.
func (i *InsecureIndexer) ProcessBlock(block *Block) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.lastIndexedBlock != nil && block.Height <= i.lastIndexedBlock.Height && block.Hash != i.lastIndexedBlock.Hash {
		// A very basic check, but doesn't handle re-orgs correctly.
		// It might log a warning but won't revert previous state for a shorter, competing chain.
		fmt.Printf("Warning: Received block %d (%s) which is not directly built on top of last indexed %d (%s) or is shorter. Likely a re-org, but not handled correctly.\n",
			block.Height, block.Hash, i.lastIndexedBlock.Height, i.lastIndexedBlock.Hash)
		// In a real scenario, this is where the re-org rollback logic would be missing or flawed.
		// The indexer might just ignore this block, or worse, overwrite existing data without proper reversal.
		// Or it might simply proceed, thinking "newer height means better chain," which is not always true initially.
	} else if i.lastIndexedBlock != nil && block.Height < i.lastIndexedBlock.Height {
		// This path would be hit if a shorter chain becomes canonical, which our indexer won't detect or revert to.
		fmt.Printf("Warning: Received block %d (%s) which is shorter than last indexed %d (%s). Re-org not handled.\n",
			block.Height, block.Hash, i.lastIndexedBlock.Height, i.lastIndexedBlock.Hash)
		return // Simply ignores it, leading to stale data
	}


	fmt.Printf("Indexing Block %d (%s) with Parent %s\n", block.Height, block.Hash, block.ParentHash)
	for _, tx := range block.Transactions {
		i.indexedTransactions[tx] = true
		fmt.Printf("  Indexed transaction: %s\n", tx)
	}
	i.lastIndexedBlock = block
}

// IsTransactionIndexed checks if a transaction is in the index
func (i *InsecureIndexer) IsTransactionIndexed(txID string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.indexedTransactions[txID]
}

func main() {
	indexer := NewInsecureIndexer()

	// Simulate initial chain growth
	fmt.Println("--- Initial Chain Growth ---")
	block1 := &Block{Height: 1, Hash: "hash1", ParentHash: "genesis", Transactions: []string{"txA"}}
	indexer.ProcessBlock(block1)
	block2 := &Block{Height: 2, Hash: "hash2", ParentHash: "hash1", Transactions: []string{"txB", "txC"}}
	indexer.ProcessBlock(block2)
	block3 := &Block{Height: 3, Hash: "hash3", ParentHash: "hash2", Transactions: []string{"txD"}}
	indexer.ProcessBlock(block3)

	fmt.Printf("\nIs txB indexed? %t\n", indexer.IsTransactionIndexed("txB")) // Should be true

	// Simulate a re-org at height 2
	fmt.Println("\n--- Simulating Re-org ---")
	// A new, competing block 2' (different hash, different parent, or same height different parent)
	// This would typically come from a different branch gaining consensus.
	// Let's assume a slightly different block 2', which then leads to a longer chain.
	// The original block 2 had txB and txC. The re-org block 2' will have txX and txY, and txB will be orphaned.
	reorgBlock2Prime := &Block{Height: 2, Hash: "hash2prime", ParentHash: "hash1", Transactions: []string{"txX", "txY"}}
	indexer.ProcessBlock(reorgBlock2Prime) // Our indexer might just ignore this or cause inconsistent state.
	
	// A new block 3' built on top of 2' - this chain is now "longer" (or same length, but became canonical)
	reorgBlock3Prime := &Block{Height: 3, Hash: "hash3prime", ParentHash: "hash2prime", Transactions: []string{"txE"}}
	indexer.ProcessBlock(reorgBlock3Prime)

	// In a real scenario, the indexer should have now reverted txB/txC and indexed txX/txY and txE.
	// But our insecure indexer will still have txB indexed.
	fmt.Printf("\nIs txB indexed after re-org? %t (Expected: false, Actual: %t)\n", indexer.IsTransactionIndexed("txB"), indexer.IsTransactionIndexed("txB"))
	fmt.Printf("Is txX indexed after re-org? %t (Expected: true, Actual: %t)\n", indexer.IsTransactionIndexed("txX"), indexer.IsTransactionIndexed("txX"))
	fmt.Printf("Is txE indexed after re-org? %t (Expected: true, Actual: %t)\n", indexer.IsTransactionIndexed("txE"), indexer.IsTransactionIndexed("txE"))

	// The problem is that txB is still considered indexed, even though it was orphaned by the re-org.
}

```

## Detection Steps
1.  **Observational Discrepancy:** Compare the data reported by the indexer with the actual state of the blockchain (e.g., using a blockchain explorer or direct node queries). Look for discrepancies in transaction status, balances, or block numbers.
2.  **Log Analysis:** Look for unusual patterns in indexer logs, such as warnings about skipped blocks, inconsistent parent hashes, or rapid changes in chain height without proper data adjustments.
3.  **Metrics Monitoring:** Monitor indexer health metrics. While a direct "re-org" metric might not exist, sudden drops in indexed transactions or an inability to keep up with the chain tip might indicate issues.
4.  **Controlled Re-org Simulation (Testnets):** On a testnet, intentionally create a re-org by submitting conflicting blocks or using specific chain manipulation tools. Observe if the indexer's data correctly reflects the new canonical chain.
5.  **Code Review:** Examine the indexer's block processing logic, specifically how it handles blocks with heights lower than the current indexed height or blocks with different parent hashes for the same height. Look for `copy` or `rollback` logic when re-orgs are suspected.

## Proof of Concept (PoC)
A PoC for this vulnerability would typically involve:

1.  **Setup a Local Blockchain:** Run a local blockchain environment (e.g., a Ganache or a private Geth instance) where you have control over block production.
2.  **Start the Vulnerable Indexer:** Deploy and run the Go indexer application, configured to connect to your local blockchain.
3.  **Generate Initial Blocks:** Mine a few blocks on the initial chain, and let the indexer process them, indexing some specific transactions.
4.  **Induce a Re-org:**
    * Stop mining on the initial chain.
    * Mine a *different* block at a previous height (e.g., the parent of your previously mined block) that diverges from the original chain. This new branch must eventually become longer than the original one.
    * Continue mining on this new branch until it surpasses the length of the previously indexed chain.
5.  **Verify Inconsistency:** Query the indexer for the status of transactions that were present only in the *orphaned* chain. The PoC demonstrates the vulnerability if these transactions are still reported as indexed, or if transactions from the *new canonical chain* are missing.

## Risk Classification
* **CVSS v3.1:**
    * **Attack Vector (AV):** Network (N) - an attacker can manipulate the blockchain, which is a network resource.
    * **Attack Complexity (AC):** High (H) - requires control over block production or significant network manipulation to induce a re-org. However, for some smaller, less decentralized chains, it could be Medium (M) or even Low (L).
    * **Privileges Required (PR):** None (N) - usually no specific privileges on the indexer are needed; the attack is on the underlying blockchain.
    * **User Interaction (UI):** None (N).
    * **Scope (S):** Changed (C) - if the indexer's data influences critical application logic or financial outcomes, the impact extends beyond just data inconsistency.
    * **Confidentiality Impact (C):** None (N) - typically doesn't leak confidential data.
    * **Integrity Impact (I):** High (H) - data integrity is severely compromised, leading to false positives/negatives in transaction status.
    * **Availability Impact (A):** Low (L) or None (N) - the indexer itself usually remains available, but the availability of *correct* data is compromised.

    Given the integrity compromise and potential for financial loss, a common score might be around **7.0 (High)**.

## Fix & Patch Guidance
1.  **Implement Robust Block Tracking:** Store not just the block height and hash, but also the parent hash for each indexed block. This allows for quick verification of chain continuity.
2.  **Define a "Finality" Threshold:** Do not consider transactions "final" until a sufficient number of blocks (e.g., 6, 12, 100, or a specific finalized block tag from the blockchain) have been mined on top of the block containing the transaction. This threshold depends on the specific blockchain's consensus mechanism and desired security level.
3.  **Polling and Re-org Detection Logic:**
    * Regularly poll the blockchain node for its current canonical chain head (e.g., `eth_getBlockByNumber(latest, true)`).
    * Compare the block hash and parent hash of the node's chain with the indexer's last indexed block.
    * If a discrepancy is detected (e.g., the node's block at `N` has a different hash or parent hash than the indexer's block at `N`), it indicates a re-org.
4.  **Atomic Rollback and Re-indexing:**
    * Upon detecting a re-org, determine the common ancestor block between the indexer's stale chain and the new canonical chain.
    * Perform a transactional rollback of all indexed data from the stale chain, starting from the last known good common ancestor. This might involve deleting records, reverting updates, or using database transactions.
    * Then, re-index all blocks from the common ancestor up to the new canonical chain's tip.
5.  **Utilize Blockchain Node Features:** Many modern blockchain nodes or services (like QuickNode Streams) offer built-in re-org handling, ensuring data consistency by automatically re-emitting events from the canonical chain. Leverage these if possible.

## Scope and Impact
* **Scope:** Primarily impacts blockchain indexers and any applications that consume data from them.
* **Impact:**
    * **Incorrect Application State:** DApps or services relying on the indexer will display wrong balances, transaction statuses, or smart contract states.
    * **Financial Loss/Fraud:** Can facilitate double-spending attacks or lead to incorrect settlement of funds if financial systems rely on the indexer.
    * **Reputation Damage:** Loss of user trust due to unreliable data.
    * **Operational Overhead:** Requires manual intervention or complex recovery mechanisms to bring the indexer back into a consistent state.

## Remediation Recommendation
Developers should:
1.  **Implement a robust chain reconciliation algorithm:** This algorithm should:
    * Regularly fetch the current chain tip from the blockchain node.
    * Trace back the chain from the current tip until a block is found that is already indexed by the indexer. This common ancestor determines the point of divergence.
    * Identify all blocks in the indexer's database that are *not* part of the new canonical chain (i.e., those on the orphaned branch).
    * Atomically delete or mark as invalid all data associated with the orphaned blocks from the index.
    * Process and index all new blocks from the common ancestor up to the new canonical chain tip.
2.  **Choose an appropriate block finality strategy:** For example, waiting for "safe" or "finalized" blocks on Ethereum, or a certain number of confirmations on Bitcoin, before considering transactions immutable in the index.
3.  **Use transactional database operations:** Ensure that index updates (especially during re-orgs) are atomic, so that either all changes are applied, or none are. This prevents partially updated states.
4.  **Add comprehensive logging and alerts:** Log when re-orgs are detected and the steps taken to handle them. Set up alerts for unhandled re-orgs or persistent data inconsistencies.

## Summary
The "Failure to detect re-orgs in indexer" vulnerability in Golang refers to an indexer's inability to correctly handle blockchain reorganizations, leading to an inconsistent and inaccurate representation of the blockchain's state. This can result in severe data integrity issues, potentially enabling financial fraud or misleading applications. The fix involves implementing robust chain reconciliation logic, adhering to appropriate block finality thresholds, and utilizing atomic database operations to ensure data consistency during re-org events.

## References
* [Blockchain Reorganization - River.com](https://river.com/learn/terms/r/reorganization/)
* [How to Build a Blockchain Indexer with Streams - QuickNode Guides](https://www.quicknode.com/guides/quicknode-products/streams/building-a-blockchain-indexer-with-streams) (Mentions automatic re-org handling in their service)
* [Block Finality (Reorgs) - Tatum Developer Documentation](https://docs.tatum.io/docs/evm-block-finality-and-confidence)
* [Go Secure Coding Best Practices - CloudDevs](https://clouddevs.com/hire/go-developers/best-practices/) (General Go security, though not specific to re-orgs)
* Ethereum Developer Documentation on Block Finality
* Bitcoin Wiki on Block Reorganization