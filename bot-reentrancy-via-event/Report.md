# **Bot-Triggered Reentrancy via On-Chain Event**

## **1. Vulnerability Title**

Bot-Triggered Reentrancy via On-Chain Event

This title reflects the composite nature of the attack pattern: an automated entity ("Bot") initiates or facilitates an attack by exploiting a "Reentrancy" vulnerability within a smart contract, using an "On-Chain Event" as the trigger mechanism. This clarifies that the bot is part of the attack chain, leveraging the event signal, rather than being the component containing the reentrancy flaw itself.

## **2. Severity Rating**

**Rating:** High 🟠 to Critical 🔴(Simulated CVSS Base Score Range: 8.0-9.8)

**Justification:** Reentrancy vulnerabilities are consistently classified as severe due to their potential for causing direct, substantial financial loss, often leading to the complete draining of funds from affected smart contracts. The introduction of an automated bot acting on public on-chain event triggers significantly amplifies this severity. Automation allows attackers to react almost instantaneously when a vulnerable condition is signaled by an event, potentially exploiting narrow time windows or complex state conditions that manual exploitation might miss. This speed and efficiency increase the likelihood of successful exploitation and maximize the potential damage before defensive actions can be taken. The impact is typically direct financial loss, state corruption, and significant disruption to the application's intended functionality.

## **3. Description**

Overview:

Bot-Triggered Reentrancy via On-Chain Event describes a specific attack scenario targeting smart contracts. It involves an off-chain automated process, commonly referred to as a "bot," which actively monitors the blockchain for specific events emitted by smart contracts. Upon detecting a predefined target event, this bot initiates transactions designed to interact with a function in a vulnerable smart contract. This interaction exploits a pre-existing reentrancy flaw within that contract's logic.

Mechanism:

The attack unfolds through a sequence of steps:

1. A vulnerable smart contract executes a function that involves an external interaction (like sending Ether or calling another contract) or emits an event *before* it finalizes critical internal state updates (e.g., updating user balances). This sequence explicitly violates the widely recommended Checks-Effects-Interactions security pattern.
    
2. An off-chain bot, potentially developed using languages like Golang with blockchain interaction libraries (e.g., `ethereum-watcher` , `ethereum-events` ), is configured to listen for the specific event emitted in step 1.

    
3. Once the bot detects the target event, it automatically crafts and sends a transaction to the vulnerable contract (or an intermediary contract designed by the attacker). This transaction aims to call back into the vulnerable function or another function that shares the same flawed state logic.
4. Because the vulnerable contract's state was not properly updated before the event emission or the external interaction that allowed the bot to react, the bot's transaction executes the reentrant call under incorrect assumptions about the contract's state (e.g., assuming a user balance is higher than it should be after the withdrawal). This leads to successful exploitation, such as executing repeated withdrawals of funds.
    
Context:

This pattern is not a fundamentally new type of reentrancy flaw but rather a specific method for triggering and automating known reentrancy vulnerabilities. It often serves to facilitate various forms of reentrancy, including single-function, cross-function, cross-contract 2, and even complex cross-chain reentrancy attacks where events are relayed between different blockchains.8 The defining characteristic is the use of an automated off-chain listener reacting to an on-chain event as the primary trigger for initiating the exploit sequence. This highlights that security considerations must extend beyond the smart contract code itself to encompass the interactions with off-chain components that monitor and react to its behavior. Secure contract code alone may prove insufficient if insecurely designed bots interact with it based on prematurely emitted events.

**Types of Reentrancy Vulnerabilities:**

The following table contextualizes Bot-Triggered Reentrancy within the broader landscape of known reentrancy attacks:

| **Type** | **Description** | **Key Characteristic** |
| --- | --- | --- |
| Single-Function Reentrancy | The vulnerable function calls an external contract which calls back into the *same* function before the initial call completes.| Re-enters the same function during its execution. |
| Cross-Function Reentrancy | The vulnerable function calls an external contract which calls back into a *different* function within the same contract that shares state. | Re-enters a different function sharing state with the initial function. |
| Cross-Contract Reentrancy | Reentrancy occurs across multiple, potentially interconnected, smart contracts, often exploiting shared state or complex interactions. | Exploitation path involves interactions between two or more distinct contracts. |
| Read-Only Reentrancy | Exploits reentrancy during view/read functions where a contract's behavior depends on the state of another contract being called. | Exploits state dependencies during read operations, potentially leading to incorrect decisions or calculations. |
| Cross-Chain Reentrancy | Reentrancy occurs during interactions spanning multiple blockchains, often triggered by relayed messages or events. | Vulnerability involves function calls or state changes across different blockchain networks. |
| **Bot-Triggered via Event** | An off-chain bot monitors on-chain events and uses a specific event emission as a trigger to initiate a reentrancy attack (any of the above types). | Triggered by an automated off-chain listener reacting to a (potentially premature) on-chain event emission. |

## **4. Technical Description (for security professionals)**

Detailed Flow:

The execution flow of a Bot-Triggered Reentrancy attack typically proceeds as follows:

1. **Initialization:** A Victim Contract (`V`) contains a function, `funcA`, which, upon execution, performs actions such as processing a deposit or initiating a withdrawal. Critically, `funcA` either emits an event (`EventX`) or makes an external call (e.g., `address.call{value: amount}("")`) *before* completing essential state updates (e.g., decrementing `balances[msg.sender]`).
2. **Setup:** An attacker deploys an Attacker Contract (`A`) designed to facilitate reentrancy, or prepares an off-chain Bot (`B`) equipped with wallet credentials and logic to interact with `V`.
3. **Monitoring:** Bot `B` connects to an Ethereum node (often via WebSocket for real-time updates) and subscribes to logs matching `EventX` emitted by Contract `V`. This typically uses Ethereum JSON-RPC methods like `eth_subscribe` facilitated by libraries such as `go-ethereum` , `web3.js`, or `ethers.js`.

4. **Trigger:** A user (legitimate or the attacker) invokes `funcA` in Contract `V`.
5. **Vulnerable Execution Point:** Contract `V` executes `funcA` up to the point where it emits `EventX` or makes the external call that transfers execution control externally. The crucial state update associated with `funcA` has not yet occurred.
6. **Event Detection:** Bot `B` receives the notification for `EventX` almost immediately after its emission within the transaction execution.
7. **Reaction:** Bot `B` rapidly constructs and broadcasts a new transaction. This transaction targets either Contract `V` directly (calling `funcA` again or another vulnerable function `funcB` sharing state) or calls a function within the Attacker Contract `A`, which in turn calls back into `V`.
8. **Reentrant Call:** The transaction initiated by Bot `B` gets mined and executed. It invokes `funcB` (or `funcA` recursively) within `V`. Since the state update from the original `funcA` execution is still pending, `funcB` operates on stale state information (e.g., the balance appears unchanged). This allows the exploit, such as withdrawing the same funds multiple times.

Checks-Effects-Interactions (CEI) Violation:

This attack pattern fundamentally relies on the violation of the CEI principle within the smart contract code.5 The "Interaction" – either the emission of EventX that the bot listens for, or the external call that gives the attacker contract control – occurs before the "Effect" – the critical state update (e.g., balance decrement, flag setting). This premature interaction exposes the contract's transient inconsistent state, which the bot exploits.

Role of Events:

While normally serving as signals for off-chain applications or user interfaces 6, on-chain events in this context become an active component of the attack vector. They act as a public broadcast, signaling the exact moment the contract enters a vulnerable state to any listening bot. In cross-chain scenarios, events relayed between chains serve a similar triggering function, initiating the reentrant logic on the destination chain based on an action on the source chain.8

Golang Role:

Golang is well-suited for building the off-chain bot component due to its strong concurrency model (goroutines, channels) and mature Ethereum libraries like go-ethereum. These features allow developers to create efficient, responsive bots capable of monitoring events and dispatching transactions quickly.6 However, it is crucial to understand that the reentrancy vulnerability itself resides within the logic of the smart contract (typically written in Solidity and executed on the EVM), not within the Golang code of the bot. The bot is merely the tool used to trigger the pre-existing flaw based on the event signal.

Timing Criticality:

The success of this attack pattern often hinges on timing. The bot must detect the event and have its subsequent transaction mined and executed before the original transaction containing funcA completes its execution and finalizes the state update. This introduces a race condition influenced by factors such as network latency between the node and the bot, the bot's processing speed, the gas price chosen for the reentrant transaction, overall network congestion, and miner behavior regarding transaction ordering. The window of vulnerability exists only during the transient state between the premature interaction/event and the final state settlement.

## **5. Common Mistakes That Cause This**

The Bot-Triggered Reentrancy via On-Chain Event vulnerability arises from a combination of mistakes, primarily within the smart contract logic but also potentially exacerbated by the design of interacting off-chain components.

**Smart Contract Level (Solidity):**

- **Violating Checks-Effects-Interactions (CEI):** This is the most fundamental error. Performing external calls (using `.call()`, `.send()`, or `.transfer()`) or emitting events *before* finalizing all associated state changes (like updating balances or marking a process as complete) creates the window for reentrancy. The state reflects an intermediate, potentially inconsistent point when external actors (contracts or bots via events) are notified or given control.

    
- **Incorrect Handling of External Callbacks:** Functions involving callbacks, such as the `onERC721Received` check often used in `_safeMint` for NFTs, can inadvertently provide a hook for reentrancy if critical state updates (e.g., incrementing `tokenId` counters) occur *after* this external call.

- **Implicit Trust in External Contracts:** Assuming that contracts called externally will behave benignly and not attempt malicious callbacks is a dangerous oversight. Any external call to an unknown or potentially attacker-controlled address must be considered a potential reentrancy vector.
    
- **Ignoring Cross-Function/Cross-Contract/Cross-Chain Implications:** Developers may secure individual functions against single-function reentrancy but fail to consider how state shared between different functions  or interactions triggered across multiple contracts or even blockchains  can create more complex reentrancy pathways. Events emitted in one function might trigger a reentrant call into another function that operates on the same, not-yet-updated state.

**Bot/Off-Chain Logic Level:**

- **Overly Aggressive Reaction:** Designing bots to react instantaneously to specific events without performing additional safety checks can be risky. A safer bot might query the contract's current state via a read call or wait for confirmations before initiating a transaction based solely on an event log.
- **Ignoring Blockchain Reorganizations (Reorgs):** Bots acting decisively based on events observed in unconfirmed blocks risk executing incorrect or invalid actions if a reorg occurs, potentially reverting the block containing the trigger event. Robust bots should wait for a certain number of block confirmations before considering an event final.

**Development Process:**

- **Inadequate Security Testing:** Failing to specifically test for various reentrancy scenarios, including those triggered by event emissions followed by immediate callbacks, during the development and QA phases. Standard unit or functional tests may miss these interaction-based flaws.
- **Misplaced Trust in Audits or Forked Code:** Relying solely on external security audits without internal understanding or assuming that code forked from popular projects is inherently secure can lead to vulnerabilities being overlooked. Audits might not cover all possible interaction patterns, especially with custom off-chain components.
    
- **Prioritizing Speed Over Security:** Development teams under pressure to "ship fast" may de-prioritize rigorous security analysis and testing, leading to common vulnerabilities like reentrancy being missed.
    

The combination of a contract emitting an event prematurely (the potential) and a bot reacting naively or aggressively to that event (the trigger) creates the successful exploit pattern. Both the contract developer and the bot developer share responsibility in preventing such scenarios through secure design patterns.

## **6. Exploitation Goals**

Attackers exploiting Bot-Triggered Reentrancy via On-Chain Events typically aim for one or more of the following objectives:

- **Fund Extraction:** This is the most common and direct goal. The attacker uses the reentrancy loop to repeatedly call a function that transfers funds (like Ether or ERC-20 tokens) out of the vulnerable contract before the contract's internal accounting can update the attacker's balance. The automation provided by the bot allows for rapid draining of available funds.
    
- **State Manipulation:** Beyond direct theft, attackers might aim to corrupt the internal state of the smart contract for other advantages. This could involve illegitimately minting valuable tokens or NFTs , gaining unauthorized administrative privileges, altering voting outcomes in DAOs, or manipulating other critical state variables to disrupt the application's logic.
    
- **Denial of Service (DoS):** By repeatedly entering a function and manipulating state, an attacker might aim to make the contract unusable for legitimate users. This could involve locking resources, causing transactions to consistently fail due to gas limits or unexpected state conditions , or triggering logic errors that halt contract operations.
    
- **Arbitrage or Price Manipulation:** In the context of Decentralized Finance (DeFi), reentrancy triggered by specific events (e.g., oracle price updates, liquidity addition/removal events) could be a component of more complex attacks. These might involve flash loans and reentrant calls to manipulate asset prices within a protocol, execute unfair trades, or extract value through arbitrage opportunities created by the temporary state inconsistency.

The use of a bot to automate the exploit based on event triggers suggests attackers are aiming for efficiency, speed, and potentially scale. A bot can tirelessly monitor the blockchain for specific event patterns across multiple contracts, reacting instantly to exploit vulnerabilities that might only exist for a very short duration. This automation maximizes the chances of achieving the desired exploitation goal before detection or intervention.

## **7. Affected Components or Files**

The Bot-Triggered Reentrancy attack pattern involves several components working in concert:

- **Primary Vulnerable Component:**
    - **Smart Contract Code:** The core vulnerability resides within the smart contract itself, typically written in Solidity (`.sol` files) and deployed on an EVM-compatible blockchain. Specifically, functions within the contract that violate the Checks-Effects-Interactions pattern by emitting events or making external calls before finalizing state updates are the locus of the flaw.
- **Secondary Facilitating Components:**
    - **Off-Chain Bot Script/Application:** This is the code responsible for monitoring the blockchain, listening for specific events, and dispatching the exploiting transactions. This code can be written in various languages, including Golang (`.go` files), Python (`.py`), JavaScript (`.js`), etc. It utilizes blockchain interaction libraries such as `go-ethereum` , `web3.js` , `ethers.js` , `web3.py` , or specialized event listeners like `ethereum-watcher`  or `ethereum-events`.
        
    - **Attacker Smart Contract (Optional):** In many reentrancy exploits, the attacker deploys an intermediary smart contract. The bot triggers this attacker contract, which then performs the reentrant call back to the victim contract via its fallback or receive function.
- **Supporting Infrastructure:**
    - **Blockchain Nodes:** The bot requires access to one or more blockchain nodes (e.g., Geth, Nethermind) to subscribe to events and send transactions. This access might be through self-hosted nodes or third-party infrastructure providers (e.g., Infura, Alchemy, QuickNode ).
        
Golang Context:

While Golang itself has its own set of vulnerabilities tracked by CVEs (many unrelated examples listed in 16), in the context of this specific attack pattern, Golang code (if used for the bot) serves as the instrument of exploitation, not the source of the vulnerability. The reentrancy flaw is a logical error within the EVM smart contract execution model, typically expressed in Solidity. Golang is merely one possible language choice for implementing the automated trigger mechanism.

This highlights a distributed attack surface. The vulnerability originates in the on-chain contract, but the exploit is actualized by the off-chain bot reacting to an on-chain event. Addressing the risk requires considering the security of both the contract logic and the design of any automated systems interacting with it based on its event emissions.

## **8. Vulnerable Code Snippet**

To illustrate the complete pattern, two code snippets are provided: one showing the vulnerable Solidity contract and another showing a conceptual Golang bot listener.

**Solidity Example (Vulnerable Contract):**

This snippet demonstrates a simplified vault contract with a `withdraw` function vulnerable to reentrancy because it emits an event and makes an external call *before* updating the user's balance.

```Solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Address.sol"; // For safe transfer checks if needed, though call is used here for reentrancy demo

contract VulnerableVault {
    using Address for address payable;

    mapping(address => uint256) public balances;

    // Event emitted prematurely
    event WithdrawalEvent(address indexed user, uint256 amount);

    // Allow deposits (simplified)
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerable withdraw function violating CEI pattern
    function withdraw(uint256 amount) public {
        uint256 userBalance = balances[msg.sender]; // Read balance initially
        require(userBalance >= amount, "Insufficient balance");

        // --- INCORRECT ORDER ---
        // 1. EVENT EMISSION (Interaction): Signals withdrawal attempt prematurely
        emit WithdrawalEvent(msg.sender, amount);
        // A bot listening for this event can react NOW, before balance is updated.

        // 2. EXTERNAL CALL (Interaction): Transfers Ether, potentially giving control to attacker contract
        // Using.call() is necessary to demonstrate reentrancy via fallback/receive functions.
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed"); // Check success, but reentrancy happens before this line if attacker calls back

        // 3. STATE UPDATE (Effect): Happens TOO LATE!
        balances[msg.sender] = userBalance - amount; // Balance updated only after external call and event
        // --- END INCORRECT ORDER ---
    }

    // Fallback function to receive Ether, necessary for attacker contract interaction
    receive() external payable {}

    // Function to check contract balance (for PoC verification)
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
```

- **Explanation:** The critical flaw lies in the order within the `withdraw` function. The `WithdrawalEvent` is emitted, and the external Ether transfer via `msg.sender.call{value: amount}("")` is performed *before* the line `balances[msg.sender] = userBalance - amount;` executes. An attacker contract receiving the Ether via `.call()` can use its `receive()` function to immediately call `withdraw` again. Because the balance hasn't been updated yet, the `require` check passes, allowing multiple withdrawals. A bot listening for `WithdrawalEvent` can initiate this attack sequence as soon as the event is detected.
    
**Golang Example (Conceptual Bot Listener):**

This conceptual Golang code demonstrates how a bot could use the `go-ethereum` library to listen for the `WithdrawalEvent` and trigger an attack. **Note:** This bot code itself is *not* vulnerable to reentrancy; it acts as the trigger.

```Go

package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time" // Added for potential delays/timeouts

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto" // Needed for signing transactions
	"github.com/ethereum/go-ethereum/ethclient"
)

// Simplified ABI for VulnerableVault focusing on the event and withdraw function
const vaultABI = `,"name":"WithdrawalEvent","type":"event"},
    {"inputs":,"name":"withdraw","outputs":,"stateMutability":"nonpayable","type":"function"}
]`
const vulnerableVaultAddress = "0xYourVulnerableContractAddress" // Replace with actual deployed address
const nodeWSS_URL = "wss://your-ethereum-node-wss-url"           // Replace with your WebSocket endpoint
const attackerPrivateKeyHex = "YOUR_BOT_PRIVATE_KEY"             // Replace with bot's private key (handle securely!)

func main() {
	client, err := ethclient.Dial(nodeWSS_URL)
	if err!= nil {
		log.Fatalf("Failed to connect to Ethereum client: %v", err)
	}
	defer client.Close()

	contractAddress := common.HexToAddress(vulnerableVaultAddress)
	query := ethereum.FilterQuery{
		Addresses:common.Address{contractAddress},
	}

	logs := make(chan types.Log)
	subCtx, subCancel := context.WithTimeout(context.Background(), 5*time.Minute) // Add timeout for subscription
	defer subCancel()

	sub, err := client.SubscribeFilterLogs(subCtx, query, logs)
	if err!= nil {
		log.Fatalf("Failed to subscribe to logs: %v", err)
	}
	fmt.Println("Bot listening for WithdrawalEvent from", contractAddress.Hex())

	contractAbi, err := abi.JSON(strings.NewReader(vaultABI))
	if err!= nil {
		log.Fatalf("Failed to parse ABI: %v", err)
	}

	withdrawalEventSig := contractAbi.Events["WithdrawalEvent"].ID
	fmt.Println("Listening for event signature:", withdrawalEventSig.Hex())

	privateKey, err := crypto.HexToECDSA(attackerPrivateKeyHex)
	if err!= nil {
		log.Fatalf("Error parsing private key: %v", err)
	}
	botAddress := crypto.PubkeyToAddress(privateKey.PublicKey)
	fmt.Println("Bot address:", botAddress.Hex())

	chainID, err := client.NetworkID(context.Background())
	if err!= nil {
		log.Fatalf("Failed to get chain ID: %v", err)
	}

	for {
		select {
		case err := <-sub.Err():
			log.Printf("Subscription error: %v. Resubscribing...", err)
			// Implement robust resubscription logic here
			time.Sleep(5 * time.Second) // Wait before retrying
			// Re-establish subscription (simplified example)
			sub, err = client.SubscribeFilterLogs(subCtx, query, logs)
			if err!= nil {
				log.Fatalf("Failed to resubscribe: %v", err)
			}
			continue // Skip processing this loop iteration
		case vLog := <-logs:
			// Basic check for confirmation (optional, adjust as needed)
			// if vLog.Removed {
			//  fmt.Println("Log removed due to reorg:", vLog.TxHash.Hex())
			//  continue
			// }

			// Check if it's the WithdrawalEvent
			if len(vLog.Topics) > 0 && vLog.Topics == withdrawalEventSig {
				fmt.Printf("\n[%s] Detected WithdrawalEvent! Block: %d, Tx: %s\n",
					time.Now().Format(time.RFC3339), vLog.BlockNumber, vLog.TxHash.Hex())

				// Decode event data (optional, needed if attack depends on event params)
				var eventData struct {
					User   common.Address
					Amount *big.Int
				}
				// Note: Non-indexed fields are in Data, indexed are in Topics
				// Simplified: Assuming we just need to know the event occurred to trigger reentrancy
				// err := contractAbi.UnpackIntoInterface(&eventData, "WithdrawalEvent", vLog.Data)
				// if err!= nil {
				//  log.Printf("Failed to unpack event data: %v", err)
				//  continue
				// }
				// fmt.Printf("  User: %s, Amount: %s\n", eventData.User.Hex(), eventData.Amount.String())

				// *** ATTACKER LOGIC: Trigger reentrancy ***
				// This example triggers the 'withdraw' function again using the same amount
				// A real attack might use an attacker contract or different parameters.
				// For simplicity, assume the bot itself has funds in the vault and triggers its own withdrawal again.
				// Use the amount from the event or a predefined amount for the reentrant call.
				reentrantAmount := big.NewInt(1000000000000000000) // Example: 1 Ether, adjust as needed

				fmt.Println(">>> Initiating reentrant call to withdraw function <<<")
				go triggerReentrancyTransaction(client, contractAddress, contractAbi, privateKey, botAddress, chainID, reentrantAmount)
			}
		case <-subCtx.Done():
			fmt.Println("Subscription context done.")
			return
		}
	}
}

// Function to craft and send the exploiting transaction
func triggerReentrancyTransaction(client *ethclient.Client, contractAddress common.Address, contractAbi abi.ABI, pk *crypto.PrivateKey, fromAddress common.Address, chainID *big.Int, amount *big.Int) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nonce, err := client.PendingNonceAt(ctx, fromAddress)
	if err!= nil {
		log.Printf("Failed to get nonce: %v", err)
		return
	}

	gasPrice, err := client.SuggestGasPrice(ctx)
	if err!= nil {
		log.Printf("Failed to suggest gas price: %v", err)
		return
	}
	// Increase gas price slightly to prioritize the transaction
	gasPrice.Mul(gasPrice, big.NewInt(12)).Div(gasPrice, big.NewInt(10)) // +20%

	// Pack the call to the 'withdraw' function
	callData, err := contractAbi.Pack("withdraw", amount)
	if err!= nil {
		log.Printf("Failed to pack call data: %v", err)
		return
	}

	gasLimit := uint64(300000) // Set a reasonable gas limit, estimate if needed

	tx := types.NewTransaction(nonce, contractAddress, big.NewInt(0), gasLimit, gasPrice, callData)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), pk)
	if err!= nil {
		log.Printf("Failed to sign transaction: %v", err)
		return
	}

	err = client.SendTransaction(ctx, signedTx)
	if err!= nil {
		log.Printf("Failed to send reentrancy transaction: %v", err)
		return
	}

	fmt.Printf(">>> Reentrancy transaction sent: %s\n", signedTx.Hash().Hex())
}
```

- **Explanation:** This Golang code sets up a WebSocket connection to an Ethereum node, subscribes to logs from the `VulnerableVault` contract address, and specifically filters for the `WithdrawalEvent`. Upon detecting the event, it launches a goroutine (`triggerReentrancyTransaction`) that crafts, signs, and sends a new transaction calling the `withdraw` function again. This demonstrates how an off-chain process, triggered by the on-chain event, can initiate the reentrant call. The separation of concerns is clear: the Solidity contract contains the reentrancy flaw, while the Golang bot provides the automated trigger based on the event signal.

Presenting both snippets is essential to fully illustrate the interaction dynamics of the "Bot-Triggered Reentrancy via On-Chain Event" pattern, clarifying the distinct roles and responsibilities of the on-chain contract and the off-chain automation.

## **9. Detection Steps**

Detecting Bot-Triggered Reentrancy via On-Chain Event requires a combination of static analysis, dynamic analysis, and real-time monitoring, addressing both the contract vulnerability and the behavioral pattern of the attack.

- **Static Analysis (SAST):**
    - Automated tools like Slither , Mythril, Oyente , and others should be used to scan the smart contract's Solidity source code. These tools are designed to identify known vulnerability patterns, including violations of the Checks-Effects-Interactions (CEI) principle. Specifically look for functions where external calls (`.call()`, `.send()`, `.transfer()`) or `emit` statements occur before state variables (e.g., balances, flags) are updated.

    - Advanced tools like SliSE aim to improve detection accuracy, especially in complex contracts with intricate logic or inter-contract dependencies, by combining program slicing and symbolic execution.
        
    - Manual review should supplement automated tools, tracing data flow and control flow around external interactions and event emissions.
- **Dynamic Analysis (DAST) / Fuzzing:**
    - Execute the smart contract's functions in a simulated blockchain environment (e.g., Hardhat Network, Ganache) or a dedicated testnet.
    - Develop test cases that specifically attempt to trigger reentrancy. This involves creating mock attacker contracts that call back into the target contract upon receiving funds or interacting with specific functions.
    - Employ fuzzing tools that automatically generate diverse inputs and explore different execution paths, potentially uncovering non-obvious reentrancy vectors that might be triggered under specific conditions or sequences of calls.
- **On-Chain Monitoring:**
    - Deploy real-time monitoring solutions (custom bots or platforms like Forta ) to observe transactions interacting with deployed contracts.
    - Configure detection bots to identify suspicious sequences: a specific event emission from a contract followed immediately (often in the next few blocks or even the same block if orchestrated) by a transaction from an external account calling back into the same contract, particularly targeting state-changing functions like `withdraw` or `transfer`.
    - Monitor for recursive call patterns where a contract directly or indirectly calls itself multiple times within the same transaction trace.
    - Analyze event logs for unusual frequency or patterns associated with known vulnerable functions. Machine learning or heuristic-based approaches can help distinguish legitimate activity from attack patterns.

- **Manual Code Review / Audits:**
    - Engage experienced blockchain security auditors to perform in-depth reviews of the smart contract codebase. Auditors specifically look for reentrancy flaws (all types, including single-function, cross-function, cross-contract ) and violations of best practices like CEI. While valuable, reliance solely on audits without internal understanding can be insufficient, as highlighted by research.
        
- **Bot Behavior Analysis (If Applicable):**
    - If the code of bots interacting with the contract is available, analyze their logic for reacting to events. Look for immediate, state-agnostic reactions to potentially sensitive events.
    - If the bot code is unknown, monitor the on-chain behavior of addresses interacting with the contract shortly after events are emitted. Look for accounts exhibiting rapid, repetitive, or seemingly exploitative behavior patterns.

A multi-layered detection strategy is crucial. Static analysis identifies potential weaknesses in the code, dynamic analysis attempts to confirm exploitability, and on-chain monitoring provides the capability to detect actual attack attempts as they happen, which is particularly relevant for the bot-triggered aspect of this pattern.

## **10. Proof of Concept (PoC)**

A Proof of Concept (PoC) for Bot-Triggered Reentrancy via On-Chain Event aims to demonstrate the entire attack chain, validating both the contract's vulnerability and the feasibility of using an event-triggered bot to exploit it.

**Conceptual Steps:**

1. **Deploy Vulnerable Contract:**
    - Compile and deploy the `VulnerableVault` contract (from Section 8) onto a test network (e.g., Sepolia, Goerli) or a local development network (e.g., Hardhat Network).
    - Fund the deployed `VulnerableVault` contract with a noticeable amount of test Ether. Note its deployed address.
2. **Deploy Attacker Contract (Optional but Recommended):**
    - While the bot could potentially hold funds in the vault and re-enter directly, a common reentrancy pattern involves an intermediary attacker contract.
    - Create and deploy an `Attacker` contract similar in principle to `StealFromVault`. This contract needs:
        
        - A reference to the `VulnerableVault` address.
        - An `attack()` function that deposits a small amount into `VulnerableVault` and then calls `VulnerableVault.withdraw()`.
        - A `receive()` external payable function. This function is crucial: when `VulnerableVault` sends Ether to the `Attacker` contract via `.call()`, this function executes. Its logic should check if `VulnerableVault` still has funds and, if so, call `VulnerableVault.withdraw()` again, creating the reentrancy loop.
            
3. **Develop and Run Event Listener Bot:**
    - Implement the conceptual Golang bot (from Section 8) or use a similar script in another language (Python/JS).
    - Configure the bot with:
        - The test network's RPC endpoint (WebSocket URL for subscriptions).
        - The deployed `VulnerableVault` contract address.
        - The ABI of `VulnerableVault` (specifically the `WithdrawalEvent`).
        - Credentials (private key) for an account funded with test Ether (to pay gas for transactions).
        - Logic: Upon detecting `WithdrawalEvent`, the bot should send a transaction that initiates the exploit. This transaction could either:
            - Call the `attack()` function on the deployed `Attacker` contract.
            - *Or*, if not using an attacker contract, directly call `VulnerableVault.withdraw()` from the bot's address (assuming the bot deposited funds earlier).
4. **Execute the PoC:**
    - Start the event listener bot. Ensure it successfully connects and subscribes to events.
    - **Initiate Deposit:** Send a transaction to `VulnerableVault.deposit()` from the address that will perform the withdrawal (either the `Attacker` contract address via its `attack` function, or the bot's address).
    - **Trigger Vulnerable Function:** Send a transaction calling `VulnerableVault.withdraw()` with a valid amount.
    - **Observe the Attack:**
        - Monitor the bot's console output: It should detect the `WithdrawalEvent`.
        - The bot should then automatically send its transaction (calling `Attacker.attack()` or `VulnerableVault.withdraw()`).
        - Monitor the blockchain (using a block explorer like Etherscan for the testnet): Observe the sequence of transactions. You should see the initial withdrawal, followed by the bot's transaction, which triggers further calls to `withdraw` within the same or subsequent transactions, rapidly decreasing the `VulnerableVault`'s balance.
        - Verify that the `Attacker` contract's balance (or the bot's balance) increases by more than the initially withdrawn amount, while the `VulnerableVault` balance is significantly depleted or emptied.

This PoC methodology, combining standard reentrancy exploitation techniques with the event-driven automation trigger, specifically validates the risk posed by the "Bot-Triggered Reentrancy via On-Chain Event" pattern. While discusses PoC environments, its focus is different (GDPR compliance). The structure aligns with general exploit PoC development seen in security reports.

## **11. Risk Classification**

The Bot-Triggered Reentrancy via On-Chain Event vulnerability carries significant risk, categorized as follows:

- **CWE (Common Weakness Enumeration):**
    - **CWE-841: Improper Enforcement of Behavioral Workflow:** This classification accurately reflects the core issue. The contract executes actions (event emission, external call) in an order that violates the secure workflow, where state updates should precede external interactions. Reentrancy exploits this workflow violation.

    - **CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection'):** While not a typical injection, the prematurely emitted event acts as an improperly controlled output. This output signals an inconsistent state to a downstream component (the bot), which then uses this signal to "inject" harmful reentrant calls back into the system.
- **OWASP Smart Contract Top 10:** This vulnerability pattern directly falls under **SC01: Reentrancy Attacks**. The bot-triggered mechanism is a specific vector for initiating this well-known attack class.
- **DASP Top 10 (Older classification):** Clearly aligns with **DASP-1: Reentrancy**.
- **Technical Risk:**
    - **Likelihood:** High. Reentrancy vulnerabilities are common, and the public nature of blockchain events makes them easily monitorable. If a contract has the flaw and emits a relevant event prematurely, a bot can be readily developed to exploit it. The automation increases the likelihood of exploitation compared to manual methods.
    - **Impact:** High to Critical. Successful exploitation typically leads to substantial or complete loss of funds held by the contract, manipulation of critical state, or denial of service.
        
- **Business Risk:**
    - **Financial Loss:** Direct theft of assets (cryptocurrency, tokens) can lead to millions of dollars in losses, as evidenced by numerous historical hacks like The DAO, Fei Protocol, and Grim Finance.
        
    - **Reputational Damage:** Exploits severely damage user trust and the project's reputation, potentially leading to user exodus and platform abandonment.
    - **Operational Disruption:** Halting contract functionality, dealing with state inconsistencies, and managing recovery efforts consume significant resources.
    - **Legal/Regulatory Consequences:** Depending on the application's nature and jurisdiction, significant financial losses or data corruption could lead to legal challenges or regulatory scrutiny.

Classifying the risk using established frameworks like CWE and OWASP aids in prioritizing mitigation efforts and communicating the severity to stakeholders. The combination of a known high-impact vulnerability (reentrancy) with an efficient, automatable trigger (event-listening bot) results in a high-priority risk that demands robust preventative measures.

## **12. Fix & Patch Guidance**

Addressing the Bot-Triggered Reentrancy via On-Chain Event vulnerability requires fixes primarily at the smart contract level, supplemented by defensive programming practices in any interacting off-chain bots.

**Smart Contract Level (Primary Fixes):**

- **Implement Checks-Effects-Interactions (CEI) Pattern:** This is the most crucial and effective defense. Ensure that all state changes (Effects) related to a function's logic are completed *before* any external calls (`.call()`, `.send()`, `.transfer()`) or event emissions (`emit`) (Interactions) occur. By updating state first, the contract accurately reflects its status before potentially yielding control flow or signaling external listeners.

- **Use Reentrancy Guards (Mutex):** Implement a mutual exclusion mechanism, often referred to as a reentrancy guard or mutex. Libraries like OpenZeppelin provide a standard `ReentrancyGuard` contract with a `nonReentrant` modifier. Applying this modifier to sensitive functions prevents them from being called again while they are already executing within the same transaction context.
    
    ```Solidity
    
    import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
    
    contract GuardedVault is ReentrancyGuard {
        mapping(address => uint256) public balances;
        event WithdrawalEvent(address indexed user, uint256 amount);
    
        function deposit() public payable { balances[msg.sender] += msg.value; }
    
        // Apply the nonReentrant modifier and follow CEI
        function guardedWithdraw(uint256 amount) public nonReentrant { // Modifier prevents re-entry
            uint256 userBalance = balances[msg.sender];
            require(userBalance >= amount, "Insufficient balance");
    
            // --- CORRECT ORDER (CEI + Guard) ---
            // 1. EFFECT: Update state first
            balances[msg.sender] = userBalance - amount;
    
            // 2. INTERACTION: Emit event after state change
            emit WithdrawalEvent(msg.sender, amount);
    
            // 3. INTERACTION: Perform external call last (if necessary)
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");
            // --- END CORRECT ORDER ---
        }
        receive() external payable {}
    }
    ```
    
- **Favor Pull Payments over Push Payments:** Where feasible, design systems where users actively withdraw (pull) their funds or entitlements rather than having the contract automatically send (push) them via external calls. This shifts the responsibility and potential risks of the external call to the user initiating the pull.

**Bot/Off-Chain Logic Level (Secondary Defenses):**

- **Implement Sanity Checks and Delays:** Bots reacting to events should not act blindly. Before sending a potentially exploiting transaction, the bot could:
    - Perform a read call (`eth_call`) to the contract to verify the state relevant to the event.
    - Wait for a small, potentially randomized delay.
    - Check the status of the transaction that emitted the event.
- **Handle Blockchain Reorganizations:** Design bots to wait for a reasonable number of block confirmations (e.g., 6-12 blocks, depending on chain and security requirements) before treating an event as final and acting upon it. This mitigates risks associated with acting on events in blocks that might be orphaned.

- **Implement Rate Limiting:** Prevent bots from sending excessive transactions in response to events, which could exacerbate issues or be perceived as network spam.

**General Practices:**

- **Thorough Security Audits:** Regularly subject smart contracts to audits by reputable security firms, with a specific focus on reentrancy vulnerabilities and adherence to the CEI pattern.
    
- **Use Secure Libraries:** Leverage well-audited and community-vetted libraries like OpenZeppelin for standard components like `ReentrancyGuard`.

**Reentrancy Mitigation Techniques Comparison:**

| **Technique** | **Description** | **Pros** | **Cons** | **Applicability** |
| --- | --- | --- | --- | --- |
| Checks-Effects-Interactions | Perform state updates *before* external calls/events. | Fundamental fix, addresses root cause, generally applicable. | Requires careful code structuring, easy to get wrong. | Universal (Essential) |
| Reentrancy Guard / Mutex | Use a lock/modifier (`nonReentrant`) to prevent recursive calls within a transaction.| Strong protection, relatively easy to implement using libraries. | Adds gas cost, doesn't fix underlying CEI violation if present. | High (Standard Practice) |
| Pull Payments | Users initiate withdrawals instead of the contract pushing funds. | Reduces contract's external call risks, shifts gas cost to user. | Not always feasible depending on application logic, can be less UX friendly. | Specific scenarios (e.g., claiming rewards) |
| Gas Limiting | Explicitly limit gas forwarded in external calls (e.g., using `transfer` or low-gas `.call`). | Can prevent complex reentrant calls due to gas exhaustion. | Brittle (gas costs change), may break legitimate interactions. | Low (Generally discouraged as primary fix) |
| Bot-Side Checks/Delays/Reorg Handling | Off-chain bot verifies state, waits for confirmations before reacting to events. | Adds defense-in-depth, mitigates bot-specific risks. | Doesn't fix contract vulnerability, adds latency, complexity to bot. | Secondary (Good practice for bot design) |

Fixing the smart contract using CEI and reentrancy guards is paramount. However, incorporating safer design principles into interacting bots provides valuable defense-in-depth for the overall system.

## **13. Scope and Impact**

The Bot-Triggered Reentrancy via On-Chain Event vulnerability has a broad scope and potentially devastating impact within the blockchain ecosystem.

**Scope:**

- **Affected Systems:** Any smart contract deployed on an EVM-compatible blockchain (like Ethereum, Polygon, BNB Chain, etc.) that fails to strictly adhere to the Checks-Effects-Interactions pattern when emitting events or making external calls is potentially vulnerable.
- **Application Domains:** This vulnerability is particularly relevant in Decentralized Finance (DeFi) protocols involving lending, borrowing, automated market makers (AMMs), yield farming vaults, and staking pools. It also affects NFT marketplaces, DAO governance contracts, and any application managing valuable assets or critical state based on external interactions or event signals.
- **Trigger Origin:** Since the bot operates off-chain and listens to public blockchain data, the trigger for the attack can originate from anywhere on the internet capable of running the necessary event-listening and transaction-dispatching code.
- **Cross-Chain Interactions:** The scope extends to multi-chain architectures. Events emitted on one chain can be relayed (e.g., by bridges or oracles) and trigger reentrant logic on another chain, potentially leading to inconsistencies or asset duplication across chains.

**Impact:**

- **Direct Financial Loss:** This is the most immediate and severe impact. Attackers can drain substantial amounts, often millions of dollars worth of cryptocurrency or tokens, from vulnerable contracts before the vulnerability is detected or patched. Numerous high-profile DeFi hacks involving reentrancy have resulted in catastrophic losses, such as The DAO ($60M in 2016) , Fei Protocol (~$80M in 2022), Grim Finance (~$30M in 2021), and SIREN Protocol (~$3.5M in 2021).
    
- **State Inconsistency and Corruption:** Beyond fund theft, reentrancy can corrupt the internal state of the contract. This can lead to malfunctioning applications, incorrect accounting of user balances or permissions, issuance of unbacked tokens, broken governance mechanisms, or duplication of assets in cross-chain scenarios.

- **Loss of User Trust and Reputational Damage:** Successful exploits severely erode user confidence in the affected protocol and its development team. This often leads to a loss of users, liquidity withdrawal, and long-lasting reputational harm.
- **Broader Ecosystem Effects:** Major exploits can negatively impact the price of the protocol's native token, affect interconnected DeFi protocols that rely on the compromised one, and diminish overall confidence in the security of the broader blockchain or DeFi ecosystem.

The impact is significantly amplified by the inherent immutability of blockchain transactions. Once funds are successfully extracted via a reentrancy attack, recovering them is typically impossible without extraordinary and often contentious measures like a hard fork of the entire blockchain, as occurred in the aftermath of The DAO hack. The automation provided by the bot ensures that this potentially irreversible damage can occur rapidly and efficiently.

## **14. Remediation Recommendation**

Remediating a Bot-Triggered Reentrancy vulnerability requires a swift response to contain damage, followed by robust technical fixes and long-term preventative measures.

**Immediate Actions (If Exploited or Vulnerability Confirmed):**

- **Pause Vulnerable Functions/Contract:** If the contract includes emergency pause mechanisms (e.g., OpenZeppelin's `Pausable`), immediately activate them to halt interactions with the vulnerable functions or the entire contract. This prevents further exploitation while a fix is prepared.
- **Notify Community and Stakeholders:** Transparently communicate the discovery of the vulnerability or exploit, the actions being taken (e.g., pausing), and the plan for remediation. Maintaining trust requires openness, even during crises.
- **Identify Attacker Address(es):** Analyze blockchain data to pinpoint the address(es) initiating the reentrant calls (likely the bot's address or an intermediary attacker contract). While stopping the attacker directly is difficult in a decentralized system, this information is crucial for analysis and potential coordination with exchanges (if funds are moved there).

**Short-Term Remediation:**

- **Develop and Audit Patch:** Correct the vulnerable smart contract code. This *must* involve:
    - Strictly implementing the Checks-Effects-Interactions (CEI) pattern.
        
    - Adding a reentrancy guard (`nonReentrant` modifier) to all sensitive functions that involve external interactions or state changes susceptible to reentrancy.
    - Thoroughly test the patched code.
    - Obtain an expedited security audit of the patched code, specifically verifying the fix for the reentrancy flaw.
- **Deploy Patched Contract:** Deploy the audited, fixed version of the smart contract to the blockchain.
- **Plan and Execute Secure Migration:** Develop a clear and secure process for users to migrate their funds, assets, or state from the old, vulnerable contract to the newly deployed, patched version. This often involves deploying a separate migration contract or providing detailed instructions. Ensure the migration process itself is secure and resistant to manipulation.
- **Implement Enhanced Monitoring:** Deploy or enhance on-chain monitoring tools  specifically configured to detect reentrancy patterns around the newly deployed contract and any associated event emissions. This provides early warning if the fix was incomplete or if new vectors emerge.

**Long-Term Prevention:**

- **Integrate Secure Development Lifecycle (SDL):** Embed security practices throughout the entire development process. This includes mandatory adherence to secure coding patterns like CEI, threat modeling for interaction patterns, rigorous code reviews focused on security, and comprehensive testing including specific scenarios for reentrancy and other common vulnerabilities.
- **Continuous Developer Education:** Regularly train developers on smart contract security best practices, common vulnerabilities like reentrancy, and the importance of patterns like CEI. Ensure they understand the risks associated with external calls and event emissions.
    
- **Regular, In-Depth Security Audits:** Schedule periodic, comprehensive security audits by reputable third-party firms, not just before initial launch but also after significant upgrades.

- **Establish Bot Security Guidelines:** If the project involves off-chain bots interacting with smart contracts based on events, develop clear security guidelines for bot development. These should cover safe event handling (confirmations, state verification), robust error handling, secure key management, and tolerance for blockchain reorgs.
    
Remediation must address both the immediate technical flaw in the contract and the underlying process failures that allowed it to occur. Because this pattern involves interaction between on-chain and off-chain components, preventative measures should encompass the security of the entire system, not just the smart contract in isolation.

## **15. Summary**

The "Bot-Triggered Reentrancy via On-Chain Event" vulnerability represents a significant threat pattern in the smart contract ecosystem. It combines a classic on-chain vulnerability – reentrancy – with an off-chain automation vector. The core weakness resides within the smart contract's code, specifically when it violates the Checks-Effects-Interactions (CEI) security pattern by emitting an event or making an external call before finalizing critical state updates.

An off-chain bot, potentially written in Golang or other languages using blockchain libraries, monitors the blockchain for these prematurely emitted events. Upon detection, the bot automatically initiates transactions designed to call back into the vulnerable contract function. Because the contract's state has not yet been updated, these reentrant calls execute based on stale information, allowing the attacker to drain funds, manipulate state, or cause other harm.

The severity is rated High to Critical due to the high likelihood of exploitation (given the public nature of events and the ease of automation) and the potentially catastrophic impact, primarily irreversible financial loss. Key mitigation strategies focus on fixing the contract by strictly adhering to the CEI pattern and implementing reentrancy guards. Additionally, designing safer off-chain bots (e.g., handling confirmations, performing state checks) and employing robust on-chain monitoring provide crucial layers of defense-in-depth. Thorough security audits and secure development practices are essential for prevention.

## **16. References**

- The Hacker News (Feb 17, 2025). *New Golang-Based Backdoor Uses Telegram Bot API for Evasive C2 Operations*. https://thehackernews.com/2025/02/new-golang-based-backdoor-uses-telegram.html
- QuickNode Guides (Mar 18, 2025). *A Broad Overview of Reentrancy Attacks in Solidity Contracts*. https://www.quicknode.com/guides/ethereum-development/smart-contracts/a-broad-overview-of-reentrancy-attacks-in-solidity-contracts
- Cyfrin Glossary (May 12, 2025). *Reentrancy*. https://www.cyfrin.io/glossary/reentrancy
- OWASP Smart Contract Top 10 (2023). *SC01: Reentrancy Attacks*. https://owasp.org/www-project-smart-contract-top-10/2023/en/src/SC01-reentrancy-attacks.html
- Smart Contract Security Field Guide (SCSFG). *Reentrancy*. https://scsfg.io/hackers/reentrancy/
- ResearchGate (Publication Date Unavailable). *Efficiently Detecting Reentrancy Vulnerabilities in Complex Smart Contracts*. https://www.researchgate.net/publication/382235557_Efficiently_Detecting_Reentrancy_Vulnerabilities_in_Complex_Smart_Contracts
- Artela Network Blog (Date Unavailable). *Eliminate Reentrancy Attacks With On-Chain Runtime Protection*. https://artela.network/blog/eliminate-reentrancy-attacks-with-on-chain-runtime-protection
- USENIX Security '23 Symposium (Date Unavailable). *Understanding the Practices, Challenges, and Needs of Smart Contract Developers*. https://www.usenix.org/system/files/usenixsecurity23-sharma.pdf
- GeeksforGeeks (Date Unavailable). *Reentrancy Attack in Smart Contracts*. https://www.geeksforgeeks.org/reentrancy-attack-in-smart-contracts/
- Tech Science Press - CMC Journal (Vol. 83, No. 2, Date Unavailable). *Smart Contract Reentrancy Vulnerability Detection Method Based on Multi-Feature Fusion and Graph Attention Neural Network*. https://www.techscience.com/cmc/v83n2/60555/html
- Go Vulnerability Database (pkg.go.dev). *Vulnerability List*. https://pkg.go.dev/vuln/list?ref=0x434b.dev (Accessed Feb 2025, content may vary)
- UTRGV ScholarWorks (Date Unavailable). *EPF: An Event Processing Framework for Blockchain-based Smart Contracts*. https://scholarworks.utrgv.edu/cgi/viewcontent.cgi?article=1067&context=cs_fac
- arXiv (Apr 21, 2025). *Smart Contract Vulnerability Analysis and Security Audit*. https://arxiv.org/html/2504.21480v1
- OpenSCV Project (Date Unavailable). *Open Smart Contract Vulnerability Database*. https://openscv.dei.uc.pt/
- Tech Science Press - CMC Journal (Vol. 83, No. 2, Date Unavailable). *Smart Contract Reentrancy Vulnerability Detection Method Based on Multi-Feature Fusion and Graph Attention Neural Network (PDF)*. https://www.techscience.com/cmc/v83n2/60555/pdf
- Devcon Archive (Devcon 6, Date Unavailable). *Hunting and Monitoring for On-Chain Attacks*. https://archive.devcon.org/devcon-6/hunting-and-monitoring-for-on-chain-attacks/
- AEPD (Spanish Data Protection Agency) (Date Unavailable). *Annex: Blockchain and GDPR*. https://www.aepd.es/guias/Annex-blockchain.pdf
- OASIcs - FMBC 2022 (Vol. 105, Date Unavailable). *Generating Attackers for Smart Contracts using Property-Based Testing*. https://drops.dagstuhl.de/storage/01oasics/oasics-vol105-fmbc2022/OASIcs.FMBC.2022.3/OASIcs.FMBC.2022.3.pdf
- Hedera Learning Center (Date Unavailable). *DeFi Risks*. https://hedera.com/learning/decentralized-finance/defi-risks
- Halbon Blog (Date Unavailable). *What Is a Re-entrancy Attack?*. https://www.halborn.com/blog/post/what-is-a-re-entrancy-attack
- curl project (Apr 2, 2025). *Changelog*. https://curl.se/changes.html (Context: General software patching example)
- CVE Mitre (Date Unavailable). *CVE Search Results for keyword=3Drace+condition*. https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=3Drace+condition (Context: General concurrency fix example)
-IETF Datatracker (Jan 20, 2022). *Recommendations for the Remediation of Bots in ISP Networks (draft-oreirdan-mody-bot-remediation-20)*. https://datatracker.ietf.org/doc/draft-oreirdan-mody-bot-remediation/20/
- Code4rena Reports (Oct 2023). *2023-10-party Report*. https://code4rena.com/reports/2023-10-party
- Ackee Blog (Mar 17, 2025). *Cross-chain Reentrancy Attack*. https://ackee.xyz/blog/cross-chain-reentrancy-attack/
- KTH DiVA Portal (Date Unavailable). *HIGHGUARD: Cross-Chain Runtime Monitoring of Smart Contracts*. https://kth.diva-portal.org/smash/get/diva2:1947353/FULLTEXT02.pdf
- GitHub Repository. *HydroProtocol/ethereum-watcher*. https://github.com/HydroProtocol/ethereum-watcher
- GitHub Repository. *AleG94/ethereum-events*. https://github.com/AleG94/ethereum-events
- QuickNode Guides (Date Unavailable). *How To Interact with Smart Contracts*. https://www.quicknode.com/guides/ethereum-development/smart-contracts/how-to-interact-with-smart-contracts
- MetaMask News (Date Unavailable). *Top Three Libraries for Web3 Developers*. https://metamask.io/news/developers/top-three-libraries-for-web3-developers
- Ackee Blog (Mar 17, 2025). *Cross-chain Reentrancy Attack*. https://ackee.xyz/blog/cross-chain-reentrancy-attack/
- Cyfrn Glossary (May 12, 2025). *Reentrancy*. https://www.cyfrin.io/glossary/reentrancy
- QuickNode Guides (Mar 18, 2025). *A Broad Overview of Reentrancy Attacks in Solidity Contracts*. https://www.quicknode.com/guides/ethereum-development/smart-contracts/a-broad-overview-of-reentrancy-attacks-in-solidity-contracts