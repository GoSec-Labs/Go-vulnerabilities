# **Calldata Validation Broken in Off-Chain Simulation (calldata-validation-bug)**

## **Severity Rating**

**High 🟠 to Critical 🔴**

The severity of the "Calldata Validation Broken in Off-Chain Simulation" vulnerability is typically assessed as **High🟠 to Critical 🔴**. This rating is determined by several factors, including the potential for direct financial loss, the extent of control an attacker can gain, the ease of exploitation, and the prevalence of the vulnerable Golang component or architectural pattern.

When calldata validation is compromised in an off-chain simulation environment, an attacker can mislead a user into signing a transaction they believe to be benign, while it actually executes a malicious operation. The impact can be devastating, as demonstrated by incidents like the Bybit hack, where off-chain UI deception related to transaction data led to losses exceeding $1.4 billion. Similarly, UI spoofing attacks, such as the Radiant Capital hack ($50 million) and the Ledger Connect Kit exploit ($600,000+), highlight the significant financial damage that can occur when users are tricked into approving malicious calldata.

The severity is particularly amplified because this vulnerability often targets the human element of trust in the user interface or simulation results. Off-chain simulations are designed to provide users with clarity and confidence before they commit to signing a transaction. If the calldata validation within this simulation process is broken, the system can effectively lie to the user about the transaction's true nature. Consequently, users, trusting the displayed information, may provide a valid cryptographic signature for what is, in reality, harmful calldata. This circumvents purely on-chain defenses because the transaction itself, once signed, appears legitimate from the blockchain's perspective. The potential for direct theft of assets or irreversible compromise of smart contract states justifies the high to critical severity rating.

## **Description**

This vulnerability, termed "Calldata Validation Broken in Off-Chain Simulation," occurs within Golang-based systems responsible for the off-chain simulation, preparation, or facilitation of blockchain transactions. It arises when these systems fail to adequately validate the integrity, source, or parameters of `calldata`—the input data for a smart contract function—before this `calldata` is either presented to a user for signing or used in a simulation whose results the user trusts to make a signing decision.

Attackers can exploit this vulnerability by manipulating the `calldata` within the off-chain environment. This manipulation is engineered such that the simulation shown to the user (or the information upon which the user bases their approval) depicts a benign or intended outcome. However, the actual transaction, once signed by the unsuspecting user and broadcast to the blockchain, executes a different, malicious operation. The core of the vulnerability lies in this discrepancy: a gap between what the user *perceives* they are authorizing off-chain and what the blockchain *actually executes* on-chain based on the tampered `calldata`.

The Bybit hack serves as a pertinent example of this principle in action, where signers were deceived by the application display, trusting it while unknowingly signing tampered transactions. The malicious JavaScript involved manipulated transaction data (`safeTx.data`) off-chain before the signing process was completed by the first signer, leading to a cascade of seemingly valid approvals for a malicious operation. Similarly, the concept of UI spoofing, where transaction interfaces are manipulated to deceive users into approving harmful actions, directly aligns with the mechanism of this vulnerability. These attacks fundamentally exploit the gap between user perception and blockchain execution.

In contexts like ERC-4337 Account Abstraction, where simulation functions are explicitly moved off-chain for use by bundlers or other off-chain infrastructure, Golang implementations of such components could be susceptible if their `calldata` validation logic is flawed. The vulnerability is not typically a flaw in the Golang language itself, but rather in the design and implementation of the Golang application's logic for handling, processing, and validating transaction data in an off-chain setting. Blockchain transactions demand precise `calldata`. Off-chain tools, potentially built using Golang, are employed to construct, simulate, and present these transactions. If these tools harbor defects in how they ensure `calldata` integrity during this pre-chain phase, the `calldata` becomes a vector for attack, leading to users signing transactions that deviate from their intended actions.

## **Technical Description (for security pros)**

In a Golang application tasked with off-chain transaction simulation—such as a decentralized application (dApp) backend, a transaction batching service, a wallet gateway, or an ERC-4337 bundler component—this vulnerability manifests when input `calldata` is sourced from an untrusted origin, inadequately sanitized, or insecurely transformed before being used to generate a transaction hash for signing or to populate simulation parameters.

More specifically, if a Golang service receives `calldata` components (e.g., target contract address, function signature, arguments) and fails to perform critical validation steps, it becomes vulnerable. These failures include:

1. **Lack of Verification:** Not verifying that the received components match an expected, legitimate template or align with the user's explicitly stated intention.
2. **Display-Signature Mismatch:** Failing to ensure that the transaction details displayed to the user or used for simulation accurately and completely reflect the final `calldata` that will be cryptographically signed.
3. **Injection Vulnerabilities:** Not preventing the injection or modification of `calldata` segments by an attacker. This could occur through various vectors, such as a compromised frontend submitting malicious data, a man-in-the-middle attack between distributed services, or insecure API endpoints that allow `calldata` manipulation.

The fundamental technical failure is a breakdown in the chain of trust and validation for the `calldata` as it traverses the off-chain system components en route to signature generation. The Golang component might erroneously assume the integrity of data received from other parts of the system (e.g., a web frontend) or neglect to perform its own rigorous, independent checks.

The Bybit hack illustrates a scenario where malicious JavaScript replaced `safeTx.data` with tampered parameters (`to`, `data`, `operation`) before the initial signature.**1** If a Golang backend were responsible for assembling this `safeTx` object based on inputs from a compromised frontend without re-validating these inputs against the intended operation, it would be directly culpable. While the Bybit incident involved JavaScript for the client-side manipulation, a backend Golang service failing to validate the subsequently received data would perpetuate the attack. clarifies that the JavaScript replaced `signedTx.data` with `origData` *after* the tampered data was signed, to deceive subsequent signers in the multi-sig scheme. The initial tampering of `safeTx.data` before the *first* signature is crucial, and a Golang backend's failure to catch this would be a key vulnerability.

In the context of ERC-4337, simulation functions are explicitly designed for off-chain use by bundlers. If a Golang bundler implements these off-chain simulations, it must meticulously handle and validate the `UserOperation` calldata to prevent exploitation. The overarching principle is that supporting on-chain validation with robust off-chain security measures is critical for maintaining a strong security posture; a breakdown in a Golang component's off-chain validation capabilities directly leads to this vulnerability.

A critical point of failure in a Golang service is the absence of cryptographically sound re-verification of `calldata` against the user's confirmed intent *after* any simulation occurs but *before* the final message is constructed for signing. For instance, if a simulation indicates a "transfer of X tokens to address Y," but the message ultimately signed is an "unlimited approval for token Z to an attacker's address," the Golang service that constructed the "approve" message based on manipulated inputs, without re-confirming the original "transfer X to Y" intent, is at fault. This represents a technical breakdown in the validation chain within the Golang component's operational logic. The service might receive calldata parameters from an upstream component, use these for simulation (e.g., via `eth_call` or a local EVM), and then prepare the transaction. If these parameters were manipulated upstream and the Golang service does not re-validate them against a strict policy or the user's original, confirmed intent *after* simulation and *before* signing, it effectively propagates the malicious `calldata`.

## **Common Mistakes That Cause This**

Several common mistakes in the design and implementation of Golang-based off-chain systems can lead to this calldata validation vulnerability:

1. **Trusting Unvalidated Inputs:** A prevalent error is when Golang services accept pre-formed `calldata`, or its constituent components, from less trusted sources (e.g., web frontends, other microservices) without performing rigorous server-side validation. This includes failing to re-verify inputs against expected schemas, whitelists of allowed functions/contracts, or the user's confirmed intent. Developers might erroneously assume that data received from a frontend has already undergone sufficient validation.
2. **Discrepancy Between Displayed/Simulated and Signed Data:** Golang backend logic may inadvertently allow the data used for UI display or simulation to diverge from the data ultimately packaged for signing. This can occur if data is fetched, transformed, or updated between the simulation step and the signing step without a corresponding re-validation and re-approval cycle. For example, simulating a transaction and then, in a separate step, fetching parameters anew or using a slightly different data structure to build the actual transaction for signing can introduce exploitable discrepancies.
    
3. **Inadequate Decoding and Inspection of Complex Calldata:** Services may not deeply decode and inspect complex `calldata` structures, particularly for operations like `delegatecall` or transactions involving multiple nested calls. Relying on superficial checks (e.g., only verifying the target contract and function selector) can allow malicious payloads to go undetected. The EIP-712 standard, while helpful for structured data, has been noted as insufficient for clearly representing nested operations, making deep inspection by the backend even more critical.
    
4. **Poor Session Management or State Integrity:** If the Golang application manages user sessions or maintains transaction state across multiple requests, flaws in this state management (e.g., susceptibility to session hijacking or state manipulation) could allow an attacker to inject malicious `calldata` into an otherwise legitimate user session or transaction flow.
5. **Ignoring or Misimplementing Clear Signing Standards (e.g., EIP-712):** Failure to implement, or incorrect implementation of, standards like EIP-712 in the Golang backend can deprive users of a human-readable format of what they are signing, making deception easier. While EIP-712 has limitations , its absence or incorrect use removes a valuable layer of user verification.
    
6. **Lack of "What You See Is What You Sign" (WYSIWYS) Enforcement in Backend Logic:** The Golang code responsible for the final construction of the transaction for signing must programmatically ensure that the parameters being signed are *identical* to what was last validated and presented to, and explicitly approved by, the user.
7. **Insufficient Validation Rules in Golang-based Simulation Logic:** If the Golang component itself is responsible for running the simulation (e.g., as part of an ERC-4337 bundler), a failure to implement comprehensive validation rules for incoming `UserOperation` objects or for the states simulated can lead to vulnerabilities. The ERC-4337 specification itself highlights the need for distinct validation rules (e.g., OP-xxx, COD-xxx series) to protect the system. The absence or misimplementation of such rules in a Golang-based simulator is a critical mistake.
    
8. **Weak Validation of Proposal Properties:** In systems where users can propose transactions or actions (e.g., DAO governance), if the properties of these proposals, including their `calldata`, are not fully validated, it can create opportunities for attackers to craft destructive proposals that appear benign.
    
A common underlying theme across these mistakes is an "assumption of trust" at various junctures within the off-chain transaction processing pipeline. The Golang component might incorrectly assume that data received from a frontend is already validated, or that a simulation result perfectly reflects the final on-chain outcome without requiring further stringent checks before the signing event. These assumptions create exploitable gaps.

## **Exploitation Goals**

Attackers exploiting broken calldata validation in off-chain simulations aim to achieve various malicious outcomes, primarily by tricking users into cryptographically authorizing actions they do not intend or understand. Common exploitation goals include:

1. **Unauthorized Fund Transfer:** The most direct goal is to deceive the user into signing a transaction that transfers their cryptocurrencies or other digital assets to an attacker-controlled address. The simulation would show a benign transaction (e.g., a small payment to a known service), but the actual `calldata` executes a high-value transfer to the attacker.
2. **Malicious Contract Approval:** A frequent objective is to trick the user into granting an attacker's smart contract unlimited (or very large) approval to spend their tokens (e.g., via the ERC20 `approve` function). The user might believe they are interacting with a legitimate dApp for a minor operation, but the signed transaction gives the attacker carte blanche over their tokens.
    
3. **Contract Ownership or Parameter Modification:** Attackers may target users with administrative privileges (e.g., contract owners, multi-sig participants) to mislead them into signing transactions that alter critical parameters of a smart contract, transfer ownership to the attacker, or upgrade a proxy contract to a malicious implementation. The Bybit hack exemplifies this, where the ultimate goal was to change the `masterCopy` (implementation contract) of their Gnosis Safe proxy via a manipulated `delegatecall` operation, thereby gaining control over the funds.
    
4. **Logic Exploitation via `delegatecall`:** Inducing a user to sign a transaction that performs a `delegatecall` to an attacker-controlled contract is a powerful exploitation technique. This allows the attacker to execute arbitrary code within the context of the victim's contract (or a contract the victim has authority over), potentially leading to storage manipulation, logic hijacking, or fund drainage, as seen in the Bybit attack.
    
5. **Data Exfiltration or State Corruption:** Forcing the execution of functions that are not intended to be called by the user, which might lead to the exposure of sensitive on-chain data or the corruption of important contract states, disrupting the contract's normal operation.
6. **Circumventing Multi-Signature Protections:** In a multi-signature scheme, if the off-chain simulation or display is compromised, an attacker can deceive individual signers one by one. Each signer might see what appears to be a legitimate, routine transaction (e.g., an internal transfer), while the underlying `calldata` (and its hash, which is signed) is consistently malicious. Once enough signatures for the malicious `calldata` are collected, the attack succeeds. The Bybit hack involved manipulating the Safe{Wallet} interface to achieve this against their multi-sig setup.
    
The success of these exploitation goals often hinges on the attacker's ability to craft `calldata` that is semantically different from what is represented to the user during the off-chain simulation or approval phase. If the vulnerability allows such a discrepancy, the attacker can leverage the user's trust in the simulation environment to obtain a valid signature for their malicious payload. The impact is not necessarily confined to the individual user; if the compromised transaction affects a large protocol (e.g., altering a key parameter in a widely used DeFi contract), the repercussions can be systemic, affecting numerous users or undermining the stability of the entire protocol.

## **Affected Components or Files (in a Golang context)**

The "Calldata Validation Broken in Off-Chain Simulation" vulnerability can affect a range of Golang components and files that are part of systems processing blockchain transactions before they are signed and submitted on-chain. These include:

1. **Golang Backend Services for dApps:** Go applications that serve as the backend for decentralized applications, particularly those that construct, simulate, or relay transactions based on requests from frontend interfaces. If these services do not rigorously validate `calldata` received from the frontend or fail to ensure a WYSIWYS (What You See Is What You Sign) experience, they are prime candidates for this vulnerability.
2. **Transaction Simulation Modules:** Any Golang library, custom module, or microservice specifically designed to simulate Ethereum transactions. This includes tools that use RPC calls like `eth_call` or `eth_estimateGas` , embed a local EVM instance for execution tracing, or implement specialized simulation logic, such as those required for ERC-4337 bundlers. Flaws in how these modules ingest, process, or present `calldata` and simulation results are critical.
    
3. **API Gateway Layers:** Golang-based API gateways that act as intermediaries between clients (e.g., frontends, other services) and Ethereum nodes or transaction-building services. If these gateways handle or transform `calldata` without implementing their own robust validation checks, they can become a weak link.
4. **Wallet Backend Systems:** Server-side infrastructure for wallets, potentially written in Golang, that assists in preparing transaction data for mobile or web clients to sign. If these backend systems are responsible for generating or validating `calldata` based on user requests transmitted through less secure channels, they can be vulnerable.
5. **Custom ERC-4337 Bundler Implementations:** If an ERC-4337 bundler, or parts of its logic (like `UserOperation` validation and simulation), is implemented in Golang, these components are directly affected if `calldata` validation is insufficient. This includes validating the `callData`, `initCode`, and other fields within a `UserOperation`.
    
6. **Smart Contract Interaction Libraries/SDKs in Golang:** Wrapper functions, libraries, or SDKs developed in Golang to simplify interactions with smart contracts. If these tools abstract away the complexities of `calldata` construction but do not enforce strict validation of the inputs used to generate that `calldata`, they can inadvertently contribute to the vulnerability.
7. **Go-Ethereum (Geth) Client Interaction Code:** While the primary focus of this vulnerability is often on the application logic built *around* an Ethereum client, the Golang code that interfaces with Geth (or other Ethereum clients) to send RPC calls like `eth_call` or `eth_estimateGas` for simulation purposes is a key area. If the `calldata` passed to these methods is not rigorously validated against user intent, and the simulation results are then used to gain user approval for signing a potentially different transaction, the application logic is flawed. In rare cases, a vulnerability within Geth's own simulation RPCs that could return misleading results for certain `calldata` might also contribute, although this is distinct from application-level validation failures.

The more complex the off-chain transaction preparation pipeline—for instance, one involving multiple microservices where some are written in Golang—the larger the potential attack surface for this type of `calldata` validation bug. Each point where `calldata` is handled, transformed, or passed between components represents a potential point of failure if validation is not consistently and rigorously applied. Consider a typical dApp architecture: a JavaScript frontend communicates with a Golang backend, which in turn interacts with an Ethereum node like Geth. The Golang backend might receive transaction parameters from the frontend, use a Golang EVM library or an `eth_call` via a Geth client to simulate the transaction, and then construct the final transaction object for the frontend to propose to a user's wallet for signing. Any Golang code involved in receiving these parameters, invoking the simulation, interpreting its results, or constructing the final transaction object is an "affected component" if it harbors `calldata` validation flaws.

## **Vulnerable Code Snippet (Hypothetical Golang Example)**

The following conceptual Golang code snippet illustrates a scenario where a backend service could be vulnerable to broken calldata validation in an off-chain simulation context. This example is simplified for clarity and does not represent a complete, production-ready system.

```Go

// Hypothetical Golang Code Snippet
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	// Assume some Ethereum library for types and simulation
	"github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/ethclient" // For actual simulation with a node
)

// UnvalidatedTxParams represents simplified transaction parameters received from a client.
// In a real attack, 'Calldata' could be malicious while other fields suggest a benign action.
type UnvalidatedTxParams struct {
	From     string `json:"from"`
	To       string `json:"to"`       // Target contract address
	Value    string `json:"value"`    // e.g., "0.1" ETH, often "0" for token interactions
	Calldata string `json:"calldata"` // Hex-encoded calldata, potentially manipulated
	// Fields intended to guide a naive simulation or UI display:
	UserIntentAction string `json:"userIntentAction"` // e.g., "transferTokens", "stake", "simpleEthSend"
	UserIntentTo     string `json:"userIntentTo"`     // Expected recipient by user
	UserIntentValue  string `json:"userIntentValue"`  // Expected value by user
}

// simulateTransaction provides a human-readable summary based on potentially naive checks.
// A real simulation would involve eth_call or a local EVM execution.
func simulateTransaction(params UnvalidatedTxParams) (string, error) {
	// NAIVE SIMULATION LOGIC:
	// This simulation might primarily rely on 'UserIntentAction' or superficial aspects
	// of 'To' and 'Value', without deeply inspecting 'Calldata'.
	// Example: If UserIntentAction is "simpleEthSend", it might only check 'To' and 'Value'.
	// If 'Calldata' actually encodes a malicious 'approve' or 'delegatecall',
	// this simulation will be misleading.

	summary := fmt.Sprintf("Simulated Action: %s to address %s with value %s.",
		params.UserIntentAction, params.UserIntentTo, params.UserIntentValue)

	// A slightly more advanced, but still potentially flawed, check:
	if len(params.Calldata) > 2 && params.Calldata[:10] == "0xa9059cbb" { // ERC20 transfer selector
		summary += " Calldata appears to be an ERC20 transfer."
	} else if len(params.Calldata) > 2 && params.Calldata[:10] == "0x095ea7b3" { // ERC20 approve selector
		// Problem: Doesn't check WHO is being approved or for HOW MUCH from the calldata itself.
		summary += " Calldata appears to be an ERC20 approve."
	} else if len(params.Calldata) > 2 {
		summary += fmt.Sprintf(" Calldata starts with: %s...", params.Calldata[:10])
	} else {
		summary += " No significant calldata provided."
	}

	// The critical flaw is that this summary might not accurately reflect the true
	// nature of `params.Calldata` if it's complex or intentionally deceptive.
	return summary, nil
}

// handleTransactionRequest processes the transaction request from a client.
func handleTransactionRequest(w http.ResponseWriter, r *http.Request) {
	var params UnvalidatedTxParams
	if err := json.NewDecoder(r.Body).Decode(&params); err!= nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 1. Perform simulation based on received parameters.
	simulationSummary, err := simulateTransaction(params)
	if err!= nil {
		http.Error(w, fmt.Sprintf("Simulation failed: %v", err), http.StatusInternalServerError)
		return
	}

	// 2. Present simulationSummary to the user (e.g., via API response to frontend).
	//    The user is expected to approve the transaction based on this summary.

	// 3. VULNERABILITY POINT: Construct the actual transaction for signing.
	//    The transaction is prepared using `params.To` and `params.Calldata` directly
	//    from the initial, potentially manipulated, client request.
	//    There is no re-validation of `params.Calldata` against the user's true,
	//    verified intent, nor is there a check to ensure the `simulationSummary`
	//    was a complete and accurate representation of what `params.Calldata` will execute.
	finalTxToAddress := common.HexToAddress(params.To)
	finalTxCalldata := common.FromHex(params.Calldata) // Using the potentially malicious calldata

	// (Code to construct the full transaction object to be signed would follow here,
	// using finalTxToAddress, finalTxCalldata, params.Value, params.From etc.)

	// Respond to client, indicating transaction is ready for signing with these parameters.
	// The wallet/signer would then use these `finalTxToAddress` and `finalTxCalldata`.
	responseMessage := fmt.Sprintf("Simulation Result: '%s'. Transaction ready for signing with To: %s, Value: %s, Calldata: %s",
		simulationSummary, finalTxToAddress.Hex(), params.Value, params.Calldata)

	// If `params.Calldata` was, for example, an "approve all tokens to attacker"
	// but `simulationSummary` was misleadingly benign (e.g., "Simulated Action: simpleEthSend..."),
	// the user is tricked into signing a harmful transaction.
	fmt.Fprint(w, responseMessage)
}

func main() {
	http.HandleFunc("/prepareTransaction", handleTransactionRequest)
	fmt.Println("Starting vulnerable Golang transaction handler on port 8080...")
	http.ListenAndServe(":8080", nil)
}
```

**Explanation of Vulnerability in Snippet:**

The vulnerability in this hypothetical Golang service arises from a "semantic gap." The `simulateTransaction` function is naive; it might provide a summary based on `UserIntentAction` or superficial checks of `params.Calldata` (like the function selector). An attacker can craft `UnvalidatedTxParams` where `UserIntentAction`, `UserIntentTo`, and `UserIntentValue` suggest a harmless operation (e.g., sending 0.01 ETH to a friend), while `params.Calldata` contains a malicious payload (e.g., `approve(ATTACKER_ADDRESS, MAX_UINT256)` targeting a valuable token contract, with `params.To` set to that token contract's address and `params.Value` set to "0").

The `handleTransactionRequest` function presents the misleading `simulationSummary` to the user. Upon user approval (based on this flawed summary), the service proceeds to prepare the transaction for signing using the original, untrustworthy `params.Calldata`. The Golang code fails to:

- Perform a deep, semantic validation of `params.Calldata` against the claimed `UserIntentAction`.
- Ensure that the `simulationSummary` is a truthful, complete, and unambiguous representation of what `params.Calldata` will actually do on-chain.
- Re-generate the `calldata` from a canonical, validated representation of the user's intent *after* the simulation and approval, rather than using the potentially tainted input `calldata`.

This scenario is analogous to the core issue in the Bybit hack, where client-side JavaScript manipulated transaction data before signing. This Go snippet represents a backend that fails to detect or prevent such manipulation if it receives the already tampered data and processes it insecurely. The principle of "decoding calldata tells us what a transaction is supposed to do, but simulating the transaction shows us what happens on-chain" is violated because the simulation here does not accurately reflect the on-chain consequences of the provided `calldata`.

## **Detection Steps**

Detecting the "Calldata Validation Broken in Off-Chain Simulation" vulnerability in Golang applications requires a multi-faceted approach, combining static analysis, dynamic testing, and logical review of the transaction lifecycle:

1. **Manual Code Review (Golang):**
    - **Trace Data Flow:** Meticulously trace the flow of `calldata` and its constituent parts (target address, value, function selector, arguments) from all input sources (e.g., HTTP request handlers, message queue consumers, inter-service API calls) through any simulation logic to the point where a transaction is constructed for signing.
    - **Identify Discrepancies:** Scrutinize whether the data used for generating simulation results or UI displays is guaranteed to be identical to the data that forms the actual transaction to be signed. Look for any re-fetching, transformation, or modification of transaction parameters between the simulation/display step and the signing preparation step that doesn't trigger a new validation and user approval cycle.
    - **Assess Validation Robustness:** Examine the validation logic in the Golang code. Does it comprehensively validate all parts of the `calldata` against strict schemas, whitelists of allowed contracts and function signatures, expected parameter types and value ranges, and, crucially, the user's explicit and verified intent *before* the transaction is finalized for signing?
    - **Inspect Simulation Logic:** Review how simulation results are generated and presented. Are they comprehensive, unambiguous, and do they accurately reflect all potential state changes and effects of the `calldata`? Superficial simulations are a red flag.
    - **Look for Direct Use of Unvalidated Inputs:** Identify instances where `calldata` (or its components) received from external or less trusted sources is used directly in the construction of the transaction to be signed, without undergoing thorough server-side validation and sanitization within the Golang service.
2. **Security Testing / Fuzzing:**
    - **Craft Discrepancy Test Cases:** Develop test cases where input parameters are intentionally mismatched. For example, provide parameters that would lead to a benign simulation display (e.g., small value transfer to a known address) but include underlying `calldata` that encodes a malicious operation (e.g., `approve` all tokens to an attacker, `delegatecall` to a malicious contract).
    - **Fuzz Input Fields:** Systematically fuzz all input fields that contribute to the formation of `calldata`. This includes API parameters, configuration values, or any data retrieved from external systems. The goal is to discover edge cases or unexpected inputs that could bypass validation logic or lead to the injection/alteration of `calldata` components.
3. **Transaction Analysis / "Diffing":**
    - In a controlled testing environment, implement mechanisms to capture two critical pieces of information:
        - The data exactly as it is presented to the user by the simulation (i.e., what the user *believes* they are signing).
        - The actual transaction parameters (to, value, data/calldata, gas, etc.) that are constructed by the Golang backend and prepared for signing.
    - Perform a "diff" or comparison between these two sets of data. Any discrepancies in the target address, value, function signature, or substantive arguments are strong indicators of this vulnerability. This approach is inspired by the principle of comparing expected versus actual outcomes. The fixes implemented in the Safe Gateway after the Bybit hack involved controls to verify a matching hash and signature, implying that such "matching" or "diffing" became a crucial detection and prevention step.
        
4. **Log Analysis:**
    - Review application logs from the Golang service, assuming they are sufficiently detailed. Look for logged information regarding received `calldata` parameters, inputs to and outputs from the simulation logic, and the final parameters used for transaction construction. Anomalies, mismatches, or evidence of parameter tampering in the logs can point to potential vulnerabilities.
5. **Utilize Calldata Decoding Tools:**
    - At various stages of processing within the Golang application (e.g., upon receipt, before simulation, after simulation, before signing), decode the `calldata` using appropriate ABI decoding tools and libraries. This helps in understanding the true semantic meaning of the `calldata`, rather than relying on superficial interpretations. This is particularly important for complex `calldata`, such as those involving `delegatecall` or multiple nested calls.

Effective detection requires a holistic understanding of the entire transaction lifecycle as it passes through the Golang application. It is not sufficient to audit the Golang code in isolation; one must also consider its interactions with frontends, wallets, users, and other services, and how data is transformed and validated (or not) across these boundaries. The core of detection is to find or prove that a divergence can occur between the user's informed consent and the actual transaction they are asked to sign.

## **Proof of Concept (PoC) (Conceptual)**

This conceptual Proof of Concept (PoC) outlines how the "Calldata Validation Broken in Off-Chain Simulation" vulnerability in a hypothetical Golang backend service could be demonstrated.

**1. Setup:**

- **Vulnerable Golang Backend:** Deploy the vulnerable Golang service as described in the "Vulnerable Code Snippet" section. This service exposes an HTTP endpoint (e.g., `/prepareTransaction`) that accepts transaction parameters, performs a naive/misleading simulation, and then prepares a transaction for signing using potentially unvalidated `calldata`.
- **Attacker-Controlled Client:** A script or tool (e.g., `curl`, a Python script using `requests`) capable of sending crafted JSON payloads to the Golang backend's API endpoint.
- **Observation Mechanism:** A method to observe:
    - The "simulation summary" returned by the Golang service.
    - The "actual transaction data" (to, value, calldata) that the Golang service indicates is ready for signing.
- **Victim's Wallet (Simulated):** For a PoC, actual signing can be simulated or, in a more advanced setup, integrated with a test wallet on a local development network (e.g., Hardhat, Anvil). The key is to show that the data *prepared for signing* is malicious.
- **Target Smart Contract:** Deploy a standard ERC20 token contract on the local development network. The victim account should hold some tokens in this contract.

**2. Attack Execution:**

- The attacker identifies the vulnerable Golang backend and the ERC20 token contract address (`ERC20_TOKEN_ADDRESS`) and the victim's address (`VICTIM_ADDRESS`). The attacker also has their own address (`ATTACKER_ADDRESS`).
- The attacker crafts a JSON payload to send to the `/prepareTransaction` endpoint. The goal is to make the `UserIntent...` fields suggest a benign, low-impact action, while the `Calldata` field contains a malicious instruction.
    
    ```JSON
    
    {
      "from": "VICTIM_ADDRESS",
      "to": "ERC20_TOKEN_ADDRESS", // Target the token contract
      "value": "0",                 // ETH value is 0 for token operations
      "calldata": "0x095ea7b3000000000000000000000000ATTACKER_ADDRESS_HEX000000000000000000000000ffffffffffffffffffffffffffffffffffffffff", // Calldata for: approve(ATTACKER_ADDRESS, MAX_UINT256)
      "userIntentAction": "checkTokenBalance", // Misleading intent
      "userIntentTo": "ERC20_TOKEN_ADDRESS",   // Consistent with checking balance
      "userIntentValue": "0"                    // Consistent with checking balance
    }
    ```
    
    *(Note: `ATTACKER_ADDRESS_HEX` is the attacker's address, padded, and `ffff...` is `MAX_UINT256`)*
    
- The attacker sends this payload to the Golang backend.

**3. Vulnerable Behavior Observation:**

- **Simulated Output:** The Golang service's `simulateTransaction` function, due to its naive logic, processes the `userIntentAction` and might return a summary like:
`"Simulation Result: 'Simulated Action: checkTokenBalance to address ERC20_TOKEN_ADDRESS with value 0. Calldata appears to be an ERC20 approve.'. Transaction ready for signing with To: ERC20_TOKEN_ADDRESS, Value: 0, Calldata: 0x095ea7b3...ffff"`
Even if it mentions "approve," it doesn't highlight the malicious parameters (attacker address, max amount), and the primary intent shown is benign. A more naive simulation might not even detect the `approve` if it only focuses on `userIntentAction`.
- **User Deception:** The victim (or an automated system acting on their behalf based on rules) sees the "checkTokenBalance" or a similarly innocuous part of the simulation summary and authorizes the transaction, assuming it's safe.
- **Actual Transaction Prepared:** The Golang service, however, constructs the transaction parameters for signing using the malicious `calldata` provided by the attacker:
    - `To`: `ERC20_TOKEN_ADDRESS`
    - `Value`: `0`
    - `Calldata`: `0x095ea7b3...ATTACKER_ADDRESS...MAX_UINT256`

**4. Outcome (Simulated or Actual):**

- The victim (or their wallet, prompted by the frontend that received these parameters from the Golang backend) signs the transaction with the malicious `calldata`.
- If executed on-chain, the transaction grants the `ATTACKER_ADDRESS` approval to spend all of the `VICTIM_ADDRESS`'s tokens from the `ERC20_TOKEN_ADDRESS` contract.

**5. Verification:**

- **Compare Outputs:** The PoC clearly demonstrates that the `simulationSummary` (what the user was led to believe) is drastically different and misleading compared to the `actual transaction data` prepared for signing.
- **On-Chain State (if executed):** On a testnet, an blockchain explorer would show that the victim's transaction was indeed the malicious `approve` call, not a "checkTokenBalance" action. The attacker can then demonstrate their ability to transfer the victim's tokens.

This PoC illustrates the critical failure of the Golang backend to validate the incoming `calldata` against the purported user intent and to ensure that the simulation accurately and completely reflects the true nature of the transaction being signed. It mirrors the core principle of the Bybit hack where off-chain data manipulation led to users signing transactions different from their understanding. The use of attack simulation scripts to deploy contracts, fund them, and observe outcomes is a common practice in identifying such vulnerabilities. The PoC establishes a clear causal chain: deceptive input leads to flawed simulation by the vulnerable Golang service, which misleads the user into approving the signing of a transaction constructed with the original malicious input, ultimately allowing the attacker to achieve their goal.

## **Risk Classification**

The "Calldata Validation Broken in Off-Chain Simulation" vulnerability presents a **High** overall risk. This classification is derived from assessing its likelihood and potential impact.

- Likelihood: Medium to High
    
    The likelihood of this vulnerability being present and exploited depends on several factors. The increasing complexity of decentralized applications and the associated off-chain infrastructure (e.g., sophisticated backends, transaction relayers, ERC-4337 bundlers) means more opportunities for such flaws to exist if not explicitly designed against. If Golang components handling transaction preparation have public-facing APIs with weak input validation or interact with frontends that can be compromised (e.g., via XSS, malicious browser extensions, or compromised dependencies 1), the likelihood of an attacker successfully injecting manipulated calldata increases.
    
    The "human factor" also plays a significant role.1 Users are often conditioned to trust the information presented by UIs and simulation summaries, especially if the application is otherwise reputable. Attack techniques like UI spoofing and social engineering that exploit this trust are well-documented.3 Therefore, if the technical vulnerability exists in the Golang backend, the probability of successful user deception can be considerable.
    
- Impact: High to Critical
    
    The potential impact of successful exploitation is severe. As demonstrated by major incidents, this type of vulnerability can lead to:
    
    - **Direct Financial Loss:** Attackers can drain user wallets or specific contract holdings.
        
    - **Compromise of Smart Contracts:** Unauthorized changes to contract ownership, critical parameters, or malicious upgrades can occur.

    - **Loss of Sensitive Data or System Integrity.**
    - **Significant Reputational Damage** to the dApp, wallet provider, or service involved.
    The financial impact seen in breaches like the Bybit hack ($1.4 billion) , Radiant Capital ($50 million), and the Ledger Connect Kit exploit ($600k+)  underscores the critical nature of the impact. It is important to distinguish this from vulnerabilities with inherently lower impact, such as a denial-of-service bug in a Golang library that doesn't directly lead to asset loss.
        
        
- Overall Risk: High
    
    Combining a medium to high likelihood with a high to critical impact results in an overall risk assessment of High.
    
- **Illustrative CVSSv3.1 Vector: `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N`**
    - **AV:N (Attack Vector: Network):** The attack can typically be initiated over the network.
    - **AC:L (Attack Complexity: Low):** Assuming a vulnerable endpoint and a known method to manipulate `calldata` that bypasses naive simulation.
    - **PR:N (Privileges Required: None):** The attacker often does not need prior privileges on the system.
    - **UI:R (User Interaction: Required):** The victim user must typically be tricked into signing the transaction.
    - **S:C (Scope: Changed):** Exploitation can impact components beyond the initially vulnerable Golang service (e.g., user's wallet, on-chain contracts).
    - **C:L (Confidentiality Impact: Low):** Direct confidentiality impact might be low, though data exfiltration could be a secondary goal.
    - **I:H (Integrity Impact: High):** Significant impact on the integrity of user assets and contract states.
    - **A:N (Availability Impact: None):** Typically, availability is not the primary target, though some exploits might cause denial of service as a side effect.
    *(This CVSS vector is illustrative and would need to be refined based on the specifics of a concrete vulnerability instance.)*

The risk is amplified because it exploits user trust in interfaces and simulations, which are meant to be safeguards. This psychological component, coupled with technical flaws in Golang services, creates a potent threat.

## **Fix & Patch Guidance**

Addressing the "Calldata Validation Broken in Off-Chain Simulation" vulnerability in Golang applications requires a multi-layered approach focusing on rigorous validation, ensuring data integrity throughout the transaction lifecycle, and providing clarity to the user.

1. **Implement Strict Input Validation in Golang Backend:**
    - All components of incoming `calldata` (target address, function selector, arguments) or parameters used to construct `calldata` must be rigorously validated by the Golang service. This validation should occur as soon as the data is received from any external or less trusted source (e.g., frontend API requests, messages from other services).
    - Validation rules should include whitelists of allowed smart contract addresses and function signatures, type checking, range checks for numerical values, and length checks for byte arrays, all based on the specific, explicitly confirmed user intent.
    - The ERC-4337 specification's approach of defining clear validation rules (e.g., OP-xxx, COD-xxx) for UserOperations serves as a good model for the level of rigor required.
        
2. **Ensure WYSIWYS (What You See Is What You Sign):**
    - The Golang service bears the primary responsibility for guaranteeing that the data used to generate any simulation or display for the user is cryptographically bound to, or verifiably identical with, the data ultimately used to construct the transaction for signing.
    - **Strategy:** After a user approves an action based on a simulation of `Intent A`, the Golang backend must re-construct the final `Calldata A` based *solely* on the validated parameters of `Intent A`. No unvalidated or potentially tainted `calldata` from the initial request should be used beyond this point. Any change to the intent or critical parameters must void the previous approval and re-trigger the entire validation, simulation, and approval process.
3. **Comprehensive Calldata Decoding and Semantic Analysis:**
    - Before both simulation and final transaction construction for signing, the Golang service should decode the `calldata` as deeply as possible. This is especially critical for complex interactions, such as those involving `delegatecall` or nested calls.
    - The service should attempt to understand the semantic meaning of the decoded `calldata` and compare it against the user's stated intent or predefined security policies. This goes beyond simple syntax checks.
        
4. **Use Secure Libraries for Calldata Handling:**
    - Employ well-audited and maintained Golang libraries for ABI encoding/decoding and for interacting with Ethereum nodes. Avoid custom, untested implementations for these critical functions.
5. **Contextual Confirmation and Clear Presentation:**
    - For sensitive operations, the Golang backend should ensure that the frontend (or other user interface) prompts the user for explicit confirmation of all critical transaction details. This confirmation step should occur *after* any simulation and *immediately before* the signing request is dispatched to the user's wallet. The details presented for this final confirmation must be sourced directly from the fully validated, to-be-signed transaction data generated by the backend.
6. **Implement EIP-712 for Structured Signing:**
    - Where applicable, the Golang backend should structure transaction data for signing according to the EIP-712 standard. This allows compatible wallets to display a more human-readable format of the data being signed, providing an additional layer of verification for the user. However, it's important to acknowledge that EIP-712 may be insufficient for clearly representing complex nested operations , so it should not be the sole defense.
        
7. **Post-Signature Verification (Defense in Depth):**
    - In scenarios involving gateways or multi-signature schemes, consider implementing a post-signature verification step. Before proposing or broadcasting a signed transaction, the Golang service (or an intermediary component) can re-verify that the provided signature indeed corresponds to the hash of the *intended and validated* transaction data, not some tampered version. This was a key part of the fix implemented by Safe{Wallet} after the Bybit incident.
        
8. **Secure Development Practices and Audits:**
    - Regularly audit Golang code involved in transaction processing.
    - Train developers on secure coding practices specific to blockchain applications, emphasizing the risks discussed.

The overarching goal of these fixes is to eliminate any possible divergence between the user's informed understanding of a transaction and the actual data they cryptographically sign. This requires a defense-in-depth approach within the Golang application, treating `calldata` with suspicion until proven safe and ensuring transparency for the user at every critical step.

## **Scope and Impact**

**Scope:**

The "Calldata Validation Broken in Off-Chain Simulation" vulnerability can manifest in any Golang application or service that plays a role in the off-chain lifecycle of blockchain transactions, specifically where user signatures are obtained based on information, simulations, or states managed or presented by that Golang component. The scope includes, but is not limited to:

- **dApp Backends:** Golang services that receive user requests from web or mobile frontends, construct transaction parameters, perform simulations (e.g., gas estimation, state change previews), and then prepare transactions for signing by the user's wallet.
- **Custom Wallet Solutions:** Backend systems for proprietary custodial or non-custodial wallets, if written in Golang and involved in generating or validating `calldata` before presenting it to the wallet's signing mechanism.
- **Transaction Relayers and Meta-Transaction Services:** Golang applications that relay transactions on behalf of users, especially if they construct or modify `calldata` as part of this process.
- **ERC-4337 Bundler Components:** If an ERC-4337 bundler, which is responsible for validating `UserOperation` objects (containing `calldata`), simulating them, and bundling them into on-chain transactions, is implemented in Golang, its validation and simulation logic is within scope.
    
- **Institutional Crypto Platforms:** Golang-based systems used by exchanges or financial institutions for managing transactions, especially from cold storage or multi-signature setups where off-chain approval workflows are common. The Bybit hack, involving their Safe{Wallet} setup, underscores this risk area.
    
- **Any System Interfacing Between User Intent and On-Chain Execution:** Essentially, any Golang code that sits between a user's high-level intention (e.g., "swap token A for token B") and the low-level `calldata` that gets signed to execute that intention.

**Impact:**

The impact of successfully exploiting this vulnerability is typically severe, leading to a range of detrimental consequences:

- **Financial Loss:** This is the most direct and common impact. Attackers can trick users into signing transactions that transfer their funds to attacker-controlled accounts or grant malicious contracts approval to drain their token balances. The scale of loss can range from individual user accounts to billions of dollars, as seen in the Bybit incident  and other UI spoofing related hacks.
    
- **Compromise of Smart Contracts:** Users with administrative privileges (e.g., contract owners, DAO members, multi-sig signers) can be deceived into signing transactions that maliciously alter contract ownership, change critical operational parameters, pause/unpause contracts inappropriately, or upgrade proxy contracts to attacker-controlled logic.
    
- **Reputational Damage:** A successful exploit causing significant user losses or contract compromises can severely damage the reputation of the affected dApp, wallet provider, exchange, or service. This loss of trust can be difficult and costly to recover from.
- **Systemic Risk:** If the vulnerable Golang component is part of a widely used platform, a critical piece of infrastructure (e.g., a popular wallet's backend, a major DeFi protocol's transaction handler, or a broadly adopted ERC-4337 bundler), the impact could be widespread, affecting a large number of users or even the stability of related ecosystems.
    
- **User Deception and Loss of Control:** At its core, the vulnerability exploits user trust, leading to users being tricked into actions that are detrimental to their interests. This undermines their autonomy and security within the blockchain ecosystem.
- **Regulatory and Legal Consequences:** For regulated entities, such a breach could lead to investigations, fines, and legal action.

A crucial aspect that magnifies the impact is that the vulnerability leverages a *valid cryptographic signature* from the user. From the perspective of the blockchain and smart contracts, the malicious transaction appears to be legitimately authorized by the user. This makes it challenging to distinguish from non-malicious user actions post-facto without a deep off-chain investigation into how the user was deceived. This characteristic means that on-chain defenses alone are often insufficient to prevent the consequences once a malicious transaction, validated by this off-chain flaw, is signed and broadcast. The scope of this vulnerability clearly extends beyond on-chain code, highlighting the critical importance of security in off-chain components.

## **Remediation Recommendation**

Remediating the "Calldata Validation Broken in Off-Chain Simulation" vulnerability in Golang applications requires a comprehensive strategy that emphasizes a zero-trust approach to `calldata`, ensures end-to-end data integrity, and empowers users with clear, verifiable information.

1. **Adopt a Zero-Trust Approach to Calldata:**
    - Golang services must treat any `calldata` or `calldata` components received from external sources (including frontends, other microservices, or even different modules within the same application) as untrusted by default.
    - Implement rigorous, policy-defined validation for all parts of the `calldata` against the specific, confirmed user intent *before* any simulation and, critically, *before* final transaction construction for signing.
2. **Implement End-to-End Calldata Integrity Checks (WYSIWYS):**
    - The core principle is "What You See Is What You Sign." The Golang backend must enforce that the `calldata` used for simulation, displayed to the user (or its effects clearly described), and approved by the user is verifiably identical to the `calldata` that is ultimately signed.
    - This can be achieved by:
        - Hashing critical transaction parameters at the point of user approval and re-verifying this hash against the parameters used for final signing.
        - Preferably, re-generating the entire `calldata` from a canonical, validated representation of the user's explicit intent *immediately before* constructing the message for signing, discarding any previously received `calldata`.
3. **Comprehensive Security Audits:**
    - Conduct thorough security audits of all Golang code involved in transaction handling. These audits should specifically focus on:
        - `Calldata` validation logic and input sanitization.
        - The accuracy and completeness of transaction simulation logic.
        - The integrity of the data flow between off-chain components and the point of signing.
        - The interface between the Golang service and user-facing components or wallets.
    - Audits should include negative testing, fuzzing, and attempts to bypass validation mechanisms by simulating attacker behavior.
4. **Developer Training and Secure Coding Standards:**
    - Train Golang developers on secure coding practices specifically for blockchain applications. This training should emphasize the risks of improper `calldata` handling, common UI spoofing vectors, the importance of the WYSIWYS principle, and secure interaction with cryptographic wallets.
    - Establish and enforce secure coding standards for `calldata` processing.
5. **Enhance User-Side Verification (Defense in Depth):**
    - While primary responsibility lies with the backend, encourage and facilitate user-side verification:
        - **Hardware Wallets with EIP-712 Support:** Promote the use of hardware wallets that can parse and clearly display EIP-712 structured messages, allowing users an independent channel to verify critical transaction details before signing. However, it's crucial to recognize that EIP-712 is not a panacea and has limitations, especially with complex nested operations.
            
        - **Client-Side Decoding and Display:** Frontend applications interacting with the Golang backend should also implement robust `calldata` decoding and display mechanisms to provide users with as much clarity as possible regarding the transaction they are about to approve.
            
6. **Defense-in-Depth for Golang Services:**
    - Implement rate limiting and anomaly detection for transaction requests processed by the Golang service to identify suspicious patterns or bulk exploitation attempts.
    - Monitor on-chain transactions originating from or facilitated by the service for unusual activities that might indicate a compromise.
    - Consider internal services or checks that validate transactions against predefined policies before they are relayed or broadcast, even after signing.

A security-first approach necessitates validating that the entire security flow, including off-chain simulation and `calldata` handling, provides robust guarantees comparable to on-chain security measures. Supporting on-chain validation with proper off-chain security in Golang components is critical to maintaining a strong overall security posture.

The following table summarizes common mistakes and their corresponding remediation strategies in a Golang context:

**Table 1: Common Mistakes Leading to Calldata Validation Bugs in Golang Off-Chain Simulation and Corresponding Remediation Strategies.**

| **Common Mistake** | **Description of Mistake** | **Potential Consequence** | **Golang-Specific Remediation Strategy** | **Relevant Principle Source(s)** |
| --- | --- | --- | --- | --- |
| Trusting Unvalidated Inputs | Golang services accept `calldata` or its components from less trusted sources (e.g., frontends, other services) without rigorous server-side validation against user intent or whitelisted patterns. | Attacker injects malicious `calldata`, leading to unauthorized actions like fund theft or contract compromise. | Implement strict server-side validation in Golang HTTP handlers or service interfaces using whitelists for contracts/functions, schema checks for arguments, and comparison against verified user intent. | **1** |
| Discrepancy Between Displayed/Simulated and Signed Data | Golang backend logic allows the data used for UI display or simulation to diverge from the data ultimately packaged for signing, often due to re-fetching or transformations without re-validation and re-approval. | User approves a benign-looking simulation but signs a transaction with different, malicious `calldata`. | Ensure Golang service cryptographically binds or guarantees identity between simulated/approved data and signed data. Re-generate `calldata` from a canonical, validated user intent immediately post-approval and before signing. | **1** |
| Inadequate Decoding and Inspection of Complex Calldata | Golang services perform only superficial checks on `calldata`, especially for `delegatecall` operations or nested calls, failing to understand the true semantic meaning or potential risks. | Malicious logic hidden in complex `calldata` (e.g., a `delegatecall` target or harmful nested call parameters) is executed. | Golang services must deeply decode and semantically analyze `calldata`. For `delegatecall`, rigorously validate the target contract and the nested call's function signature and arguments against strict policies and known-good patterns. | **1** |
| Lack of WYSIWYS Principle in Golang Backend Logic | Golang code responsible for final transaction construction does not programmatically ensure that the parameters being signed are identical to what was last validated and presented to/approved by the user. | User is tricked into signing a transaction whose effects are different from their understanding and approval. | The Golang backend must enforce that the final `calldata` for signing is derived *only* from the user-approved, validated intent. Any deviation must require a full re-simulation and re-approval cycle. | General Security Principle|
| Insufficient Validation Rules in Golang-based Simulation Logic | If the Golang component itself runs simulations (e.g., as part of an ERC-4337 bundler), it lacks comprehensive and strict validation rules for incoming operations (e.g., `UserOperation` objects) or for the state changes observed during simulation. | Malicious `UserOperations` can pass simulation, cause Denial of Service against the simulator, or provide misleading simulation results, deceiving users or bundlers. | Golang-based simulators must implement robust validation rules (akin to ERC-4337's OP-xxx, COD-xxx rules) for all inputs and state transitions within the simulation environment. | **4** |

Remediation is fundamentally about shifting towards a model where off-chain components, including those built in Golang, are developed and scrutinized with the same security rigor as on-chain smart contracts. The "trusted off-chain simulator" must itself be demonstrably trustworthy.

## **Summary**

The "Calldata Validation Broken in Off-Chain Simulation" (calldata-validation-bug) is a significant and high-risk vulnerability that can affect Golang applications involved in the off-chain preparation, simulation, or facilitation of blockchain transactions. It arises when these Golang systems fail to properly validate `calldata` (the input data for smart contract functions) before it is used in a simulation presented to a user or before it is packaged for the user to sign. This failure allows attackers to create a critical discrepancy between the transaction a user *perceives* they are authorizing (based on misleading off-chain information) and the actual malicious operation that gets executed on the blockchain.

Exploitation of this vulnerability can lead to severe consequences. These include, but are not limited to, unauthorized transfer of user funds, malicious approvals granting attackers control over tokens, and the compromise of smart contract ownership or critical parameters. Attackers achieve this by tricking users into providing valid cryptographic signatures for transactions that are, in reality, detrimental to their interests, all because the off-chain simulation or presentation layer, underpinned by the vulnerable Golang component, misrepresented the transaction's true nature.

Detection of this vulnerability involves a combination of meticulous manual code review of Golang components (tracing `calldata` flow and validation logic), targeted security testing (including fuzzing and crafting discrepancy test cases), dynamic analysis by "diffing" simulated versus actual transaction data, and thorough log analysis. The use of `calldata` decoding tools is also essential to understand the true semantics of the data at various processing stages.

Remediation strategies are centered on bolstering the validation and integrity checks within the Golang backend. Key measures include implementing strict input validation for all `calldata` components, rigorously enforcing "What You See Is What You Sign" (WYSIWYS) principles by ensuring simulated data is identical to signed data, performing comprehensive `calldata` decoding and semantic analysis, conducting thorough security audits, and adopting defense-in-depth strategies. Developer training on secure coding practices for blockchain applications is also paramount.

The Bybit hack serves as a stark real-world example of the underlying principles, where off-chain manipulation of transaction data before signing (albeit via JavaScript in that specific case) led to catastrophic losses of over $1.4 billion.**1** This incident underscores the critical need for robust `calldata` validation in *all* off-chain components, including those built with Golang, as they form an increasingly vital part of the blockchain ecosystem's security posture. The security of decentralized systems is no longer solely reliant on on-chain smart contract security but is deeply intertwined with the integrity and trustworthiness of the off-chain infrastructure that supports user interaction and transaction preparation. Golang, as a popular language for building such infrastructure, must be utilized with a heightened focus on validating external inputs and ensuring the fidelity of information presented to users, especially when significant financial assets or critical control functions are at stake.

## **References**

- **1** `https://www.nccgroup.com/us/research-blog/in-depth-technical-analysis-of-the-bybit-hack/`
- **4** `https://github.com/eth-infinitism/account-abstraction/releases`
- **15** `https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=encoding`
- **14** `https://github.com/ChainSafe/lodestar/security/advisories/GHSA-m9c9-mc2h-9wjw`
- **16** `https://socket.dev/blog/malicious-package-exploits-go-module-proxy-caching-for-persistence`
- **17** `https://arxiv.org/html/2503.09317v1`
- **11** `https://nvd.nist.gov/vuln/detail/CVE-2025-24883`
- **3** `https://www.cyfrin.io/blog/secure-dapps-against-ui-spoofing-part-1-decoding-transactions`
- **13** `https://www.kayssel.com/post/web3-5/`
- **7** `https://ethereum.stackexchange.com/questions/104206/about-geths-method-eth-call-and-simulating-state-changing-transactions`
- **3** `https://www.cyfrin.io/blog/secure-dapps-against-ui-spoofing-part-1-decoding-transactions`
- **8** `https://www.coinfabrik.com/blog/exploiting-eth_call-for-optimization-purposes/`
- **5** `https://www.fireblocks.com/blog/security-first-approach-to-eip-7702/`
- **2** `https://www.halborn.com/blog/post/bybit-hack-smart-contract-audits-wont-stop-off-chain-attacks`
- **12** `https://discuss.ens.domains/t/spp2-blockful-application/20463`
- **6** `https://mixbytes.io/blog/dao-voting-vulnerabilities`
- **18** `https://pkg.go.dev/github.com/getamis/go-ethereum`
- **19** `https://github.com/ethereum/go-ethereum/security/advisories/GHSA-9856-9gg9-qcmq`
- **20** `https://leftasexercise.com/2021/09/`
- **9** `https://github.com/ethereum/go-ethereum/releases`
- **10** `https://docs.arbitrum.io/how-arbitrum-works/gas-fees`
- **21** `https://op-geth.optimism.io/`
- **22** `https://github.com/getclave/suave-geth-ethglobal-istanbul`
- **23** `https://blog.openzeppelin.com/mantle-op-geth-audit`
- **24** `https://github.com/ethereum/solidity/issues/15483`
- **25** `https://www.certora.com/blog/certora-goes-open-source`
- **26** `https://docs.arbitrum.io/how-arbitrum-works/state-transition-function/modified-geth-on-arbitrum`
- **27** `https://www.reddit.com/r/ethstaker/comments/1aioe54/how_much_would_geth_validators_stand_to_lose_if/`
- **11** `https://nvd.nist.gov/vuln/detail/CVE-2025-24883` (and its sub-links: `https://www.kayssel.com/post/web3-5/`, `https://ethereum.stackexchange.com/questions/104206/about-geths-method-eth-call-and-simulating-state-changing-transactions`, `https://www.cyfrin.io/blog/secure-dapps-against-ui-spoofing-part-1-decoding-transactions`, `https://www.coinfabrik.com/blog/exploiting-eth_call-for-optimization-purposes/`, `https://www.fireblocks.com/blog/security-first-approach-to-eip-7702/`, `https://www.halborn.com/blog/post/bybit-hack-smart-contract-audits-wont-stop-off-chain-attacks`, `https://discuss.ens.domains/t/spp2-blockful-application/20463`, `https://mixbytes.io/blog/dao-voting-vulnerabilities`, `https://pkg.go.dev/github.com/getamis/go-ethereum`, `https://github.com/ethereum/go-ethereum/security/advisories/GHSA-9856-9gg9-qcmq`)
- **1** `https://www.nccgroup.com/us/research-blog/in-depth-technical-analysis-of-the-bybit-hack/`
    
- **4** `https://github.com/eth-infinitism/account-abstraction/releases`
    
- **28** `https://github.com/ethereum/go-ethereum/security/advisories/GHSA-q26p-9cq4-7fc2` (and its sub-links: `https://leftasexercise.com/2021/09/`, `https://github.com/ethereum/go-ethereum/releases`, `https://docs.arbitrum.io/how-arbitrum-works/gas-fees`, `https://op-geth.optimism.io/`, `https://github.com/getclave/suave-geth-ethglobal-istanbul`, `https://blog.openzeppelin.com/mantle-op-geth-audit`, `https://github.com/ethereum/solidity/issues/15483`, `https://www.certora.com/blog/certora-goes-open-source`, `https://docs.arbitrum.io/how-arbitrum-works/state-transition-function/modified-geth-on-arbitrum`, `https://www.reddit.com/r/ethstaker/comments/1aioe54/how_much_would_geth_validators_stand_to_lose_if/`)
- **29** `https://github.com/ethereum/go-ethereum/commit/fa9a2ff8687ec9efe57b4b9833d5590d20f8a83f` (Noted as inaccessible in source material)
- **19** `https://github.com/ethereum/go-ethereum/security/advisories/GHSA-9856-9gg9-qcmq`
    
**Note**: ⚠️

The breadth of these references, spanning specific hack analyses, protocol specifications, client implementation details, and general security advisories, indicates that a comprehensive understanding of off-chain `calldata` validation issues requires drawing knowledge from diverse areas within blockchain technology and security.