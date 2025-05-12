## **ABI Upgrade Mismatch: When Old Interfaces Meet New Logic**

### **Severity Rataing**

Medium 🟡

### **1. Description**

An "ABI Upgrade Mismatch" occurs when an off-chain application (like a dApp frontend or a backend service) or another on-chain smart contract tries to interact with an upgraded smart contract using an outdated Application Binary Interface (ABI). Smart contracts, especially those using proxy patterns for upgradeability, can change their underlying logic and, consequently, their interface (functions, parameters, events). If client applications are not updated with the new ABI, their attempts to call functions or interpret data will be based on old, incorrect definitions, leading to errors or unexpected behavior The ABI acts as the "how-to" guide for interacting with a contract; using an old guide with a new contract version is like trying to use an old map for a city that has since been rebuilt.

### **2. Technical Description (for security pros)**

This issue is prevalent in systems using proxy upgrade patterns (e.g., Transparent Proxy, UUPS) where a stable proxy address delegates calls to an evolving implementation contract. When the implementation contract is upgraded, its ABI—which defines function signatures (name, parameter types, order, count), return types, and event structures—may change.

Clients (dApps, backend services, other contracts) interact with the proxy address but must use the ABI of the *current* implementation contract. If a client uses an ABI from a *previous* implementation, the data it sends (calldata) will be encoded according to the old function signatures. When the proxy `DELEGATECALL`s to the new implementation, this calldata may:

- Not match any function selector in the new implementation.
- Match a function selector but provide parameters of incorrect types, count, or order.
- Lead to misinterpretation of return values or event data if their structures have changed.
    
This isn't a flaw in the ABI JSON format itself (like in `abi-json-unverified` ) but a desynchronization between the client's expected interface and the contract's actual interface.

### **3. Common Mistakes That Cause This**

- **Failure to Update Client-Side ABIs:** The most common mistake is neglecting to update ABIs in dApp frontends, backend services (e.g., Golang applications), or interacting smart contracts after a target contract upgrade.
    
- **Lack of ABI Versioning and Communication:** Not implementing a clear ABI versioning strategy or failing to communicate ABI changes effectively to all users and dependent developers.
    
- **Hardcoding Outdated ABIs:** Clients might hardcode ABIs which then become stale when the contract is upgraded.
- **Incorrect Proxy Interaction:** Misunderstanding that interactions with a proxy address require the ABI of the *current* logic contract, not the proxy's own ABI (which might only be for admin functions).
    
- **Insufficient Post-Upgrade Testing:** Failing to conduct thorough integration tests with all interacting components after an upgrade to catch ABI mismatches.
    
### **4. Exploitation Goals**

Direct exploitation for theft is less common than causing operational disruption. Goals include:

- **Denial of Service (DoS):** Causing legitimate user interactions or dependent contract calls to consistently fail, rendering parts of the application unusable.
    
- **Disruption of Service:** Making dApps or backend processes unreliable due to frequent transaction reverts or data decoding errors.

- **Data Integrity Issues (Less Common):** In rare cases where a call doesn't revert but is misinterpreted, it could lead to incorrect state changes or event logging if not carefully handled by the new contract logic.
- **Wasting User/System Gas:** Failed transactions due to ABI mismatches still consume gas.
    
### **5. Affected Components or Files**

- **Off-Chain Clients:**
    - **dApp Frontends (JavaScript/TypeScript):** User interfaces become non-functional, displaying errors or failing to send transactions.
        
    - **Backend Services (e.g., Golang):** Systems that automate contract interactions, index data, or provide APIs will experience errors during ABI packing, transaction submission, or data decoding.

    - **Wallets and Tooling:** Any tool interacting with the contract based on an old ABI.
- **On-Chain Components:**
    - **Interacting Smart Contracts:** Other contracts calling the upgraded contract can fail if their interfaces are not updated.
    - **Proxy Contracts:** While the proxy itself isn't vulnerable, its utility is undermined if clients cannot correctly interact with the underlying logic.
- **Data Integrity:** Off-chain databases or states derived from contract events can become corrupted or incomplete if events are misparsed due to an outdated ABI.
    
- **Specific Files:**
    - ABI JSON files bundled with client applications.
    - Generated contract wrapper code in languages like Go (e.g., files produced by `abigen`).
### **6. Vulnerable Code Snippet (Conceptual Golang Example)**

Imagine a TokenV1 contract with transfer(address to, uint256 amount).

A Golang backend uses this ABI.

`TokenV1` is upgraded to `TokenV2` with `transfer(address to, uint256 amount, uint256 fee)`. The Golang backend is *not* updated.

```go
package main

import (
	//... other imports
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	// Assume 'oldtokenabi' is the ABI string for TokenV1
	// Assume 'contractInstance' is bound using this oldtokenabi but points to TokenV2 address
)

// Outdated Go struct for TokenV1 transfer
type TransferArgsV1 struct {
    To     common.Address
    Amount *big.Int
}

func attemptTransfer(contract *bind.BoundContract, txOpts *bind.TransactOpts, recipient common.Address, transferAmount *big.Int) {
    // This call uses the V1 signature (2 arguments)
    // but the contract at contract.Address() is TokenV2 (expects 3 arguments for transfer)
    tx, err := contract.Transact(txOpts, "transfer", recipient, transferAmount) // [11]
    if err!= nil {
        // Likely error: transaction reverted, method not found, or ABI packing error
        // if go-ethereum detects mismatch with its loaded (old) ABI before sending.
        fmt.Printf("Transaction failed due to ABI mismatch: %v\n", err)
        return
    }
    fmt.Printf("Transaction potentially sent, but may revert on-chain: %s\n", tx.Hash().Hex())
}
```

In this scenario, `contract.Transact` would likely build calldata for a two-argument `transfer` function. When this hits the `TokenV2` contract (which expects three arguments for `transfer`), the EVM will not find a matching function signature, leading to a transaction revert.

### **7. Detection Steps**

- **Monitor Transaction Failures:** A surge in reverted transactions to a recently upgraded contract is a key indicator. Look for generic revert reasons or function selector mismatches.
    
- **Analyze Client-Side Logs:**
    - **dApp/Frontend:** Check browser console logs for errors during transaction creation or event processing.
    - **Backend (Golang):** Look for errors from `go-ethereum` related to ABI packing (e.g., "field... not found in the given struct" ), function calls, or event decoding.

    - Libraries like `web3.py` might emit `MismatchedABI` warnings for events.
- **Compare ABIs:** Manually or programmatically compare the ABI used by the client with the actual ABI of the current implementation contract (obtainable from compilation artifacts or verified source on explorers like Etherscan ).
    
- **Post-Upgrade Integration Testing:** Execute a comprehensive test suite covering all interactions with the upgraded contract. Failures here often point to ABI mismatches or other regressions.
    
### **8. Proof of Concept (PoC)**

1. **Setup:**
    - Deploy `ContractV1` with a function `doSomething(uint256 value)`.
    - Develop a client (e.g., Go script using `go-ethereum`) that successfully calls `doSomething` using `ContractV1`'s ABI.
2. **Upgrade:**
    - Deploy `ContractV2` where `doSomething` is changed to `doSomething(uint256 value, string memory note)`.
    - Upgrade the proxy to point to `ContractV2`.
3. **Attempt Interaction with Old ABI:**
    - Use the same client (with `ContractV1`'s ABI) to call `doSomething` on the proxy address (which now delegates to `ContractV2`).
4. **Expected Outcome:**
    - The transaction will fail/revert on-chain because the calldata (encoded for one `uint256` argument) does not match the signature of `doSomething(uint256, string)` in `ContractV2`.
    - The client application will receive an error indicating transaction failure.

### **9. Risk Classification**

- **CVSS v3.1 Score:** 6.5 (Medium) (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L`)
    - **Attack Vector: Network** (Interaction happens over the network)
    - **Attack Complexity: Low** (Relies on developers not updating ABIs)
    - **Privileges Required: None** (Any user/client can trigger it)
    - **User Interaction: None** (Automated systems can be affected)
    - **Scope: Unchanged** (Typically affects the direct interaction, not other systems' security context)
    - **Confidentiality: None**
    - **Integrity: Low** (Can lead to failed state changes or misinterpretation of data, but direct unauthorized modification is less common solely from this)
    - **Availability: Low** (Can make specific functions or dApps unusable, but not usually a full system DoS)
    *(CVSS score calculated using)*
- **Likelihood:** Medium to High, especially in rapidly evolving projects or ecosystems with many independent integrators.
- **Impact:** Low to Medium. Primarily operational disruption, user experience degradation, and wasted gas. Direct financial loss is less common unless combined with other vulnerabilities or extremely poor error handling in the new contract logic.

### **10. Fix & Patch Guidance**

- **Client-Side ABI Updates:** The primary fix is to ensure all client applications (dApps, backends, other contracts) are updated with the latest ABI of the implementation contract immediately after an upgrade.
    
- **ABI Versioning & Communication:**
    - Implement semantic versioning for ABIs.
        
    - Clearly communicate ABI changes, especially breaking ones, to all stakeholders well in advance.
        
- **Golang Specifics:**
    - Regenerate Go contract bindings using `abigen` with the new ABI.

    - Update Go struct definitions used for ABI packing/unpacking to match the new ABI.
        
    - Use `abi:"fieldName"` struct tags for explicit mapping to avoid ambiguity.
        
- **Automated Checks:** Incorporate ABI compatibility checks into CI/CD pipelines.
- **Thorough Testing:** Conduct extensive integration testing post-upgrade with all client types.


### **11. Scope and Impact**

- **Scope:** Affects any system or user interacting with an upgraded smart contract if their ABI knowledge is outdated. This includes dApp frontends, backend services, other smart contracts, and individual users employing scripts or tools.
    
- **Impact:**
    - **Functional:** Transactions fail, dApps become unusable or display incorrect data, automated processes break.
        
    - **Financial:** Wasted gas on reverted transactions. Potential (though less direct) for financial loss if misinterpreted data leads to flawed decisions in DeFi or other value-handling applications.
        
    - **Reputational:** Degraded user experience and loss of trust in the application or protocol.
        
    - **Data Integrity:** Off-chain databases relying on event data can become inconsistent if event ABIs change and are not updated on the client side.

### **12. Remediation Recommendation**

1. **Immediate Action:**
    - Halt interactions from clients known to be using outdated ABIs if causing significant issues.
    - Obtain the correct, current ABI for the upgraded contract.
    - Update all affected client applications (dApps, backends, scripts) with the new ABI. For Golang, this involves updating ABI files, regenerating bindings with `abigen`, and modifying struct definitions.
        
    - Communicate the issue and resolution to users.
2. **Preventative Measures:**
    - **Establish ABI Management Protocol:** Implement strict ABI versioning (e.g., SemVer ) and maintain an accessible ABI registry.
        
    - **Proactive Communication:** Announce planned ABI changes (especially breaking ones) well in advance to all developers and users in the ecosystem.
        
    - **Automated Testing:** Develop comprehensive integration test suites that run post-upgrade to verify ABI compatibility across all interacting components.
        
    - **Client-Side Best Practices:** Encourage client developers to subscribe to update channels and design their applications to handle potential ABI updates gracefully.
    - **Documentation:** Maintain clear documentation for all ABI versions and changes.

### **13. Summary**

ABI Upgrade Mismatch occurs when clients (dApps, backends, other contracts) use an outdated ABI to interact with a smart contract that has been upgraded, typically via a proxy pattern. This desynchronization leads to failed transactions, data misinterpretation, and operational disruptions because the client's understanding of the contract's functions and data structures no longer matches the actual on-chain implementation. The primary cause is the failure to update client-side ABIs after a contract upgrade. Remediation involves updating clients with the correct ABI, while prevention focuses on robust ABI versioning, clear communication of changes, and thorough post-upgrade testing.

### **14. References**

- `github.com/ethereum/go-ethereum/blob/master/accounts/abi/abi.go`
- `github.com/oceanprotocol/ocean.py/issues/348`
- `22x.to/posts/solidity-abi-packing-errors-in-go/`
- `22x.to/posts/solidity-abi-packing-errors-in-go/`
- `arxiv.org/pdf/2406.05712`
- `arxiv.org/pdf/2406.05712`
- `github.com/oceanprotocol/ocean.py/issues/348`
- `rustsec.org/advisories/RUSTSEC-2024-0362.html`
- `metana.io/blog/upgrade-bugs/`
- `github.com/rainbow-me/rainbow/blob/develop/CHANGELOG.md`
- `www.quicknode.com/guides/ethereum-development/smart-contracts/different-ways-to-verify-smart-contract-code`
- `metamask.io/news/understanding-how-to-write-upgradable-smart-contracts`
- `www.quicknode.com/guides/ethereum-development/smart-contracts/an-introduction-to-upgradeable-smart-contracts`
- `nvd.nist.gov/vuln-metrics/cvss/v3-calculator`
- `arxiv.org/html/2411.18935v2`
- `22x.to/posts/solidity-abi-packing-errors-in-go/`
- `www.quicknode.com/guides/ethereum-development/smart-contracts/what-is-an-abi`
- `www.cachefly.com/news/the-complexities-of-abi-and-api-in-software-development/`
- `ethereum.stackexchange.com/questions/234/what-is-an-abi-and-why-is-it-needed-to-interact-with-contracts`
- `josnif.hashnode.dev/understanding-abi-and-bytecode-in-ethereum-smart-contract-development-concepts-tools-and-best-practices`
- `www.cyfrin.io/blog/what-happens-when-a-smart-contract-reverts`
- `osl.com/academy/article/understanding-opportunities-and-limitations-of-dapps`
- `build.avax.network/docs/dapps/smart-contract-dev/interact-golang-app`
- `build.avax.network/docs/dapps/smart-contract-dev/interact-golang-app`
