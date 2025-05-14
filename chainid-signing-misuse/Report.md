# **Misused ChainID in Raw Transaction and Message Signing (chainid-signing-misuse)**

## **Severity Rating**

**Overall Severity: High🟠**

The misuse of `chainID` in raw transaction and off-chain message signing is classified as a high-severity vulnerability. This rating stems from its potential to directly facilitate unauthorized access to funds, enable illicit contract interactions, and significantly undermine the integrity of affected blockchain systems. While the likelihood of exploitation can vary depending on the specific context—such as whether it involves a public blockchain transaction versus a bespoke signature scheme within a decentralized application (dApp)—the potential impact is frequently critical.

The Common Vulnerability Scoring System (CVSS) provides a framework for assessing severity. Although no single CVE identifier with a published CVSS score directly corresponds to the general category of "chainid-signing-misuse," analogous vulnerabilities, particularly those enabling replay attacks that result in financial loss, consistently receive high CVSS scores. For instance, a successful replay attack leading to the theft of assets would align with high severity metrics (e.g., Confidentiality: None, Integrity: High, Availability: None, resulting in substantial financial loss). The CISA Vulnerability Bulletin defines high severity as vulnerabilities with a CVSS base score of 7.0–10.0.

Contextual factors can influence perceived severity. For example, a zkSync issue related to the non-enforcement of EIP-155 was debated, with its severity ultimately judged as Medium in that specific instance, though initial reports considered it High due to the potential for fund theft. This illustrates that while specific circumstances matter, the capacity for chainid-signing-misuse to lead to severe outcomes, especially financial theft, warrants a high-severity classification from a security research perspective. The core issue is that misuse of `chainID` primarily enables replay attacks. These attacks can lead to unauthorized fund transfers or contract interactions. The Bybit hack, a complex event, involved discussions surrounding EIP-155 and transaction validity across chains, underscoring the severe financial implications of failures in transaction security. Even if development libraries or client software permit the disabling of EIP-155 protections (e.g., by setting `chainId: 0` in ethers.js), doing so without a complete understanding and explicit, controlled intent—such as for specific CREATE2 deployment strategies —constitutes a high-risk action. Consequently, any misuse, whether accidental or due to a lack of awareness, that leads to the unintended replayability of value-bearing transactions or state-altering messages, is considered a high-severity vulnerability.

## **Description**

Misused ChainID in raw transaction and message signing, abbreviated as "chainid-signing-misuse," refers to a category of vulnerabilities where the `chainID` parameter is improperly handled during the signing process of Ethereum transactions or off-chain messages. The `chainID` is a critical component introduced by Ethereum Improvement Proposal 155 (EIP-155) primarily to prevent replay attacks.

This mishandling can manifest in several ways: omitting the `chainID` entirely, using an incorrect `chainID` value, or failing to validate the `chainID` within custom signature verification schemes implemented in smart contracts. The fundamental consequence of such misuse is the compromise of replay protection. A signed transaction or message, originally intended for a specific blockchain network or a particular contract interaction context, can be maliciously re-submitted and accepted on a different, unintended network. It can also be replayed in an unintended context on the same network if other protections like nonces are also improperly handled or bypassed in specific scenarios. This can lead to unauthorized actions, theft of funds, or corruption of contract state.

Essentially, this vulnerability negates the security benefits that EIP-155 was designed to provide, re-opening avenues for attackers to exploit signed messages across different blockchain environments or contexts where they were not intended to be valid.

## **Technical Description**

A thorough understanding of chainid-signing-misuse requires a detailed examination of EIP-155, the mechanics of transaction signing both before and after its introduction, and how failures in handling `chainID` lead to replay attacks.

### **The Role of EIP-155 and ChainID in Replay Protection**

EIP-155 was a pivotal enhancement to the Ethereum protocol, specifically designed to thwart replay attacks. These attacks became a significant concern, particularly after the hard fork that resulted in Ethereum (ETH) and Ethereum Classic (ETC). Since both chains initially shared a common history and transaction format, a transaction valid on one could be "replayed" on the other, leading to unintended consequences like double-spending or duplicated actions.

EIP-155 addresses this by incorporating a unique `chainID` into the transaction signing process. Key aspects of EIP-155 include:

1. **Inclusion in Signed Data:** For a transaction to be EIP-155 compliant, the `chainID` of the target network must be included in the data that is hashed and subsequently signed. Instead of hashing six RLP-encoded elements `(nonce, gasprice, startgas, to, value, data)`, EIP-155 specifies hashing nine elements: `(nonce, gasprice, startgas, to, value, data, chainid, 0, 0)`. The two zero values are placeholders for the `r` and `s` components of the signature itself, which are not known at the time of hashing the message for signing.
    
2. **Modification of the `v` Signature Value:** The `v` component of an ECDSA signature, which is used in public key recovery, is redefined to encode the `chainID`. The formula is v={0,1}+CHAIN_ID×2+35. For example, on Ethereum Mainnet (`chainID` 1), `v` would be 37 or 38. On the Ropsten testnet (`chainID` 3), `v` would be 41 or 42.
    
3. **Chain Specificity:** This mechanism ensures that a transaction signed for a specific chain is cryptographically bound to that chain. Attempting to submit an EIP-155 compliant transaction to a chain with a different `chainID` will result in an invalid signature because the `chainID` used for verification by the receiving chain's nodes will not match the `chainID` encoded in the transaction's `v` value and used in the original signature hash computation.
    
The introduction of EIP-155 was a crucial step in enhancing the security of the Ethereum ecosystem by making transaction validity explicitly dependent on the intended chain. The official specification for EIP-155 can be found at `https://eips.ethereum.org/EIPS/eip-155`.

### **Transaction Signing Mechanics: Legacy (Pre-EIP-155) vs. EIP-155**

The introduction of EIP-155 marked a significant shift in how Ethereum transactions are structured and signed.

- **Legacy Transactions (Pre-EIP-155):**
    - **Signed Data:** The data hashed for signing consisted of six RLP-encoded elements: `(nonce, gasprice, startgas, to, value, data)`.
    - **`v` Value:** The `v` value was typically 27 or 28.
    - **Replayability:** These transactions lacked inherent chain-specificity. If an account had a sufficient balance and the same nonce was valid on multiple chains, a legacy transaction could be replayed across those chains. While most modern networks and clients discourage or disallow legacy transactions by default, some specialized use cases, like deploying singleton factory contracts deterministically across chains, sometimes still leverage pre-EIP-155 transaction characteristics.
        
- **EIP-155 Compliant Transactions:**
    - **Signed Data:** The data hashed for signing includes nine RLP-encoded elements: `(nonce, gasprice, startgas, to, value, data, chainid, 0, 0)`.
        
    - **`v` Value:** Calculated as v={0,1}+CHAIN_ID×2+35.
    - **Replay Protection:** Provides strong replay protection across chains with differing `chainID`s.

The following table summarizes the key differences:

**Table 1: EIP-155 vs. Pre-EIP-155 (Legacy) Transaction Signing**

| **Feature** | **Pre-EIP-155 (Legacy)** | **EIP-155 Compliant** |
| --- | --- | --- |
| Signed Data Elements | `(nonce, gasprice, startgas, to, value, data)` | `(nonce, gasprice, startgas, to, value, data, chainid, 0, 0)` |
| `v` Value Calculation | 27 or 28 | {0,1}+CHAIN_ID×2+35 |
| Replay Protection | None (vulnerable to cross-chain replay) | Strong (prevents cross-chain replay on differing `chainID`s) |
| Chain Specificity | Low (transaction is chain-agnostic) | High (transaction is bound to a specific `chainID`) |
| Common Use Cases | Original Ethereum transactions; some niche `CREATE2` deployments | Standard for most modern Ethereum transactions |

This change in the fundamental structure of what is being signed makes the signature itself intrinsically tied to a specific chain. However, the continued (though often restricted) validity or acceptance of legacy transactions by some clients or for specific purposes means that if a system is configured to accept them, the risk of replay for those specific transaction types persists if the `chainID` was the only differentiating factor.

### **Mechanics of Replay Attacks Enabled by ChainID Misuse**

ChainID misuse can lead to replay attacks in several ways:

- Cross-Chain Replay of Raw Transactions:
    
    This is the classic replay attack that EIP-155 was designed to prevent. If a transaction is signed in the legacy format (without a chainID) or if it's signed with a chainID of 0 (which some libraries interpret as disabling EIP-155 protections 6), it becomes vulnerable. An attacker can capture such a transaction broadcast on Chain A and then re-broadcast it on Chain B. If the sender's account has a sufficient balance and the transaction's nonce is valid on Chain B, the transaction will be executed, leading to unintended fund transfers or contract interactions.3 The discussions surrounding the Bybit hack, for instance, touched upon the possibility of transactions being valid on multiple chains due to the intentional deployment of a "singleton contract" without EIP-155 for cross-chain compatibility, highlighting the security considerations even for deliberate omissions.5
    
- Intra-Chain and Cross-Chain Replay of Smart Contract Signatures:
    
    Many dApps utilize off-chain signed messages for operations like gasless approvals (e.g., ERC20 permit), voting, or meta-transactions. EIP-712 is a standard for typed structured data hashing and signing, which includes a domain separator typically containing the chainID. However, custom signature schemes are also common.
    
    If these custom schemes, or even EIP-712 implementations, fail to correctly incorporate the block.chainid (the current chain's ID, accessible via the CHAINID opcode in Solidity) into the message hash that the user signs, the resulting signature becomes replayable. An attacker could take a signature generated for an interaction with Contract X on Chain A and replay it against an instance of Contract X on Chain B (if deployed at the same address or if the contract logic doesn't otherwise prevent it).9 This is particularly dangerous for contracts deployed deterministically to the same address across multiple chains. An audit finding for the Boost Protocol highlighted a SignerValidator.sol contract where the chainId was missing from the signature hashing process, making signatures replayable across chains.21 This demonstrates that the vulnerability extends beyond simple EOA transactions and deeply impacts smart contract security when off-chain signing is employed. The fundamental principle is that the "context" of a signature, including the specific chain it is intended for, must be cryptographically bound to the signature itself.
    

### **Role of `v, r, s` Components and `chainID` Encoding in `v`**

In ECDSA signatures used by Ethereum:

- `r` and `s` are the two main components of the signature, derived from the cryptographic process.
    
- `v` is a recovery identifier. It helps in recovering the public key (and thus the sender's address) from the signature and the message hash. For pre-EIP-155 transactions, `v` was 27 or 28.
- With EIP-155, `v` takes on an additional role: encoding the `chainID`, as per the formula v=parity+CHAIN_ID×2+35, where parity is 0 or 1. This encoding is crucial. If `v` is calculated or interpreted incorrectly, signature validation will fail. More importantly, if a system attempts to validate an EIP-155 signature but ignores the `chainID` encoded within `v` (or if it accepts legacy `v` values without further chain checks), it opens the door to replay attacks. Other ecosystems building on EVM concepts, like Filecoin, have developed sophisticated mechanisms to distinguish between Homestead (legacy, V=27/28) and EIP-155 transactions by analyzing the `V` value in relation to the `ChainID`, sometimes even prepending marker bytes to signatures for clarity in their network protocols. This underscores the importance of robust `v` value handling for chain-specific transaction validation.

## **Common Mistakes That Cause This Vulnerability**

Several common mistakes during development and deployment can lead to chainid-signing-misuse vulnerabilities:

1. Omitting chainID During Transaction Signing:
    
    Developers might inadvertently use older libraries or transaction construction methods that do not enforce EIP-155 by default. In some modern libraries, explicitly setting chainID to 0 or null can disable EIP-155 protections, often with warnings about the associated dangers.6 This might be done for perceived cross-chain compatibility or during testing, without fully understanding the replay risks if such transactions are broadcast to a network that might process them. Some node configurations or RPC providers may still accept non-EIP-155 transactions, creating an avenue for replay if such transactions are crafted and submitted.7 For instance, Geth has historically provided options like --rpc.allow-unprotected-txs which, if enabled, would allow nodes to accept these replayable transactions.8
    
2. Using an Incorrect chainID Value:
    
    Hardcoding an incorrect chainID or fetching it from an unreliable or compromised source can render a transaction invalid on the intended chain or, worse, valid on an unintended chain if the incorrect chainID matches another network's ID.
    
3. Flawed chainID Validation in Smart Contract Signature Schemes (Off-Chain Signatures):
    
    This is a frequent error in custom smart contract development. When contracts verify signatures for off-chain messages (e.g., meta-transactions, permit functions, or custom authorization schemes), failing to include block.chainid in the EIP-712 domain separator or within the custom signed message hash is a critical oversight.9 This omission makes the signature replayable across different chains where the same contract logic is deployed, as the signature remains valid irrespective of the chain context. The SignerValidator.sol example from an audit finding is a direct illustration of this mistake.21
    
4. Issues with Wallet Software, Libraries, or Tools Not Enforcing EIP-155 Correctly:
    
    Older, unmaintained, or poorly implemented transaction signing libraries might contain bugs in their EIP-155 handling. For example, older versions of ethereumjs-tx were noted to have edge cases where Type 0x00 legacy transactions (with v=27 or v=28 and no chainId present) were not handled correctly according to EIP-155 principles.23 Users relying on tools that offer excessive flexibility without adequate warnings (e.g., easily signing legacy transactions without emphasizing the risks) can also be exposed.
    
5. Misunderstanding of Transaction Types and Intentional Replayability:
    
    There are legitimate, albeit niche, use cases for replayable transactions, such as deterministic contract deployments across multiple chains using the CREATE2 opcode, often involving pre-EIP-155 style transactions or specific chainID handling.7 However, if these intentionally replayable transactions or their signatures are mishandled or exposed, they can lead to unintended replays. The debate around allowing chainId: 0 for keyless contract deployment highlights this tension: what is a feature in one very specific context becomes a severe vulnerability in most others.8
    

A significant underlying factor in many of these mistakes is the incorrect assumption that a signature is inherently and uniquely tied to its first context of use. Without explicit cryptographic binding to the specific chain (achieved by including the `chainID` in the signed hash), this assumption is dangerously false. Developers might focus on the primary functionality of getting a transaction or message signed and executed, potentially overlooking the nuanced security implications of parameters like `chainID`, especially when dealing with multi-chain environments or custom off-chain signature schemes. The ease of deploying identical smart contract code across multiple EVM chains further amplifies this risk if chain-specificity is not enforced in signed messages.

## **Exploitation Goals**

Attackers exploit chainid-signing-misuse vulnerabilities with several objectives, primarily centered around unauthorized value extraction or state manipulation:

1. Cross-Chain Replay for Unauthorized Fund Transfers:
    
    The most direct goal is financial theft. An attacker captures a transaction signed without EIP-155 protection (or with a chainID that allows replay, like 0 in some contexts) on an originating chain (Chain A). They then re-broadcast this identical signed transaction on a different target chain (Chain B) where the victim also possesses funds and the transaction nonce aligns. If Chain B processes the transaction, funds are transferred from the victim's account to the attacker's account on Chain B, without the victim's explicit consent for that specific chain.3 The Bybit hack, while multifaceted, included discussions about identical transaction hashes on Ethereum and Base, raising concerns about potential cross-chain replay scenarios, even if the specific instance was attributed to an intentional non-EIP-155 deployment of a singleton contract.5
    
2. Cross-Chain Replay for Unauthorized Smart Contract Interactions/State Changes:
    
    Beyond direct fund transfers, attackers can replay transactions that interact with smart contracts. If a transaction calling a specific function (e.g., approve, mint, claimReward) is replayed on an unintended chain, it can lead to unauthorized token approvals, illicit minting of assets, fraudulent reward claims, or other detrimental state changes within the contract on the target chain.4
    
3. Intra-Chain and Cross-Chain Replay of Signatures for Smart Contract Exploitation:
    
    This is particularly relevant for dApps using off-chain signed messages. An attacker might obtain a signature for a specific action on a smart contract (e.g., an ERC20 permit approval, a vote in a DAO, a withdrawal authorization). If the contract's signature verification logic does not incorporate block.chainid (making the signature chain-agnostic relative to that contract's deployments), the attacker can replay this signature:
    
    - **Cross-Chain:** On another chain where the same contract (or a similarly vulnerable one) is deployed. A notable example is replaying a signature obtained on a low-cost chain to claim rewards or execute actions on a high-value chain.

        
    - **Intra-Chain (Contextual Replay):** In some complex systems, even if `chainID` is present, other contextual elements might be missing from the signature, allowing replay in different parts of the same application if not properly managed with nonces or other unique identifiers. Users often express concern about attackers storing signed messages (like ERC20 permits) off-chain and using them opportunistically when the user acquires tokens. If these signatures lack chain-specificity, the risk is magnified across multiple chains.
        
4. Nonce Mismanagement Combined with Lack of ChainID:
    
    While nonces primarily prevent same-chain replay of identical transactions from the same EOA, if chainID is also missing, an attacker might find opportunities to replay a transaction on a different chain where the nonce sequence for the victim's account happens to align, especially if the victim uses their account infrequently on the target chain.
    
5. Exploiting User Deception (Phishing):
    
    Attackers can create phishing websites that trick users into signing messages. If these messages are crafted as legacy transactions or messages lacking chainID protection, the attacker can then take these "chain-agnostic" signatures and replay them on a target chain where the victim holds assets.24
    

The following table outlines common exploitation scenarios:

**Table 2: ChainID Misuse Scenarios and Impacts**

| **Scenario** | **Description of Misuse** | **Potential Impact** |
| --- | --- | --- |
| Cross-Chain Raw Transaction Replay (Legacy/`chainID:0` Tx) | Transaction signed without EIP-155 protection or with `chainID:0` is re-broadcast on an unintended chain. | Unauthorized fund transfer from victim's account on the target chain; unintended contract interaction. |
| Cross-Chain Smart Contract Message Replay (Missing `chainID` in hash) | Off-chain signed message for a smart contract lacks `block.chainid` in its digest, replayed on another chain. | Unauthorized actions (e.g., token claims, votes, approvals) on the target chain's contract instance. |
| Intentional Replayable Deployment (e.g., `CREATE2`) - Mismanagement | Signature for a deterministically deployed contract (often using legacy tx features) is leaked or misused. | Attacker might front-run deployment or exploit related functionalities if the deployment process is not secure. |

The proliferation of Layer 2 solutions and sidechains significantly expands the attack surface for these vulnerabilities. If `chainID` is not handled with rigorous attention to detail, the ease of deploying identical contract logic across multiple EVM environments creates more opportunities for attackers to find and exploit replay vulnerabilities. The attacker's goal is often to find a context where replaying a transaction or signed message is economically beneficial, such as when a victim has assets on multiple chains or when a legitimate action on a low-cost chain can be replayed for a higher-value outcome on another.

## **Affected Components or Files**

The chainid-signing-misuse vulnerability can manifest in various components across the Ethereum ecosystem:

1. Ethereum Clients (e.g., Geth, Nethermind, Erigon, Besu):
    
    Client software is responsible for validating incoming transactions against network consensus rules, including EIP-155 compliance. While modern clients typically enforce EIP-155 by default, some offer configuration options that can relax these rules, potentially allowing non-EIP-155 transactions (e.g., Geth's --rpc.allow-unprotected-txs flag, which has been discussed in contexts like enabling keyless deployment strategies).8 If a client is misconfigured or has a bug in its EIP-155 validation logic, it could become a vector for processing replayed transactions.3 Node peering also relies on matching genesis files, which include the chainID, to ensure nodes are part of the correct network.25
    
2. Wallet Software (Hardware and Software):
    
    Wallets are at the forefront of transaction creation and signing. They bear a significant responsibility for correctly implementing EIP-155. If a wallet:
    
    - Allows users to easily sign legacy (non-EIP-155) transactions without adequate warnings.
    - Uses an incorrect `chainID` for the connected network.
    - Has flaws in its EIP-155 implementation.
    it can expose its users to replay attacks. The user interface and how transaction details (including the network) are presented are also critical, as highlighted by discussions around the Bybit hack where UI manipulation of a multisig wallet was a concern. The handling of `chainID` in ERC-4337 UserOperations by wallets is also crucial to prevent replay attacks in account abstraction scenarios.
        
3. Transaction Signing Libraries:
    
    Developers rely heavily on libraries to handle the complexities of Ethereum transaction signing. Flaws or misuse of these libraries can lead to vulnerabilities:
    
    - **Go-ethereum (`go-ethereum/core/types`, `go-ethereum/accounts`):** Functions like `LatestSignerForChainID` demonstrate how `chainID` is used to select the appropriate signer. If `chainID` is `nil`, it defaults to the `HomesteadSigner` (legacy), indicating a path for non-EIP-155 signing if not handled carefully by the calling application.
        
    - **Web3.py (Python):** This library supports `chain_id` in transaction parameters. However, older discussions or specific edge cases have noted potential misalignments with EIP-155 for legacy transactions if `v=27/28` was used without an explicit `chainId`.
        
    - **Ethers.js (JavaScript):** Documentation explicitly states that if `chainId` is set to 0, EIP-155 is disabled. This feature, if misused, can lead to the creation of replayable transactions.
        
    - **EthereumJS (`@ethereumjs/tx`, older `ethereumjs-tx`):** These libraries are fundamental for transaction handling in the JavaScript ecosystem. Later versions default to EIP-155, but older versions or specific configurations could allow for non-EIP-155 behavior, for instance, by setting an older hardfork as the context.
        
4. Smart Contracts with Custom Signature Verification:
    
    Contracts employing ecrecover for verifying signatures of off-chain messages (e.g., for meta-transactions, permit functions, voting mechanisms, or conditional claims) are a major affected component. If the signed message hash does not include block.chainid, the signature becomes replayable on other chains where the contract is identically deployed.4
    
5. Transaction Construction and Broadcasting Tools/Services:
    
    Any intermediary tool, script, or service that assists in constructing raw transactions or broadcasting them to the network must correctly handle chainID. This includes multi-chain explorers, dashboards, or custom backend systems that interact with Ethereum nodes. RPC providers may also have differing policies on accepting or rejecting non-EIP-155 transactions.8
    

The vulnerability's reach across these diverse components underscores its systemic nature. A weakness or misconfiguration in any part of the transaction lifecycle—from dApp-level logic and library usage to wallet implementation and node policy—can create an exploitable condition. This necessitates a holistic security approach, where each component correctly implements and enforces chain-specificity.

## **Vulnerable Code Snippet**

Understanding how chainid-signing-misuse manifests in code is crucial for both detection and prevention.

**Example 1: Client-Side Signing Potentially Leading to Replay (Conceptual using ethers.js)**

The following JavaScript snippet demonstrates how a transaction might be signed in a way that could be replayed if the `chainId` is omitted or explicitly set to 0. While `ethers.js` itself is not vulnerable, it provides functionality that, if misused, can lead to the creation of transactions susceptible to replay on networks that might accept them.

```JavaScript

// Based on ethers.js documentation [6]
// which states that chainId: 0 disables EIP-155 protection.

// Assume 'wallet' is an initialized ethers.Wallet instance
// Assume 'attackerAddress' and other parameters are defined

async function createPotentiallyReplayableTransaction(wallet, toAddress, valueInEther, nonce, gasPrice, gasLimit) {
  const tx = {
    nonce: nonce,
    gasPrice: gasPrice,
    gasLimit: gasLimit,
    to: toAddress,
    value: ethers.utils.parseEther(valueInEther.toString()),
    data: '0x',
    chainId: 0 // Explicitly disabling EIP-155. This is dangerous.
  };

  // const signedTx = await wallet.signTransaction(tx);
  // console.log("Signed Transaction (potentially replayable):", signedTx);

  // Broadcasting this signedTx could lead to a replay on another chain
  // if that chain accepts non-EIP-155 transactions or, hypothetically,
  // also operates with chainId 0 (which is not typical for public mainnets).
  // The primary risk is replay on networks that don't strictly enforce EIP-155.
  return tx; // Returning unsigned for conceptual illustration
}
```

Explanation:

In this snippet, chainId: 0 is used when defining the transaction object tx. According to ethers.js documentation 6, this disables EIP-155 replay protection for the signed transaction. If such a transaction were signed and broadcast, it would lack the chain-specific safeguards of EIP-155. An attacker could potentially take this signed transaction and attempt to replay it on a different EVM chain. The success of the replay would depend on whether the target chain's nodes accept transactions without EIP-155 protection and whether other conditions (like the account's nonce and balance on the target chain) align. The danger lies in creating a transaction that is not cryptographically bound to a specific chain.

**Example 2: Smart Contract Function Vulnerable to Signature Replay Due to Missing `chainID` Validation**

This Solidity snippet, adapted from audit findings and examples, illustrates a common vulnerability in smart contracts that verify off-chain signatures.

```Solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract VulnerableSignerValidator {
    address public immutable owner;
    // Nonce mechanism to prevent replay on the *same* chain for the same parameters
    mapping(bytes32 => bool) public usedActionHashes;

    event IncentiveClaimed(address indexed claimant, uint256 boostId, uint8 quantity);

    constructor(address _owner) {
        owner = _owner;
    }

    // Vulnerable: Does not include block.chainid in the hash generation.
    // A signature for this hash could be replayed on another chain
    // where this contract is deployed with the same owner.
    function getActionHash(
        uint256 boostId,
        uint8 incentiveQuantity,
        address claimant,
        bytes memory incentiveData
    ) public pure returns (bytes32) {
        // CRITICAL FLAW: block.chainid is missing from the packed data.
        return keccak256(abi.encodePacked(boostId, incentiveQuantity, claimant, keccak256(incentiveData)));
    }

    function claimIncentive(
        uint256 boostId,
        uint8 incentiveQuantity,
        address claimant,
        bytes calldata incentiveData, // Using calldata for external calls
        bytes memory signature
    ) external {
        bytes32 actionHash = getActionHash(boostId, incentiveQuantity, claimant, incentiveData);
        
        // ECDSA.toEthSignedMessageHash is important for compatibility with common signing methods (e.g., web3.eth.sign)
        bytes32 signedHash = ECDSA.toEthSignedMessageHash(actionHash);

        address signer = ECDSA.recover(signedHash, signature);
        require(signer == owner, "VulnerableSignerValidator: Invalid signer");
        require(signer!= address(0), "VulnerableSignerValidator: Zero address signer");
        require(!usedActionHashes[actionHash], "VulnerableSignerValidator: Signature already used on this chain");

        usedActionHashes[actionHash] = true; // Marks as used on the current chain

        //... (logic to grant incentive)
        emit IncentiveClaimed(claimant, boostId, incentiveQuantity);
    }
}
```

Explanation:

The VulnerableSignerValidator contract allows an owner to authorize actions (e.g., claiming incentives) by signing a message off-chain. The getActionHash function constructs the hash of the data to be signed. Critically, this function uses abi.encodePacked with various parameters but omits block.chainid. Consequently, the actionHash (and thus a valid signature for it) is identical across all chains where this contract might be deployed with the same owner.

An attacker could:

1. Have the `owner` sign a message for an action on Chain A (e.g., a testnet or a low-cost L2).
2. Take that signature and the corresponding parameters.
3. Call `claimIncentive` on an instance of this contract on Chain B (e.g., Ethereum Mainnet).
Since the `actionHash` calculated on Chain B would be the same, and the signature is valid for that hash, the `ECDSA.recover` call would succeed. The `usedActionHashes` mapping only prevents replay of the *exact same `actionHash` on the current chain*; it offers no protection against cross-chain replay because the `actionHash` itself is not chain-specific. This allows the attacker to illegitimately claim incentives or trigger actions on Chain B using a signature intended for Chain A.

These examples illustrate that the vulnerability can stem from client-side transaction construction choices or from flaws in on-chain signature verification logic within smart contracts.

## **Detection Steps**

Detecting chainid-signing-misuse vulnerabilities requires a combination of code auditing, tooling, and testing methodologies:

1. **Auditing Transaction Signing Logic (Client-Side):**
    - **Code Review:** Scrutinize all client-side code (JavaScript, Python, Go, etc.) responsible for constructing and signing Ethereum transactions. Verify that a valid, current `chainID` for the target network is consistently included in the transaction parameters *before* signing.
    - **Library Usage Verification:** Confirm that the Ethereum interaction libraries being used (e.g., ethers.js, web3.py, go-ethereum) are correctly implementing EIP-155. Check library documentation and, if necessary, source code to understand how `chainID` is handled. Pay special attention to default behaviors and options that might disable EIP-155.
    - **Identify Explicit EIP-155 Disabling:** Look for instances where EIP-155 might be explicitly disabled, such as setting `chainId: 0` in ethers.js. Ensure such instances are intentional, well-understood, and safe for the specific, narrow use case (e.g., certain `CREATE2` factory deployments), and not a general practice.

2. **Reviewing Smart Contract Signature Verification Code:**
    - **Manual Inspection:** Carefully examine any smart contract functions that use `ecrecover` or similar signature recovery mechanisms (e.g., OpenZeppelin's ECDSA library).
    - **`block.chainid` Inclusion Check:** The most critical step is to confirm that `block.chainid` (accessible in Solidity via the `CHAINID` opcode) is incorporated into the data that is hashed and subsequently signed by the user. This applies to EIP-712 domain separators and custom message digests created with `abi.encodePacked` or `keccak256`.
        
    - **Nonce Implementation:** Alongside `chainID` for cross-chain replay protection, ensure robust nonces (or other unique identifiers like commitment hashes) are used to prevent replay of the same signature on the *same* chain.
3. **Utilizing Static and Dynamic Analysis Tools:**
    - **Smart Contract Analyzers:** Employ static analysis tools like Slither, Mythril, Securify, and formal verification tools like Certora Prover. These tools may have built-in detectors for common signature-related vulnerabilities, including missing `chainID` in signed messages or improper use of `ecrecover`.
        
    - **Client-Side Linters/Scanners:** For client-side code, custom linters or scripts can be developed to search for patterns indicative of `chainID` misuse in popular Ethereum libraries (e.g., flagging uses of `chainId: 0`).
4. **Network Monitoring and Transaction Analysis:**
    - **`v` Value Analysis:** Monitor on-chain transactions and analyze their `v` signature components. Values of 27 or 28 typically indicate legacy (non-EIP-155) transactions. While these might be permissible if a network configuration allows them, they warrant closer inspection for potential replayability. The logic described in Filecoin's FIP-0091 for distinguishing Homestead from EIP-155 transactions based on `V` and `ChainID` can be adapted for detection tools.

    - **Cross-Referencing Transactions:** Tools can be developed to identify transactions with identical hashes or signature components across different EVM chains, which could indicate a replay attack or a misconfigured replayable deployment.
5. **Targeted Multi-Chain Testing:**
    - If smart contracts or systems are designed for multi-chain deployment, actively test for replay vulnerabilities. Generate a valid signature for an action on Chain A and attempt to use that same signature to perform the action on Chain B (and vice-versa). This provides direct empirical evidence of whether the `chainID` is being correctly validated.

A comprehensive detection strategy involves diligence at multiple stages. It requires verifying that the `chainID` is correctly included at the point of signature creation and rigorously validated at the point of signature verification, whether by an Ethereum client for on-chain transactions or by a smart contract for off-chain messages.

## **Proof of Concept (PoC)**

The following Proofs of Concept illustrate how chainid-signing-misuse can be exploited.

**PoC 1: Cross-Chain Raw Transaction Replay (Simulated Legacy Transaction)**

This PoC demonstrates the fundamental risk of transactions not protected by EIP-155.

1. **Setup:**
    - **Chain A:** An EVM-compatible testnet (e.g., Sepolia, `chainID` 11155111).
    - **Chain B:** A local development EVM chain (e.g., Anvil/Hardhat node) configured to accept non-EIP-155 transactions, or for demonstration, a chain with a different `chainID` where a non-EIP-155 transaction might be processed if submitted.
    - **Victim:** An Externally Owned Account (EOA) with a known private key, possessing funds (e.g., test ETH) on both Chain A and Chain B.
    - **Attacker:** An EOA to receive funds.
2. Transaction Crafting & Signing (Simulating Victim's Action on Chain A without EIP-155):
    
    The attacker needs to craft a transaction that appears to be from the victim but is signed without EIP-155 protection. This typically involves using a library or tool that allows specifying transaction parameters such that the chainID is omitted from the signing hash, or v is set to 27/28. For this conceptual PoC, we'll use ethers.js and set chainId: 0 to represent a transaction lacking EIP-155 chain-specificity.6
    
    ```JavaScript
    
    // Victim's private key (for demonstration only - NEVER use real private keys like this)
    const victimPrivateKey = '0xYourVictimPrivateKey'; // Replace with a test private key
    const attackerAddress = '0xAttackerAddress'; // Replace with attacker's address
    
    // Connect to Chain A (e.g., Sepolia)
    const providerA = new ethers.providers.JsonRpcProvider('YOUR_SEPOLIA_RPC_URL');
    const victimWalletA = new ethers.Wallet(victimPrivateKey, providerA);
    
    // Craft a transaction for Chain A, but sign it as if it's chain-agnostic (chainId: 0)
    const nonceOnA = await victimWalletA.getTransactionCount();
    const txToSign = {
        nonce: nonceOnA,
        gasPrice: ethers.utils.parseUnits('10', 'gwei'), // Example gas price
        gasLimit: 21000,
        to: attackerAddress,
        value: ethers.utils.parseEther('0.01'), // Amount to transfer
        chainId: 0 // Key: Disables EIP-155 protection
    };
    
    const signedTxHexString = await victimWalletA.signTransaction(txToSign);
    console.log(`Signed transaction (Chain A, chainId:0): ${signedTxHexString}`);
    // This transaction, if broadcast to Chain A, would likely be rejected by modern nodes
    // unless they are specifically configured to accept non-EIP-155 transactions.
    // For this PoC, we assume it *could* be processed or the signature is obtained by other means.
    ```
    
3. Hypothetical Execution on Chain A:
    
    If signedTxHexString were broadcast to Chain A and Chain A accepted such transactions, it would transfer 0.01 ETH from the victim to the attacker on Chain A.
    
4. Replay on Chain B (Attacker):
    
    The attacker takes the exact same signedTxHexString.
    
    ```JavaScript
    
    // Connect to Chain B (e.g., local devnet configured to accept non-EIP-155)
    const providerB = new ethers.providers.JsonRpcProvider('YOUR_LOCAL_DEVNET_RPC_URL');
    // const victimWalletB = new ethers.Wallet(victimPrivateKey, providerB); // Not needed for broadcast
    
    // Attacker broadcasts the SAME signed transaction to Chain B
    try {
        const txResponseB = await providerB.sendTransaction(signedTxHexString);
        console.log(`Transaction replayed on Chain B: ${txResponseB.hash}`);
        await txResponseB.wait();
        console.log('Replay transaction confirmed on Chain B.');
        // Check victim's and attacker's balance on Chain B
    } catch (error) {
        console.error('Error replaying transaction on Chain B:', error.message);
        // This might fail if Chain B strictly enforces EIP-155 or if nonce/balance is off.
    }
    ```
    
    If Chain B's nodes accept non-EIP-155 transactions (or transactions signed with `chainId: 0`), the victim's nonce on Chain B matches `nonceOnA` (e.g., if it's the victim's first transaction on Chain B), and the victim has at least 0.01 ETH on Chain B, the transaction will execute. The attacker receives 0.01 ETH from the victim on Chain B as well. This demonstrates the core risk of transactions not being cryptographically tied to a specific chain.
    

**PoC 2: Smart Contract Signature Replay (Cross-Chain)**

This PoC uses the `VulnerableSignerValidator` contract from Section 8, based on findings like.

1. **Setup:**
    - Deploy the `VulnerableSignerValidator` contract (from Section 8) to two EVM chains:
        - **Chain A (e.g., Polygon Mumbai testnet, `chainID` 80001)** - the "cheaper" chain.
        - **Chain B (e.g., Ethereum Sepolia testnet, `chainID` 11155111)** - the "target" chain.
    - The `owner` of the contract is the same EOA address on both chains. Let this be `ownerWallet`.
    - Attacker has an address (`attackerClaimantAddress`).
2. Legitimate Action & Signature Generation (Owner on Chain A):
    
    The ownerWallet intends to authorize attackerClaimantAddress to claim an incentive on Chain A.
    
    ```JavaScript
    
    // Using ethers.js for owner to sign the message for Chain A's contract
    // ownerWallet is an ethers.Wallet instance for the contract owner
    
    const boostId = 1;
    const incentiveQuantity = 10;
    const incentiveData = ethers.utils.toUtf8Bytes("TestIncentive"); // Example data
    
    // Connect to VulnerableSignerValidator on Chain A
    // const contractAddressA = 'ADDRESS_OF_CONTRACT_ON_CHAIN_A';
    // const contractA = new ethers.Contract(contractAddressA, VulnerableSignerValidator_ABI, ownerWallet.provider);
    
    // Owner computes the actionHash (as the contract would, but locally)
    // Note: This is simplified. In a real scenario, the contract's getActionHash pure function could be called via eth_call
    // or the hash constructed client-side identically to the contract's logic.
    const actionHashChainA = ethers.utils.solidityKeccak256(
        ["uint256", "uint8", "address", "bytes32"],
    
    );
    // This hash is MISSING chainId
    
    const ethSignedMessageHashA = ethers.utils.hashMessage(ethers.utils.arrayify(actionHashChainA)); // Simulates toEthSignedMessageHash
    const signatureFromOwner = await ownerWallet.signMessage(ethers.utils.arrayify(actionHashChainA)); // Sign the raw actionHash
    
    console.log(`Signature from owner for Chain A action: ${signatureFromOwner}`);`
    
3. Claim on Chain A (Attacker):
    
    The attacker uses this signatureFromOwner to call claimIncentive on Chain A's contract instance. This is a legitimate claim on Chain A.
    
    ```JavaScript
    
    // Attacker (using a wallet connected to Chain A) calls claimIncentive
    // const attackerWalletA = new ethers.Wallet(attackerPrivateKey, providerA);
    // const contractInstanceA_Attacker = new ethers.Contract(contractAddressA, VulnerableSignerValidator_ABI, attackerWalletA);
    // const txA = await contractInstanceA_Attacker.claimIncentive(
    //     boostId, incentiveQuantity, attackerClaimantAddress, incentiveData, signatureFromOwner
    // );
    // await txA.wait();
    // console.log("Incentive claimed on Chain A successfully.");`
    
4. Replay on Chain B (Attacker):
    
    The attacker takes the exact same signatureFromOwner and parameters. They now target Chain B's contract instance.
    
    ```JavaScript
    
    // Attacker (using a wallet connected to Chain B) calls claimIncentive
    // const contractAddressB = 'ADDRESS_OF_CONTRACT_ON_CHAIN_B';
    // const providerB = new ethers.providers.JsonRpcProvider('YOUR_SEPOLIA_RPC_URL');
    // const attackerWalletB = new ethers.Wallet(attackerPrivateKey, providerB); // Attacker's wallet
    // const contractInstanceB_Attacker = new ethers.Contract(contractAddressB, VulnerableSignerValidator_ABI, attackerWalletB);
    
    try {
        // const txB = await contractInstanceB_Attacker.claimIncentive(
        //     boostId, incentiveQuantity, attackerClaimantAddress, incentiveData, signatureFromOwner
        // );
        // await txB.wait();
        // console.log("Incentive REPLAYED and claimed on Chain B successfully!");
    } catch (error) {
        // console.error("Error replaying on Chain B:", error.message);
    }
    ```
    
    Because `VulnerableSignerValidator`'s `getActionHash` does not include `block.chainid`, the `actionHash` computed by the contract on Chain B will be identical to the one from Chain A. The `signatureFromOwner` is valid for this hash. If `usedActionHashes[actionHash]` is `false` on Chain B (which it would be for the first replay), the `require` passes, and the attacker successfully claims the incentive on Chain B without the owner ever intending to authorize this specific action on Chain B with that particular signature. This directly demonstrates the exploit from.
    

These PoCs highlight that the vulnerability is not merely theoretical. The smart contract PoC, in particular, demonstrates a common pitfall for developers implementing custom signature schemes, where omitting the chain context from signed messages can lead to direct and exploitable financial or logical vulnerabilities.

## **Risk Classification**

The risk posed by chainid-signing-misuse is classified based on its likelihood and impact.

- Likelihood: Medium-High
    
    The likelihood of this vulnerability being present and exploitable varies.
    
    - For standard EOA-to-EOA or EOA-to-contract transactions created using modern, well-maintained libraries and wallets, the likelihood of accidentally omitting `chainID` or using a `chainID` of 0 is decreasing due to improved defaults and stricter client enforcement. Most contemporary tools default to EIP-155 compliant signing.
        
    - However, the likelihood increases significantly in scenarios involving:
        - **Custom Smart Contract Signature Schemes:** Developers creating their own off-chain message signing and on-chain verification logic (e.g., for meta-transactions, permits, or unique claim systems) may easily overlook the necessity of including `block.chainid` in the signed digest. This is a common area for error.
            
        - **Legacy Systems:** Systems interacting with or supporting older transaction formats.
        - **Complex Cross-Chain Interactions:** Applications designed to work across multiple EVM chains, where managing `chainID`s correctly becomes more complex and error-prone.
        - **Misconfiguration or Intentional Disabling of EIP-155:** If node operators or developers explicitly disable EIP-155 protections (e.g., via Geth flags  or by using `chainId: 0` in libraries like ethers.js ), the likelihood of replayable transactions being processed increases.
        The ongoing discussions and the need for EIPs related to `chainID` handling (e.g., for UserOperations in ERC-4337 ) suggest it remains an area requiring careful attention.
            
- Impact: High-Critical
    
    The impact of a successful chainid-signing-misuse exploit is typically severe:
    
    - **Direct Financial Loss:** Attackers can drain funds from user accounts or smart contracts by replaying transactions or signed messages on unintended chains or in unintended contexts. The zkSync issue, though debated for its root cause being a "design decision" by some, highlighted the potential for fund theft, leading to its initial high-risk assessment.
        
    - **Unauthorized Contract Control/State Manipulation:** Replayed messages can trigger unauthorized administrative actions, minting of unbacked tokens, manipulation of governance votes, or other critical state changes.
    - **Reputational Damage and Loss of User Trust:** Security incidents involving replay attacks can severely damage the reputation of a project, wallet provider, or exchange, leading to a loss of user confidence.
- Overall CVSS Vector (Example Estimation):
    
    The CVSS score depends heavily on the specific manifestation of the vulnerability.
    
    - For a scenario like **cross-chain replay of a smart contract signature leading to fund theft** (similar to PoC 2), where an attacker exploits a missing `chainID` in a contract's verification logic and requires no user interaction beyond the initial legitimate signature:
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N -> **8.6 (High)**
    (Attack Vector: Network, Attack Complexity: Low, Privileges Required: None, User Interaction: None, Scope: Changed, Confidentiality: None, Integrity: High, Availability: None)
    - For a scenario where an attacker **replays a user's legacy raw transaction on another chain**, potentially requiring the user to have signed such a transaction (perhaps via phishing or a misconfigured wallet):
    CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N -> **7.7 (High)**
    (User Interaction: Required)

The risk is not uniform; it is significantly amplified in multi-chain ecosystems and within systems that rely on custom off-chain signature verification logic. The "human element," such as tricking users into signing improperly contextualized messages **24**, can also elevate the likelihood of exploitation. The increasing number of EVM-compatible chains and Layer 2 solutions means that the surface area for `chainID`-related vulnerabilities is expanding, making meticulous handling of chain-specificity more critical than ever.

## **Fix & Patch Guidance**

Addressing chainid-signing-misuse vulnerabilities requires adherence to EIP-155 principles and careful implementation of signature schemes across all components of an Ethereum-based application.

**For Raw Transaction Signing (Client-Side - dApps, Backends, Scripts):**

1. **Always Use EIP-155 Compliant Signing:**
    - Ensure that all transactions are signed in compliance with EIP-155. This mandates the inclusion of the correct `chainID` of the target network within the transaction data that is hashed and signed.
        
    - Utilize modern Ethereum libraries (`go-ethereum`, `ethers.js`, `web3.py`) and ensure they are configured to use the correct `chainID`. For instance, `go-ethereum` provides signers like `LatestSignerForChainID` or specific hardfork signers (e.g., `NewLondonSigner`) that correctly incorporate the `chainID`.
        
    - The official EIP-155 specification should be the guiding document.
        
        
2. **Correct `v` Value Calculation:**
    - The `v` component of the signature must be calculated as v={0,1}+CHAIN_ID×2+35 (or 36) as per EIP-155. Most contemporary libraries handle this automatically when a `chainID` is provided during transaction construction.
        
3. **Avoid `chainID = 0` or Omission Unless Explicitly and Safely Required:**
    - Setting `chainID` to 0 or omitting it generally signals a legacy (pre-EIP-155) transaction or explicitly disables EIP-155 replay protection in some libraries (e.g., `ethers.js` ). This practice should be strictly avoided for general transactions.

    - It should only be considered for highly specific, controlled use cases like certain `CREATE2` deterministic deployment strategies, with a full understanding and mitigation of the associated replay risks. Even then, such transactions should be handled with extreme care and their broadcast limited.


**For Smart Contract Off-Chain Signature Verification:**

1. **Include `block.chainid` in Signed Message Hash:**
    - When users sign messages off-chain that a smart contract will later verify using `ecrecover` (common in meta-transactions, ERC20 `permit` functions, voting systems, etc.), the hash of this message *must* include `block.chainid`. This makes the signature cryptographically specific to the chain it was intended for.
    - **EIP-712:** For typed structured data signing, ensure the `domainSeparator` correctly includes the `chainId`. This is a standardized way to achieve chain-specificity.
    - **Custom Hashes (`abi.encodePacked`):** If constructing a custom message hash, explicitly include `block.chainid` within the data being packed and hashed. A common pattern is: `keccak256(abi.encodePacked(arg1, arg2,..., block.chainid, address(this), nonce))`. The inclusion of `address(this)` (the contract address) and a `nonce` further scopes the signature.
        
    - The recommended fix in an audit finding  involved adding `chainId` to the signed data structure to make signatures unique per chain.
        
2. **Verify `chainID` On-Chain (if applicable):**
    - If the signature scheme itself embeds the `chainID` (e.g., in a custom version of `v` or as part of the signed message), the smart contract should verify that this embedded `chainID` matches the current `block.chainid`.

**Library and Tool Updates:**

- Keep all Ethereum interaction libraries, SDKs, and wallet software up-to-date. Newer versions are more likely to have robust EIP-155 compliance, better defaults, and patches for any known signature-related vulnerabilities.

**Node Configuration:**

- Node operators should generally run their nodes with default configurations that strictly enforce EIP-155 and disallow unprotected (legacy) transactions. Enabling options that allow non-EIP-155 transactions (like Geth's `-rpc.allow-unprotected-txs`  or Evmos's `allow_unprotected_txs` ) should only be done with a clear understanding of the security implications and for specific, justified reasons, typically on private or controlled networks.
    
The core principle of the fix is straightforward: ensure the `chainID` is an integral part of both the data being signed and the data being verified. However, the implementation details can be nuanced depending on the library, the type of transaction (on-chain vs. off-chain message), and the specific smart contract logic involved, necessitating careful attention by developers.

## **Scope and Impact**

The misuse of `chainID` in transaction and message signing has far-reaching consequences across the Ethereum and EVM-compatible blockchain ecosystem.

- **Financial Loss:** This is the most direct and severe impact. Attackers can exploit chainid-signing-misuse to:
    - Drain funds from user accounts by replaying transfer transactions on unintended chains.
        
    - Illegitimately claim tokens or other assets from smart contracts by replaying authorization messages.
        
    - Exploit DeFi protocols by replaying approvals, swaps, or withdrawal transactions.
    The Bybit hack, while involving multiple factors, highlighted the catastrophic financial scale (£1.4 billion) that can be associated with compromised transaction security processes, where replayability and transaction validity across chains were points of concern.

- Unauthorized Contract Interactions and State Corruption:
    
    Beyond direct theft, replayed transactions or messages can trigger unintended state changes in smart contracts. This could involve:
    
    - Unauthorized minting or burning of tokens.
    - Altering critical contract parameters or ownership.
    - Manipulating governance outcomes by replaying votes.
        
    - Interfering with the logic of bridges or other cross-chain communication protocols if messages are not properly domain-separated using `chainID`.
- Erosion of User Trust and System Integrity:
    
    Incidents stemming from replay attacks severely damage user confidence in the affected dApp, wallet, exchange, or even the underlying blockchain network. Such events can lead to users abandoning a platform and can harm the overall perception of security in the Web3 space. The integrity of the blockchain's state is compromised if transactions are processed that do not reflect genuine user intent for that specific chain.
    
- Broad Applicability Across EVM-Compatible Chains:
    
    The chainid-signing-misuse vulnerability is not confined to Ethereum Mainnet. It affects all EVM-compatible chains, including Layer 2 solutions (e.g., Optimism, Arbitrum, zkSync), sidechains (e.g., Polygon PoS), and enterprise Ethereum variants, as they typically adopt the EIP-155 standard for replay protection.3 The proliferation of these chains actually increases the attack surface, as users and contracts may exist on multiple networks, creating more opportunities for cross-chain replay if chainID is handled improperly. The problem is particularly acute if contracts are deployed with identical code and addresses across multiple chains (e.g., via CREATE2 or due to consistent deployment parameters).
    
- **Impact on Specific Use Cases:**
    - **DeFi:** Replaying approvals (`ERC20.approve`), swaps, liquidity provision/removal, and loan operations.
    - **NFTs:** Replaying mint transactions, transfer approvals, or sales.
    - **DAOs:** Replaying votes on proposals or the execution of passed proposals.
    - **Bridges:** If messages relayed between chains are not strictly segregated by `chainID` in their cryptographic commitments, replay attacks could potentially disrupt bridge operations or lead to asset theft.
    - **Wallets:** Users of wallets that improperly handle `chainID` could unknowingly sign transactions vulnerable to replay.

The impact is systemic because the security of individual assets and interactions relies on the assumption that a signed instruction is executed only in its intended context. ChainID misuse breaks this assumption. As the EVM ecosystem continues to expand and fragment into more interconnected yet distinct chains, the imperative for robust and consistent `chainID` handling becomes even more critical to prevent cascading failures and maintain the security of the overall Web3 environment.

## **Remediation Recommendation**

A defense-in-depth strategy is essential for remediating and preventing chainid-signing-misuse vulnerabilities. This involves actions by dApp developers, smart contract authors, wallet providers, and node operators.

**For dApp and Backend Developers (Client-Side Signing Logic):**

1. **Mandate EIP-155 for All Transactions:**
    - Ensure that all on-chain transactions are constructed and signed in strict compliance with EIP-155. This means always including the correct `chainID` of the target network in the transaction data that is hashed and signed.
        
    - Use modern, well-maintained Ethereum libraries (ethers.js, web3.py, go-ethereum) and verify that they are configured to enforce EIP-155 by default. Be cautious of any settings that might disable this protection (e.g., `chainId: 0`).
2. **Fetch `chainID` Dynamically and Reliably:**
    - Avoid hardcoding `chainID` values, especially if the application is intended to interact with multiple networks or if network `chainID`s might change (e.g., for testnets).
    - Dynamically fetch the `chainID` from the connected wallet provider (e.g., using `await provider.getNetwork()` in ethers.js, or `web3.eth.getChainId()` in web3.js/web3.py ). Ensure the source of this `chainID` is trusted.
        
3. **Be Explicit About Transaction Types:**
    - Understand the different Ethereum transaction types (Legacy, EIP-155, EIP-2930 Access List, EIP-1559 Dynamic Fee) and how `chainID` applies to each. Prefer modern, EIP-155 compliant types (like EIP-1559) for new development as they offer better fee markets and inherently include `chainID` protection.
        
4. **User Education and Warnings:**
    - If there are any scenarios where a user might be asked to sign a message or transaction that could be chain-ambiguous (a rare and generally discouraged practice), the UI must provide extremely clear warnings and explanations of the potential risks.

**For Smart Contract Developers (On-Chain Signature Verification):**

1. **Incorporate `block.chainid` in All Off-Chain Signed Message Digests:**
    - For any system involving `ecrecover` to verify signatures of messages signed off-chain (e.g., meta-transactions, ERC20 `permit`, custom approvals, votes), the hash of the message that the user signs *must* include `block.chainid` (accessible in Solidity via `CHAINID` opcode). This makes the signature cryptographically specific to the chain it was intended for.
        
    - **EIP-712:** Strongly prefer using the EIP-712 standard for typed structured data signing. Its `domainSeparator` is designed to include `chainId`, providing a robust and standardized way to prevent cross-chain replay.
    - **Custom Hashes:** If using `abi.encodePacked` for custom message hashing, explicitly include `block.chainid`, `address(this)` (the contract address), and a unique nonce in the packed data before hashing. Example: `keccak256(abi.encodePacked(userAddress, actionId, amount, nonce, block.chainid, address(this)))`.
2. **Implement and Verify Nonces:**
    - In addition to `chainID` for cross-chain protection, always use a robust nonce mechanism (e.g., an incrementing counter per user, or a hash of unique parameters) for off-chain signed messages to prevent replay of the same signature on the *same* chain. The contract must track used nonces.
3. **Comprehensive Security Audits:**
    - Engage reputable third-party security auditors to review smart contract code. Specifically request that they scrutinize all signature verification logic for replay attack vulnerabilities, including checks for `chainID` inclusion and correct nonce handling.

**For Wallet Developers:**

1. **Default to EIP-155 Signing:**
    - Wallets must default to signing all transactions with EIP-155 protection, using the `chainID` of the currently connected network.
    - Signing legacy (non-EIP-155) transactions or transactions with `chainId: 0` should be strongly discouraged, require explicit user overrides, and be accompanied by prominent warnings about replay risks.
2. **Clear UI/UX for Network and Signing Context:**
    - The wallet interface must clearly display the network name and `chainID` for which a transaction or message is being signed.
    - Users should be able to easily verify this information before approving any signature request.
3. **Robust EIP-712 Support:**
    - Provide excellent and user-friendly support for EIP-712 signing, making it easy and safe for dApps to request typed data signatures from users.

**For Node Operators:**

1. **Enforce EIP-155 by Default:**
    - Run Ethereum client nodes (Geth, Nethermind, etc.) with configurations that reject non-EIP-155 (unprotected) transactions by default.
    - Options to allow such transactions (e.g., Geth's `-rpc.allow-unprotected-txs` , Evmos's `allow_unprotected_txs` parameter ) should only be enabled in specific, controlled environments (like private testnets or for very specialized, understood use cases) after a thorough risk assessment.

The following table provides a summary of key remediation actions for different stakeholders:

**Table 3: Mitigation Checklist for ChainID-Signing-Misuse**

| **Stakeholder Role** | **Key Action** | **Rationale/Benefit** |
| --- | --- | --- |
| dApp/Backend Developer | Always include correct `chainID` in raw transactions; fetch `chainID` dynamically. | Ensures transactions are EIP-155 compliant and target the intended chain, preventing cross-chain replay. |
| Smart Contract Developer | Include `block.chainid` (and `address(this)`, `nonce`) in hash for off-chain signed messages; prefer EIP-712. | Makes signatures specific to the contract instance on a particular chain, preventing cross-chain replay. |
| Wallet Developer | Default to EIP-155 signing; provide clear UI on `chainID`; warn for legacy/`chainID:0` signing. | Protects users from unknowingly signing replayable transactions; enhances transparency. |
| Node Operator | Configure nodes to reject non-EIP-155 transactions by default. | Acts as a network-level defense against the propagation and processing of replayable legacy transactions. |

Effective remediation requires a concerted effort across the ecosystem. It is not solely the responsibility of one group; rather, a shared understanding and diligent application of these principles are necessary to safeguard against chainid-signing-misuse.

## **Summary**

The "Misused ChainID in Raw Transaction and Message Signing (chainid-signing-misuse)" vulnerability arises from the incorrect handling or omission of the `chainID` parameter during the signing of Ethereum transactions or off-chain messages intended for smart contract verification. This fundamentally undermines the replay protection mechanism introduced by EIP-155.

The primary and most severe consequence of this misuse is the enabling of **replay attacks**. These attacks can manifest as:

- **Cross-chain replay of raw transactions:** A transaction signed without EIP-155 protection (or with `chainID:0`) for one EVM chain can be maliciously rebroadcast and executed on another EVM chain, leading to unauthorized fund transfers or contract interactions.
- **Cross-chain or cross-context replay of signed messages for smart contracts:** If off-chain signed messages (e.g., for meta-transactions, permits) do not incorporate the `block.chainid` (and often `address(this)` and a `nonce`) into their signed digest, these signatures can be replayed against contract instances on different chains or in different contexts, leading to similar unauthorized outcomes.

This vulnerability is classified as **High severity** due to its potential for direct financial loss, unauthorized control over assets and contracts, and erosion of user trust. It affects a wide range of components, including Ethereum clients, wallet software, transaction signing libraries, and custom smart contract logic.

The core preventative measure is the strict adherence to **EIP-155** for on-chain transactions and the consistent inclusion of `block.chainid` (along with other contextual data like contract address and nonces) in the data hashed for off-chain signatures verified by smart contracts. Diligence is required from all participants in the ecosystem—dApp developers ensuring correct transaction construction, smart contract developers implementing robust signature verification, wallet providers offering secure signing environments, and node operators maintaining secure network configurations—to effectively mitigate the risks associated with chainid-signing-misuse.

## **References**

- **EIP-155: Simple replay attack protection:** `https://eips.ethereum.org/EIPS/eip-155`
    
- **EIP-712: Ethereum typed structured data hashing and signing:** `https://eips.ethereum.org/EIPS/eip-712`
- **Go-ethereum `core/types/transaction_signing.go`:** (Illustrative of `chainID` handling in Go)
    
- **Ethers.js Documentation (Transaction Parameters, Network Object):** (Illustrative of `chainId` handling in JavaScript)
    
- **Web3.py Documentation (Eth module, `chain_id`):** (Illustrative of `chain_id` handling in Python)

- **QuickNode Guide: What are Replay Attacks?:** `https://www.quicknode.com/guides/ethereum-development/smart-contracts/what-are-replay-attacks-on-ethereum`
    
- **QuillAudits Blog: Replay Attack in Web3 Security:** `https://www.quillaudits.com/blog/web3-security/replay-attack`

    
- **OpenZeppelin Blog: Web3 Security Auditor's 2024 Rewind (mentions chainId in signature context):** `https://blog.openzeppelin.com/web3-security-auditors-2024-rewind`
    
- **Smart Contract Security Field Guide (Signature Attacks):** `https://scsfg.io/hackers/signature-attacks/`
    
- **Sherlock Audit Issue: Cross-chain replay attack due to missing chainId in signature validation:** `https://github.com/sherlock-audit/2024-06-boost-aa-wallet-judging/issues/259`
    
- **Blockworks: Bybit Hack Raises Security Questions (EIP-155 context):** `https://blockworks.co/news/bybit-hack-raises-security-questions`
    
- **Bugcrowd Blog: Hacking Crypto Part II (Replay Attacks):** `https://www.bugcrowd.com/blog/hacking-crypto-part-ii-hacking-blockchains-for-fun-and-profit/`

    
- **Code4rena Issue: EIP-155 not enforced (zkSync context):** `https://github.com/code-423n4/2023-10-zksync-findings/issues/882`
