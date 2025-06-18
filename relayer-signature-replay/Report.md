# Golang Vulnerability Report: Signature Replay Attack in Relayer API

## Vulnerability Title
**Signature Replay Vulnerability in Relayer API (relayer-signature-replay)**

## Severity Rating
**HIGH🟠 (CVSS 7.5-8.5)**

## Description
A signature replay attack vulnerability exists in Go-based relayer APIs where previously valid signatures can be reused maliciously. The system fails to implement proper nonce management or timestamp validation, allowing attackers to intercept and replay legitimate signed requests.

## Technical Description (for security pros)
The vulnerability occurs when relayer APIs accept signed messages without implementing replay protection mechanisms. Attackers can capture valid signed transactions and resubmit them multiple times, potentially causing duplicate operations, unauthorized state changes, or financial losses in blockchain/DeFi applications.

## Common Mistakes That Cause This
- Missing nonce implementation in signature verification
- Lack of timestamp-based signature expiration
- Insufficient request deduplication mechanisms
- Poor signature scheme design without replay protection
- Missing transaction ID tracking

## Exploitation Goals
- Execute duplicate transactions
- Drain user funds through repeated operations
- Manipulate application state
- Bypass rate limiting mechanisms
- Cause denial of service through resource exhaustion

## Affected Components or Files
- `relayer/api/handler.go`
- `auth/signature.go`
- `middleware/verify.go`
- Transaction processing endpoints
- Message signing/verification modules

## Vulnerable Code Snippet
```go
func (h *Handler) ProcessSignedMessage(w http.ResponseWriter, r *http.Request) {
    var msg SignedMessage
    json.NewDecoder(r.Body).Decode(&msg)
    
    // VULNERABLE: No nonce or timestamp validation
    if !crypto.VerifySignature(msg.Payload, msg.Signature, msg.PublicKey) {
        http.Error(w, "Invalid signature", 400)
        return
    }
    
    // Process message without replay protection
    h.executeTransaction(msg.Payload)
}
```

## Detection Steps
1. **Code Review**: Search for signature verification without nonce checks
2. **API Testing**: Submit identical signed requests multiple times
3. **Traffic Analysis**: Monitor for duplicate signature patterns
4. **Static Analysis**: Use tools like `gosec` to identify missing replay protection

## Proof of Concept (PoC)
```bash
# Capture legitimate request
curl -X POST /api/relay \
  -H "Content-Type: application/json" \
  -d '{"payload":"transfer_100_tokens","signature":"0xabc123...","pubkey":"0xdef456..."}'

# Replay the same request multiple times
for i in {1..10}; do
  curl -X POST /api/relay \
    -H "Content-Type: application/json" \
    -d '{"payload":"transfer_100_tokens","signature":"0xabc123...","pubkey":"0xdef456..."}'
done
```

## Risk Classification
- **Confidentiality**: Medium (signature exposure)
- **Integrity**: High (duplicate operations)
- **Availability**: Medium (resource exhaustion)
- **Financial Impact**: High (duplicate transactions)

## Fix & Patch Guidance
```go
type SignedMessage struct {
    Payload   string `json:"payload"`
    Signature string `json:"signature"`
    PublicKey string `json:"pubkey"`
    Nonce     uint64 `json:"nonce"`     // Add nonce
    Timestamp int64  `json:"timestamp"` // Add timestamp
}

func (h *Handler) ProcessSignedMessage(w http.ResponseWriter, r *http.Request) {
    var msg SignedMessage
    json.NewDecoder(r.Body).Decode(&msg)
    
    // Check timestamp validity (5-minute window)
    if time.Now().Unix()-msg.Timestamp > 300 {
        http.Error(w, "Signature expired", 400)
        return
    }
    
    // Check nonce uniqueness
    if h.nonceStore.Exists(msg.PublicKey, msg.Nonce) {
        http.Error(w, "Nonce already used", 400)
        return
    }
    
    // Verify signature including nonce and timestamp
    payload := fmt.Sprintf("%s:%d:%d", msg.Payload, msg.Nonce, msg.Timestamp)
    if !crypto.VerifySignature(payload, msg.Signature, msg.PublicKey) {
        http.Error(w, "Invalid signature", 400)
        return
    }
    
    // Store nonce to prevent replay
    h.nonceStore.Add(msg.PublicKey, msg.Nonce)
    
    h.executeTransaction(msg.Payload)
}
```

## Scope and Impact
- **Applications**: DeFi protocols, payment systems, API gateways
- **Impact Scale**: Can affect entire user base if exploited
- **Financial Risk**: Potential for significant monetary losses
- **Operational Risk**: Service disruption and reputation damage

## Remediation Recommendation
1. **Immediate**: Implement nonce-based replay protection
2. **Short-term**: Add timestamp validation with reasonable expiry
3. **Long-term**: Design comprehensive anti-replay architecture
4. **Monitoring**: Implement signature reuse detection alerts

## Summary
The signature replay vulnerability in Go relayer APIs poses significant security risks, particularly in financial applications. Without proper nonce management and timestamp validation, attackers can exploit legitimate signatures to perform unauthorized duplicate operations. Immediate implementation of replay protection mechanisms is critical.

## References
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [RFC 6287: OCRA Algorithm](https://tools.ietf.org/html/rfc6287)
- [Go Cryptography Best Practices](https://golang.org/doc/security)