# Golang Vulnerability Report: Man-in-the-Middle Attack on Node RPC

## Vulnerability Title
**Man-in-the-Middle Attack on Node RPC Communications (rpc-mitm-attack)**

## Severity Rating
**CRITICAL🔴 (CVSS 9.0-9.5)**

## Description
A Man-in-the-Middle (MITM) vulnerability exists in Go-based node RPC communications where insecure transport protocols or improper TLS configuration allows attackers to intercept, modify, or inject malicious data into RPC calls between nodes or clients.

## Technical Description (for security pros)
The vulnerability manifests when RPC servers accept unencrypted connections, use weak TLS configurations, or fail to validate certificates properly. Attackers positioned between communicating nodes can decrypt traffic, manipulate RPC calls, steal sensitive data, or perform unauthorized operations by impersonating legitimate nodes.

## Common Mistakes That Cause This
- Using HTTP instead of HTTPS for RPC endpoints
- Accepting self-signed certificates without validation
- Disabling TLS certificate verification
- Weak cipher suites or deprecated TLS versions
- Missing mutual TLS (mTLS) authentication
- Improper certificate pinning implementation

## Exploitation Goals
- Intercept sensitive transaction data
- Modify RPC requests/responses in transit
- Steal authentication credentials or API keys
- Perform unauthorized node operations
- Inject malicious transactions or commands
- Gather network topology information

## Affected Components or Files
- `rpc/server.go`
- `rpc/client.go` 
- `transport/tls.go`
- `config/network.go`
- Node communication handlers
- Certificate management modules

## Vulnerable Code Snippet
```go
// VULNERABLE: Insecure RPC server setup
func StartRPCServer() {
    server := &http.Server{
        Addr:    ":8545",
        Handler: rpcHandler,
        // Missing TLS configuration
    }
    
    // Accepting plain HTTP connections
    log.Fatal(server.ListenAndServe())
}

// VULNERABLE: Client with disabled certificate verification
func NewRPCClient(endpoint string) *rpc.Client {
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true, // DANGEROUS!
        },
    }
    
    client := &http.Client{Transport: transport}
    return rpc.NewClientWithHTTPClient(endpoint, client)
}
```

## Detection Steps
1. **Network Analysis**: Use Wireshark to capture unencrypted RPC traffic
2. **TLS Testing**: Run `testssl.sh` or `nmap --script ssl-enum-ciphers`
3. **Certificate Validation**: Test with invalid/self-signed certificates
4. **Code Review**: Search for `InsecureSkipVerify: true` patterns
5. **Port Scanning**: Identify unencrypted RPC endpoints

## Proof of Concept (PoC)
```bash
# 1. Set up MITM proxy (using mitmproxy)
mitmproxy -p 8080 --mode transparent

# 2. Test unencrypted RPC endpoint
curl -X POST http://node.example.com:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x123..."],"id":1}'

# 3. SSL/TLS vulnerability test
sslscan node.example.com:8545
testssl.sh --vulnerable node.example.com:8545

# 4. Certificate validation bypass test
curl -k https://node.example.com:8545 \
  --cert fake-cert.pem \
  -X POST -d '{"method":"admin_unlock"}'
```

## Risk Classification
- **Confidentiality**: Critical (complete data exposure)
- **Integrity**: Critical (data manipulation possible)
- **Availability**: High (service impersonation)
- **Financial Impact**: Critical (unauthorized transactions)

## Fix & Patch Guidance
```go
// SECURE: Proper TLS configuration
func StartSecureRPCServer() {
    // Load certificates
    cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Fatal(err)
    }
    
    // Configure secure TLS
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        MinVersion:   tls.VersionTLS12,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
        },
        ClientAuth: tls.RequireAndVerifyClientCert, // mTLS
    }
    
    server := &http.Server{
        Addr:      ":8545",
        Handler:   rpcHandler,
        TLSConfig: tlsConfig,
    }
    
    log.Fatal(server.ListenAndServeTLS("", ""))
}

// SECURE: Client with proper certificate validation
func NewSecureRPCClient(endpoint string, caCert []byte) (*rpc.Client, error) {
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)
    
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{
            RootCAs:    caCertPool,
            MinVersion: tls.VersionTLS12,
            // Certificate pinning
            VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
                return verifyCertificatePin(rawCerts[0])
            },
        },
    }
    
    client := &http.Client{Transport: transport}
    return rpc.NewClientWithHTTPClient(endpoint, client), nil
}

// Certificate pinning implementation
func verifyCertificatePin(certDER []byte) error {
    expectedPin := "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    
    hasher := sha256.New()
    hasher.Write(certDER)
    actualPin := base64.StdEncoding.EncodeToString(hasher.Sum(nil))
    
    if "sha256/"+actualPin != expectedPin {
        return errors.New("certificate pin mismatch")
    }
    return nil
}
```

## Scope and Impact
- **Network Level**: All RPC communications vulnerable
- **Data Exposure**: Complete transaction and state data
- **Operational Impact**: Node network compromise possible
- **Compliance Risk**: Violation of security standards
- **Financial Risk**: Unauthorized fund transfers and operations

## Remediation Recommendation
1. **Immediate**: Force HTTPS/TLS for all RPC endpoints
2. **Critical**: Implement proper certificate validation
3. **Enhanced**: Deploy mutual TLS (mTLS) authentication
4. **Advanced**: Implement certificate pinning
5. **Monitoring**: Deploy network traffic analysis tools

## Summary
MITM attacks on node RPC communications represent a critical security vulnerability that can completely compromise blockchain node networks. The lack of proper TLS implementation and certificate validation allows attackers to intercept and manipulate all communications, leading to data theft, unauthorized operations, and network compromise. Immediate implementation of secure transport protocols is essential.

## References
- [OWASP Transport Layer Protection](https://owasp.org/www-project-cheat-sheets/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [RFC 8446: TLS 1.3 Specification](https://tools.ietf.org/html/rfc8446)
- [Go TLS Configuration Guide](https://golang.org/pkg/crypto/tls/)
- [Certificate Pinning Best Practices](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)