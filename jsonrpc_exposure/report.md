# 📄 Vulnerability Report: Insecure JSON-RPC Exposure


###  **1. Vulnerability Title**

| Field             | Value                           |
|------------------|----------------------------------|
| **Name**         | Insecure JSON-RPC Exposure       |
| **Code**         | `VULN-GOSEC-RPC-001`             |
| **Category**     | Network Access / Authentication  |
| **First Seen**   | Ongoing in Web3 since 2016+      |
| **Status**       | Actively exploited in wild       |


###  **2. Severity Rating**

| Metric                  | Value                        |
|-------------------------|------------------------------|
| **Severity**            | **Critical** 🔴              |
| **CVSS v3.1 Score**     | 9.0                          |
| **OWASP Category**      | A5: Security Misconfiguration |
| **Impact**              | Remote access, DoS, Funds Theft |
| **Exploitability**      | Easy (1-step)                |
| **Affected Nodes**      | Publicly exposed RPC nodes   |


### **3. Description**

> An **Insecure JSON-RPC Exposure** occurs when a blockchain node or backend exposes its JSON-RPC interface to the internet **without any authentication, IP filtering, or TLS encryption**. This opens the door to **unauthorized execution of sensitive methods**, such as retrieving private data, sending transactions, or overloading the node.


### Description for Beginners (5-year-old version):

> Think of your blockchain node like a phone 📞. JSON-RPC is how apps call it. If anyone on the internet can call it **without asking permission**, they might **steal your coins**, **spam your system**, or **shut it down**. You left the door open 🚪 — now anyone can come in.


### 🔎 Technical Description (for security pros):

- JSON-RPC interfaces are often hosted on default ports like `8545`, `8546`, or `30303`.
- When these interfaces are **bound to `0.0.0.0`** or publicly routable IPs without:
  - TLS encryption
  - Authentication headers (JWT, API Key, etc.)
  - Method whitelisting
- ...then **anyone can interact** with the backend system using raw RPC requests.
- This allows attackers to:
  - Send unauthorized `eth_sendTransaction`
  - Spam `eth_getLogs` to create Denial-of-Service (DoS)
  - Harvest information via `web3_clientVersion`, `net_listening`, etc.


###  Common Mistakes That Cause This

| Misconfiguration Area | Example                                  | Effect                          |
|------------------------|------------------------------------------|----------------------------------|
| Node Binding           | `--http.addr 0.0.0.0`                    | Makes RPC reachable to the world |
| No Auth Middleware     | No JWT / API key                        | Anyone can call sensitive methods |
| No Firewall            | Port 8545 open to internet               | Scanners/bots can find and abuse |
| Dev Defaults in Prod   | RPC enabled during testing, forgotten    | Vulnerability left open unknowingly |



##  **4. Exploitation Goals**

An attacker exploiting this vulnerability can:

| Goal # | Objective                                | Description                                                                 |
|--------|------------------------------------------|-----------------------------------------------------------------------------|
| 1      | **Unauthorized Blockchain Access**       | Call public and sensitive JSON-RPC methods like `eth_getBalance`, `eth_sendTransaction`, or `eth_call` |
| 2      | **DoS the Node**                         | Overload with `eth_getLogs`, `trace_block`, or `debug_*` until node crashes |
| 3      | **Extract Metadata / Fingerprint Node**  | Read node version, syncing status, peers, and network info                  |
| 4      | **Inject Fake or Signed Transactions**   | If account unlock features are enabled, transactions can be sent on behalf of the node |
| 5      | **Relay Chain Surveillance**             | Index data from exposed nodes to feed bots or front-running engines         |


## **5. Affected Components or Files**

| Component Type      | Name / Example                                  | Description                            |
|---------------------|--------------------------------------------------|----------------------------------------|
| **Blockchain Nodes**| `geth`, `openethereum`, `besu`, `nethermind`     | Core Ethereum clients exposing RPC     |
| **Go-based RPC Apps**| Custom backend using `net/http`, `httputil`     | Backends using Go to serve raw JSON-RPC|
| **Node Config Files**| `start-node.sh`, `docker-compose.yml`, `env`    | Misconfigured network bindings or flags|
| **Firewall / Infra** | `iptables`, `UFW`, Cloud VPC firewall rules      | Missing deny rules for 8545, 8546      |
| **Monitoring Dashboards** | `Prometheus`, `Grafana` on same node        | Side-channel info exposure             |


## **6. Vulnerable Code Snippet**

### 🔴 Example 1 — Go HTTP Server (raw JSON-RPC handler)

```go
package main

import (
    "net/http"
)

func main() {
    // ❌ Vulnerable: Exposed to the internet without protection
    http.ListenAndServe(":8545", nil) // Listens on all interfaces
}
```

>  **Issue:** Binding to `:8545` exposes your JSON-RPC server to public internet.


### 🔴 Example 2 — Geth Launch Command (Ethereum Node)

```bash
# ❌ Vulnerable: Opens HTTP RPC to all IPs
geth --http --http.addr 0.0.0.0 --http.port 8545 --http.api "eth,web3,net"
```

>  **Issue:** No IP restriction + no authentication = world-accessible JSON-RPC


### 🔴 Example 3 — Docker Compose (Bad Expose)

```yaml
services:
  eth-node:
    image: ethereum/client-go
    ports:
      - "8545:8545"
    command: ["geth", "--http", "--http.addr=0.0.0.0"]
```

> 💣 **Issue:** Container exposing RPC interface directly to host network.


## 🔍 **7. Detection Steps**
This section outlines how to detect Insecure JSON-RPC Exposure using **manual**, **automated**, and **tool-based** methods.


###  7.1 Manual Testing (via `curl`)

```bash
curl -X POST http://<TARGET-IP>:8545 \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}'
```

- ✅ **Success response = Vulnerable**
- ❌ **Timeout or 403 = Protected**

---

### 7.2 Nmap Scan with RPC Detection

```bash
nmap -p 8545 --script http-jsonrpc-scan <target-ip>
```

>  Checks for open JSON-RPC interface and responds to known methods.

###  7.3 Custom Go Scanner (Simple Proof)

```go
package main

import (
    "bytes"
    "fmt"
    "io/ioutil"
    "net/http"
)

func main() {
    payload := []byte(`{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}`)
    resp, err := http.Post("http://TARGET-IP:8545", "application/json", bytes.NewBuffer(payload))
    if err != nil {
        fmt.Println("Error:", err)
        return
    }
    defer resp.Body.Close()
    body, _ := ioutil.ReadAll(resp.Body)
    fmt.Println("Response:", string(body))
}
```

> Returns a valid version response → exposed.


### 7.4 Metasploit Auxiliary Scanner (Optional)

```bash
use auxiliary/scanner/http/jsonrpc_login
set RHOSTS <target-ip>
set RPORT 8545
run
```


## **8. Proof of Concept (PoC)**

### PoC Request (web3_clientVersion)

```json
{
  "jsonrpc": "2.0",
  "method": "web3_clientVersion",
  "params": [],
  "id": 1
}
```

### Curl Version

```bash
curl -X POST http://<ip>:8545 \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}'
```


### PoC Response (If Vulnerable)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "Geth/v1.13.7-stable/linux-amd64/go1.20"
}
```


### Optional Critical PoC

Try sending a transaction (if `personal_unlockAccount` or `eth_sendTransaction` is enabled):

```json
{
  "jsonrpc":"2.0",
  "method":"eth_sendTransaction",
  "params":[{...}],
  "id":1
}
```

> **If that returns a tx hash — you've got full node control.**

Perfect Zakaria — now we're getting to the heart of the report 🔐  
Here's the next section of your high-impact vulnerability audit:


##  **9. Risk Classification**

| Category                | Value                                              |
|-------------------------|----------------------------------------------------|
| **Severity Level**      | **Critical** 🔴                                     |
| **CVSS v3.1 (Est.)**    | **9.0 / 10.0**                                      |
| **Exploitability**      | Very Easy – No auth, single HTTP request           |
| **OWASP Category**      | A5: Security Misconfiguration                      |
| **Threat Model Tags**   | Unauthorized Access, Remote Execution, DoS         |
| **STRIDE Mapping**      | ⛳ **S**poofing, ⛏️ **T**ampering, 🪫 **D**enial of Service |


## **10. Fix & Patch Guidance**

### ✅ Go (net/http) Server – Bind Only to Localhost

```go
// FIXED: Only binds to localhost (not 0.0.0.0)
http.ListenAndServe("127.0.0.1:8545", nil)
```


### ✅ Ethereum Geth – Harden Startup

```bash
# ✅ FIXED GETH EXAMPLE:
geth \
  --http \
  --http.addr 127.0.0.1 \
  --http.port 8545 \
  --http.api "eth,web3,net" \
  --authrpc.jwtsecret /secure/token.txt
```


### ✅ Use Firewall Rules

```bash
# Block all access to port 8545 except whitelisted IPs
ufw deny 8545
iptables -A INPUT -p tcp --dport 8545 -s 127.0.0.1 -j ACCEPT
```


### ✅ Apply Access Control in Go Server

```go
func authMiddleware(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("Authorization")
    if token != "Bearer supersecret" {
      http.Error(w, "Unauthorized", http.StatusUnauthorized)
      return
    }
    next.ServeHTTP(w, r)
  })
}
```


### ✅ Optional: Use NGINX Reverse Proxy with Auth

```nginx
location /rpc/ {
  proxy_pass http://localhost:8545;
  auth_basic "Restricted";
  auth_basic_user_file /etc/nginx/.htpasswd;
}
```


## **11. Scope and Impact**

### 🔍 Scope Table

| Area                      | Status      | Risk Level | Notes                                    |
|---------------------------|-------------|------------|------------------------------------------|
| **Production RPC Node**   | Exposed     | 🔴 Critical | Can be used to steal or send txs         |
| **Internal Testnet Node** | Exposed     | 🟡 Medium   | Can still be DoS’d or mined for data     |
| **Staging Environments**  | Sometimes   | 🟠 High     | Often forgotten and left open            |
| **Docker Deployments**    | Common      | 🔴 Critical | Port-forwarding exposes internal RPC     |
| **Cloud Instances**       | Very Common | 🔴 Critical | Public IPs often default open to world   |


> 🎯 **Impact Summary**:  
If this vulnerability exists, **an attacker can fully control the node**, overload it, extract sensitive data, or relay exploit paths through it — affecting **users, funds, and protocol stability**.


##  **12. Remediation Recommendation**

To **fully mitigate** Insecure JSON-RPC Exposure, Go Sec Labs recommends the following:

| Area                | Recommendation                                                                 |
|---------------------|---------------------------------------------------------------------------------|
| 🔐 **Access Control** | Require **JWT** or **API key** on all RPC calls                                |
| 🛡️ **Binding**        | Always bind to `127.0.0.1` or private subnets — never `0.0.0.0`                 |
| 🔥 **Firewall**       | Use host firewall (`ufw`, `iptables`) or cloud VPC rules to block port `8545` |
| 🚫 **Disable Unused Methods** | Remove dangerous APIs like `personal_unlockAccount`, `debug_*`           |
| 📦 **Rate Limiting**  | Apply rate limits on RPC endpoints to prevent spam or DoS attacks              |
| 🧪 **Monitoring**      | Monitor access logs for suspicious RPC requests                                |
| 🌐 **Reverse Proxy**  | Place an **NGINX** or **API gateway** in front of your RPC server               |
| 🐳 **Docker Hardening**| Never expose RPC ports through `docker-compose` or `-p 8545:8545`              |
| 🧱 **Zero Trust Network** | Use VPN tunnels for all internal infrastructure calls                        |


## 🧾 **13. Summary**

> An **Insecure JSON-RPC Exposure** allows an attacker to remotely interact with your blockchain node or backend via unprotected RPC methods. This issue is **easy to exploit** and poses a **critical risk**, including unauthorized transactions, data leakage, and full node compromise.

To resolve this:
- Lock down all exposed interfaces
- Require authentication and firewall protections
- Audit deployments for exposed ports and unsafe flags

**Severity:** 🔴 Critical  
**Status:** Preventable with configuration and basic security hygiene.


##  **14. References**

- XX  
- XX  
- XX

## Disclaimer
> This vulnerability report is provided for educational and research purposes only.
Go Sec Labs does not encourage or condone any malicious activity, exploitation, or unauthorized access to systems or blockchain networks.
All testing and demonstrations should be performed in controlled environments, with explicit permission, and in compliance with local laws and responsible disclosure standards.
