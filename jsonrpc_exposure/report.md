# Vulnerability Report: Insecure JSON-RPC Exposure

## Severity 

## Description 

## Code Example 

## How to fix it 

## Scope and Impact

## Scoping Methods 

## Classification of Risk 

## 🧠 Summary
The target backend exposes a JSON-RPC endpoint (`8545`) publicly without authentication or access control.






## 📍 Affected Endpoint
- http://192.168.0.24:8545

## 🧪 Reproduction Steps
1. Send JSON-RPC request:
   ```bash
   curl -X POST http://192.168.0.24:8545 \
     -H "Content-Type: application/json" \
     --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}'