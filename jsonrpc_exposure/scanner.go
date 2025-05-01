package main

/*
Go Sec Labs - JSON-RPC Exposure Scanner

Purpose:
This tool detects publicly exposed JSON-RPC endpoints on blockchain nodes or backend services.
It sends a harmless request (e.g., `web3_clientVersion`) to identify if the target responds
without authentication or restriction.

Use Case:
- Audit Ethereum nodes, RPC backends, and infrastructure for insecure exposure
- Verify misconfigurations in development or production environments
- Assist in identifying critical vulnerabilities related to open RPC ports (e.g., 8545)

Usage:
  go run scanner.go http://<target-ip>:8545

Note:
This scanner is for educational and authorized security testing only.
Do not use it on systems you do not own or have permission to test.
*/

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run scanner.go http://<target-ip>:8545")
		return
	}

	target := os.Args[1]

	payload := []byte(`{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}`)
	client := &http.Client{Timeout: 4 * time.Second}

	resp, err := client.Post(target, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		fmt.Println("❌ Error connecting:", err)
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		fmt.Println("Potentially Exposed JSON-RPC Detected at", target)
		fmt.Println("Response:", string(body))
	} else {
		fmt.Printf("Received non-200 status: %d\n", resp.StatusCode)
	}
}
