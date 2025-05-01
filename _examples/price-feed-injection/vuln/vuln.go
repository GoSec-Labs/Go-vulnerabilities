package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type PriceData struct {
	Price float64 `json:"price"`
}

func main() {
	resp, err := http.Get("https://evil-api.io/eth-usd")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var data PriceData
	_ = json.Unmarshal(body, &data)

	// Vulnerable: no validation, trusting external input directly
	fmt.Printf("Fetched ETH price: $%.2f\n", data.Price)

	// Use price to make an on-chain decision
	if data.Price < 1000.0 {
		fmt.Println("Trigger liquidation ⚠️")
	}
}
