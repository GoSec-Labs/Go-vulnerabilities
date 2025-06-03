## Vulnerability Title

No Certificate Pinning (no-cert-pinning)

### Severity Rating

**Medium🟡 to High🟠**

The severity depends on the application's context. For applications handling sensitive data like financial or personal information, the severity is high. For less critical applications, it might be considered medium.

### Description

"No certificate pinning" is a vulnerability that occurs when a mobile or web application fails to "pin" the server's SSL/TLS certificate or public key. Normally, when an application connects to a server, it verifies the server's certificate against a trusted Certificate Authority (CA) in the device's trust store. However, an attacker can exploit this by presenting a fraudulent certificate issued by a compromised or malicious CA. Without certificate pinning, the application will trust this fraudulent certificate, enabling a Man-in-the-Middle (MITM) attack.

### Technical Description (for security pros)

During a TLS handshake, a client application typically validates the server's certificate chain up to a trusted root CA present in the system's trust store. The "no-cert-pinning" vulnerability arises when the application does not perform an additional check to ensure that the certificate presented by the server is a specific, expected certificate. An attacker with the ability to issue certificates from a trusted CA (either by compromising a CA or by tricking a user into installing a malicious root CA) can intercept and decrypt traffic. Certificate pinning mitigates this by hardcoding the expected server certificate or its public key within the client application. The application then compares the server's certificate against the pinned one during the TLS handshake, rejecting any connection where they do not match.

### Common Mistakes That Cause This

  * **Relying solely on default TLS validation:** Developers often assume that the standard library's TLS validation is sufficient.
  * **Lack of awareness:** Many developers are not aware of the risks of MITM attacks, especially in mobile application environments.
  * **Complexity of implementation:** Implementing certificate pinning can be complex and requires careful management of certificate lifecycles.
  * **Misconfiguration:** Incorrectly implementing pinning, such as pinning the wrong certificate in the chain (e.g., a root or intermediate certificate that is too broad), can render it ineffective.

### Exploitation Goals

The primary goal of exploiting a lack of certificate pinning is to perform a **Man-in-the-Middle (MITM) attack**. This allows an attacker to:

  * **Intercept and decrypt sensitive traffic:** This includes usernames, passwords, session tokens, and other confidential data.
  * **Modify traffic:** Attackers can inject malicious content into the data stream, such as malware or phishing prompts.
  * **Session hijacking:** By stealing session cookies, an attacker can impersonate the user.

### Affected Components or Files

Any part of a Golang application that makes outbound HTTPS requests without implementing certificate pinning is vulnerable. This primarily involves the `net/http` and `crypto/tls` packages. Specifically, the `tls.Config` struct within an `http.Transport` is where pinning logic would be implemented.


### Vulnerable Code Snippet

A standard, vulnerable HTTP client in Go looks like this:

```go
package main

import (
	"fmt"

	"net/http"

	"io/ioutil"
)

func main() {
	resp, err := http.Get("https://example.com")
	if err != nil {

		fmt.Println("Error:", err)

		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {

		fmt.Println("Error:", err)

		return
	}

	fmt.Println(string(body))
}
```

This code uses the default HTTP client, which does not perform certificate pinning.

-----

### Detection Steps

1.  **Static Analysis:** Use static analysis security testing (SAST) tools to scan the codebase for HTTP clients that do not have a custom `tls.Config` with certificate pinning logic.
2.  **Dynamic Analysis:** Use a proxy like Burp Suite or OWASP ZAP to intercept the application's traffic. If you can successfully intercept and decrypt the HTTPS traffic by installing a proxy's root CA on the client device, then certificate pinning is not implemented.
3.  **Manual Code Review:** Manually inspect the code responsible for making HTTPS requests to see if a custom `http.Transport` with a `tls.Config` that verifies the server's certificate against a known value is being used.


### Proof of Concept (PoC)

1.  Set up a proxy server (e.g., Burp Suite) and configure it to intercept HTTPS traffic.
2.  Install the proxy's root CA certificate on the client machine running the Golang application.
3.  Run the vulnerable Golang application that makes an HTTPS request to a target server.
4.  The proxy will intercept the request, and because the application trusts the proxy's root CA, it will establish a TLS connection with the proxy.
5.  The proxy then establishes a separate TLS connection with the actual server.
6.  The attacker can now view and modify the plaintext traffic between the client and the server.

### Risk Classification

  * **OWASP Mobile Top 10:** M3 - Insecure Communication
  * **CVSS v3.1 Score:** 5.9 (Medium) - AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N (This can vary based on the data being transmitted).


### Fix & Patch Guidance

To fix this vulnerability, you need to implement certificate pinning in your Golang application. This involves customizing the `tls.Config` of your HTTP client's transport to verify the server's public key.

Here is a simplified example of how to implement certificate pinning:

```go
package main

import (
	"crypto/sha256"

	"crypto/tls"

	"fmt"

	"io/ioutil"

	"net/http"
)

func main() {
	// The SHA-256 hash of the server's public key
	pinnedPubKeyHash := "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=" // Example for publickeypinning.com

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // We will do our own verification
				VerifyConnection: func(cs tls.ConnectionState) error {
					for _, peerCert := range cs.PeerCertificates {
						hash := sha256.Sum256(peerCert.PublicKey.([]byte))
						encodedHash := "" // You would need to base64 encode the hash
						// In a real implementation, you would properly encode and compare the hash
						if encodedHash == pinnedPubKeyHash {
							return nil
						}
					}
					return fmt.Errorf("could not validate public key")
				},
			},
		},
	}

	resp, err := client.Get("https://publickeypinning.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println(string(body))
}
```

**Note:** This is a simplified example. A robust implementation would involve a more sophisticated way of handling and comparing the public key hashes.



### Scope and Impact

The lack of certificate pinning affects the confidentiality and integrity of data transmitted between the client application and the server. An attacker can gain access to sensitive information, leading to financial loss, reputational damage, and privacy breaches. The impact is most significant for applications that handle authentication credentials, personal data, or financial transactions.


### Remediation Recommendation

It is strongly recommended to **implement certificate pinning** for all applications that handle sensitive data. When implementing pinning:

  * **Pin the Public Key:** It is generally better to pin the public key rather than the entire certificate. This provides more flexibility, as certificates can be renewed with the same key pair.
  * **Have a Backup Pin:** Include a backup pin for a future certificate to avoid service disruption when the primary certificate expires.
  * **Manage Pin Updates:** Have a clear process for updating the pinned keys in your application when server certificates are rotated.

### Summary

The "No Certificate Pinning" vulnerability in Golang applications exposes them to Man-in-the-Middle attacks, which can lead to the interception and manipulation of sensitive data. This arises from relying solely on the default TLS validation without an additional check to ensure the authenticity of the server's certificate. The remediation involves implementing certificate or public key pinning within the application's `tls.Config`. While this adds complexity to certificate management, it is a crucial security measure for protecting sensitive communications.

-----

### References

  * [OWASP: Certificate and Public Key Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)
  * [Go Documentation: crypto/tls](https://pkg.go.dev/crypto/tls)
  * [Go Documentation: net/http](https://pkg.go.dev/net/http)