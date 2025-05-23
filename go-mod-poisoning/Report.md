# Dependency Poisoning via `replace` Directive in `go.mod` (go-mod-poisoning)

## Severity Rating

**High🟠 to Critical🔴** (CVSSv3.1 Base Score: 7.0 - 9.8)

The severity of dependency poisoning attacks leveraging the `go.mod` `replace` directive is generally considered **High to Critical**. The specific Common Vulnerability Scoring System (CVSS) score can range significantly, typically between 7.0 and 9.8, contingent upon the precise impact of the malicious code injected and the privileges afforded to the compromised application. For instance, a vulnerability in Go's `go.mod` toolchain directive (CVE-2023-39320) was rated 9.8 (Critical🔴) , underscoring the potential severity of attacks manipulating module resolution.

Dependency poisoning, by its nature, can facilitate arbitrary code execution (ACE) or remote code execution (RCE), enable data exfiltration, or lead to denial-of-service (DoS) conditions. The actual impact is dictated by the attacker's objectives and the nature of the malicious module introduced via the `replace` directive. Research, such as the GoLeash paper, has demonstrated that compromised Go modules can introduce potent capabilities like RCE.

The severity is highly context-dependent. An attack injecting cryptocurrency mining software into an application with minimal privileges would be less severe than an attack that injects a reverse shell into a critical infrastructure management tool, granting extensive control. Furthermore, while the `replace` directive is primarily effective within the main module's `go.mod` file, if an attacker could compromise the build process of a widely distributed application to insert a malicious `replace` directive, the downstream impact could be substantial, affecting numerous users and systems.

## Description

Dependency poisoning via the `replace` directive in a `go.mod` file is a software supply chain attack vector where an attacker manipulates a Go project's dependencies. This is achieved by maliciously introducing or altering `replace` directives within the `go.mod` file. The `go.mod` file is central to Go's module system, defining a module's properties, including its dependencies. The `replace` directive itself is a legitimate feature designed to allow developers to substitute a required module version with an alternative, such as a local copy for development or a forked repository containing custom patches.

When a `replace` directive is active, it instructs the Go build tools to fetch and incorporate an attacker-controlled, potentially malicious, version of a dependency instead of the intended, legitimate one. This mechanism can effectively bypass some standard security checks, such as checksum verification against public checksum databases (like `sum.golang.org`) for the *original* module path, because the build tools are explicitly told to look elsewhere.

Attackers can exploit this feature through several means:

1. Directly modifying an existing `go.mod` file if they gain write access to a project's repository.
2. Tampering with the `go.mod` file during a compromised Continuous Integration/Continuous Deployment (CI/CD) pipeline.
3. Tricking developers into adding or accepting a malicious `replace` directive through a compromised third-party package or via social engineering tactics, such as a deceptive pull request.

The core of this vulnerability lies in the violation of trust boundaries. Go's module system, with its reliance on immutable, versioned modules often fetched from proxies like `proxy.golang.org` and verified via checksums in `go.sum`, aims to provide a secure and reproducible build process. The `replace` directive, however, provides a sanctioned way to override this standard module discovery and acquisition process. While essential for certain development workflows, this override capability becomes a powerful tool for attackers if they can control its usage. Malicious `replace` directives can be crafted to be subtle, pointing to repositories or local paths that appear legitimate at first glance, potentially evading detection during cursory code reviews if developers are not specifically vigilant about scrutinizing `go.mod` file changes. This vulnerability is not a flaw in the Go tools themselves but rather an exploitation of a powerful feature. The term "go-mod-poisoning" is a descriptive label for this attack pattern, rather than an officially cataloged CVE identifier.

## Technical Description (for security pros)

Understanding dependency poisoning via the `replace` directive requires a detailed look at the directive's mechanics, how it can be subverted, and its interaction with Go's module verification systems.

**How the `go.mod` `replace` directive works**

The `replace` directive in a `go.mod` file allows developers to change the source location or version of a dependency. Its syntax is as follows :

```
replace oldpath [oldversion] => newpath [newversion]
```

- `oldpath`: The module path of the dependency to be replaced.
- `oldversion`: (Optional) The specific version of the `oldpath` module to be replaced. If omitted, the replacement applies to all versions of `oldpath`.
- `newpath`: The module path or local filesystem path of the replacement.
- `newversion`: (Optional) The version of the `newpath` module to use. This is required if `newpath` is a module path but must be omitted if `newpath` is a local filesystem path.

The intended purposes for the `replace` directive include :

- Using a local, uncommitted version of a module during development.
- Testing changes in a forked repository before contributing them upstream.
- Applying urgent patches to a dependency when the official maintainer is unresponsive.
- Forcing the use of a specific version of a module, potentially different from what other dependencies might request (though minimal version selection usually handles this).

A critical aspect of the `replace` directive is its scope: `replace` directives are only effective when present in the main module's `go.mod` file. They are ignored in the `go.mod` files of dependencies. This means an attacker must gain control over the main application's `go.mod` file or deceive a maintainer into incorporating the malicious directive.

**Mechanisms of dependency poisoning using `replace`**

Attackers can leverage the `replace` directive for dependency poisoning through several vectors:

1. **Direct `go.mod` Manipulation**: If an attacker gains write access to a project's version control system (e.g., a Git repository), they can directly edit the `go.mod` file to insert or alter `replace` directives, pointing legitimate dependencies to malicious sources.
2. **CI/CD Pipeline Tampering**: A compromised CI/CD pipeline can be a potent vector. Attackers could modify the pipeline script to alter the `go.mod` file before the build step or substitute it with a tampered version.
3. **Social Engineering and Malicious Pull Requests (PRs)**: An attacker might submit a PR that includes a malicious `replace` directive. This could be obfuscated among many other changes or accompanied by a deceptive justification, aiming to bypass reviewer scrutiny.
4. **Exploiting Local Development Setups**: If `replace` directives pointing to local filesystem paths are committed to version control (a discouraged practice), an attacker who can compromise the referenced local path on a developer's machine or a shared build server could inject malicious code.

The `replacement-path` in a malicious `replace` directive can point to:

- A local filesystem path controlled by the attacker (e.g., `replace example.com/legit/lib =>../malicious-lib-copy`).
- A remote repository controlled by the attacker, often a fork designed to look like the original or a typosquatted repository (e.g., `replace example.com/legit/lib => github.com/attacker/malicious-lib v1.0.0`).

**Interaction with `go.sum` and module verification processes**

The Go module system employs several mechanisms to ensure dependency integrity, primarily the `go.sum` file and module proxies with checksum databases.

- **`go.sum` File**: The `go.sum` file records cryptographic hashes (checksums) of the content of specific module versions and their respective `go.mod` files. This ensures that future downloads of the same module version retrieve identical, untampered code.
- **Module Proxies and Checksum Databases**: When Go tools download modules, they often do so via a module proxy (e.g., `proxy.golang.org`). These proxies, along with checksum databases (like `sum.golang.org`), provide a central point for module distribution and verification. The `go` command verifies downloaded modules against these checksums.
- **`replace` Directive's Effect on Verification**:
    - When a `replace` directive is used, Go tools are explicitly instructed to bypass the standard resolution path for the *original module path* (`oldpath`). Consequently, the usual authentication of `oldpath` against a public proxy or checksum database for that specific path is altered or effectively skipped for that original path.
    - However, the Go toolchain *will* calculate and record (or verify if already present) the checksum of the *replacement module* (the `newpath` and `newversion` or local path) in the `go.sum` file. This means `go.sum` ensures the integrity of the *replacement code itself* once it has been fetched and its hash recorded. If an attacker controls the replacement source, they also provide the initial code whose hash is recorded.
- **`go mod verify`**: This command checks that the dependencies stored in the local module cache have not been modified since they were downloaded. In the context of a `replace` directive, `go mod verify` would be checking the integrity of the *replacement module's* code as it exists in the cache.

The core deception in this attack vector is that while `go.sum` and `go mod verify` provide integrity for the *actual code fetched based on the `replace` directive*, they do *not* inherently verify that this replaced code is the legitimate, non-malicious version of the *original intended module path*. The trust is effectively transferred to the source specified in the `replace` directive. A developer observing a "clean" `go mod verify` output or consistent `go.sum` entries might be lulled into a false sense of security, unaware that a dependency has been entirely swapped out for a malicious one. The `replace` directive is a powerful override, and its security hinges on the trustworthiness of the replacement target. The primary challenge for an attacker is to gain the ability to modify the `go.mod` file of the target main module or to trick a maintainer into accepting such a change.

## Common Mistakes That Cause This

The vulnerability of dependency poisoning via `replace` directives is often exacerbated by common mistakes in development and operational practices. These errors can inadvertently create opportunities for attackers:

1. **Blindly Trusting Pull Requests**: Merging PRs without meticulously scrutinizing changes to the `go.mod` file, particularly the addition or modification of `replace` directives. Attackers may hide these changes within large diffs or provide plausible but false justifications.
2. **Committing Temporary Local `replace` Directives**: Developers frequently use `replace` directives to point to local versions of modules during development (e.g., `replace example.com/somemodule =>../somemodule`). Accidentally committing these to version control is a common mistake. If the relative path `../somemodule` is not universally available and consistent across all development and build environments, or if an attacker can control the content at that path in some context (e.g., on a shared build server), this can lead to compromise. The introduction of `go.work` files aims to provide a safer alternative for managing local development overrides, as `go.work` files are typically not committed to version control.
3. **Insufficient `go.mod` Review During Code Audits**: Security reviews that do not allocate sufficient attention to `go.mod` and `go.sum` files as potential attack vectors can miss malicious `replace` directives. These files should be treated with the same rigor as application source code.
4. **Misunderstanding `go.sum`'s Role with `replace`**: An over-reliance on the `go.sum` file for validating the original dependency's authenticity can be misleading. While `go.sum` verifies the integrity of the *replacement* module specified by the `replace` directive (ensuring it doesn't change unexpectedly once fetched), it does not confirm that this replacement is the legitimate version of the *original intended* package from its canonical source if the source has been altered by the `replace` directive.
5. **Using `replace` for Long-Term Forks Without Proper Vetting and Maintenance**: Employing `replace` to use a forked dependency long-term can introduce risks if the fork is not actively maintained, its maintainers are unknown or untrusted, or if the fork itself becomes vulnerable or is compromised over time. The security of the forked code becomes the responsibility of the project using the `replace`.
6. **Lack of CI/CD Pipeline Integrity Checks for `go.mod`**: Build systems that do not incorporate checks to detect suspicious `replace` directives or unexpected changes to `go.mod` files before initiating a build are more vulnerable. The pipeline should validate the provenance of dependencies.
7. **Inadequate Developer Awareness**: A lack of understanding among developers regarding the security implications of the `replace` directive and secure dependency management practices can lead to unintentional errors.

Many of these mistakes are rooted in human factors, such as oversight during reviews, or process deficiencies. While technical controls can mitigate some risks, fostering developer awareness and implementing rigorous review practices are crucial for preventing this type of dependency poisoning. The convenience of the `replace` directive for local development, before `go.work` became prevalent, often led to a form of complacency where these directives were easily forgotten and committed.

## Exploitation Goals

Attackers who successfully exploit dependency poisoning via the `go.mod` `replace` directive can pursue a variety of malicious objectives, typical of software supply chain attacks. The specific goals often depend on the nature of the compromised application and the attacker's broader strategy:

1. **Arbitrary Code Execution (ACE/RCE)**: This is often the primary goal. By injecting a malicious dependency, the attacker can execute arbitrary code either on the build server during the compilation process or within the context of the final application at runtime. This could lead to full system compromise. The impact of such RCE was seen in incidents like the BoltDB typosquatting attack, where a malicious module granted remote access.
2. **Data Exfiltration**: Stealing sensitive information is a common objective. This can include API keys, database credentials, private encryption keys, intellectual property, personally identifiable information (PII), or other confidential data accessible from the build environment or the compromised application.
3. **Denial of Service (DoS)**: An attacker might replace a critical dependency with a non-functional version, a version that deliberately crashes the application, or one that consumes excessive resources (e.g., CPU, memory, network bandwidth), leading to a DoS condition.
4. **Cryptojacking**: Illicitly using the compromised application's or build server's computational resources for cryptocurrency mining. The malicious dependency would contain code to perform mining operations, often designed to run stealthily in the background.
5. **Lateral Movement**: If the compromised application or build environment is part of a larger network, attackers can use it as a foothold to probe for other vulnerable systems and move laterally within the organization's infrastructure.
6. **Persistent Access (Backdoors)**: The malicious code can be designed to establish persistent backdoors, allowing the attacker to maintain access to the compromised system or application over an extended period, even if the initial vulnerability is remediated.
7. **Reputation Damage**: Causing a trusted application to behave maliciously or unreliably can severely damage the reputation of the developing organization or individual maintainers.
8. **Further Supply Chain Propagation**: If the compromised application is itself a dependency for other projects (e.g., a widely used library whose own `go.mod` was manipulated during *its* build process, though `replace` is main-module specific for consumers), the malicious code could potentially propagate further down the software supply chain, although this is less direct with `replace` than with other vector types.

The malicious code can be engineered to execute during the build process itself, targeting secrets and configurations within the CI/CD environment, or it can be designed to activate only when the compiled application is run in a staging or production environment. The choice depends on whether the attacker's primary target is the development infrastructure or the end-users and data of the application. Attacks can be highly targeted, focusing on a specific organization by manipulating their `go.mod` file, or more opportunistic, if a widely used but less scrutinized open-source project's `go.mod` file is compromised.

## Affected Components or Files

When dependency poisoning occurs via a malicious `replace` directive, several components and files within the Go project ecosystem are affected:

1. **`go.mod` File (Primary Target)**:
    - This is the direct entry point for the attack. The attacker's primary action is to insert or modify a `replace` directive within this file in the main module. This file dictates to the Go toolchain which dependencies to use and where to find them.
2. **`go.sum` File (Indirectly Affected)**:
    - The `go.sum` file will be affected because it records the cryptographic checksums of the actual modules used in the build. When a `replace` directive causes a different module (the malicious one) to be fetched, the `go.sum` file will contain the hash of this malicious replacement, not the hash of the original, legitimate dependency it replaced. While this ensures the *replacement* itself is consistently fetched, it also serves to legitimize the malicious module's presence from an integrity-checking perspective for that specific replacement.
3. **Go Module Cache**:
    - The Go module cache (typically located at `$GOPATH/pkg/mod` or `$HOME/go/pkg/mod`) will store the source code of the malicious dependency fetched as per the `replace` directive. This cached malicious code will be used for subsequent builds unless the cache is cleared or the `go.mod` file is corrected.
4. **Compiled Application Binary**:
    - The most critical impact is on the final compiled application binary. This binary will contain the malicious code injected from the replaced dependency. When the application is executed, this malicious code can perform its intended harmful actions.
5. **Build Environment**:
    - If the malicious code is designed to execute during the build process (e.g., via `init()` functions or by being invoked by build scripts), the CI/CD environment or the developer's machine can be directly compromised. This could lead to the theft of build secrets, environment variables, or further manipulation of the build process.
6. **Runtime Environment and Data**:
    - Any system where the compromised application is deployed and run is affected. The malicious code within the application can then impact the confidentiality, integrity, or availability of the application itself, the data it processes, and any other systems it can interact with.

The `go.mod` file serves as a critical control point in the Go build process. Its manipulation directly influences the provenance of the code that ultimately forms the application. The effects of a malicious `replace` directive are persistent if the change is committed to version control. Similarly, the malicious code remains in the module cache until explicitly cleared, and the compiled binary carries the malicious payload until it is rebuilt using a corrected `go.mod` file and clean dependencies.

## Vulnerable Code Snippet

The following illustrates how a `go.mod` file can be altered with a malicious `replace` directive to facilitate dependency poisoning.

Consider an original, legitimate `go.mod` file:

`module example.com/victim/project

go 1.21`

```go
require (
    example.com/legit/dependency v1.2.0
    // other legitimate dependencies
)
```

An attacker, having gained the ability to modify this `go.mod` file, could introduce a `replace` directive as follows:

**Scenario 1: Replacement with an Attacker-Controlled Remote Repository**

`module example.com/victim/project

go 1.21

require (
    example.com/legit/dependency v1.2.0 // The original requirement remains
    // other legitimate dependencies
)

// Malicious replace directive pointing to an attacker's repository
replace example.com/legit/dependency v1.2.0 => github.com/attacker/malicious-fork v1.0.0`

**Explanation of Scenario 1:**

- The `require` directive still lists the legitimate `example.com/legit/dependency v1.2.0`.
- The `replace` directive, however, overrides this. It instructs the Go toolchain to ignore the canonical source for `example.com/legit/dependency v1.2.0` and instead fetch the code from `github.com/attacker/malicious-fork` at version `v1.0.0`.
- The attacker's repository at `github.com/attacker/malicious-fork` would host code that mimics the API of `example.com/legit/dependency` to avoid immediate build failures but contains a hidden malicious payload. The version `v1.0.0` in the replacement is controlled by the attacker and may not correspond to any legitimate versioning scheme of the original package. This syntax is supported by Go's module system.

**Scenario 2: Replacement with an Attacker-Controlled Local Path (if committed or present in build env)**

`module example.com/victim/project

go 1.21

require (
    example.com/legit/dependency v1.2.0
    // other legitimate dependencies
)

// Malicious replace directive pointing to a local filesystem path
replace example.com/legit/dependency v1.2.0 =>../../attacker_controlled_local_dir`

**Explanation of Scenario 2:**

- In this case, the `replace` directive points to a local filesystem path: `../../attacker_controlled_local_dir`.
- This scenario is particularly dangerous if such a `go.mod` file is committed to version control and the relative path resolves to an attacker-controlled location in certain build or development environments, or if an attacker can manipulate the contents of that specific local path on a build server or developer machine.
- The attacker ensures that the `../../attacker_controlled_local_dir` contains the malicious version of the dependency.

In both scenarios, the attacker's goal is to make the malicious replacement appear as seamless as possible. The malicious fork or local directory would likely contain all the expected public functions and types of the legitimate package, ensuring that the victim's project still compiles. The malicious behavior would be subtly embedded within this otherwise functional code. For local path replacements, there's a degree of plausible deniability, as such directives are common during development. An attacker might try to make a malicious local path `replace` look like a legitimate, albeit perhaps sloppily handled, development override. For remote replacements, attackers might create forks that closely resemble the original repository, perhaps only adding a small, obfuscated malicious payload, making a superficial review insufficient for detection.

## Detection Steps

Detecting malicious `replace` directives in `go.mod` files requires a combination of manual vigilance, automated tooling, and robust CI/CD pipeline checks.

**1. Manual Review Techniques:**

- **Scrutinize `go.mod` Changes**: All modifications to `go.mod` files, especially additions or changes to `replace` directives, must undergo rigorous review in pull requests and commits. Reviewers should understand the purpose and target of every `replace` directive.
- **Verify Replacement Targets**:
    - **Remote Paths**: If a `replace` directive points to a remote repository (e.g., a GitHub fork), investigate the repository thoroughly. Examine its maintainers, commit history, code differences from the original module, number of stars/forks, and issue tracker. Look for signs of compromise, recent unexplained changes, or code that deviates suspiciously from the original.
    - **Local Paths**: If `replace` points to a local path, confirm its legitimacy. Is it an expected, controlled part of the development or build setup (e.g., a submodule, a path within a `go.work` workspace)? Be extremely cautious with local paths committed to `go.mod`, especially those outside the project's immediate subdirectory structure or if `go.work` is not being used for local development overrides.
- **Cross-Reference with `go.sum`**: While `go.sum` primarily verifies the integrity of the *replacement* module, any new or unusual entries corresponding to a `replace` target should prompt a deeper investigation into the replacement's origin and trustworthiness.
- **Question Necessity**: For every `replace` directive, its necessity should be questioned. Is it a temporary override for local development (which should ideally be handled by `go.work`)? Is it a critical, long-term fork that has been properly vetted? Could the issue be resolved by contributing upstream or using a different, maintained library?
- **Identify Suspicious Patterns**: Be alert for heuristics that might indicate malicious intent, such as replacing well-known, trusted modules with obscure or newly created forks, significant dissimilarities between the original and replacement module paths, or replacements that lack clear justification.

**2. Automated Tooling:**

- **`govulncheck`**: This official Go tool scans codebases for known vulnerabilities in dependencies. If a `replace` directive points to a module that itself contains known vulnerabilities or *is* the malicious code with a known signature, `govulncheck` might flag issues within the *replacement* code. However, it does not directly detect the act of malicious replacement based on the `replace` directive's target legitimacy.
- **Static Analysis Security Testing (SAST)**:
    - General SAST tools like `gosec` can identify security vulnerabilities in the Go code, which might include issues introduced by a maliciously replaced dependency, though `gosec` is not specifically designed for `go.mod` `replace` analysis.
    - Custom linters or SAST rules can be developed to specifically target `go.mod` files. These rules could flag:
        - Any use of `replace` directives for heightened scrutiny.
        - `replace` directives pointing to non-allowlisted remote hosts or domains.
        - `replace` directives using local paths that are outside an expected project structure or not managed by `go.work`.
    - Tools from vendors like Sonatype can analyze `go.mod` and `go.sum` files, potentially identifying if a `replace` directive points to a module with known security, license, or identity issues. The `go list -f '{{if.Replace}}{{.Path}} => {{.Replace.Path}}{{end}}' -m all` command or similar constructs (like in ) can programmatically extract replacement information for analysis.
- **Dependency Analysis Tools**:
    - Platforms like Snyk , JetBrains GoLand's built-in checks , and Semgrep  offer advanced dependency scanning. They can identify known malicious packages or flag dependencies sourced from suspicious locations. Semgrep, for example, has capabilities to detect malicious dependencies generally.
- **Programmatic `go.mod` Parsing**: The `go mod edit -json` command can be used to parse a `go.mod` file into a JSON structure, allowing programmatic inspection of the `Replace` field. This can be the foundation for custom scripts to enforce policies on `replace` directives.

**3. CI/CD Pipeline Checks:**

- **Integrate `go.mod` Scanners/Linters**: Incorporate automated checks into the CI/CD pipeline to analyze `go.mod` files for suspicious `replace` directives before any build or merge operation.
- **Diff `go.mod`**: Automatically flag and alert on any changes (additions, modifications, deletions) to `replace` directives in incoming pull requests.
- **Network Sandboxing for Builds**: For builds intended to use only vendored or locally cached dependencies, running the build in a network-sandbox (e.g., using `unshare -r -n go build` on Linux ) can help detect if the build unexpectedly tries to access the network. This might indicate a misconfiguration or a `replace` directive pointing to an unintended remote source.

A multi-layered approach, combining diligent manual reviews with the strengths of automated tooling and CI/CD enforcement, offers the most robust defense. While tools can easily detect the *presence* of `replace` directives, discerning malicious intent from legitimate use often requires human contextual understanding or more sophisticated, policy-driven heuristics (e.g., maintaining an allowlist of trusted replacement sources). The threat landscape is dynamic, necessitating continuous updates to detection tools and practices.

**Table 1: Detection Methods for Malicious `go.mod` `replace` Directives**

| Method/Tool | Description | How it Detects `replace` Misuse | Limitations |
| --- | --- | --- | --- |
| Manual Code Review | Human inspection of `go.mod` changes during PRs and audits. | Focuses on scrutinizing `replace` targets, questioning necessity, and identifying suspicious patterns or lack of justification. | Scalability issues, potential for human error, can miss subtle or well-obfuscated malicious directives. |
| `govulncheck` | Official Go tool to find known vulnerabilities in project dependencies. | May detect vulnerabilities in the *replacement* module if it is a known-vulnerable module or uses known-vulnerable code. | Does not directly detect the malicious replacement act itself; relies on known vulnerability data for the replacement. |
| Custom SAST/Linter | Static analysis rules specifically targeting `go.mod` file contents. | Can flag all `replace` usage, or specific patterns like non-allowlisted remotes, risky local paths, or changes to critical modules. | Requires initial rule development and tuning; potential for false positives on legitimate uses if not well-configured. |
| CI/CD `go.mod` Diffing | Automated check for any textual changes to `replace` directives in PRs. | Alerts maintainers to any modification of `replace` lines, prompting manual review. | Requires human follow-up to determine the legitimacy of the change; does not assess intent. |
| Dependency Scanners | Tools like Snyk, GoLand IDE checks, Semgrep. | May identify if the replacement target is a known malicious package or comes from a suspicious source. | Effectiveness depends on the tool's database of malicious packages and heuristics. |
| `go mod edit -json` | Programmatic parsing of `go.mod` for custom scripting. | Allows extraction of `Replace` fields for custom analysis against defined policies or heuristics. | Requires custom script development and maintenance of detection logic. |
| Network Sandboxing | Restricting network access during builds (e.g., `unshare -r -n go build`). | Can detect unexpected network calls if a local `replace` was intended but misconfigured, forcing a remote fetch. | Primarily detects misconfigurations rather than malicious intent of a correctly specified remote replacement. |

## Proof of Concept (PoC)

The following outlines the conceptual steps an attacker might take to execute a dependency poisoning attack using the `go.mod` `replace` directive. This PoC is illustrative and does not involve actual malicious code.

**Objective**: Inject malicious code into a target Go application to achieve Remote Code Execution (RCE).

**Steps**:

1. **Identify Target Module/Project**:
The attacker selects a Go project (`example.com/victim/project`) as their target. This could be an open-source project or an internal project within an organization.
2. **Create Malicious Dependency**:
The attacker identifies a legitimate dependency used by the target project, for instance, `example.com/legit/lib` at version `v1.2.0`.
The attacker then creates a malicious version of this dependency. This can be done by:
    - Forking the legitimate repository of `example.com/legit/lib` to their own controlled repository (e.g., `github.com/attacker/malicious-lib`).
    - Copying the code and creating a new repository.
    - Preparing a local directory (e.g., `./malicious-lib-code`) containing the malicious version.
    The malicious version is carefully crafted to:
    - Mimic the public API of the legitimate `example.com/legit/lib v1.2.0` to ensure the target project still compiles without errors.
    - Include a hidden payload (e.g., code to initiate a reverse shell, exfiltrate environment variables, or execute arbitrary commands). This payload might be placed in an `init()` function or a subtly modified existing function.
3. **Gain `go.mod` Modification Access**:
The attacker needs to find a way to modify the `go.mod` file of the `example.com/victim/project`. Possible methods include:
    - Compromising a developer's account with commit access to the target project's repository.
    - Exploiting a vulnerability in the CI/CD pipeline that allows for modification of source files before the build.
    - Submitting a Pull Request (PR) with the malicious `replace` directive. The PR might contain other seemingly legitimate changes to mask the malicious modification, or the attacker might use social engineering to convince a maintainer to merge it.
4. **Insert Malicious `replace` Directive**:
The attacker modifies the `go.mod` file of `example.com/victim/project`:Diff
    
    `module example.com/victim/project`

    ```bash
    go 1.21
    
    require (
    -    example.com/legit/lib v1.2.0
    +    example.com/legit/lib v1.2.0 // Original require directive might be kept visually similar
    )
    
    +// Malicious replace directive added by attacker
    +replace example.com/legit/lib v1.2.0 => github.com/attacker/malicious-lib v1.0.0
    ```
    
    (Alternatively, if replacing with a local path that the attacker can control in the build environment: `replace example.com/legit/lib v1.2.0 =>../../path/to/attacker/controlled/malicious-lib-code`)
    
5. **Trigger Build/Execution**:
    - When a developer or the CI/CD system builds the `example.com/victim/project` (e.g., by running `go build` or `go test`), the Go toolchain encounters the `replace` directive.
    - It resolves the dependency `example.com/legit/lib v1.2.0` not from its canonical source, but from `github.com/attacker/malicious-lib v1.0.0` (or the specified local path).
    - The `go.sum` file will be updated to include the checksum of the malicious module from `github.com/attacker/malicious-lib v1.0.0`. To an unsuspecting observer or an automated check that only verifies `go.sum` consistency, this might appear normal, as the hashes will match the fetched (malicious) content.
    - The malicious code from the attacker's module is then compiled into the application binary of `example.com/victim/project`.
6. **Payload Activation**:
    - When the compromised application binary is executed, the embedded malicious code activates.
    - If the payload was designed to execute during the build (e.g., in an `init()` function), it might activate within the CI/CD environment or on the developer's machine during compilation or testing.
    - For an RCE payload like a reverse shell, the application might attempt to connect back to an attacker-controlled server.

This PoC highlights that the critical step for the attacker is gaining the ability to modify the `go.mod` file of the main module. Once this is achieved, the `replace` directive provides a powerful mechanism to inject arbitrary code. The success of such an attack often relies on the malicious replacement mimicking the legitimate package's API to avoid immediate build failures, thus delaying detection. While real-world incidents like the BoltDB typosquatting attack  or the GitHub Actions Cache Poisoning  used different initial infection vectors, they demonstrate the severe impact of successfully injecting malicious code into the software supply chain.

## Risk Classification

The risk associated with dependency poisoning via the `go.mod` `replace` directive can be classified based on its likelihood and potential impact.

- **Likelihood: Medium**
    - The exploitation of this vulnerability requires specific preconditions. Primarily, an attacker must gain the ability to modify the `go.mod` file of the target main module or successfully deceive a project maintainer into accepting a malicious `replace` directive via a pull request. This is generally more difficult than opportunistic attacks like publishing a typosquatted package to a public registry and waiting for victims, as it often requires a more targeted approach or a compromise of existing accounts or systems.
    - However, the common use of `replace` directives for local development (especially if `go.work` is not adopted) or for incorporating unvetted forks can inadvertently increase the likelihood if these practices are not managed securely (e.g., accidental commits of local paths, insufficient vetting of forks).
    - The likelihood is significantly influenced by the security maturity of the target organization or project. Strong code review processes, CI/CD security controls, and developer awareness can reduce the probability of successful exploitation. Conversely, an insider threat (a malicious actor with legitimate commit access) dramatically increases the likelihood.
- **Impact: High to Critical**
    - If successfully exploited, the impact can be severe, aligning with the goals outlined previously (Section 6). These include:
        - **Arbitrary Code Execution (ACE/RCE)**: Gaining control over the build system or the runtime environment of the application.
        - **Data Breaches**: Exfiltration of sensitive data, credentials, or intellectual property.
        - **Denial of Service (DoS)**: Disrupting the functionality of the application or dependent systems.
        - **System Compromise**: Full compromise of the host system where the application or build process runs.
    - The impact is amplified if the compromised Go application possesses elevated privileges, handles sensitive data, or is a critical component in a larger system.
- **Overall Risk: High**
    - Despite the medium likelihood requiring specific attack conditions, the potential for high to critical impact justifies an overall risk classification of **High**. The ability to subvert the dependency chain and inject arbitrary code into an application fundamentally undermines software integrity and security.

**Relevant Common Weakness Enumerations (CWEs):**

- **CWE-829: Inclusion of Functionality from Untrusted Control Sphere**: The `replace` directive, when misused, causes the application to include and execute code from a source (the attacker's module) that is outside the legitimate, trusted control sphere of the original dependency.
- **CWE-494: Download of Code Without Integrity Check**: While `go.sum` does verify the integrity of the *replacement* module once its hash is known, the `replace` directive effectively bypasses the integrity check of the *original module path against its canonical, trusted source*. The trust is shifted to the replacement path, which may not have undergone the same level of community trust or verification as the original.
- **CWE-506: Embedded Malicious Code**: The attack directly results in malicious code being embedded within the compiled application.

The risk classification underscores the importance of treating `go.mod` file modifications, particularly `replace` directives, as security-sensitive operations requiring careful scrutiny and robust controls.

## Fix & Patch Guidance

Since "Dependency poisoning via `replace` directive" is an attack vector leveraging a legitimate feature of Go modules rather than a flaw in the Go toolchain itself, there is no traditional "patch" from the Go team to fix the `replace` directive's functionality. Instead, "fixing" involves corrective actions at the project level to remove the malicious directive and remediate any compromise, while "patch guidance" translates to adopting secure practices.

**Immediate Corrective Actions Upon Detection of a Malicious `replace` Directive:**

1. **Isolate Affected Systems**: If a malicious `replace` directive is found and compromise is suspected (e.g., the build may have already occurred with the malicious dependency), immediately isolate any potentially affected systems. This includes developer machines, CI/CD build agents, and any environments (staging, production) where the compromised application might have been deployed.
2. **Remove or Revert the Malicious Directive**:
    - Identify the malicious `replace` directive in the `go.mod` file.
    - Remove it entirely or revert the `go.mod` file to a known-good version that points to the legitimate dependency.
    - Ensure the `require` directive for the dependency points to the correct, legitimate module path and version.
3. **Clean the Go Module Cache**:
    - The malicious dependency's code might be stored in the local Go module cache. Clear the cache to ensure that subsequent builds do not inadvertently use tainted code. This can be done using the command: `go clean -modcache`.
    - Advise all developers working on the project and all build systems to perform this step.
4. **Verify `go.sum` File**:
    - After correcting the `go.mod` file and clearing the cache, run `go mod tidy` or `go get` for the legitimate dependency. This will update the `go.sum` file to reflect the checksums of the legitimate dependencies. Manually inspect `go.sum` to ensure it aligns with expectations for the legitimate modules.
5. **Rebuild and Redeploy**:
    - Rebuild the application from a known-good state of the source code (with the corrected `go.mod` and `go.sum` files) in a clean and trusted build environment.
    - Redeploy the newly built, clean application to all affected environments.
6. **Investigate for Compromise**:
    - Thoroughly investigate the scope and impact of the potential compromise. If the malicious code executed, it could have exfiltrated data, installed persistence mechanisms, or performed other harmful actions.
    - Analyze build logs, application logs, and system logs on affected machines for any suspicious activity, network connections, or unauthorized access that occurred during the period the malicious directive was active.
7. **Rotate Credentials**:
    - If there's any possibility that credentials (API keys, passwords, access tokens, SSH keys, etc.) stored in the build environment or accessible by the application were compromised, rotate them immediately.
8. **Identify the Attack Vector**:
    - Determine how the malicious `replace` directive was introduced (e.g., compromised developer account, vulnerable CI/CD pipeline, accepted malicious PR). Addressing the root cause is crucial to prevent recurrence.

It is critical to understand that the Go toolchain itself is behaving as designed when it honors a `replace` directive. The "fix" lies in ensuring that only legitimate, vetted `replace` directives are present in the `go.mod` file and in implementing processes to prevent unauthorized or malicious modifications. If malicious code did execute, a full forensic investigation might be necessary to understand the extent of the breach and ensure complete remediation, as simply removing the `replace` directive does not undo any actions the malicious code may have already performed.

## Scope and Impact

The scope of dependency poisoning via the `go.mod` `replace` directive extends to any Go project that utilizes Go modules and whose `go.mod` file becomes a target for malicious modification. The impact can be severe, affecting various aspects of software security and operational integrity.

**Scope:**

- **Affected Projects**: Any Go project relying on `go.mod` for dependency management is potentially within scope. This includes applications, services, and libraries developed in Go.
- **Point of Compromise**: The primary point of compromise is the `go.mod` file of the *main module*. `replace` directives in the `go.mod` files of dependencies are generally ignored when that dependency is built as part of a larger main module. This limits the direct propagation of this specific attack vector through the dependency graph solely via a library's `go.mod` `replace` directive being transitively applied. However, the attack directly impacts the application whose `go.mod` is altered.
- **Affected Stages**: The vulnerability can affect multiple stages of the software development lifecycle:
    - **Development Environments**: If a developer pulls a `go.mod` file with a malicious `replace` pointing to a local path, and their local environment contains the malicious code at that path, their machine can be compromised.
    - **CI/CD Systems**: Build servers are prime targets. If a malicious `replace` is processed during a build, the CI/CD environment can be compromised, leading to theft of build secrets or further supply chain attacks.
    - **Production Systems**: Ultimately, the compiled application binary containing the malicious code will run in staging or production environments, leading to compromise of those systems.

**Impact:**

The impact of a successful `go-mod-poisoning` attack can be multifaceted and severe:

- **Confidentiality Breach**: Unauthorized access to and exfiltration of sensitive data. This can include customer data, financial information, intellectual property, API keys, database credentials, and other secrets accessible by the compromised application or build environment. The GoLeash paper details malicious behaviors such as exfiltrating system configuration data (M2) and stealing information from user applications (M3).
- **Integrity Violation**:
    - Unauthorized modification of data or system behavior.
    - Injection of malware, ransomware, or backdoors into the application or underlying systems.
    - The application might produce incorrect results or perform unintended actions, leading to financial loss or operational disruption.
- **Availability Disruption**:
    - Denial of Service (DoS) by replacing a critical dependency with a non-functional or resource-exhausting version.
    - System crashes or instability caused by the malicious code.
- **Supply Chain Compromise**: The compromised application itself can become a vector for further attacks. If the application is a service used by other systems, or if it distributes data or software to users, the compromise can spread.
- **Privilege Escalation**: If the malicious code executes with the privileges of the Go application or build process, and these privileges are high, the attacker can gain significant control over the affected system.
- **Reputation Damage**: For organizations, having their software identified as a source of malware or a point of compromise can lead to significant loss of trust from customers and partners, resulting in financial and reputational damage.
- **Resource Hijacking**: Malicious code could use system resources for unauthorized activities like cryptocurrency mining (cryptojacking) or participating in botnets.

The overall impact is significantly amplified if the compromised Go application handles highly sensitive data (e.g., financial, healthcare), controls critical infrastructure, or has extensive network access and privileges. The fact that `replace` directives in the main module are the primary vector means attackers must target the end-application's build definition, which can be a high-value target. While the main module scope of `replace` is a partial mitigation against uncontrolled transitive poisoning via library `replace` directives, if an attacker *does* manage to inject a malicious `replace` into an application's `go.mod`, the impact on that application is direct and potentially total.

## Remediation Recommendation

Preventing and mitigating dependency poisoning via `go.mod` `replace` directives requires a multi-layered approach encompassing strict development practices, automated tooling, and continuous vigilance. The following recommendations aim to reduce the risk of this attack vector:

1. **Strict Code Review for `go.mod` and `go.sum` Files**:
    - Mandate thorough and security-conscious reviews for all changes to `go.mod` files. Pay special attention to any new or modified `replace` directives.
    - Reviewers must understand the legitimacy and origin of any replacement target. Question why a `replace` is necessary and if safer alternatives exist.
    - Changes to `go.sum` should be reviewed in conjunction with `go.mod` changes to understand what new dependencies or checksums are being introduced.
2. **Prefer `go.work` for Local Development Overrides**:
    - For managing local development versions of dependencies, strongly encourage the use of `go.work` files instead of adding `replace` directives to the `go.mod` file.
    - `go.work` files are designed for local workspace setups and are typically not committed to version control, reducing the risk of accidentally pushing local, potentially insecure, overrides.
3. **Minimize and Scrutinize the Use of `replace` Directives**:
    - Only use `replace` directives in `go.mod` when absolutely necessary (e.g., for applying critical, well-vetted patches to unmaintained dependencies, or for using long-term, trusted forks where upstreaming changes is not feasible).
    - Avoid using `replace` for mere convenience if other dependency management strategies (like version pinning or contributing to the original project) are viable.
4. **Thoroughly Vet All Replacement Sources**:
    - If a `replace` directive points to a forked repository, conduct a comprehensive security assessment of that fork. Evaluate its maintainers, commit history, code changes relative to the original, and overall trustworthiness. Continuously monitor the fork for new vulnerabilities or suspicious changes.
    - If a `replace` points to a local path that must be committed (a rare and generally discouraged scenario), ensure strict control and auditing over the contents of that local path.
5. **Enforce Principle of Least Privilege for CI/CD Systems**:
    - CI/CD pipelines and their associated service accounts should have the minimum necessary permissions. They should not have unrestricted ability to modify `go.mod` files in protected branches without review, nor should they be able to introduce arbitrary code into the build process without oversight.
6. **Automated Scanning and Linting in CI/CD Pipelines**:
    - Integrate SAST tools or custom linters into CI/CD pipelines to automatically detect and flag `replace` directives in `go.mod` files. Policies can be set to alert on any `replace` usage or specifically on those pointing to non-allowlisted domains or suspicious local paths. Tools like Sonatype Lifecycle  or scripts using `go list` can help identify such replacements.
    - Regularly run `govulncheck`  in CI/CD to scan the final set of dependencies (including any replacements) for known vulnerabilities.
7. **Maintain Integrity of `go.mod` and `go.sum`**:
    - Always commit both `go.mod` and `go.sum` files to version control. While `go.sum` verifies the integrity of the *replacement* module, its presence ensures that the chosen replacement (whether legitimate or malicious) does not change unexpectedly without detection once its hash is recorded.
8. **Regular Audits of `go.mod` Files**:
    - Periodically audit the `go.mod` files in active repositories to identify and re-evaluate any existing `replace` directives. Ensure they are still necessary, correctly configured, and point to trusted sources.
9. **Developer Training and Awareness**:
    - Educate developers on the security implications of Go modules, particularly the `replace` and `toolchain` directives in `go.mod`. Training should cover secure dependency management practices, how to vet dependencies, and the risks associated with supply chain attacks.
10. **Leverage Supply Chain Security Platforms**:
    - Consider using commercial or open-source supply chain security platforms that provide broader visibility into dependency health, provenance, and known malicious indicators. These tools can often detect suspicious patterns or known bad actors more effectively than generic linters.
11. **Immutable Tags and Signed Commits**:
    - Encourage upstream dependencies to use immutable tags for releases and sign their commits. While this doesn't directly prevent `replace` misuse, it adds to the overall integrity of the ecosystem.

By implementing these recommendations, organizations can significantly reduce the risk of dependency poisoning attacks that exploit the `go.mod` `replace` directive. A defense-in-depth strategy, combining policy, technical controls, and developer education, is paramount.

**Table 2: Remediation and Prevention Strategies for `go.mod` `replace` Directive Poisoning**

| Strategy Category | Specific Recommendation | Rationale/Benefit |
| --- | --- | --- |
| **Policy & Governance** | Establish strict code review policies for all `go.mod` and `go.sum` file changes, with mandatory security sign-off for `replace` directives. | Ensures expert oversight on critical dependency changes, reducing the chance of malicious or accidental insecure configurations. |
|  | Define an allowlist of trusted sources/repositories for `replace` directives if their use is unavoidable. | Limits replacements to vetted sources, reducing the attack surface from unknown or untrusted forks/modules. |
|  | Mandate regular security audits of `go.mod` files across all active projects. | Proactively identifies and remediates lingering, unnecessary, or newly suspicious `replace` directives. |
| **Technical Controls** | Integrate automated SAST/linters in CI/CD pipelines to detect and flag `replace` directives violating defined policies. | Provides consistent, automated checks before code is merged or built, catching policy violations early. |
|  | Utilize `govulncheck` in CI/CD to scan final dependencies (including replacements) for known vulnerabilities. | Helps ensure that even if a replacement is used, it doesn't introduce known security flaws into the application. |
|  | Implement network sandboxing for build environments where feasible to detect unexpected network activity. | Can help identify misconfigured `replace` directives that attempt to fetch code from unintended remote sources. |
|  | Enforce the Principle of Least Privilege for CI/CD systems and developer accounts regarding `go.mod` modifications. | Minimizes the attack surface by restricting who and what can alter critical build configuration files. |
| **Developer Practices** | Strongly prefer `go.work` files for local development overrides instead of committing `replace` directives to `go.mod`. | Reduces the risk of accidentally committing temporary, potentially insecure local path replacements to the shared codebase. |
|  | Minimize the use of `replace` directives in `go.mod`; use only when absolutely necessary and fully vetted. | Reduces reliance on a powerful override mechanism that can be subverted, encouraging more standard and verifiable dependency management. |
|  | Conduct thorough security vetting of any module or local path used as a replacement target. | Ensures that if a replacement is used, its source is trustworthy and its code has been reviewed for malicious content or vulnerabilities. |
|  | Regularly update developer training on secure coding, Go module security, and supply chain attack awareness. | Equips developers with the knowledge to identify and avoid insecure practices related to dependency management. |

## Summary

Dependency poisoning via the `replace` directive in Go's `go.mod` file represents a significant software supply chain risk. This attack vector allows malicious actors, upon gaining the ability to modify a project's `go.mod` file, to redirect legitimate dependencies to attacker-controlled sources. While the `replace` directive is a legitimate and often necessary feature for Go developers—facilitating local development, the use of forks, or patching—its power can be subverted to inject malicious code, leading to severe consequences such as arbitrary code execution, data exfiltration, or denial of service.

The core of the vulnerability lies not in a flaw within the Go toolchain itself, but in the potential for misuse of this feature. The Go tools will honor a `replace` directive, and while the `go.sum` file will ensure the integrity of the *replacement* code, it does not inherently validate the trustworthiness of the replacement source against the original, canonical dependency path. This shift in trust is what attackers exploit.

Detection of such malicious `replace` directives requires a combination of vigilant manual code reviews, particularly for `go.mod` changes, and the use of automated tools. SAST tools, custom linters, and dependency analysis platforms can help flag suspicious `replace` patterns or known malicious replacement targets. CI/CD pipelines should incorporate checks to scrutinize `go.mod` modifications before builds occur.

Remediation and prevention hinge on a defense-in-depth strategy. This includes minimizing the use of `replace` directives in `go.mod`, preferring `go.work` files for local development overrides, thoroughly vetting any replacement sources, and implementing strict code review processes. Automated scanning within CI/CD pipelines and continuous developer education on secure dependency management are also critical. Ultimately, while the `replace` directive offers flexibility, its use demands a high degree of caution and robust security practices to prevent it from becoming an entry point for supply chain attacks. The security of a Go application relies heavily on the integrity of its `go.mod` file and the trustworthiness of the dependencies it resolves, including those specified through replacements.

## References

Go.dev. (n.d.). *Tutorial: Find and fix vulnerable dependencies with govulncheck*.
 Go.dev. (n.d.). *Managing dependencies*.
 NVD.NIST.gov. (2023). *CVE-2023-39320 Detail*.
 OWASP. (n.d.). *Free for Open Source Application Security Tools*.
 Go.dev. (n.d.). *Vulnerability Management for Go*.
 Go.dev. (n.d.). *go.mod file reference*.
 Golangbridge.org. (2022). *Semantics of the replace directive*.
 Socket.dev. (2025). *Malicious Package Exploits Go Module Proxy Caching for Persistence*.
 Go.dev. (n.d.). *Tutorial: Find and fix vulnerable dependencies with govulncheck*.  Go.dev. (n.d.). *go.mod file reference*.  Snyk.io. (n.d.). *Go Security cheatsheet*.
 Stackoverflow.com. (2022). *Should commit replace directive if it's pointing to a local module?* Jetbrains.com. (2024). *Find vulnerable and malicious dependencies | GoLand Documentation*.
 Semgrep.dev. (n.d.). *Detect and remove malicious dependencies*.
 Practical-go-lessons.com. (n.d.). *Go modules*.
 Go.dev. (n.d.). *go.mod file reference*.  Go.dev. (n.d.). *Managing dependencies*.  Go.dev. (n.d.). *Go Modules Reference*.
 Help.sonatype.com. (n.d.). *Go Application Analysis*.
 Go.dev. (n.d.). *Managing dependencies*.  Practical-go-lessons.com. (n.d.). *Go modules*.  [Github.com/AdnaneKhan](https://github.com/AdnaneKhan). (n.d.). *ActionsCacheBlasting*.
 Semgrep.dev. (n.d.). *Detect and remove malicious dependencies*.  Semgrep.dev. (n.d.). *Policies*.
 [Github.com/gnolang/gno](https://github.com/gnolang/gno). (2024). *Issue #3992: Add govulncheck to Makefile for continuous supply chain security checks*.
 Studyraid.com. (n.d.). *Auditing dependencies for security issues*.
 Jit.io. (n.d.). *Securing CI/CD Pipelines: Common Misconfigurations and Exploit Paths*.
 OWASP.org. (n.d.). *CI/CD Security Cheat Sheet*.
 [Github.com/gojp/goreportcard](https://github.com/gojp/goreportcard). (2019). *Issue #276: add a check for a 'replace' directive in a 'go.mod'*.
 [Reddit.com/r/golang](https://reddit.com/r/golang). (2019). *Easy solution to check go.mod replace directives via Linux namespaces*.
 Help.sonatype.com. (n.d.). *Go Application Analysis*.  Digialert.com. (2025). *Malicious Go Modules Threaten Developers*.
 Socket.dev. (2025). *Malicious Package Exploits Go Module Proxy Caching for Persistence*.  Devops.com. (2025). *Typosquat Supply Chain Attack Targets Go Developers*.
 Go.dev. (n.d.). *Tutorial: Find and fix vulnerable dependencies with govulncheck*.  Combined search result on `go.mod replace vulnerability exploit`, `go.mod replace attack vector`, `secure use of go.mod replace directive`, `go.mod replace best practices security`, `detecting malicious go.mod replace`, `go.sum and replace directive interaction security`.
Combined search result on technical details of `replace` directive, its intended use cases, how it can be subverted, and interaction with `go mod verify` and `go.sum`.
 Go.dev. (n.d.). *Vulnerability Management for Go*.  Socket.dev. (2025). *Malicious Package Exploits Go Module Proxy Caching for Persistence*.  Snyk.io. (n.d.). *Go Security cheatsheet*.  Stackoverflow.com. (2022). *Should commit replace directive if it's pointing to a local module?*  Arxiv.org. (2025). *GoLeash: Mitigating Golang Software Supply Chain Attacks with Runtime Policy Enforcement*.  [Github.com/gojp/goreportcard](https://github.com/gojp/goreportcard). (2019). *Issue #276: add a check for a 'replace' directive in a 'go.mod'*.  Help.sonatype.com. (n.d.). *Go Application Analysis*.