# **Analysis of Insecure Dockerfile Practices and Secret Exposure in Golang Applications**

## **1. Vulnerability Title**

Insecure Dockerfiles (e.g., exposing secrets) (dockerfile-insecure)

## **2. Severity Rating**

The severity of vulnerabilities stemming from insecure Dockerfiles is not uniform; it is a composite risk contingent upon the specific misconfiguration and the nature of any exposed data or inherited vulnerabilities. Severity can range from **Low🟢** to **Critical🔴**.

Hardcoding highly sensitive secrets, such as AWS root access keys or production database administrator credentials, directly into image layers accessible in the final deployment artifact typically warrants a **Critical🔴** severity rating, corresponding to a CVSS (Common Vulnerability Scoring System) score of 9.0-10.0. Similarly, utilizing a base image with a known critical remote code execution (RCE) vulnerability would also be classified as **Critical🔴**. For instance, CVE-2024-21626, a vulnerability affecting `runc` which could be exploited via a malicious container image, received CVSS scores of 8.2 and 8.6 (High) for different attack vectors.

The exposure of less sensitive secrets, or the use of base images with medium-severity vulnerabilities, might be categorized as **High🟠** (CVSS 7.0-8.9) or **Medium🟡** (CVSS 4.0-6.9). Minor misconfigurations, such as failing to pin the version of a non-critical software package, could be rated as **Low🟢** (CVSS 0.1-3.9).

The CVSS framework provides a standardized method for assessing severity. Base metrics—Attack Vector (AV), Attack Complexity (AC), Privileges Required (PR), User Interaction (UI), Scope (S), Confidentiality (C), Integrity (I), and Availability (A)—are used to calculate the score. In cases of secret exposure, the Confidentiality impact is typically High. If the exposed secret allows data modification, Integrity impact is also High. If service control is compromised, Availability is affected. The Attack Vector is often Network if the image is publicly accessible and pulled for execution, or Local if an attacker needs to inspect an already obtained image. Privileges Required by an attacker might be None if the vulnerable image is publicly available. Tools like Docker Scout and Snyk provide severity ratings based on CVSS scores and vendor advisories.

A nuanced understanding of severity is crucial. The actual risk posed by an insecure Dockerfile is often obscured until the specific nature of the insecurity is identified. A generic finding of an "insecure Dockerfile" is less actionable than a specific alert, such as "hardcoded AWS secret key found in Dockerfile ENV instruction." Dockerfiles can harbor insecurities in numerous ways. For example, a linter might flag the failure to use a non-root user as a medium or high-severity issue due to privilege escalation risks, whereas exposing a potent API key via an `ENV` instruction could be critical if that key grants extensive permissions. The resulting CVSS score will vary dramatically based on *what* secret is exposed or *which* CVE is present in the base image. This variability underscores the need for vulnerability management tools to provide specific and contextualized findings.

Furthermore, the accessibility of the Docker image—whether it resides in a public or a private, authenticated registry—significantly influences the practical risk. This is true even if the CVSS base score, which often assumes a worst-case exposure scenario for certain attack vectors, remains constant. An image containing a hardcoded secret stored in a private, secure registry presents a more complex attack vector or requires higher privileges for an external attacker to obtain, compared to an identical image on a public repository like Docker Hub. The CVSS Environmental metric group is designed to adjust for such contextual factors but is often not calculated or reported by automated scanning tools.

**Table 1: CVSS v3.1 Severity Rating Scale**

| **Qualitative Rating** | **CVSS Score Range** |
| --- | --- |
| None🔵 | 0.0 |
| Low🟢 | 0.1 – 3.9 |
| Medium🟡 | 4.0 – 6.9 |
| High🟠 | 7.0 – 8.9 |
| Critical🔴 | 9.0 – 10.0 |


## **3. Description**

Insecure Dockerfiles are build scripts used for creating Docker images that contain configurations or instructions which introduce security vulnerabilities into the resultant container images. A primary and critical concern within this category is the **exposure of secrets**. This includes, but is not limited to, API keys, passwords, access tokens, cryptographic keys, or other sensitive credentials.

These vulnerabilities typically arise from the improper handling of sensitive data during the image build process. Often, secrets are inadvertently or intentionally embedded directly into image layers or build configurations. This practice makes them accessible to any individual or system that can pull or inspect the image. Docker's layered filesystem architecture, while beneficial for efficiency and caching, can unintentionally perpetuate the existence of secrets if not managed with security-conscious practices.

Beyond direct secret exposure, other insecure Dockerfile practices contribute to overall image vulnerability. These include the use of compromised or outdated base images, failing to minimize the attack surface by including unnecessary tools or libraries, and neglecting to apply the principle of least privilege, such as by running containerized applications as the root user. The ease with which Docker images can be shared and distributed means that a single insecure Dockerfile can propagate vulnerabilities across numerous environments and applications.

It is important to recognize that the "Insecure Dockerfiles" vulnerability often acts as a precursor or a "meta-vulnerability." The insecure *practice* during the Dockerfile creation (e.g., hardcoding a password) leads to a more specific, well-defined vulnerability (e.g., CWE-798: Use of Hard-coded Credentials) being present in the *resulting image*. The Dockerfile itself is not typically the direct target of an attack; rather, it is the blueprint that creates a vulnerable artifact. This distinction is critical for remediation strategies, which must focus on correcting the Dockerfile to prevent the generation of insecure images in the future.

A common misunderstanding among developers contributes to this problem: the belief that secrets "removed" in later Dockerfile layers are truly eliminated from the image. Docker layers are immutable and additive. If a secret is introduced in layer N (e.g., via `COPY secret.txt.`), and an attempt is made to remove it in layer N+1 (e.g., via `RUN rm secret.txt`), the secret data remains fully intact and accessible within layer N. Tools designed for layer inspection, such as Dive, can readily demonstrate this persistence. This fundamental aspect of Docker's design is often overlooked, leading to unintentional secret exposure.

## **4. Technical Description (for security pros)**

The security posture of a Docker container is largely determined by its Dockerfile. Understanding how Docker processes these files and how specific instructions can introduce vulnerabilities, particularly secret exposure, is crucial for security professionals.

Docker Image Layering and Immutability:

Each instruction in a Dockerfile (e.g., FROM, RUN, COPY, ADD, ENV) typically creates a new, immutable layer in the resulting Docker image. These layers are stacked, forming the final image filesystem. A key characteristic of this architecture is that data written to a layer persists within that layer. If sensitive data is written to a layer, and a subsequent instruction in a later layer "deletes" that data, the deletion is merely a marker in the upper layer. The original data remains present and accessible in the lower layer.1 This immutability and additive nature of layers is fundamental to how Docker works but is a primary reason for accidental secret persistence.

**Mechanisms of Secret Exposure via Dockerfile Instructions:**

- **`ENV VAR=secret`**: Secrets defined using the `ENV` instruction are embedded into the image's metadata and become part of the default environment for any container launched from the image. These are easily inspectable using `docker inspect` or by simply running `env` inside the container.
    
- **`ARG VAR=secret`**: Build-time arguments (`ARG`) can also lead to secret exposure. While `ARG` values themselves are not directly available in the final image's environment by default (unless also set with `ENV`), they are recorded in the image's history. If an `ARG` containing a secret is used in a `RUN` command that logs its inputs, or if its value is written to a file within an intermediate layer not properly discarded by multi-stage builds, it can be retrieved. The `docker history --no-trunc` command can reveal these build-time arguments and the commands executed.

- **`COPY secret.txt /app` or `ADD secret.tar.gz /app`**: These instructions directly transfer files from the build context (or a remote URL in the case of `ADD`) into the image's filesystem. If these files contain secrets (e.g., `credentials.txt`, `.env` files, private keys), the secrets become part of an image layer. The `ADD` instruction carries additional risk as it can automatically extract archives or fetch remote URLs, potentially introducing vulnerabilities if the source is untrusted or the archive is maliciously crafted.

- **`RUN command_using_secret`**: Secrets used within `RUN` commands (e.g., `RUN curl -u user:secret https://api.example.com/data`, or `RUN export API_KEY=temporary_secret &&./configure_app.sh`) can be embedded in the layer. This can occur if the command itself is logged in the image history with the secret visible, or if the script executed by `RUN` writes the secret to a temporary file that becomes part of the layer.

**Table 2: Dockerfile Instructions and Associated Secret Exposure Risks**

| **Instruction** | **Mechanism of Secret Exposure** | **Example of Misuse** |
| --- | --- | --- |
| `ENV` | Embeds secret in image metadata and container environment. | `ENV API_KEY="supersecret"` |
| `ARG` | Secret can persist in image history or intermediate layers if not managed by multi-stage builds. | `ARG PAT_TOKEN="personalaccesstoken"` |
| `COPY` | Directly copies files containing secrets into an image layer. | `COPY.env /app/.env` |
| `ADD` | Similar to `COPY`; additional risk if fetching secrets from remote URLs or auto-extracting archives containing secrets. | `ADD http://internal.com/secrets.tar.gz /tmp/` |
| `RUN` | Secrets used in commands can be logged in layer history or written to files within the layer. | `RUN git clone https://user:secret@githost/repo` |

*(Data Sources: **1**)*

**Golang-Specific Considerations:**

- **Build Artifacts and Toolchain Inclusion:** A common pitfall in Dockerizing Golang applications is the failure to use multi-stage builds. Without them, the final image often includes the entire Go compiler, source code, build tools, and all intermediate build artifacts. This not only significantly inflates the image size but also dramatically expands the attack surface. Vulnerabilities present in the Go toolchain or any of its dependencies could then be exploited within the production container.
    
- **Static Linking and Base Image Vulnerabilities:** Golang applications are frequently statically linked, which bundles dependencies directly into the executable. This can reduce reliance on shared libraries from the base operating system. However, if CGO is enabled (often for interacting with C libraries like those for DNS resolution or cryptographic operations), the Go binary will dynamically link against libraries present in the base OS image (e.g., `glibc`, `musl-libc`). Vulnerabilities in these underlying OS libraries can then affect the security of the container or even the behavior of the Go application if it interacts with the vulnerable library functions. Even fully static Go binaries operate on the host's kernel, meaning kernel-level exploits can still impact the container, irrespective of the base image's userland libraries.

- **Configuration File Exposure:** Golang applications commonly use external configuration files (e.g., `config.yaml`, `config.json`), often managed by libraries like Viper. If these configuration files contain secrets (database connection strings, API keys for third-party services) and are copied into the image using insecure `COPY` instructions (e.g., `COPY config.prod.yaml /app/config.yaml`), these secrets become part of an image layer and are exposed.
    
The Docker build cache, while enhancing build speeds, can inadvertently contribute to secret persistence if not managed with care, particularly when multi-stage builds are not employed. Intermediate layers containing secrets might be cached and reused if subsequent Dockerfile instructions do not invalidate the cache for those specific layers. Multi-stage builds are effective in mitigating this, as they ensure that these intermediate, potentially secret-laden layers are not part of the final production image.

For Golang applications, the convenience of a simple `COPY..` instruction to transfer the entire project context into the build stage is a significant vector for accidental secret exposure. Development environments often contain local `.env` files, `.git` directories (which may have secrets in commit history if not properly managed), or test credentials. If the `.dockerignore` file is missing or inadequately configured, `COPY..` will indiscriminately include these sensitive items into an image layer, creating a vulnerability. This scenario exemplifies a common clash between developer workflow convenience and secure image construction practices.

## **5. Common Mistakes That Cause This**

Vulnerabilities related to insecure Dockerfiles, particularly secret exposure, often arise from a set of recurring mistakes made during the image creation process. These errors typically stem from a lack of awareness regarding Docker's layered architecture, an oversight of security best practices, or a prioritization of development speed over security considerations.

- **Hardcoding Secrets:** The most direct mistake is embedding sensitive information like API keys, database passwords, or private tokens directly within Dockerfile instructions. This includes using `ENV` to set an environment variable to a secret value, passing secrets via `ARG` that are then used in `RUN` commands in a way that makes them persistent, or including secrets directly in `RUN` command strings.
    
- **Copying Secret-Bearing Files:** Utilizing `COPY` or `ADD` instructions to transfer files containing plaintext secrets (e.g., `credentials.txt`, `.env` files, SSH keys, `config.json` with passwords) into the image filesystem is a frequent error. These files then become part of an image layer.

- **Overly Broad `COPY..` and Inadequate `.dockerignore`:** A very common pattern, especially for convenience, is `COPY..` to bring the entire build context into the image. If a `.dockerignore` file is missing, or if it doesn't comprehensively exclude sensitive local files and directories (such as `.git/`, local `.env` files, IDE configuration folders, or temporary secret files), these items are unintentionally incorporated into the image.
    
- **Misunderstanding `ARG` Persistence:** Developers may incorrectly assume that build-time arguments (`ARG`) used for secrets are ephemeral and do not persist. However, if these arguments are used in `RUN` commands that are logged, or if they become part of an intermediate layer that is not discarded through a multi-stage build, their values can be discovered in the image history.
    
- **Absence or Improper Use of Multi-Stage Builds:** Failing to use multi-stage builds is a critical mistake, especially for compiled languages like Golang. This results in the final production image containing build tools (e.g., the Go compiler), source code, intermediate build artifacts, and extensive dependencies that are unnecessary for runtime and significantly increase the attack surface.
    
- **Insecure Use of `ADD` with Remote URLs:** The `ADD` instruction can fetch resources from remote URLs. If these URLs are untrusted or if the fetched content is not validated (e.g., via checksums), malicious content or unintended secrets from a compromised remote source could be introduced into the image.
    
- **Defaulting to Root User:** Neglecting to include a `USER` directive to switch from the default `root` user to a non-privileged user for the application runtime. Running containers as root provides an attacker who compromises the application with elevated privileges within the container.
    
- **Using Untrusted or Outdated Base Images:** Selecting base images from unverified public repositories or failing to update base images regularly means the application inherits any known (and often patched) vulnerabilities present in those base layers.
    
- **Not Pinning Base Image and Package Versions:** Using mutable tags like `:latest` for base images or not specifying versions for packages installed via `RUN` commands leads to non-deterministic builds and the risk of unintentionally pulling in vulnerable newer versions.
    
- **Including Unnecessary Packages and Tools:** Adding debugging utilities, compilers, or other software not strictly required for the application's runtime operation bloats the image and expands the potential attack surface.
    
- **Attempting to Delete Secrets in a Later Layer:** A fundamental misunderstanding of Docker's layered filesystem leads to the belief that `RUN rm secret_file` in a layer subsequent to where `secret_file` was added will remove the secret. The secret remains in the earlier layer and is still part of the image history.
    

The "it works on my machine" syndrome often contributes to insecure Dockerfiles. Local development environments frequently use configuration files or environment variables containing actual or test secrets for convenience. When containerizing the application, developers might replicate this setup using broad `COPY` commands or `ENV` instructions, inadvertently embedding these development-time secrets into the distributable image. This reflects a common disconnect between local development practices and the principles of secure image construction.

Furthermore, the organizational pressure to rapidly adopt containerization and deploy applications can lead to the de-prioritization of crucial security steps. Implementing robust multi-stage builds, thoroughly vetting base images for minimal footprint and known vulnerabilities, or integrating secure secret management solutions requires more initial time and expertise compared to creating a simple, single-stage Dockerfile. When faced with tight deadlines or a lack of specialized security knowledge, these best practices may be overlooked, resulting in the adoption of insecure default configurations.

## **6. Exploitation Goals**

Attackers who identify and exploit vulnerabilities stemming from insecure Dockerfiles, particularly those involving secret exposure, have several objectives. These goals range from direct data theft to achieving broader system compromise.

- **Steal Sensitive Data:** The most immediate goal is often the exfiltration of exposed secrets. This includes API keys (for cloud providers like AWS, GCP, Azure), database connection strings and credentials, private SSH keys, TLS certificates, OAuth tokens, session keys, and other sensitive configuration parameters embedded in the image layers or metadata.
    
- **Unauthorized Access to Systems and Services:** Stolen credentials are then used to gain unauthorized entry into databases, cloud platforms (e.g., S3 buckets, EC2 instances), internal corporate services, version control systems (like private GitHub repositories), artifact repositories, or any other system that the exposed secrets were intended to protect.
    
- **Privilege Escalation:** If the container is misconfigured to run as the root user or with excessive capabilities (a common result of insecure Dockerfile `USER` settings or the use of the `-privileged` flag at runtime), an attacker who gains initial access (perhaps by exploiting a vulnerability in the application using an exposed secret or a flaw in a vulnerable component from the base image) can attempt to escalate privileges within the container. In severe cases, this can lead to container escape and compromise of the underlying host system.
    
- **Lateral Movement:** Compromised credentials or access gained from one insecurely built container can serve as a foothold for attackers to move laterally within the victim's network or cloud environment. They may target other containers, services, or infrastructure components accessible from the initially compromised point.
    
- **Data Exfiltration, Modification, or Deletion:** Once access to data stores (e.g., databases, file storage) is achieved using stolen credentials, attackers can exfiltrate sensitive information, modify critical data to disrupt operations or cause financial harm, or delete data, leading to operational failure or data loss.
- **Service Disruption (Denial of Service):** If exposed secrets grant control over critical service configurations, infrastructure components (e.g., load balancers, orchestration platforms), or billing accounts, attackers could intentionally disrupt services, leading to denial of service for legitimate users.
    
- **Code Execution / Application Takeover:** Secrets that provide access to deployment systems, code repositories with write permissions, or application management APIs can be used by attackers to deploy malicious code, modify application behavior, or completely take over the application.
- **Supply Chain Attacks:** A particularly dangerous goal involves using exposed secrets for artifact repositories (e.g., Artifactory, Nexus, private npm/PyPI/Maven registries) or code signing keys. Attackers could poison legitimate software packages or introduce backdoors into the software supply chain, affecting all downstream users of those components. The CodeCov attack, where a secret extracted from a public Docker image facilitated a broader supply chain compromise, serves as a notable example.
    

It is important to understand that attackers often chain vulnerabilities. An exposed secret obtained from an insecure Dockerfile might provide the initial, low-privilege access needed to exploit a separate, more complex vulnerability that requires some level of authentication or internal network access. For example, a publicly known Remote Code Execution (RCE) vulnerability in a web framework might be difficult to exploit externally without knowledge of specific internal API endpoints or debug flags. A configuration file leaked through an insecure Dockerfile could reveal such details, thereby enabling the RCE. Similarly, an exposed non-administrative credential might grant access to a system where a local privilege escalation vulnerability can then be triggered.

The "value" and therefore the attractiveness of an exposed secret to an attacker is not uniform; it is highly dependent on the permissions and scope of access granted by that specific secret. An exposed read-only API key for a non-critical, publicly available data source has a significantly lower impact than an AWS master access key, a root password for a production database, or a private key for a code-signing certificate Consequently, a thorough risk assessment must consider the privileges associated with any leaked secret, not merely the fact that a secret has been exposed.

## **7. Affected Components or Files**

Vulnerabilities originating from insecure Dockerfiles can affect a range of components and files throughout the container lifecycle, from the build process to the runtime environment.

- **Dockerfile:** This is the source file where insecure instructions (e.g., hardcoding secrets, using vulnerable base images, improper `USER` directive) are defined. It is the blueprint for the insecure image.
- **Image Layers:** Each instruction in the Dockerfile typically generates a new layer. Secrets or vulnerable files/packages introduced by instructions like `ENV`, `ARG` (if its value is captured), `COPY`, `ADD`, or `RUN` become embedded within these layers. Due to Docker's copy-on-write filesystem, data written to a layer remains part of that layer even if subsequent layers attempt to "delete" it.

- **Final Docker Image:** The fully assembled image, comprising all its layers, is the primary affected artifact. This image, when distributed or run, carries all the vulnerabilities and exposed secrets defined in its Dockerfile.
- **Build Cache:** Docker's build cache stores intermediate layers to speed up subsequent builds. If these cached layers contain secrets from a previous build phase (especially in poorly constructed multi-stage builds or single-stage builds), they can inadvertently persist and potentially be misused or exposed.

    
- **Specific Files Copied or Generated:**
    - **Secret Files:** Any files explicitly containing secrets that are copied into the image, such as `.env` files, `credentials.txt`, `config.json`, `id_rsa` (private SSH keys), `.pem` (certificate private keys), `settings.py` (Django settings with secret keys), or `database.yml` (Rails database configurations)
        
    - **Version Control History:** The `.git` directory, if accidentally included via a broad `COPY..` instruction, can contain historical versions of code or configuration files that might have exposed secrets, even if those secrets are no longer in the current version of the source code.
- **Environment Variables:** Secrets set as environment variables using the `ENV` instruction in the Dockerfile become part of the image's configuration and are directly accessible to processes running within the container.
    
- **Golang-Specific Components:**
    - **Go Application Binary:** While Go compiles to a single binary, if secrets are hardcoded directly into the Go source code (a poor practice in itself), and that source code is part of the build context copied into the image, the compiled binary will contain these secrets. Static analysis of the binary could potentially reveal them.
    - **Go Application Configuration Files:** Golang applications often utilize external configuration files (e.g., `config.yaml`, `config.json`, `.env` files) managed by libraries such as Viper. If these files store sensitive information (database credentials, third-party API keys) and are included in the image via `COPY` or `ADD` instructions, the secrets within them are exposed.
        
    - **Go Toolchain and Build Dependencies:** In the absence of multi-stage builds, the final image for a Golang application may contain the Go compiler, build tools, and all build-time dependencies. These components are unnecessary for runtime, enlarge the image, and increase its attack surface by including potentially vulnerable software.

The impact of an insecure Dockerfile is not confined to the image itself; it can extend to the image registry if a compromised or secret-laden image is pushed and distributed. This creates a supply chain risk, as other users or systems might pull and use this insecure image, unknowingly propagating the vulnerability.

For Golang applications, the nature of static linking presents a specific consideration. While static linking can reduce dependencies on the base OS's shared libraries, if CGO is used (e.g., for certain networking or cryptographic operations), the Go binary will link against system libraries (like `glibc` or `musl`). If the Dockerfile uses a base image containing vulnerable versions of these libraries, the compiled Go application, when run in the container, can be affected by these vulnerabilities. In such cases, the "affected component" is effectively the Go binary itself, as it incorporates or relies on the vulnerable OS library code.

## **8. Vulnerable Code Snippet**

The following snippets illustrate common insecure practices in Dockerfiles that can lead to secret exposure or other vulnerabilities.

**Snippet 1: Hardcoding Secret in `ENV` Instruction**


```Dockerfile

# Vulnerable Dockerfile Snippet 1: Secret in ENV
FROM alpine
ENV API_SECRET_KEY="s3cr3tValu3F0rAP1ExAmpl3" # Secret exposed as environment variable

#... application setup...
# Example command that might use the secret or just show it's present
CMD
```

*Explanation:* The `API_SECRET_KEY` is directly embedded into an image layer via the `ENV` instruction. This makes the secret readily available as an environment variable to any process running within containers derived from this image. It can be easily discovered by inspecting the image configuration or the environment of a running container.**1**

**Snippet 2: Copying a File Containing Secrets**

```Dockerfile

# Vulnerable Dockerfile Snippet 2: Copying secret file
# Assume 'db_config.ini' contains:
# [database]
# password = mySuperSecurePassword123

FROM ubuntu
COPY db_config.ini /etc/myapp/db_config.ini # Secret file copied into image#... application setup...
# Example command that might use the secret file
CMD ["sh", "-c", "cat /etc/myapp/db_config.ini && sleep infinity"]
```

*Explanation:* The file `db_config.ini`, which contains a plaintext password, is copied into the image using the `COPY` instruction. This action makes the secret file part of an image layer, and thus accessible to anyone who can inspect the image's filesystem or gain access to a running container.**1**

**Snippet 3: Secret in `RUN` Command & Golang Single-Stage Build Context**

```Dockerfile

# Vulnerable Dockerfile Snippet 3: Secret in RUN & Golang single-stage build
# This Dockerfile demonstrates multiple vulnerabilities if used as a single stage for production

FROM golang:1.21 # Base image includes entire Go toolchain

WORKDIR /app

# Simulate fetching a private Go module using a token in a URL (bad practice)
# The token might be logged or cached by git/go tools within this layer
RUN go get private.example.com/user/privaterepo.git?token=ghp_thisIsALeakedTokenExample

# Copying all source code, potentially including local.env files or.git folder
COPY..

# Hardcoding configuration with secrets for a Go application directly in a RUN command
RUN echo "{\"database_dsn\": \"postgres://adminuser:P@$$wOrd@dbhost:5432/production_db\"}" > /app/config.json

# Building the Go application
RUN CGO_ENABLED=0 go build -o mygoapp./cmd/server

# If this were the CMD for the final image, all build tools and secrets would be present
CMD ["./mygoapp"]
```

*Explanation:* This snippet, if used as a single-stage build for a production Golang application, exhibits several insecure practices:

1. **Secret in `RUN` command:** The `go get` command includes a token directly in the URL. This token can be logged in the image history or cached by build tools within this layer.
2. **Hardcoded Secret in `RUN` command:** The `RUN echo` command writes a `config.json` file containing a plaintext database DSN (Data Source Name), including username and password, directly into an image layer.
3. **Inclusion of Build Environment:** By using `golang:1.21` as the final base and including `COPY..` and `go build`, the resulting image would contain the Go compiler, the entire source code (potentially with more secrets if not properly `.dockerignore`d), the `config.json` with the hardcoded DSN, and any artifacts from the `go get` command. This significantly increases the attack surface.
A multi-stage build would be essential here to separate the build environment (with build-time secrets handled carefully, e.g., via BuildKit secret mounts) from a minimal runtime image containing only the compiled Go binary and necessary runtime configurations (with secrets injected securely at runtime).
    
These examples underscore how easily secrets can be mishandled in Dockerfiles. The most dangerous scenarios often arise from a combination of such practices: for instance, hardcoding a sensitive secret, running the container as the root user, and using an outdated base image with known vulnerabilities. This combination creates a multiplicative risk, where an exposed secret provides an initial entry point, root privileges allow full control within the container, and a vulnerable base image might offer the means for container escape or further exploitation.

For Golang applications, the simplicity of a Dockerfile like:

```Dockerfile

FROM golang:1.21
WORKDIR /app
COPY..
RUN go build -o myapp.
CMD ["./myapp"]
```

is appealing for its straightforwardness, especially during early development or in tutorials. However, this pattern is inherently insecure for production environments because it bundles the entire Go development toolchain, source code, and all build dependencies into the final image. This significantly bloats the image and creates a much larger attack surface compared to a multi-stage build that produces a minimal runtime image with only the compiled Go binary. This common pattern highlights a frequent conflict between ease of initial use and robust security practices.

## **9. Detection Steps**

Identifying insecure Dockerfiles and the secrets or vulnerabilities they might introduce requires a combination of manual inspection, automated static analysis, and image scanning techniques. A multi-faceted approach provides the most comprehensive coverage.

1. Manual Dockerfile Review:

A thorough manual review of the Dockerfile is a foundational step. Key areas to scrutinize include:

- Hardcoded Secrets: Examine ENV instructions for direct credential assignments. Inspect ARG declarations and their usage in subsequent RUN commands. Look for secrets embedded in RUN command strings, such as in URLs, command-line arguments to tools like curl or git, or within inline scripts.1
- File Copying Operations: Analyze all COPY and ADD instructions. Check for the copying of potentially sensitive files like .env, config.* (e.g., config.json, config.yaml), credentials.txt, private keys (*.key, *.pem), or entire directories that might contain such files. Verify the presence and effectiveness of a .dockerignore file to prevent accidental inclusion of local development secrets, the .git directory, or other unnecessary files.1
- Base Image Selection (FROM): Confirm that the base image is from a trusted source (e.g., official Docker images, verified publishers). Ensure a specific version tag or digest is used, avoiding mutable tags like :latest. Check if the chosen base image is known to be minimal and regularly updated.9
- User Privileges (USER): Verify that the USER directive is used to switch to a non-root user before the CMD or ENTRYPOINT instruction is executed.9
- Package Installation: Review RUN commands that install packages (e.g., apt-get install, apk add, npm install, pip install). Check if package versions are pinned and if unnecessary packages or development dependencies are being installed in the final stage of a build.

2. Dockerfile Linters (e.g., Hadolint):

Static analysis tools specifically designed for Dockerfiles, such as Hadolint, can automatically detect many common misconfigurations and deviations from best practices.12

- Hadolint checks for rules like DL3002 (last user should not be root), DL3006 (always tag the version of an image explicitly), DL3007 (using latest is prone to errors), and DL3020 (use COPY instead of ADD for files and folders).47
- Hadolint integrates with ShellCheck to analyze scripts within RUN instructions, which can help identify risky shell practices or potential command injection vulnerabilities if variables are used insecurely.42

3. Image Scanning Tools (e.g., Trivy, Snyk, Docker Scout, Clair):

These tools analyze the built Docker image (rather than just the Dockerfile) for known vulnerabilities in OS packages and application dependencies.

- They compare the Software Bill of Materials (SBOM) of the image against vulnerability databases.5
- Some scanners also have capabilities to detect hardcoded secrets within image layers or certain types of misconfigurations.2
- Docker Scout, for example, analyzes image metadata and SBOM against vulnerability advisories and provides severity assessments.5
- Snyk Container can scan Dockerfiles and suggest more secure base image alternatives.49

4. Inspecting Image Layers and History:

Direct inspection of the image's layers and history is crucial for uncovering secrets that might have been embedded and are not easily found by static Dockerfile analysis alone.

- docker history <image_name> --no-trunc: This command displays the history of how an image was built, including the commands executed for each layer. It can reveal secrets passed as build arguments (ARG) if those arguments were used in RUN commands that were logged, or if secrets were part of the command strings themselves.1 The --no-trunc flag ensures full command visibility.
- Layer Inspection Tools (e.g., Dive): Tools like Dive allow interactive exploration of Docker image layers. Users can navigate the filesystem of each layer to see exactly which files were added, modified, or deleted. This is particularly effective for finding secrets that were copied into an earlier layer and then "deleted" in a subsequent layer, as Dive will show the secret still present in the original layer.1
- Manual Layer Extraction and Analysis: An image can be saved to a tarball using docker save <image_name> -o image.tar. This tarball can then be extracted (tar xvf image.tar), revealing individual layer tarballs (<layer_id>/layer.tar). Each of these layer tarballs can be further extracted to inspect its filesystem contents manually. This method can uncover secrets written to files within any layer.1
- docker inspect <image_name_or_id>: This command provides detailed information about the image configuration in JSON format, including environment variables set with ENV, which might contain hardcoded secrets.

**Table 3: Dockerfile Security Detection Methods**

| **Method** | **Description** | **Tools/Commands Examples** | **Focus Area** |
| --- | --- | --- | --- |
| Manual Dockerfile Review | Careful examination of Dockerfile instructions for insecure patterns, hardcoded secrets, and bad practices. | Text editor, knowledge of best practices | Static Dockerfile Analysis |
| Dockerfile Linters | Automated static analysis against predefined rules and best practices. | Hadolint, Checkov | Static Dockerfile Analysis |
| Image Vulnerability Scanners | Analysis of the built image for known CVEs in OS packages and application dependencies; some detect secrets. | Trivy, Snyk, Docker Scout, Clair | Image Composition & Vulnerability |
| Image Layer Inspection | Examination of individual image layers to find embedded files, secrets, or historical command data. | Dive, `docker history`, `docker save` + `tar` | Image Layer Inspection |
| Image Configuration Query | Retrieval of image metadata, including environment variables. | `docker inspect` | Image Metadata Analysis |

*(Data Sources: **1**)*

Effective detection of insecure Dockerfiles necessitates a defense-in-depth strategy. Manual reviews, while fundamental, are prone to human error and do not scale well. Linters like Hadolint offer rapid, automated checks for adherence to Dockerfile best practices and identification of common syntactical errors, serving as an excellent first pass for catching obvious issues. Image scanners such as Trivy, Snyk, and Docker Scout delve deeper by examining the actual built image, identifying vulnerabilities within OS packages and application dependencies that might be introduced by the base image or software installed via `RUN` commands; some also incorporate secret scanning capabilities. Layer inspection tools like Dive, or manual inspection via `docker history` and `docker save`, are indispensable for uncovering secrets that might be concealed in intermediate layers or embedded in build arguments, which could be missed if scanners only analyze the final filesystem state. No single method or tool is infallible. A combination of these approaches provides a more robust defense against the multifaceted risks posed by insecure Dockerfiles. For instance, a linter might not detect an obfuscated secret, but layer inspection could reveal it. Conversely, an image scanner will identify a CVE in an installed package, a task beyond the scope of a typical linter.

## **10. Proof of Concept (PoC)**

The following conceptual Proof of Concept demonstrates how secrets can be extracted from a Docker image built from an insecure Dockerfile.

**Scenario:** A Dockerfile is created with several common mistakes leading to secret exposure.

**1. Create a Vulnerable Dockerfile (`Dockerfile.vulnerable`):**

```Dockerfile

FROM alpine:latest

# Mistake 1: Hardcoding secret in ENV
ENV MY_CRITICAL_API_KEY="env_secret_key_12345_abcdef"

# Create a dummy secret file
RUN echo "DB_PASSWORD=supersecretpassword_from_file" > /tmp/secret_file.txt

# Mistake 2: Copying a file containing a secret (even if "removed" later)
COPY /tmp/secret_file.txt /app/copied_secret_file.txt

# Mistake 3: Secret in RUN command output to a file
RUN echo "SECRET_FROM_RUN_CMD=run_command_secret_value" > /app/run_output_secret.txt

# Mistake 4: "Removing" the secret file in a later layer (ineffective for prior layers)
RUN rm /app/copied_secret_file.txt

# Application entry point (dummy)
CMD ["sh", "-c", "echo 'Vulnerable container running. Inspect for secrets.' && sleep 3600"]
```

2. Create the Dummy Secret File on Host:

Create a file named secret_file.txt in the same directory as Dockerfile.vulnerable (or in /tmp/ on the host as per the COPY source, though for PoC, local context is easier):

`DB_PASSWORD=supersecretpassword_from_file`

If copying from `/tmp/secret_file.txt` directly from the host, ensure that file exists there before building. For simplicity in this PoC, let's assume `secret_file.txt` is in the build context. Modify `COPY` to `COPY secret_file.txt /app/copied_secret_file.txt`.

**3. Build the Vulnerable Image:**

```Bash

`docker build -f Dockerfile.vulnerable -t vulnerable-app:latest.`
```

**4. Exploitation/Secret Extraction Methods:**

- **Method A: Inspecting Environment Variables (for `ENV` secrets):**
    - Command: `docker inspect vulnerable-app:latest`
    - Look for the `Env` section in the JSON output. The `MY_CRITICAL_API_KEY` will be visible:
        
        ```JSON
        
        `//...
        "Env":,
        //...
        ```
        
    - Alternatively, run the container and print its environment:
    
    This will list all environment variables, including `MY_CRITICAL_API_KEY`.
    
        ```BASH
        
        `docker run --rm vulnerable-app:latest env`
        ```
        
- **Method B: Accessing Files in Running Container (for secrets not "effectively" removed):**
    - The `RUN rm /app/copied_secret_file.txt` command removes the file from the *topmost* layer. However, the file `/app/run_output_secret.txt` created by a `RUN` command will persist in the final image if not removed.
    - Command:
        
        ```Bash
        
        `docker run --rm -it vulnerable-app:latest sh
        # Inside the container:
        cat /app/run_output_secret.txt
        ```
        
    - Output: `SECRET_FROM_RUN_CMD=run_command_secret_value`
- **Method C: Inspecting Image Layers with Dive (for `COPY` and `RUN` artifacts):**
    - Command: `dive vulnerable-app:latest`
    - Using Dive's interface:
        1. Navigate to the layer created by `COPY secret_file.txt /app/copied_secret_file.txt`. The contents of `copied_secret_file.txt` (i.e., `DB_PASSWORD=supersecretpassword_from_file`) will be visible in that layer's filesystem view, even though a later `RUN rm` command "deleted" it from the final merged view.
        2. Navigate to the layer created by `RUN echo "SECRET_FROM_RUN_CMD=..." > /app/run_output_secret.txt`. The file `/app/run_output_secret.txt` and its content will be visible.
- Method D: Manual Layer Inspection (for COPY and RUN artifacts):
    
    This demonstrates the underlying accessibility of layer data.
    
    1. Save the image: `docker save vulnerable-app:latest -o vulnerable-app.tar`
    2. Extract the main tarball: `tar -xvf vulnerable-app.tar`
    3. This will create several files, including a `manifest.json` and directories for each layer. Find the layer ID corresponding to the `COPY secret_file.txt...` instruction (e.g., by inspecting `manifest.json` or layer directory names which are often hashes of layer content).
    4. Extract the specific layer tarball: `tar -xvf <layer_id_of_copy>/layer.tar` (The exact path structure might vary slightly based on Docker version).
    5. Navigate into the extracted layer filesystem: `cat./app/copied_secret_file.txt` (path relative to the extracted layer root). The secret `DB_PASSWORD=supersecretpassword_from_file` will be found.
    The CodeCov attack, which involved extracting a secret from a public Docker image, underscores the real-world applicability of such inspection techniques.

Golang Application Context:

If a Golang application running inside this vulnerable-app container were programmed to read MY_CRITICAL_API_KEY from its environment, or to read database credentials from /app/copied_secret_file.txt (if it hadn't been "removed" from the final view) or /app/run_output_secret.txt, an attacker who gains execution within the container (perhaps through a separate vulnerability in the Go application itself) could easily access these secrets.

This Proof of Concept illustrates that secrets are not inherently "hidden" or "secured" simply by being placed within a Docker image. The image's layered filesystem and metadata are often inspectable. Attackers do not need to exploit complex binary vulnerabilities to extract these secrets; they often only need to know where to look and use standard Docker commands or file system utilities. This accessibility significantly lowers the barrier to exploitation compared to other vulnerability types.

## **11. Risk Classification**

The risk associated with insecure Dockerfiles, particularly those leading to secret exposure, is generally **High to Critical**. The precise classification depends on the nature of the misconfiguration, the sensitivity of any exposed secrets, and the vulnerabilities present in base images or installed components.

- Likelihood: High.
    
    Mistakes leading to insecure Dockerfiles are common due to oversight, lack of awareness of Docker's layered architecture, or prioritization of speed over security.1 Research has shown that a significant percentage of publicly available Docker images contain leaked secrets.1 Tools and techniques for inspecting image layers and discovering these vulnerabilities are readily available to attackers.
    
- Impact: High to Critical.
    
    The impact of exploiting an insecure Dockerfile can be severe:
    
    - **Confidentiality Breach:** Exposure of API keys, database credentials, private keys, or other sensitive tokens can lead to unauthorized access to critical systems and data, resulting in significant data breaches.
        
    - **Integrity Compromise:** Attackers with stolen credentials may be ableto modify sensitive data, alter system configurations, or inject malicious code into applications or infrastructure.
        
    - **Availability Disruption:** Compromised secrets could be used to disrupt services, delete data, or trigger denial-of-service conditions if they control critical infrastructure components.
        
    - **Full System Compromise:** If secrets grant administrative access, or if vulnerabilities in the base image combined with misconfigurations (like running as root) allow container escape, attackers could gain full control over the host system and potentially pivot to other parts of the network.


**Relevant Common Weakness Enumerations (CWEs):**

The following table outlines key CWEs associated with insecure Dockerfile practices:

**Table 4: Key CWEs Related to Insecure Dockerfiles**

| **CWE ID** | **CWE Name** | **Description** | **Relevance to Dockerfile Security** |
| --- | --- | --- | --- |
| **CWE-798** | Use of Hard-coded Credentials | The software contains hard-coded credentials, such as a password or cryptographic key. | Directly applicable when secrets (API keys, passwords, tokens) are embedded in Dockerfile instructions like `ENV`, `ARG`, `RUN`, or copied files. |
| **CWE-522** | Insufficiently Protected Credentials | Credentials are stored or transmitted in a way that does not adequately protect them from unauthorized access. | Applicable when secrets are stored in plaintext within image layers, even if not directly "hardcoded" in an instruction (e.g., a config file copied into the image). |
| **CWE-1395 (Category)** / **CWE-937 / CWE-1035 / CWE-1352** | Using Component with Known Vulnerabilities | The product uses a third-party component that contains one or more publicly known vulnerabilities. | Relevant when Dockerfiles use outdated base images or install software packages (via `RUN`) with known CVEs.|
| **CWE-269** | Improper Privilege Management | The product does not properly assign, check, or restrict privileges for an actor, allowing that actor to access unintended resources. | Occurs if containers run as root (missing `USER` directive or `--privileged` flag at runtime), granting excessive permissions. |
| **CWE-276** | Incorrect Default Permissions | During installation or setup, permissions for a resource are set in a way that is overly permissive. | Can apply if files copied or created within the Dockerfile are given world-writable or world-readable permissions unnecessarily, potentially exposing them. |
| **CWE-200** | Exposure of Sensitive Information to an Unauthorized Actor | The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information. | A general category for any information leak, including secrets exposed through various Dockerfile misconfigurations. |
| **CWE-532** | Insertion of Sensitive Information into Log File | The product writes sensitive information to a log file, where it might be read by unauthorized actors. | Can occur if `RUN` commands echo secrets or if application logging within the container (configured via Dockerfile) inadvertently captures secrets. |
| **CWE-403** / **CWE-668** | Exposure of File Descriptor to Unintended Control Sphere / Exposure of Resource to Wrong Sphere | A resource, such as a file descriptor, is made accessible to an unintended control sphere, potentially leading to unauthorized actions. | Relevant if Dockerfile configurations contribute to or enable the exploitation of underlying runtime vulnerabilities, such as specific `runc` flaws like CVE-2024-21626. |

*(Data Sources: **3**)*

CVSS scores for vulnerabilities stemming from insecure Dockerfiles can be high. For example, CVE-2024-21626, a `runc` vulnerability exploitable through malicious images (which could be defined by an insecure Dockerfile), was assigned CVSS scores of 8.2 and 8.6 (High). Secret exposure vulnerabilities, if the secrets are critical, often receive Critical ratings (CVSS 9.0-10.0) due to the high impact on confidentiality and potentially integrity/availability.

The risk associated with insecure Dockerfiles is significantly amplified by the ease of distribution and reuse inherent in Docker images. A single insecurely crafted Dockerfile, when used to build an image that is subsequently shared (e.g., on public registries like Docker Hub or private organizational registries), can lead to widespread vulnerability. Other developers or automated systems might pull this compromised image, unaware of the embedded risks, and use it as a foundation for their own applications or as a base for further image derivations. This creates a cascading effect where one insecure Dockerfile can propagate vulnerabilities across a multitude of systems and organizations. The widespread availability of tools designed to scan Docker Hub and other registries for exposed secrets or known vulnerabilities means that attackers are actively searching for such insecure images. Therefore, the risk is not merely isolated to the original creator of the Dockerfile but extends to the entire ecosystem that might consume the resulting image.

## **12. Fix & Patch Guidance**

Addressing vulnerabilities stemming from insecure Dockerfiles requires a combination of adopting secure build practices, utilizing appropriate tools, and managing secrets effectively. The primary goal is to prevent sensitive information from being embedded in image layers and to minimize the attack surface of the final container image.

**Key Fixes and Best Practices:**

- **Utilize Multi-Stage Builds:** This is arguably the most critical practice, especially for compiled languages like Golang. Multi-stage builds allow for the separation of the build environment (which may require tools, SDKs, and build-time secrets) from the final runtime environment. Only the necessary compiled artifacts (e.g., the Go binary) are copied to a minimal final stage image (e.g., based on `alpine`, `distroless`, or `scratch`), leaving behind the build tools and any intermediate files or secrets.
    - *Example (Golang):*
        
        ```Dockerfile
        
        # Build stage
        FROM golang:1.21-alpine AS builder
        WORKDIR /app
        COPY go.mod go.sum./
        RUN go mod download
        COPY..
        # Handle build-time secrets securely here if needed (e.g., for private repos)
        RUN CGO_ENABLED=0 GOOS=linux go build -o /app/main./cmd/server
        
        # Final stage
        FROM alpine:latest 
        # Or FROM scratch for truly minimal images if no OS tools are needed
        WORKDIR /root/
        COPY --from=builder /app/main.
        # COPY --from=builder /app/config.prod.yaml /app/config.yaml # If config is needed
        # Ensure non-root user if not using scratch
        # RUN addgroup -S appgroup && adduser -S appuser -G appgroup
        # USER appuser
        CMD ["./main"]
        ```
        
- **Employ BuildKit Secret Mounts for Build-Time Secrets:** For secrets that are required *during* the build process (e.g., tokens to access private repositories, API keys for downloading dependencies), use BuildKit's `-secret` mount feature. These secrets are mounted into the `RUN` instruction's context temporarily and are not persisted in any image layer or the build cache.
    - *Example:*
    Build command: `docker build --secret id=mysecret,src=./local_secret_file.txt.`
    
        ```Dockerfile
        
        # syntax=docker/dockerfile:1
        FROM alpine
        RUN --mount=type=secret,id=mysecret,dst=/etc/secret_file \
            cat /etc/secret_file # This command can use the secret# The secret is not in the layer after this RUN command
        ```
        
- **Avoid Hardcoding Secrets:** Never embed secrets directly into `ENV` instructions, `ARG` values that persist into the final image, or within `RUN` command strings in the Dockerfile.
- **Use Minimal and Trusted Base Images:** Start with the smallest possible base image that meets the application's runtime requirements (e.g., `alpine`, `gcr.io/distroless/static-debian11` for Go static binaries, or `scratch` for self-contained binaries). Always pull base images from official and trusted repositories. Pin base images to specific versions or digests instead of using mutable tags like `:latest`.
- **Keep Base Images and Packages Updated:** Regularly rebuild images to incorporate the latest security patches from the base image maintainers and to update any OS packages installed within the Dockerfile. Use package manager commands like `apt-get update && apt-get upgrade -y` (or equivalent for other distributions) cautiously in the build stage, and ensure versions are pinned where possible to maintain build determinism.
- **Run as a Non-Root User:** Create a dedicated, unprivileged user within the Dockerfile and use the `USER` instruction to switch to this user before executing the application's `CMD` or `ENTRYPOINT`. Ensure that file permissions within the image are correctly set for this non-root user to access necessary application files and directories.
    - *Example:*
        
        ```Dockerfile
        
        #... (in final stage)
        RUN addgroup -S appgroup && adduser -S appuser -G appgroup
        USER appuser
        COPY --from=builder --chown=appuser:appgroup /app/mygoapp /app/mygoapp
        CMD ["/app/mygoapp"]
        ```
        
- **Utilize `.dockerignore` Effectively:** Create a comprehensive `.dockerignore` file at the root of the build context to prevent sensitive files (e.g., `.git` directory, local `.env` files, `node_modules`, IDE configurations, temporary files, local secret files) from being sent to the Docker daemon and inadvertently copied into the image.
- **Prefer `COPY` over `ADD` for Local Files:** For copying local files and directories into the image, `COPY` is generally safer and more explicit than `ADD`. `ADD` has additional features like URL fetching and auto-extraction of archives, which can introduce risks if the source is untrusted or the archive is malicious.
- **Manage Runtime Secrets Externally:** Secrets required by the application at runtime (e.g., database passwords, live API keys) should never be baked into the image. Instead, use orchestration platform secret management features (like Kubernetes Secrets or Docker Swarm Secrets), inject them as environment variables at container startup (from a secure source like a vault), or have the application fetch them from a dedicated secrets management service (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) upon initialization.

The most effective fixes are those that prevent secrets from ever becoming part of the image layers destined for production. Multi-stage builds achieve this by ensuring that build-time secrets and development tools used in an initial stage are entirely absent from the lean, final runtime stage; the secret effectively never makes it into the production image's layers. Similarly, BuildKit's `--secret` mount provides secrets to a `RUN` command on a temporary basis without writing them to the layer, thus avoiding layer persistence. For runtime secrets, externalizing them through mechanisms like Docker secrets or HashiCorp Vault means they are injected into the container only when it's running, and are not stored within the image itself.These methods fundamentally address the problem of secret persistence in image layers, which is a more robust solution than attempting to remove a secret in a later layer (an action that doesn't truly erase the data from the image's history).

**Table 5: Secure Dockerfile Practices for Secret Management & General Security**

| **Practice** | **Description** | **Dockerfile Example/Instruction** | **Security Benefit** |
| --- | --- | --- | --- |
| Multi-Stage Builds | Separate build environment from runtime, copying only necessary artifacts to a minimal final image. | `FROM golang:alpine AS builder... COPY --from=builder /app/binary /app/binary` | Reduces image size, removes build tools/secrets from final image, minimizes attack surface. |
| BuildKit Secret Mounts | Securely pass build-time secrets to `RUN` commands without embedding them in layers. | `RUN --mount=type=secret,id=myapitoken,dst=/tmp/token cat /tmp/token` | Secrets are not persisted in image layers or build cache. |
| Use Non-Root User | Create and switch to an unprivileged user for running the application. | `RUN addgroup -S app && adduser -S app -G app USER app` | Limits potential damage if the container is compromised (Principle of Least Privilege). |
| Minimal Base Images | Use small, trusted base images like `alpine`, `distroless`, or `scratch`. | `FROM alpine:latest` or `FROM gcr.io/distroless/static-debian11` | Reduces attack surface by including fewer packages and vulnerabilities. |
| Pin Base Image Versions | Use specific version tags or digests for base images instead of `latest`. | `FROM ubuntu:22.04` or `FROM alpine@sha256:...` | Ensures build reproducibility and prevents accidental use of vulnerable newer versions. |
| Effective `.dockerignore` | Prevent sensitive files (e.g., `.git`, `.env`, local configs) from being included in the build context and image. | Create `.dockerignore` file listing patterns to exclude. | Avoids accidental leakage of local secrets and unnecessary files into the image. |
| Prefer `COPY` over `ADD` | Use `COPY` for local files/directories; `ADD` has risky auto-extraction and remote URL features. | `COPY./app /app` instead of `ADD./app /app` | Reduces risk of unintended behavior from `ADD`'s extra capabilities. |
| Externalize Runtime Secrets | Use orchestrator secrets (Kubernetes/Swarm Secrets) or a vault system for secrets needed at runtime. | Configure container orchestrator to inject secrets as env vars or mounted files. | Secrets are not stored in the image; managed securely by external systems.|

*(Data Sources: **1**)*

## **13. Scope and Impact**

The scope of vulnerabilities introduced by insecure Dockerfiles is extensive, potentially affecting the confidentiality, integrity, and availability of the containerized application, its data, and even the underlying host system and connected services. The impact can range from minor information disclosure to complete system compromise.

- **Confidentiality:** This is often the most direct and severe impact. Exposed secrets such as API keys, database credentials, private keys, or personally identifiable information (PII) can lead to significant data breaches. Attackers gaining access to these secrets can read sensitive application data, user information, or proprietary business logic. Research indicates that a notable percentage of images on public registries like DockerHub have been found to leak secrets, including private keys and API tokens. The CodeCov supply chain attack, for example, originated from a secret extracted from a Docker image.
    
- **Integrity:** If exposed secrets grant write access to databases, configuration systems, or code repositories, attackers can modify critical data, alter system configurations to facilitate further attacks, or inject malicious code into the application or its dependencies. Vulnerable base images or improperly managed permissions might also allow attackers to modify the container's filesystem or application binaries.
    
- **Availability:** Attackers could leverage compromised credentials or vulnerabilities to disrupt services, delete critical data, or exhaust resources, leading to denial-of-service (DoS) conditions. For instance, if an exposed API key controls critical infrastructure components or has high usage quotas, an attacker could abuse it to shut down services or incur significant costs.
    
- **Host Compromise:** This represents one of the most severe impacts. If an insecure Dockerfile leads to a container running with excessive privileges (e.g., as root, or with the `-privileged` flag), or if the base image contains a container escape vulnerability, an attacker who gains initial access to the container might be able to break out and compromise the underlying host system. This grants the attacker control over all other containers on that host and potentially the wider network.
    
- **Impact on Golang Applications:**
    - **Inclusion of Go Toolchain/Build Dependencies:** If multi-stage builds are not properly implemented, the final Golang application image may contain the Go compiler, source code, and numerous build-time dependencies. This unnecessarily increases the image size, but more critically, it expands the attack surface. Vulnerabilities in these development tools or unused dependencies could be exploited by an attacker who gains execution within the container.

    - **Exposure of Go Application Configuration/Secrets:** Golang applications often use configuration files (e.g., `config.yaml` for Viper, JSON files) to store settings, including database connection strings or API keys. If these files are copied into the image via insecure `COPY` instructions without proper secret management, any sensitive data within them is exposed.
        
    - **Static Linking and Base OS Vulnerabilities:** While Golang's static linking capabilities can produce self-contained binaries, this doesn't eliminate all risks from the base OS image. If CGO is used, the Go application will link against shared libraries from the base OS (e.g., `glibc`). Vulnerabilities in these OS libraries can still affect the Go application or the container's security. Even fully static binaries rely on the host kernel's system calls, so kernel vulnerabilities remain a threat.

        
    - **Secrets in Go Source Code:** If secrets are hardcoded into the Golang source files themselves (a generally discouraged practice) and the source code is copied into an intermediate build stage (or, worse, the final image), these secrets become part of the image layers.

The overall scope of impact is often not limited to the initially compromised container. Due to the interconnected nature of modern applications and infrastructure, an attacker leveraging an exposed secret or a container breakout can potentially move laterally to other systems, escalate privileges further, and cause widespread damage. The ease of distributing Docker images means that a single insecure Dockerfile used to build a popular base image or application can propagate vulnerabilities across countless downstream users and organizations, turning a localized mistake into a systemic risk.

## **14. Remediation Recommendation**

A comprehensive remediation strategy for insecure Dockerfiles involves a multi-layered approach that integrates secure development practices, automated tooling within the CI/CD pipeline, robust secret management, and ongoing vigilance.

- **CI/CD Integration for Security:**
    - **Automated Scanning:** Integrate Dockerfile linters (e.g., Hadolint) and image vulnerability scanners (e.g., Trivy, Snyk, Docker Scout, Clair) directly into Continuous Integration/Continuous Deployment (CI/CD) pipelines. These tools can automatically detect misconfigurations, hardcoded secrets, and known vulnerabilities in base images or dependencies before an image is pushed to a registry or deployed. For example, SonarQube can be configured to scan Dockerfiles for hardcoded secrets , and tools like GitLab CI and AWS Inspector Sbomgen offer container scanning capabilities.

        
    - **Build Failure Policies:** Configure CI/CD pipelines to fail builds if critical or high-severity vulnerabilities or significant misconfigurations are detected, preventing insecure images from progressing.
        
- **Developer Training and Awareness:**
    - Educate developers on secure Dockerfile authoring best practices, the principles of Docker's layered architecture, effective secret management techniques (both build-time and runtime), and the importance of minimizing attack surfaces. OWASP Docker Top 10 provides valuable guidance in this area.
        
- **Secure Secret Management:**
    - **Build-Time Secrets:** Utilize Docker BuildKit's `-secret` mount functionality to securely pass secrets required during the build process without embedding them in image layers.
        
    - **Runtime Secrets:** Employ dedicated secrets management systems such as HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or orchestrator-native solutions like Kubernetes Secrets or Docker Swarm Secrets for secrets needed by the application at runtime. Applications should fetch these secrets upon startup or as needed, rather than having them pre-loaded in the image.
        
- **Image Management Best Practices:**
    - **Regular Updates and Patching:** Implement a consistent process for regularly updating base images to their latest patched versions and rebuilding application images to incorporate these updates and any patches for OS packages or application dependencies. Monitor vulnerability feeds for relevant CVEs.
        
    - **Minimal Base Images:** Prefer minimal base images (e.g., `alpine`, `distroless`, `scratch`) to reduce the attack surface.

    - **Trusted Sources:** Only use base images from official and trusted repositories.
        
    - **Version Pinning:** Pin base image versions and versions of packages installed within the Dockerfile to ensure deterministic and secure builds.
        
- **Principle of Least Privilege:**
    - **Non-Root Execution:** Always configure containers to run application processes as a non-root user using the `USER` directive in the Dockerfile.
        
    - **Drop Unnecessary Capabilities:** Use `-cap-drop=all` and then selectively add only the essential capabilities required by the container (`-cap-add=...`).
        
    - **Read-Only Filesystem:** Where feasible, run containers with a read-only root filesystem (`-read-only` flag in `docker run` or equivalent in orchestrators) and use volumes for any paths that require write access.
        
- **Image Integrity and Provenance:**
    - Utilize image signing and verification mechanisms (e.g., Docker Content Trust, Notary) to ensure the authenticity and integrity of images pulled from registries.
        
- **Network Security:**
    - Implement network segmentation and firewall rules to restrict inter-container communication and limit the exposure of container ports to only necessary networks or services.

A holistic approach is paramount for effective remediation. Relying on a single tool or practice is insufficient. Instead, organizations should foster a security-conscious culture through developer education, implement automated security checks throughout the development lifecycle using tools like linters and scanners integrated into CI/CD pipelines , and adopt robust, specialized solutions for challenges like secret management. The continuous discovery of new vulnerabilities necessitates ongoing processes for updating base images and dependencies. Consistently applying the principle of least privilege in all aspects of container configuration further hardens the environment. Remediation, therefore, is not a one-time fix for a specific Dockerfile but an ongoing commitment to a secure software development lifecycle that incorporates these multiple layers of defense.

## **15. Summary**

Insecure Dockerfiles, particularly those that lead to the exposure of secrets, represent a critical vulnerability in modern containerized application development. These insecurities often arise from common misconfigurations such as hardcoding credentials in `ENV` variables or `RUN` commands, improperly using `COPY` or `ADD` to include sensitive files, utilizing outdated or untrusted base images, and failing to run containers as non-root users. For Golang applications, specific risks include embedding the Go toolchain and build dependencies in final production images due to a lack of multi-stage builds, and the exposure of application-specific configuration files containing secrets.

The impact of such vulnerabilities can be severe, ranging from unauthorized data access and data breaches to full system compromise and lateral movement within an organization's infrastructure. Attackers can leverage exposed secrets to gain access to databases, cloud services, and other critical systems.

Effective mitigation relies on a multi-pronged strategy. Key remediation steps include the rigorous use of multi-stage builds to create minimal, production-ready images, the adoption of secure secret management practices (such as BuildKit secret mounts for build-time secrets and external vaults or orchestrator secrets for runtime), and consistently running containers as non-privileged users. Furthermore, integrating automated security scanning tools (linters and vulnerability scanners) into CI/CD pipelines, along with regular updates of base images and dependencies, is crucial for proactive vulnerability management.

The ease of use associated with Docker can sometimes obscure the underlying complexities and security responsibilities that come with containerization. Developers may inadvertently create insecure Dockerfiles by following simplistic examples or prioritizing rapid deployment over thorough security vetting. Therefore, fostering a security-first mindset, providing ongoing developer education, and implementing tools and processes that make secure practices the default path are essential to mitigating the risks associated with insecure Dockerfiles.

## **16. References**

- **12** Sysdig. (n.d.). *Top 20 Dockerfile best practices*. Sysdig.
- **17** Wiz. (2025, March 18). *Docker Container Security Best Practices*. Wiz Academy.
- **29** OWASP. (n.d.). *Container Security: Implementation Do's and Don'ts*. OWASP Developer Guide.
- **9** OWASP. (n.d.). *NodeJS Docker Cheat Sheet*. OWASP Cheat Sheet Series.
- **32** Docker Inc. (n.d.). *Manage sensitive data with Docker secrets*. Docker Documentation.
- **1** Truffle Security. (2023, September 11). *How Secrets Leak Out of Docker Images*. Truffle Security Blog.
- **5** Docker Inc. (2025). *Docker Scout image analysis*. Docker Documentation.
- **3** Docker Inc. (n.d.). *Vulnerability Report: CVE-2024-21626*. Docker Scout.
- **38** Docker Inc. (2024, February 1). *Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby*. Docker Blog.
- **13** idsulik. (2024, October 29). *Container Anti-Patterns: Common Docker Mistakes and How to Avoid Them*. dev.to.
- **10** eCloudControl. (n.d.). *Mistakes To Avoid In Docker Images With Reason And Solution*. eCloudControl.
- **33** Fluid Attacks. (n.d.). *Criteria fixes: Docker*. Fluid Attacks Docs.
- **36** Red Hat. (n.d.). *Detecting Docker exploits and vulnerabilities: Your how-to guide*. Red Hat Blog.
- **40** Patel, A. (2025, April 3). *Why Docker Scout Is Changing How Developers Scan for Vulnerabilities*. The New Stack.
- **65** YouTube. (n.d.). *Docker Scout - Build More Secure Container Images*.
- **16** Microsoft ISE Team. (2025, March 20). *Hidden Risks of Docker Build-Time Arguments and How to Secure Your Secrets*. Microsoft Security Developer Blog.
- **2** GitGuardian. (2025, May 15). *Fresh From The Docks: Uncovering 100,000 Valid Secrets in DockerHub*. GitGuardian Blog.
- **11** Hostinger. (n.d.). *How to use Docker build secrets to securely pass sensitive data*. Hostinger Tutorials.
- **27** OWASP. (n.d.). *Use of Hard-coded Password*. OWASP Community.
- **28** SonarQube. (n.d.). *Docker rule: Credentials should not be hard-coded*. SonarQube Rules.
- **51** CWE/CAPEC. (n.d.). *CWE-1395: Use of Component with Known Vulnerabilities*. MITRE CWE.
- **35** Avesnetsec. (n.d.). *CVE-2025-3224 Vulnerability Details*. Avesnetsec.
- **54** NVD. (n.d.). *CVE-2025-3224 Detail*. National Vulnerability Database.
- **14** Augmented Mind. (2024, June 12). *Optimize Docker Image Security*. Augmented Mind Blog.
- **31** Scalable Backend. (n.d.). *Stop using insecure and inefficient Dockerfiles*. Scalable Backend Blog.
- **59** Earthly. (2024, January 10). *How to Handle Secrets with BuildKit*. Earthly Blog.
- **66** GitHub. (n.d.). *Issue 13490: Handling secrets in Dockerfiles*. Moby Project.
- **61** GitLab. (n.d.). *Container Scanning*. GitLab Documentation.
- **62** AWS. (n.d.). *Using Sbomgen Dockerfile checks*. AWS Inspector Documentation.
- **30** Opster. (n.d.). *Docker Security Guide*. Opster.
- **49** Snyk. (n.d.). *Docker Security Scanning Explained*. Snyk.
- **41** Sysdig. (n.d.). *12 container image scanning best practices*. Sysdig.
- **5** Docker Inc. (2025). *Vulnerability severity assessment*. Docker Scout Documentation.
- **4** SentinelOne. (n.d.). *What is Container Image Security?*. SentinelOne Cybersecurity 101.
- **67** Armo. (n.d.). *Vulnerability Base Images CVE*. ARMOsec Blog.
- **34** Sysdig. (n.d.). *7 Docker Security Vulnerabilities and How to Prevent Them*. Sysdig Blog.
- **37** Infosecurity Magazine. (n.d.). *Researchers Detail Public PoC for Critical Docker Flaw*.
- **32** Docker Inc. (n.d.). *Manage sensitive data with Docker secrets* (Swarm). Docker Documentation.
- **42** Hadolint. (n.d.). *Hadolint - Dockerfile linter*. Linux Command Library.
- **43** Spot by NetApp. (n.d.). *Docker Security: 6 Best Practices with Code Examples*. Spot.io.
- **17** Wiz. (2025, March 18). *Impact of Insecure Dockerfiles on Golang Applications*. Wiz Academy.
- **12** Sysdig. (n.d.). *Dockerfile Best Practices for Golang Applications*. Sysdig.
- **17** Wiz. (n.d.). *Golang Dockerfile Security Best Practices*. Wiz Academy.
- **12** Sysdig. (n.d.). *Dockerfile Best Practices (General)*. Sysdig.
- **18** MoldStud. (n.d.). *Best Practices Guide: Creating Efficient Docker Images for Go Applications*. MoldStud.
- **19** Blacksmith. (n.d.). *Understanding Multi-Stage Docker Builds*. Blacksmith Blog.
- **21** Stack Overflow. (2022, September 25). *Fixing security vulnerabilities in Docker image*.
- **22** Google Groups. (n.d.). *Static linking as a security deal-breaker?*. golang-nuts.
- **60** Docker Inc. (n.d.). *Build secrets*. Docker Build Documentation.
- **32** Docker Inc. (n.d.). *Manage sensitive data with Docker secrets* (Swarm context). Docker Documentation.
- **58** Prisma Cloud. (n.d.). *CVSS Scoring*. Prisma Cloud Documentation.
- **6** Snyk. (n.d.). *Severity levels*. Snyk Documentation.
- **44** BellSoft. (n.d.). *How to Use a Dockerfile Linter*. BellSoft Blog.
- **45** DevToDevOps. (n.d.). *A Comprehensive Guide to Dockerfile Linting with Hadolint*. DevToDevOps.
- **55** Palo Alto Networks. (n.d.). *Insecure System Configuration CICD-SEC-7*. Palo Alto Networks Cyberpedia.
- **56** Mend. (n.d.). *OWASP Top 10 CWE Coverage*. Mend Documentation.
- **17** Snyk. (n.d.). *Test Docker Image: golang:latest*. Snyk.
- **23** Snyk. (n.d.). *Vulnerability: glibc/libc-bin in golang:latest*. Snyk.
- **63** QwietAI. (2023, September 6). *An Introduction to the OWASP Docker Top 10*. QwietAI Blog.
- **44** BellSoft. (n.d.). *Hadolint Rules and Severity Levels*. BellSoft Blog.
- **46** DevToDevOps. (n.d.). *Hadolint Rule Codes and Severity*. DevToDevOps.
- **24** TechSchool.Guru. (n.d.). *A Guide to Configuration Management in Go with Viper*. dev.to.
- **68** YouTube. (n.d.). *Secure Golang Viper Configuration in Docker*.
- **50** Snyk. (n.d.). *Fix vulnerable base images in your Dockerfile*. Snyk Documentation.
- **69** SEI CMU. (n.d.). *An Introduction to Hardening Docker Images*. SEI Blog.
- **7** FIRST.org. (n.d.). *Common Vulnerability Scoring System v3.1: Specification Document*.
- **64** OWASP. (n.d.). *OWASP Docker Top 10*. OWASP.
- **15** OWASP. (n.d.). *Docker Security Cheat Sheet*. OWASP Cheat Sheet Series.
- **12** Sysdig. (n.d.). *Top 20 Dockerfile best practices*. Sysdig.
- **44** BellSoft. (n.d.). *How to Use a Dockerfile Linter*. BellSoft Blog.
- **25** benchkram. (n.d.). *Ultimate Config for Golang Apps*. benchkram.de.
- **26** Reddit. (n.d.). *How do you store config values?*. r/golang.
- **57** Acunetix. (n.d.). *Vulnerability Categories - Configuration*. Acunetix.
- **52** Docker Scout. (n.d.). *Vulnerability Report: CVE-2024-23653*. Docker Scout.
- **5** Docker Inc. (2025). *Vulnerability severity assessment*. Docker Scout Documentation.
- **8** Balbix. (n.d.). *What Are CVSS Base Scores?*. Balbix Insights.
- **19** Blacksmith. (n.d.). *Understanding Multi-Stage Docker Builds for Golang*. Blacksmith Blog.
- **39** SRE Panchanan. (n.d.). *Deep Dive into Multistage Dockerfile with a Golang App*. dev.to.
- **9** OWASP. (n.d.). *NodeJS Docker Cheat Sheet*. OWASP Cheat Sheet Series.
- **1** Truffle Security. (2023, September 11). *How Secrets Leak Out of Docker Images*. Truffle Security Blog.
- **38** Docker Inc. (2024, February 1). *Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby*. Docker Blog.
- **5** Docker Inc. (2025). *Docker Scout image analysis*. Docker Documentation.
- **16** Microsoft ISE Team. (2025, March 20). *Hidden Risks of Docker Build-Time Arguments and How to Secure Your Secrets*. Microsoft Security Developer Blog.
- **29** OWASP. (n.d.). *Container Security: Implementation Do's and Don'ts*. OWASP Developer Guide.
- **17** Wiz. (2025, March 18). *Docker Container Security Best Practices*. Wiz Academy.
- **13** idsulik. (2024, October 29). *Container Anti-Patterns: Common Docker Mistakes and How to Avoid Them*. dev.to.
- **2** GitGuardian. (2025, May 15). *Fresh From The Docks: Uncovering 100,000 Valid Secrets in DockerHub*. GitGuardian Blog.
- **59** Earthly. (2024, January 10). *How to Handle Secrets with BuildKit*. Earthly Blog.
- **28** SonarQube. (n.d.). *Docker rule: Credentials should not be hard-coded*. SonarQube Rules.
- **14** Augmented Mind. (2024, June 12). *Optimize Docker Image Security*. Augmented Mind Blog.
- **9** OWASP. (n.d.). *NodeJS Docker Cheat Sheet*. OWASP Cheat Sheet Series.
- **47** GitHub. (2022, November 9). *Hadolint - Dockerfile linter*. Hadolint Repository.
- **53** CWE/CAPEC. (2025, April 3). *CWE-1035: OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities*. MITRE CWE.
- **70** NVD. (2024, November 21). *CVE-2024-21626 Detail*. National Vulnerability Database.
- **1** Truffle Security. (2023, September 11). *How Secrets Leak Out of Docker Images (PoC with Dive)*. Truffle Security Blog.
- **20** GeeksforGeeks. (2023, March 30). *How to Dockerize a Golang Application*.
- **20** GeeksforGeeks. (2023, March 30). *Impacts of Including Go Compiler in Production Docker Image*.
- **47** GitHub. (2022, November 9). *Hadolint - Dockerfile linter*. Hadolint Repository.
- **47** GitHub. (2022, November 9). *Hadolint - Dockerfile linter*. Hadolint Repository.
- **48** GitHub. (n.d.). *Hadolint README*. Hadolint Repository.
- **15** OWASP. (n.d.). *Docker Security Cheat Sheet*. OWASP Cheat Sheet Series.# Analysis of Insecure Dockerfile Practices and Secret Exposure in Golang Applications

klkllkl