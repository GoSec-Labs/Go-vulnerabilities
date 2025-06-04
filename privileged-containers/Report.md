## Vulnerability Title
Privileged Containers in Production (short: privileged-containers)

### Severity Rating
**Critical🔴** (potentially High to Critical depending on context and other layered defenses). Running privileged containers in production effectively nullifies many of the security benefits of containerization, making host compromise trivial if the container is breached.

### Description
A "privileged container" is a container started with elevated capabilities that allow it to access all devices on the host system, manipulate the host's kernel, and effectively bypass many of the isolation mechanisms that typically separate a container from its underlying host. When a Go application (or any application) runs within such a container in a production environment, it presents an extremely high risk. If an attacker gains control of the application or the container itself, they can easily escalate privileges to the host system, leading to a complete compromise of the host and potentially other containers running on it.

### Technical Description (for security pros)
Containers, by default, run with a limited set of Linux capabilities and namespaces, providing a degree of isolation from the host kernel. When a container is run in "privileged" mode (e.g., using `docker run --privileged` or `securityContext.privileged: true` in Kubernetes), it gains nearly all the capabilities of the host system. This includes, but is not limited to:

* **`CAP_SYS_ADMIN`**: Allows for a wide range of administrative operations, including mounting host file systems, loading kernel modules, and manipulating namespaces. This capability is often described as "the new root" within containers.
* **Direct device access**: The container can access all devices (`/dev`) on the host, including disk devices, which can be mounted and manipulated.
* **Bypass of cgroup and seccomp limitations**: Privileged containers are not subject to the same device cgroup controller limitations and can bypass default seccomp profiles, which usually restrict system calls.
* **Kernel module loading**: An attacker gaining access to a privileged container could load malicious kernel modules, giving them full control over the host.

An attacker who compromises a Go application running in such a container can use these elevated privileges to:

* **Container Escape**: Break out of the containerized environment to gain root access on the host machine.
* **Lateral Movement**: Access and compromise other containers or services on the same host.
* **Data Exfiltration**: Access sensitive data stored on the host's file system or in other containers.
* **Denial of Service**: Manipulate host resources to cause service disruption.
* **Persistence**: Establish persistent backdoors on the host.

### Common Mistakes That Cause This
* **Misunderstanding of Container Security**: Developers or operations teams might not fully grasp the security implications of `privileged` mode, assuming it's simply "more permissions" rather than a security bypass.
* **Convenience over Security**: Using `privileged` mode to quickly resolve permission issues or for applications that genuinely need broad host access (e.g., container-in-container scenarios, security tools, or system-level agents) without proper segmentation or additional hardening.
* **"Works on my machine" mentality**: Privileged mode might be used in development/testing for ease, and then inadvertently carried over into production.
* **Lack of granular capability management**: Instead of granting specific, minimal capabilities, the `privileged` flag is used as a blunt instrument.
* **Default configurations**: Not explicitly disabling privileged mode in orchestration manifests (e.g., Kubernetes Pod Security Standards not enforced).
* **Legacy applications**: Containerizing older applications that were not designed with fine-grained permissions in mind and require extensive host access.

### Exploitation Goals
* **Host Compromise**: Gaining root access to the underlying host operating system.
* **Lateral Movement**: Accessing and compromising other containers or applications running on the same host.
* **Data Theft**: Exfiltrating sensitive data from the host or other containers.
* **Resource Hijacking**: Using host resources (CPU, network) for malicious activities like cryptocurrency mining.
* **Supply Chain Attacks**: Injecting malicious code or backdoors into the host system that can affect other deployments.
* **Persistence**: Establishing covert access to the host for future exploitation.

### Affected Components or Files
* **Container Runtime Configuration**: `docker run --privileged` flag, or equivalent for other runtimes.
* **Orchestration Manifests**: Kubernetes `Pod.spec.containers[].securityContext.privileged: true`.
* **Go Application**: The Go binary itself, though the vulnerability lies in its deployment environment rather than the Go code logic directly. Any Go application deployed in such a container is vulnerable.

### Vulnerable Code Snippet
(This is a configuration vulnerability, not a code vulnerability within the Go application itself. The "vulnerable code snippet" refers to the configuration of the container.)

**Docker CLI (Command Line Interface):**
```bash
docker run --privileged -p 8080:8080 my-golang-app:latest
```

**Kubernetes Pod YAML:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privileged-golang-pod
spec:
  containers:
  - name: golang-app
    image: my-golang-app:latest
    securityContext:
      privileged: true # This is the vulnerability
    ports:
    - containerPort: 8080
```

### Detection Steps
1.  **Scan container orchestration manifests**: Use tools like `kube-bench`, `kube-hunter`, Open Policy Agent (OPA) Gatekeeper, or cloud security posture management (CSPM) tools to check for `privileged: true` in Kubernetes manifests.
2.  **Scan running containers**: Use container security tools (e.g., Aqua Security, Sysdig, Lacework) that can identify running containers with elevated privileges.
3.  **Audit Docker/Containerd configurations**: Manually inspect Docker daemon configurations and container run commands for the `--privileged` flag.
4.  **Check `proc` filesystem from within a container**: Inside a running container, `cat /proc/1/cgroup` can indicate if it's a container, and checking `/dev/` contents or attempting `fdisk -l` can reveal privileged access. This is more of a post-exploitation check, but can be used for verification.
5.  **Runtime monitoring**: Look for anomalous activities like attempts to mount host directories, access host devices, or load kernel modules from within a container.

### Proof of Concept (PoC)
(Assuming an attacker has gained shell access to the privileged container where the Go application runs)

1.  **Gain shell access to the privileged container:** This often occurs through an application vulnerability (e.g., command injection, deserialization vulnerability, exposed API endpoint) in the Go application itself.
2.  **Verify privileged status:**
    ```bash
    root@privileged-container:/app# ls -la /dev/sda
    brw-rw---- 1 root disk 8, 0 Jan 1 00:00 /dev/sda
    # The presence of block devices like /dev/sda indicates device access.
    # Also, try:
    root@privileged-container:/app# fdisk -l
    # This command would list host disk partitions if privileged.
    ```
3.  **Mount the host filesystem (container escape):**
    ```bash
    root@privileged-container:/app# mkdir /host_root
    root@privileged-container:/app# mount /dev/sda1 /host_root
    # Assuming /dev/sda1 is the root partition of the host. An attacker would need to discover the correct device.
    root@privileged-container:/app# ls /host_root
    # This should show the host's root directory contents (e.g., etc, home, usr, var).
    ```
4.  **Achieve root on host (via `chroot`):**
    ```bash
    root@privileged-container:/app# chroot /host_root /bin/bash
    # You are now in a root shell on the host system.
    host-root@host-machine:/# whoami
    root
    host-root@host-machine:/# hostname
    # This will be the host machine's hostname, not the container's.
    ```
This PoC demonstrates a full host compromise, highlighting the extreme risk.

### Risk Classification
* **OWASP Top 10:** A05:2021 - Security Misconfiguration (specifically container misconfiguration).
* **MITRE ATT&CK:** T1611 - Container Escape; T1068 - Exploitation for Privilege Escalation.
* **CWE:** CWE-276: Incorrect Default Permissions; CWE-732: Incorrect Permission Assignment for Critical Resource; CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag (broadly, misconfiguration leading to sensitive data exposure).

### Fix & Patch Guidance
The fix is to **eliminate the use of privileged containers in production environments** for applications that do not strictly require it (which is most applications, including typical Go web services or APIs).

1.  **Remove `privileged: true`**:
    * For Docker, remove the `--privileged` flag from `docker run` commands.
    * For Kubernetes, remove `securityContext.privileged: true` from Pod and Container definitions in YAML manifests.
2.  **Apply Least Privilege**: Instead of `privileged`, grant only the *specific Linux capabilities* (e.g., `CAP_NET_BIND_SERVICE` for binding to low ports) that the Go application absolutely needs using `cap_add` and `cap_drop`.
3.  **Run as Non-Root User**: Configure the container to run the Go application as a non-root user. This is a fundamental container security best practice.
    * In Dockerfile: `USER appuser` (after creating `appuser`).
    * In Kubernetes: `securityContext.runAsNonRoot: true` and `securityContext.runAsUser: <non-root-uid>`.
4.  **Implement Pod Security Standards (PSS) in Kubernetes**: Enforce policies at the cluster level to prevent privileged containers from being deployed. The `Restricted` PSS profile specifically disallows privileged containers.
5.  **Utilize Security Contexts**: Beyond `privileged`, use other `securityContext` options to harden containers, such as `allowPrivilegeEscalation: false` and `seccompProfile`.
6.  **Immutable Infrastructure**: Ensure that container images are built securely and not modified at runtime in production.
7.  **Automated Security Scanning**: Integrate container image scanners and Kubernetes manifest scanners into CI/CD pipelines to detect misconfigurations early.

### Scope and Impact
* **Scope**: Any Go application (or any containerized application) deployed in a Docker, Kubernetes, or other container runtime environment where the container is explicitly granted "privileged" access.
* **Impact**:
    * **Direct Host Compromise**: The most severe impact, leading to root-level control over the host machine.
    * **Breach of Isolation**: Complete breakdown of container isolation, allowing an attacker to move freely between containers on the same host.
    * **Data Breach**: Access to all data on the host, including sensitive application data, configuration files, and credentials.
    * **Service Disruption**: Ability to stop, restart, or tamper with critical host services and other workloads.
    * **Supply Chain Contamination**: If the compromised host is used for building or distributing other artifacts, it can lead to further supply chain attacks.

### Remediation Recommendation
**Immediately identify and eliminate all privileged containers** running your Go applications in production environments. Prioritize applications handling sensitive data or exposed to external networks. For cases where some elevated privileges are genuinely required (which should be rare for most Go applications), apply the principle of least privilege by granting only the necessary capabilities instead of the full `privileged` flag. Enforce security policies at the cluster level (e.g., Kubernetes PSS) to prevent future deployments of privileged containers. Regularly audit your container configurations as part of your security development lifecycle (SDL).

### Summary
Running Go applications in privileged containers in production is a critical security misconfiguration that undermines the fundamental isolation provided by container technology. It allows an attacker who compromises the container to easily escalate privileges to the host system, leading to full control over the underlying infrastructure and all other workloads. The primary remediation is to remove the `privileged` flag and instead apply the principle of least privilege by granting only specific, necessary capabilities, coupled with running containers as non-root users and enforcing strict security policies.

### References
* **Docker Security Best Practices**: `https://docs.docker.com/engine/security/security/`
* **Kubernetes Pod Security Standards**: `https://kubernetes.io/docs/concepts/security/pod-security-standards/`
* **OWASP Container Security Cheat Sheet**: `https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html`
* **MITRE ATT&CK - Container Escape (T1611)**: `https://attack.mitre.org/techniques/T1611/`
* **MITRE ATT&CK - Exploitation for Privilege Escalation (T1068)**: `https://attack.mitre.org/techniques/T1068/`
* **Linux Capabilities**: `https://man7.org/linux/man-pages/man7/capabilities.7.html`