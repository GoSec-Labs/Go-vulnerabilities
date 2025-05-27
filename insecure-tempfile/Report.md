# Golang Vulnerability Report: Insecure Temporary File Creation

## Vulnerability Title

Insecure Temporary File Creation (CWE-377, CWE-378, CWE-379)

## Severity Rating

The vulnerability of insecure temporary file creation, while distinct from issues like SQL Injection which often receive Critical🔴 severity ratings (CVSS 9.0-10.0) , can still lead to severe consequences. Its specific impact and exploitability determine the Common Vulnerability Scoring System (CVSS) score. For instance, a notable instance of this vulnerability is identified as CVE-2024-45339, affecting the `github.com/golang/glog` package.

Initially, this vulnerability was described with a "Moderate severity" by GitHub. However, a detailed CVSS v3.1 analysis provides a more precise and often higher assessment of the risk. The CVSS v3.1 vector for CVE-2024-45339 is `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`. This vector translates to a base score of 7.8, which falls squarely into the "High" severity category (7.0-8.9) according to CVSS definitions.

This difference between a qualitative "Moderate" label and a calculated "High" CVSS score highlights a crucial aspect of vulnerability assessment. High-level qualitative descriptions, while useful for quick categorization, can sometimes underestimate the true risk. A detailed, metric-based evaluation like CVSS offers a more objective and granular understanding of exploitability and potential damage, which is essential for accurate risk prioritization and resource allocation. Security professionals rely on such detailed metrics to make informed decisions about remediation efforts and to communicate the true impact to stakeholders.

The breakdown of the CVSS v3.1 metrics for CVE-2024-45339 is provided below:

| CVSS Metric | Value | Description |
| --- | --- | --- |
| **Attack Vector (AV)** | Local (L) | The vulnerability requires local access to the system, as an unprivileged attacker needs to pre-create a symbolic link or predict a log file path. |
| **Attack Complexity (AC)** | Low (L) | The attack is relatively easy to perform, typically involving predicting a file path and creating a symlink. |
| **Privileges Required (PR)** | Low (L) | The attacker needs only unprivileged access to exploit this vulnerability. |
| **User Interaction (UI)** | None (N) | No user interaction is required from the victim for the exploit to succeed. |
| **Scope (S)** | Unchanged (U) | The vulnerability's impact remains within the same security authority as the vulnerable component. |
| **Confidentiality (C)** | High (H) | Exploitation can lead to unauthorized access to sensitive information. |
| **Integrity (I)** | High (H) | The attacker can achieve overwriting of sensitive files or data tampering. |
| **Availability (A)** | High (H) | The vulnerability can result in data loss or a denial of service condition. |
| **Base Score** | **7.8** | **High** |

## Description

Insecure temporary file creation refers to a class of vulnerabilities where an application generates transient files in a manner that makes them susceptible to unauthorized access, modification, or deletion by other users or processes on the same system. This vulnerability is not a singular, atomic flaw but rather encompasses a spectrum of related issues that arise from inadequate temporary file handling practices.

The core problem stems from a failure to ensure the uniqueness, confidentiality, and integrity of temporary files throughout their lifecycle. This typically results from a combination of factors, including: predictable file names that can be guessed by an attacker; overly permissive file permissions that allow unintended actors to read or write to the file; and susceptibility to Time-of-Check to Time-of-Use (TOCTOU) race conditions, where an attacker can manipulate the file system between a security check and the actual file operation.

Attackers can exploit these weaknesses by predicting the temporary file paths, pre-creating files or symbolic links (symlinks) to sensitive system files, or manipulating file contents before the legitimate application uses them. The ability to redirect file operations via symlinks is a particularly potent exploitation vector, as it transforms a seemingly isolated file handling issue into a broader systemic risk.

This class of vulnerabilities is broadly categorized under Common Weakness Enumeration (CWE) 377, "Insecure Temporary File Creation." Specific manifestations often map to CWE-378, "Creation of Temporary File With Insecure Permissions," which focuses on the access rights of the file itself, and CWE-379, "Creation of Temporary File in Directory with Insecure Permissions," which pertains to the security of the directory where the temporary file is placed. The consistent presence of these multiple CWEs underscores that addressing this vulnerability requires a holistic approach, considering all facets of temporary file management, rather than focusing on a single, isolated fix.

## Technical Description (for security pros)

Understanding insecure temporary file creation requires a detailed examination of the underlying mechanisms that enable its exploitation. These vulnerabilities typically arise from an interplay of predictable naming, insecure permissions, and timing-based attacks.

### Predictable File Names (CWE-377)

Applications that generate temporary file names using easily guessable patterns, such as sequential numbers, non-random timestamps, or hardcoded names (e.g., `tempfile.txt`), create a significant window of opportunity for attackers. An attacker can predict the name of the temporary file that a legitimate, potentially privileged, process intends to create. Before the legitimate process creates its file, the attacker can pre-create a file or a symbolic link (symlink) with that exact predicted name. This leads to a file collision, where the legitimate application either fails to create its file or, more dangerously, is tricked into operating on the attacker-controlled file or the target of the attacker's symlink.

### Insecure File and Directory Permissions (CWE-378, CWE-379)

The permissions assigned to temporary files and the directories they reside in are critical. If temporary files are created with overly permissive file permissions (e.g., `0666` or `0777`, allowing world-read/write access), or if they are placed within widely writable directories (such as `/tmp` or `/var/tmp` on Unix-like systems), other users or processes on the same system can access or modify them. These directories are often default locations returned by `os.TempDir()` in Go. This is a common oversight, particularly when developers manually create files using functions like `os.OpenFile` without explicitly specifying restrictive `perm` flags (e.g., `0600` for owner-only read/write). The lack of proper permissions transforms a temporary storage location into a potential data leak or modification point.

### Race Conditions (Time-of-Check to Time-of-Use - TOCTOU) (CWE-361)

A particularly insidious aspect of insecure temporary file creation is the susceptibility to Time-of-Check to Time-of-Use (TOCTOU) race conditions. This is a timing vulnerability where an application first performs a security check (e.g., checking for the non-existence of a file name or its permissions – the "Time-of-Check"), and then proceeds to perform an operation on that file (e.g., creating or writing to it – the "Time-of-Use"). In the brief interval between these two operations, an attacker can interject, creating a file or symlink with the same name. This manipulation causes the legitimate application to then operate on the attacker-controlled file or the target of the symlink, leading to unintended data modification, disclosure, or even privilege escalation. The non-deterministic nature of race conditions makes them challenging to reproduce and diagnose.

### Symbolic Link (Symlink) Attacks

Symlink attacks are a prevalent exploitation vector for insecure temporary file creation vulnerabilities. An unprivileged local attacker can pre-create a symbolic link in a widely writable temporary directory (like `/tmp`), pointing it to a sensitive target file elsewhere on the system (e.g., `/etc/passwd`, a critical configuration file, or a sensitive log file). When a privileged process attempts to create or write to its temporary file (whose name the attacker predicted or raced), it inadvertently follows the attacker's symlink. This redirection causes the privileged application to perform operations (such as overwriting or appending data) on the sensitive target file instead of its intended temporary file. This direct cause-and-effect relationship stems from the combination of predictable names, insecure directory permissions, and the TOCTOU race condition.

### Go-specific Context

The Go standard library provides robust and secure methods for creating temporary files and directories. `os.CreateTemp()` and `os.MkdirTemp()` are the recommended functions for this purpose. These functions are designed to generate unique, unpredictable names and set secure default permissions, significantly mitigating the risks of race conditions and symlink attacks. They handle the complexities of secure temporary file creation internally.

Historically, the `io/ioutil.TempFile()` function was commonly used for temporary file creation. While it offered similar functionality, it has been deprecated in newer Go versions in favor of `os.CreateTemp()`, which provides more explicit control and clarity regarding security.

Manual file creation using `os.OpenFile`  or `os.Create` can reintroduce these vulnerabilities if not handled with extreme care. Developers must ensure that the `os.O_EXCL` flag is used in conjunction with `os.O_CREATE` to guarantee exclusive file creation, preventing an attacker from pre-creating the file. Furthermore, appropriate restrictive permissions (e.g., `0600` for owner-only read/write) must be explicitly set to prevent unauthorized access by other users or processes.

The vulnerability in the `glog` package (CVE-2024-45339) serves as a concrete example of how insecure temporary file creation can manifest. In this case, even if `glog` internally used a function that generated a unique name, the vulnerability arose because the application did not handle the scenario where the configured log file *already existed* in a widely writable directory. This allowed an unprivileged attacker to pre-create a symbolic link to a sensitive file. When the privileged `glog` process then attempted to write its log, it inadvertently followed the planted symlink and overwrote the sensitive file. The patch for `glog` specifically addresses this by causing the program to exit (with status code 2) when it finds that the configured log file already exists. This demonstrates that secure temporary file handling extends beyond just naming conventions to include robust checks for pre-existing files or symlinks, especially in shared temporary directories.

## Common Mistakes That Cause This

Many common mistakes leading to insecure temporary file creation stem from a fundamental lack of understanding regarding the underlying operating system's file handling mechanisms, the shared nature of temporary directories (like `/tmp`), and the inherent risks of concurrency.

1. **Using Predictable File Names:** Developers might hardcode temporary file names (e.g., `/tmp/tempfile.txt`) or use sequential numbering or timestamps without sufficient randomness, making it easy for attackers to guess the name. This predictability is a primary enabler for race conditions and symlink attacks.
2. **Insufficiently Restrictive File Permissions:** Creating temporary files with default permissions (e.g., `0666` or `0777`) that allow other users or processes to read, write, or execute them is a common oversight. This is particularly prevalent when `os.OpenFile` is used without explicitly setting secure permissions, allowing unauthorized access to potentially sensitive data.
3. **Storing Sensitive Data in Temporary Files:** Writing confidential information (e.g., API keys, user data, credentials) to temporary files on disk, even for a short duration, creates a window of opportunity for data exposure. This risk is amplified when such files are placed in shared temporary directories, where other users might have access. In-memory storage is often a safer alternative for transient sensitive data.
4. **Not Using Secure Temporary File APIs:** Developers might opt for manual file creation using `os.OpenFile` or `os.Create` without correctly implementing the `os.O_EXCL` flag (to ensure exclusive creation) and secure permissions, instead of leveraging `os.CreateTemp()` or `os.MkdirTemp()`. These standard library functions are designed to handle secure temporary file creation by default. The use of the deprecated `io/ioutil.TempFile`  in older codebases also falls into this category, as it offered less control over permissions compared to `os.CreateTemp()`.
5. **Improper Cleanup:** Failing to explicitly delete temporary files after their intended use (e.g., forgetting `defer os.Remove(tempFile.Name())`) leads to file accumulation, potential disk space issues, and lingering vulnerabilities. If sensitive data remains or if the file name/permissions are still exploitable, this becomes a persistent risk.
6. **Lack of Robust Error Handling for File Operations:** Not anticipating and handling potential errors like "permission denied," "disk full," or "file already exists" during temporary file operations can lead to unexpected program behavior, crashes, or insecure states. Proper error handling ensures the application behaves predictably and securely even under adverse conditions.
7. **Ignoring Race Conditions:** A subtle but critical mistake in concurrent environments is not accounting for the Time-of-Check to Time-of-Use (TOCTOU) window. This allows an attacker to interfere between a security check (e.g., checking if a file exists) and the subsequent file operation (e.g., creating the file). The persistence of this mistake indicates a gap in developer education regarding secure file handling principles, particularly for cross-platform and multi-user environments.

The evolution of Go's standard library, such as the deprecation of `io/ioutil.TempFile` in favor of `os.CreateTemp`, reflects a community-wide effort to provide safer defaults. However, developers must actively adopt these newer, safer APIs and understand the security implications of lower-level APIs to prevent these common pitfalls. The problem is not inherent to Go itself, but rather to how developers interact with the underlying operating system's file system without a full understanding of its security implications.

The table below contrasts common insecure practices with their secure counterparts in Go:

| Common Insecure Practice | Secure Counterpart (Go Function/Flag) | Why Insecure | Why Secure | Relevant Sources |
| --- | --- | --- | --- | --- |
| Hardcoded or predictable temp file names (e.g., `/tmp/temp.txt`) | `os.CreateTemp(dir, "prefix-*.txt")` | Easily guessed by attackers, enabling file collision or symlink attacks. | Generates unique, unpredictable names, significantly reducing collision and symlink attack surface. |  |
| Creating files with default/permissive permissions (e.g., `0666`) | `os.CreateTemp()` defaults to secure permissions; `os.OpenFile(..., 0600)` | Allows other users/processes to read/write sensitive data. | Restricts access to the file owner only, preventing unauthorized access. |  |
| Storing sensitive data directly in temporary files on disk | In-memory storage or encrypted temporary files | Creates a window for data exposure, especially in shared directories. | Eliminates disk exposure; encryption protects data at rest if disk storage is unavoidable. |  |
| Using `os.OpenFile` or `os.Create` without `O_EXCL` for new files | `os.OpenFile(..., os.O_CREATE\ | os.O_EXCL,...)`or`os.CreateTemp()` | Vulnerable to TOCTOU; attacker can pre-create file/symlink. | Ensures atomic creation; fails if file already exists, preventing attacker pre-emption. |
| Forgetting to delete temporary files | `defer os.Remove(tempFile.Name())` | Leads to file accumulation, potential lingering data, and continued exploitability. | Ensures explicit cleanup, preventing resource exhaustion and data persistence. |  |

## Exploitation Goals

Attackers exploit insecure temporary file creation to achieve various malicious objectives, often leveraging the compromised temporary file as a stepping stone for more severe attacks. These goals directly map to the core tenets of cybersecurity: Confidentiality, Integrity, and Availability (the CIA triad).

1. **Data Tampering/Modification (Integrity):** A primary goal is to alter or corrupt critical application or system files. By tricking the vulnerable application into writing to an attacker-controlled symlink, an attacker can overwrite or modify sensitive configuration files, log files, or even system binaries, leading to incorrect application behavior or system instability.
2. **Information Disclosure (Confidentiality):** Attackers aim to read sensitive data that is temporarily stored in files with insecure permissions or predictable names. This can include personally identifiable information (PII), financial data, login credentials, API keys, or other confidential business information. Even if the data is present for a short duration, a race condition can allow an attacker to exfiltrate it.
3. **Denial of Service (Availability):** Exploiting insecure temporary file creation can lead to the disruption or complete prevention of legitimate application or system functionality. This can be achieved by preemptively creating temporary files with names the application expects, thereby preventing its legitimate use, or by corrupting essential files, leading to resource exhaustion, application crashes, or system unresponsiveness.
4. **Privilege Escalation:** If the vulnerable Go application runs with elevated privileges (e.g., as a root user or a system service account), an unprivileged local attacker can exploit the insecure temporary file creation to gain higher-level access. By forcing the privileged process to write to or modify a sensitive system file (like `/etc/sudoers` or `/etc/passwd`) via a symlink, the attacker can then grant themselves elevated permissions or create new privileged accounts. This is a common and high-impact goal for local vulnerabilities.
5. **Arbitrary Code Execution/Malware Installation:** In more advanced scenarios, if the temporary file is used in a context that involves code execution (e.g., a script, a configuration file loaded by a privileged process, or a dynamically loaded library), an attacker might inject malicious code into the temporary file. When the privileged process then attempts to execute or interpret this file, it could lead to arbitrary code execution, allowing the attacker to run any command on the system, or facilitate the installation of malware.

The ability to achieve Privilege Escalation and Arbitrary Code Execution demonstrates that this vulnerability, while often requiring local access, can serve as a critical pivot point for attackers to gain full control over a system. The wide range of potential impacts, from data breaches to full system takeover, underscores that insecure temporary file creation is a severe vulnerability that warrants immediate attention.

## Affected Components or Files

The impact of insecure temporary file creation extends beyond the temporary file itself, potentially compromising a wide range of system components and files.

1. **Application-Specific Temporary Files:** These are the direct targets of the insecure creation. Any files generated by the vulnerable Go application for transient storage of data, intermediate processing results, or temporary configuration are susceptible. These files, if created insecurely, can be read, modified, or deleted by an attacker.
2. **System-Wide Temporary Directories:** Files created in common, widely writable temporary directories such as `/tmp` or `/var/tmp` on Unix-like operating systems are particularly vulnerable. These are frequently the default locations used by `os.TempDir()` in Go. The shared and often loosely permissioned nature of these directories is a key enabler for symlink attacks and race conditions, as they provide a common ground for attackers to plant their malicious files or symlinks.
3. **Sensitive System Files:** This category represents the ultimate targets of symlink attacks. Any critical system files (e.g., `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, critical configuration files, or system binaries) that an attacker might target via symbolic links are at risk. The vulnerability allows the application, especially if running with elevated privileges, to inadvertently operate on these unintended targets, leading to their modification, corruption, or disclosure. This transforms a seemingly isolated file handling issue into a systemic risk to the entire operating system.
4. **Log Files:** The `glog` package vulnerability (CVE-2024-45339) specifically highlights log files as a prime example of affected components. When log files are configured to write to widely writable directories, an attacker can pre-create a symlink from the expected log file path to a sensitive system file. The logging process, often running with elevated privileges, then inadvertently overwrites the sensitive system file, demonstrating how even seemingly benign application components can become vectors for severe system compromise.
5. **Any Go Application with Insecure File Creation Patterns:** This vulnerability is not confined to a specific Go library or framework. While `glog` is a known example, any Go application that incorrectly handles temporary file creation, especially when dealing with sensitive information or running with elevated privileges, can be affected. The risk is pervasive across the Go ecosystem if developers do not adhere to secure coding practices for file system interactions.

The understanding that the vulnerability allows an attacker to pivot from the temporary file to *any other file on the system* via symlink attacks is crucial. This means the vulnerability poses a risk not just to the data processed by the vulnerable application, but to the entire system's integrity and confidentiality.

## Vulnerable Code Snippet

The essence of insecure temporary file creation lies in the failure to use secure, atomic file creation methods and to apply restrictive permissions. While the exact vulnerable code for CVE-2024-45339 in `glog` is not provided in the research, the vulnerability description and fix imply a scenario where the application did not robustly handle the case of a pre-existing file or symlink in a widely writable directory. The fix involved making the program exit if the log file already exists, indicating that the prior behavior allowed an attacker to win a race condition.

A general example of insecure manual temporary file creation in Go, illustrating the common pitfalls:

```go
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// This function demonstrates insecure temporary file creation practices.
// It is highly vulnerable to race conditions and symlink attacks.
func createInsecureTempFile(content string) error {
	// Insecure approach 1: Manually constructing a predictable path.
	// This is vulnerable to race conditions (TOCTOU) and symlink attacks.
	// An attacker could create `/tmp/my_app_temp_data.txt` as a symlink to `/etc/passwd`
	// before this code runs, and the application would then write to `/etc/passwd`.
	tempFileName := fmt.Sprintf("my_app_temp_data_%d.txt", time.Now().UnixNano()) // Predictable suffix
	tempFilePath := filepath.Join(os.TempDir(), tempFileName) // Uses default, often widely-writable, temp directory

	// Insecure approach 2: Using os.OpenFile without O_EXCL and with permissive permissions.
	// O_EXCL ensures exclusive creation and prevents TOCTOU.
	// Permissive permissions (0666) allow world-read/write.
	file, err := os.OpenFile(tempFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666) // Insecure permissions
	if err!= nil {
		// If an attacker pre-created a symlink, this might succeed but write to the symlink's target.
		// Or it might fail if the symlink points to an uncreatable location.
		return fmt.Errorf("failed to open insecure temp file: %w", err)
	}
	defer file.Close()
	defer os.Remove(file.Name()) // Cleanup is good, but doesn't prevent initial symlink attack

	_, err = file.WriteString(content)
	if err!= nil {
		return fmt.Errorf("failed to write to insecure temp file: %w", err)
	}
	log.Printf("Insecure temp file created at: %s", file.Name())
	return nil
}

func main() {
	log.Println("Attempting to create an insecure temporary file...")
	err := createInsecureTempFile("This is sensitive data that should not be exposed!")
	if err!= nil {
		log.Printf("Error: %v", err)
	} else {
		log.Println("Insecure temp file operation completed (check logs for path).")
	}
}
```

In this example, the `createInsecureTempFile` function demonstrates several insecure practices:

- **Predictable Naming:** While `time.Now().UnixNano()` provides some uniqueness, the overall pattern and reliance on a timestamp are still predictable enough for an attacker to potentially win a race condition, especially if they can flood the system with attempts.
- **Widely Writable Directory:** `os.TempDir()` often points to `/tmp` or `/var/tmp`, which are system-wide temporary directories with broad write permissions. This makes them ideal targets for attackers to plant symlinks.
- **Insecure `os.OpenFile` Usage:**
    - The `os.O_EXCL` flag is omitted. This flag, when used with `os.O_CREATE`, ensures that the file is created *exclusively* and fails if the file already exists. Without it, if an attacker pre-creates a symlink, `os.OpenFile` will happily open and write to the target of that symlink.
    - The `0666` permission mode grants read and write access to all users (owner, group, and others). This allows any other user on the system to read or modify the contents of the temporary file, leading to information disclosure or data tampering.

This combination of factors creates a significant vulnerability window for race conditions and symlink attacks, especially if the Go application runs with elevated privileges.

## Detection Steps

Detecting insecure temporary file creation vulnerabilities in Go applications requires a combination of manual and automated analysis techniques.

### Manual Code Review

Manual code review is a critical step for identifying these vulnerabilities, as it allows security professionals to understand the context and intent behind file operations. Key areas to scrutinize include:

- **Temporary File Creation Functions:** Look for calls to `os.OpenFile` or `os.Create` that are intended for temporary file creation. If these are used, verify that:
    - The `os.O_EXCL` flag is always used in conjunction with `os.O_CREATE` to ensure exclusive file creation and prevent race conditions.
    - File permissions are explicitly set to be restrictive (e.g., `0600` for owner-only read/write). Avoid default or overly permissive modes like `0666`.
- **Use of `os.TempDir()`:** Examine how the path returned by `os.TempDir()` is used. While `os.CreateTemp()` and `os.MkdirTemp()` use this securely, manual path concatenation with `os.TempDir()` can lead to vulnerabilities if not handled with extreme caution regarding naming and permissions.
- **Deprecated `io/ioutil.TempFile()`:** Identify usage of `io/ioutil.TempFile()`. While it generates unique names, it offers less control over permissions compared to `os.CreateTemp()`, and its deprecation signals a move towards more robust alternatives.
- **Temporary File Naming Patterns:** Look for hardcoded file names or predictable naming patterns (e.g., simple sequential numbers, timestamps without sufficient randomness). Secure functions like `os.CreateTemp()` generate cryptographically secure random suffixes.
- **Sensitive Data in Temporary Files:** Review code that writes sensitive information (e.g., credentials, PII, API keys) to temporary files. Consider if in-memory storage is a safer alternative.
- **Cleanup Procedures:** Verify that `defer os.Remove(file.Name())` or similar explicit cleanup mechanisms are consistently used to delete temporary files after use.
- **Input Validation for File Paths:** Check if any user-controlled input directly or indirectly influences temporary file paths or names. Implement rigorous allow-listing validation for such inputs.

### Static Application Security Testing (SAST)

SAST tools analyze source code or compiled binaries without executing them to identify security flaws. They are effective in detecting insecure temporary file creation patterns by identifying problematic API calls, hardcoded paths, and insufficient permission settings.

- **Capabilities:** SAST tools can identify instances where `os.OpenFile` is used without `O_EXCL`, or where predictable naming conventions are employed. They can also flag the use of deprecated `io/ioutil.TempFile` in favor of more secure `os.CreateTemp`.
- **Go-compatible Tools:** Several SAST tools support Go, including GolangCI-Lint , CodeSonar , Snyk , SonarQube , and Aikido SAST. These tools can be integrated into IDEs or CI/CD pipelines to provide early feedback.
- **Limitations:** While SAST is crucial, it may produce false positives and might not detect all runtime-specific vulnerabilities, such as complex race conditions that depend on specific timing. They also typically cannot find configuration issues that are not represented in the code.

### Dynamic Application Security Testing (DAST)

DAST tools perform black-box testing on running applications to uncover vulnerabilities that an attacker could exploit. They simulate cyberattacks and monitor the application's behavior, which can reveal issues that static analysis might miss.

- **Capabilities:** DAST tools can detect runtime behaviors related to insecure temporary file usage, especially if the vulnerability leads to observable impacts like file system errors, unexpected file creations, or data leakage during application execution. They are language-agnostic as they interact with the deployed application from an outsider's perspective.
- **Limitations:** DAST tools do not have access to the source code , making it harder for them to pinpoint the exact line of vulnerable code. They also require a running application, meaning they are typically used later in the development lifecycle.

A comprehensive detection strategy combines both manual review and automated SAST/DAST to cover various aspects of the vulnerability throughout the software development lifecycle.

## Proof of Concept (PoC)

A conceptual Proof of Concept (PoC) for exploiting an insecure temporary file creation vulnerability, particularly through a symbolic link (symlink) attack, involves a race condition where an attacker creates a symlink to a sensitive file before a vulnerable, privileged process attempts to create its temporary file.

**Scenario:**
Assume a Go application, running with elevated privileges (e.g., as a service or root user), creates a temporary file in a widely writable directory like `/tmp`. The application uses a predictable naming convention or does not robustly check for pre-existing files before creation, making it vulnerable to a TOCTOU race condition. The goal of the attacker is to overwrite a sensitive system file, such as `/etc/passwd` (to potentially add a new user or modify an existing one).

**Attacker Steps:**

1. **Identify Target and Predict Path:** The attacker first identifies the vulnerable Go application and determines the predictable naming pattern or the default temporary directory it uses (e.g., `/tmp/my_app_temp_data.txt` or `/tmp/glog.<hostname>.<user>.log.INFO.<timestamp>.<pid>`). This might involve observing the application's behavior or examining its binaries for patterns.
2. **Pre-create Symbolic Link:** The attacker, as an unprivileged local user, continuously attempts to create a symbolic link in the widely writable temporary directory, pointing to the sensitive target file. For example:
Bash
The `ln -sf` command creates a symbolic link (`/tmp/my_app_temp_data.txt`) that points to `/etc/passwd`. The `f` flag forces the creation, overwriting any existing file or symlink at the target path.
    
    `# Attacker's shell (unprivileged user)
    # Continuously try to create the symlink
    while true; do
        ln -sf /etc/passwd /tmp/my_app_temp_data.txt
        # Or for glog-like vulnerability:
        # ln -sf /etc/passwd /tmp/glog.examplehost.user.log.INFO.1234567890.12345
        sleep 0.001 # Small delay to avoid busy-looping excessively, but still race
    done`
    
3. **Trigger Vulnerable Application:** The attacker then triggers the vulnerable Go application to create its temporary file. This could be by initiating a specific function, restarting the service, or waiting for a scheduled operation.
4. **Race Condition and Exploitation:**
    - When the vulnerable Go application attempts to create its temporary file (e.g., `/tmp/my_app_temp_data.txt`), it first checks if the file exists.
    - In the brief moment between this check and the actual file creation (the TOCTOU window), the attacker's script might successfully create the symbolic link.
    - Because the application does not use `os.O_EXCL` or does not check for pre-existing files/symlinks (as in the `glog` CVE ), it proceeds to open and write to `/tmp/my_app_temp_data.txt`.
    - However, due to the attacker's symlink, the write operation is redirected to `/etc/passwd`.
5. **Verify Impact:** The attacker can then check the `/etc/passwd` file to confirm that the sensitive data intended for the temporary file (e.g., new user entry, modified password hash) has been written to it, achieving data tampering and potentially privilege escalation.

This conceptual PoC illustrates how an attacker can leverage predictable naming, insecure permissions, and race conditions to redirect a privileged application's file operations to sensitive system files, leading to severe consequences.

## Risk Classification

The risk classification for insecure temporary file creation vulnerabilities is generally **High**. This classification is primarily driven by the potential for severe consequences across the Confidentiality, Integrity, and Availability (CIA) triad, as well as the high likelihood of achieving privilege escalation and arbitrary code execution in many real-world scenarios.

As demonstrated by CVE-2024-45339, which achieved a CVSS v3.1 base score of 7.8, the vulnerability can be exploited with low attack complexity and low privileges, requiring no user interaction. This makes it a highly attractive target for attackers once local access is gained.

The potential impacts that justify this high-risk classification include:

- **Confidentiality (High Impact):** Unauthorized access to sensitive data, including personally identifiable information (PII), financial records, credentials, or proprietary business information, can occur if temporary files contain such data and are exposed.
- **Integrity (High Impact):** Data tampering or modification of critical application or system files (e.g., configuration files, log files, system binaries) can lead to system instability, incorrect operations, or the introduction of malicious code.
- **Availability (High Impact):** Denial of service (DoS) can result from an attacker preventing the legitimate application from creating necessary temporary files, or by corrupting essential system files, leading to application crashes or system unresponsiveness.
- **Privilege Escalation:** A common and high-impact outcome is for an unprivileged local attacker to gain higher-level access on the system, especially if the vulnerable application runs with elevated privileges. This can lead to full system compromise.
- **Arbitrary Code Execution:** In certain contexts, an attacker might inject malicious code into a temporary file that is later executed by the privileged application, leading to arbitrary code execution and further system compromise.

Even though the attack vector is often "local," the severe consequences—ranging from data breaches to full system takeover—warrant a high classification. Such vulnerabilities can serve as critical pivot points for attackers to establish persistence or expand their control within a compromised environment.

## Fix & Patch Guidance

Addressing insecure temporary file creation vulnerabilities in Golang requires a multi-faceted approach focusing on secure API usage, robust file handling practices, and proactive security measures.

1. **Prioritize Secure Temporary File APIs:** The most effective and recommended approach is to exclusively use Go's built-in secure functions for temporary file and directory creation:
    - `os.CreateTemp(dir, pattern string)`: This function creates a new temporary file in the specified directory (or the system default if `dir` is empty) with a unique, randomly generated name. It also sets secure permissions (only the owner can read/write), significantly mitigating race conditions and symlink attacks.
    - `os.MkdirTemp(dir, pattern string)`: Similarly, this function creates a new temporary directory with a unique, random name and secure permissions. It should be used when multiple temporary files need to be grouped in a secure, isolated location.
2. **Explicit Permissions for Manual `os.OpenFile`:** If there are compelling reasons to use `os.OpenFile` for temporary files (which should be rare), developers must meticulously apply secure flags and permissions:
    - Always use `os.O_CREATE | os.O_EXCL | os.O_RDWR`: `O_CREATE` creates the file if it doesn't exist, `O_EXCL` ensures that the file is created *exclusively* (failing if it already exists), and `O_RDWR` opens it for reading and writing. The `O_EXCL` flag is crucial for preventing TOCTOU race conditions.
    - Set restrictive permissions: Specify `0600` as the permission mode (e.g., `os.OpenFile(path, flags, 0600)`) to grant read/write access only to the file owner. Avoid `0666` or other world-writable permissions.
3. **Avoid Storing Sensitive Data in Temporary Files:** As a general principle, sensitive information (e.g., credentials, API keys, PII) should not be written to disk, even temporarily. In-memory storage is often a safer alternative. If disk persistence is absolutely necessary, ensure the data is encrypted before writing and securely deleted immediately after use.
4. **Immediate and Explicit Cleanup:** Ensure that all temporary files and directories are explicitly removed after their intended use. The `defer os.Remove(file.Name())` or `defer os.RemoveAll(dirName)` pattern is highly recommended to guarantee cleanup, even if errors occur during execution.
5. **Input Validation for Paths:** If any part of a temporary file path or name is influenced by user-controlled input, implement rigorous input validation and sanitization. Use allow-listing (defining what is explicitly permitted) rather than block-listing (trying to exclude malicious input). Fully resolve any absolute or relative paths from user input.
6. **Regularly Update Dependencies:** Keep all Go modules and third-party libraries, including logging packages like `glog`, updated to their latest secure versions. Security patches often address known vulnerabilities related to file handling. For instance, CVE-2024-45339 in `glog` was fixed in version 1.2.4.
7. **Principle of Least Privilege:** Ensure that the Go application runs with the minimum necessary privileges required for its operations. This limits the potential impact of a successful exploitation of any vulnerability, including insecure temporary file creation.

By adhering to these guidelines, developers can significantly reduce the attack surface related to temporary file management and enhance the overall security posture of their Go applications.

## Scope and Impact

The scope of an insecure temporary file creation vulnerability is typically **local**, meaning an attacker generally requires some level of access to the system where the vulnerable application is running to exploit it. This usually involves an unprivileged local user or a process with limited permissions. However, it is crucial to recognize that local vulnerabilities can often be chained with other, remotely exploitable flaws (e.g., a remote code execution vulnerability that grants initial local access) to achieve a broader, remote impact.

The impact of such a vulnerability, if successfully exploited, can be severe and far-reaching, directly affecting the core tenets of cybersecurity:

- **Confidentiality:** There is a high risk of unauthorized access to sensitive data. If the application temporarily stores confidential information (e.g., user credentials, financial data, PII, API keys) in insecure temporary files, an attacker can read or exfiltrate this data. This can lead to data breaches, identity theft, or compromise of other systems.
- **Integrity:** The integrity of system and application data can be severely compromised. Attackers can modify or corrupt critical configuration files, log files, or even system binaries by redirecting write operations through symlinks. This can lead to incorrect application behavior, system instability, or the introduction of malicious code.
- **Availability:** The vulnerability can lead to a denial of service (DoS) condition. An attacker might prevent the legitimate application from creating necessary temporary files, or corrupt essential system files, causing the application or the entire system to crash or become unresponsive. This can disrupt critical business operations and lead to significant financial losses.
- **Privilege Escalation:** A particularly high-impact consequence is privilege escalation. If the vulnerable Go application runs with elevated privileges (e.g., as a root user or a system service), an unprivileged local attacker can exploit the insecure temporary file creation to gain higher-level access. By tricking the privileged process into modifying sensitive system files (like `/etc/passwd` or `/etc/sudoers`), the attacker can grant themselves administrative rights, leading to full system compromise.
- **Arbitrary Code Execution:** In more advanced scenarios, if the temporary file is processed in a context that allows code execution (e.g., interpreted as a script or loaded as a configuration file by a privileged process), an attacker might inject malicious code into the file. When the privileged process then attempts to execute or interpret this file, it can lead to arbitrary code execution, allowing the attacker to run any command on the compromised system.

The potential for significant reputational damage, regulatory fines, and financial losses due to data breaches, service disruptions, and system compromise underscores the critical nature of this vulnerability, even if its primary attack vector is local.

## Remediation Recommendation

Effective remediation of insecure temporary file creation vulnerabilities in Golang applications requires a multi-layered and proactive approach, emphasizing secure coding practices, robust testing, and continuous vigilance.

1. **Immediate Code Refactoring for Secure APIs:** The foremost recommendation is to identify and refactor all instances of temporary file creation to exclusively use `os.CreateTemp()` and `os.MkdirTemp()`. These functions are designed to generate unique, unpredictable names and set secure default permissions, inherently mitigating common risks like predictable naming, insecure permissions, and TOCTOU race conditions. For any legacy code using `io/ioutil.TempFile()`, migration to `os.CreateTemp()` is strongly advised due to its deprecation and improved security guarantees. If manual `os.OpenFile` is unavoidable, ensure `os.O_EXCL` is always used with `os.O_CREATE` and permissions are set to `0600`.
2. **Comprehensive Input Validation and Sanitization:** Implement rigorous input validation and sanitization for any user-supplied data that might influence file paths or names. This should primarily be an allow-listing approach, defining what is explicitly permitted rather than attempting to block all known malicious patterns. Canonicalize paths where necessary to prevent path traversal attacks.
3. **Principle of Least Privilege:** Configure Go applications and their underlying processes to run with the absolute minimum necessary privileges. This limits the potential damage and scope of impact if a temporary file vulnerability is exploited, preventing an attacker from gaining full system control even if the vulnerability is triggered.
4. **Integrate Security Testing into CI/CD:**
    - **Static Application Security Testing (SAST):** Incorporate Go-compatible SAST tools (e.g., GolangCI-Lint, SonarQube, Snyk) into the CI/CD pipeline. These tools can automatically detect insecure temporary file creation patterns in source code early in the development lifecycle, providing immediate feedback to developers.
    - **Dynamic Application Security Testing (DAST):** Utilize DAST tools against deployed applications in test environments. DAST can identify runtime vulnerabilities that might be missed by SAST, including complex race conditions or issues arising from environmental configurations.
5. **Regular Security Audits and Penetration Testing:** Conduct periodic manual code audits and penetration tests by security experts. These activities can uncover subtle vulnerabilities, including complex race conditions or logical flaws in file handling, that automated tools might overlook.
6. **Developer Training and Awareness:** Provide continuous training to developers on secure coding practices in Go, specifically focusing on secure file handling, concurrency pitfalls, and the implications of interacting with the operating system's file system. Fostering a security-conscious mindset within the development team is paramount.

By adopting these recommendations, organizations can significantly enhance their defense against insecure temporary file creation vulnerabilities, moving beyond reactive patching to a proactive security posture.

## Summary

Insecure temporary file creation in Golang applications represents a significant security vulnerability, categorized broadly under CWE-377, CWE-378, and CWE-379. This class of flaws arises from predictable file naming, overly permissive file permissions, and susceptibility to Time-of-Check to Time-of-Use (TOCTOU) race conditions. Attackers exploit these weaknesses, often through symbolic link (symlink) attacks, to redirect a legitimate application's file operations to sensitive system files.

The consequences of successful exploitation are severe, encompassing high impacts on Confidentiality (information disclosure), Integrity (data tampering/modification), and Availability (denial of service). Furthermore, these vulnerabilities frequently serve as critical stepping stones for privilege escalation and arbitrary code execution, allowing an unprivileged local attacker to gain full control over a system. A real-world example, CVE-2024-45339 in the `glog` package, underscores this risk, with a CVSS v3.1 score of 7.8 (High severity), demonstrating how a seemingly minor file handling oversight can lead to critical system compromise.

Common mistakes include manual path construction, neglecting secure permissions, failing to use Go's secure `os.CreateTemp()` and `os.MkdirTemp()` functions, storing sensitive data in temporary files, and inadequate cleanup.

Effective remediation requires a shift towards secure-by-design principles:

- Prioritize the use of `os.CreateTemp()` and `os.MkdirTemp()` for all temporary file and directory operations, as they provide robust, secure defaults.
- If manual file handling is necessary, strictly enforce exclusive creation (`os.O_EXCL`) and restrictive permissions (`0600`).
- Avoid storing sensitive data in temporary files on disk; prefer in-memory storage.
- Implement rigorous input validation for any user-controlled data influencing file paths.
- Ensure explicit and immediate cleanup of all temporary files and directories.
- Regularly update all Go modules and dependencies to incorporate the latest security patches.
- Integrate both Static (SAST) and Dynamic (DAST) Application Security Testing into the development lifecycle to detect and prevent these vulnerabilities proactively.
- Foster a culture of security awareness and provide continuous training to developers on secure file handling practices.

By adopting these comprehensive measures, organizations can significantly reduce their exposure to insecure temporary file creation vulnerabilities, safeguarding their applications and underlying systems from potentially devastating attacks.

## References

- https://gorm.io/docs/query.html
- https://tutorialedge.net/golang/secure-coding-in-go-input-validation/
- https://www.bytebase.com/blog/golang-orm-query-builder/
- https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/injection-attack/
- https://owasp.org/www-community/Source_Code_Analysis_Tools
- https://www.wiz.io/academy/top-open-source-sast-tools
- https://last9.io/blog/getting-started-with-golang-orms/
- https://www.sqlite.org/cves.html
- https://www.reddit.com/r/golang/comments/10cms6j/golang_programming_and_security_vulnerabilities/
- https://github.com/github/codeql/issues/15707
- https://nvd.nist.gov/vuln/detail/CVE-2019-15562
- https://www.qodo.ai/blog/best-static-code-analysis-tools/
- https://forum.nim-lang.org/t/1961
- https://pkg.go.dev/github.com/volatiletech/sqlboiler/v4
- https://www.stackhawk.com/blog/golang-sql-injection-guide-examples-and-prevention/
- https://en.wikipedia.org/wiki/SQL_injection
- https://about.gitlab.com/topics/devsecops/sast-vs-dast/
- https://moldstud.com/articles/p-leveraging-orms-to-prevent-sql-injection-risks
- https://nvd.nist.gov/vuln/detail/CVE-2019-15562
- https://www.reddit.com/r/golang/comments/1jvdsr8/type_safe_orm/
- https://www.bugcrowd.com/blog/12-common-attack-vectors-you-need-to-be-aware-of/
- https://docs.guardrails.io/docs/vulnerabilities/javascript/insecure_use_of_sql_queries
- https://docs.digicert.com/en/software-trust-manager/threat-detection/best-practices-for-common-vulnerabilities-and-exposures/assess-the-risk-of-a-vulnerability.html
- https://docs.guardrails.io/docs/vulnerabilities/python/insecure_use_of_sql_queries
- https://gorm.io/docs/security.html
- https://www.pullrequest.com/blog/preventing-sql-injection-in-golang-a-comprehensive-guide/
- https://www.reddit.com/r/golang/comments/1jmlvyq/why_do_we_hate_orm/
- https://www.reddit.com/r/golang/comments/1993iv0/validation_place_in_the_system/
- https://dev.to/dzungnt98/preventing-sql-injection-with-raw-sql-and-orm-in-golang-5dhn
- https://www.balbix.com/insights/attack-vectors-and-breach-methods/
- https://socket.dev/go/package/github.com/xorm-io/core?section=alerts
- https://afine.com/sql-injection-in-the-age-of-orm-risks-mitigations-and-best-practices/
- https://www.dryrun.security/blog/say-goodbye-to-sqli-in-go-and-python
- https://dev.to/dzungnt98/preventing-sql-injection-with-raw-sql-and-orm-in-golang-5dhn
- https://afine.com/sql-injection-in-the-age-of-orm-risks-mitigations-and-best-practices/
- https://sca.analysiscenter.veracode.com/vulnerability-database/security/1/1/sid-46055/summary
- https://docs.gitlab.com/user/application_security/vulnerabilities/severities/
- https://dev.to/wiliamvj/preventing-sql-injection-with-golang-41m5
- https://www.reddit.com/r/golang/comments/1jmlvyq/why_do_we_hate_orm/
- https://vulert.com/vuln-db/go-github-com-golang-glog-181571
- https://github.com/advisories/GHSA-6wxm-mpqj-6jpf
- https://www.clouddefense.ai/cwe/definitions/377
- https://svenruppert.com/2024/08/21/cwe-377-insecure-temporary-file-in-java/
- https://www.cvedetails.com/cwe-details/379/Creation-of-Temporary-File-in-Directory-with-Insecure-Permis.html
- https://docs.datadoghq.com/security/code_security/static_analysis/static_analysis_rules/go-security/tempfile-creation/
- https://www.ibm.com/support/pages/security-bulletin-vulnerabilities-nodejs-angularjs-golang-go-java-mongodb-linux-kernel-may-affect-ibm-spectrum-protect-plus-0
- https://vulert.com/vuln-db/CVE-2025-22871
- https://docs.aws.amazon.com/codeguru/detector-library/go/temporary-files/
- https://labex.io/tutorials/go-how-to-prevent-file-handling-mistakes-461900
- https://blog.doyensec.com/2025/01/09/cspt-file-upload.html
- https://gobyexample.com/temporary-files-and-directories
- https://github.com/golang/go/issues/73042
- https://labex.io/tutorials/go-how-to-create-unique-temp-files-concurrently-446134
- https://labex.io/tutorials/go-how-to-manage-temporary-file-creation-450832
- https://labex.io/tutorials/go-how-to-verify-temp-file-creation-in-go-446143
- https://learn.snyk.io/lesson/insecure-temporary-file/
- https://labex.io/tutorials/go-how-to-manage-temporary-file-creation-450832
- https://thinhdanggroup.github.io/golang-race-conditions/
- https://www.infosecinstitute.com/resources/secure-coding/how-to-mitigate-race-conditions-vulnerabilities/
- https://www.twingate.com/blog/glossary/symlink-attack
- https://www.cybrary.it/blog/symlink-attacks
- https://labex.io/tutorials/go-how-to-manage-temporary-file-creation-450832
- https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-go-028
- https://opencourse.inf.ed.ac.uk/sites/default/files/https/opencourse.inf.ed.ac.uk/sp/2024/08-races.pdf
- https://thinhdanggroup.github.io/golang-race-conditions/
- https://learn.snyk.io/lesson/insecure-temporary-file/
- https://labex.io/tutorials/go-how-to-validate-file-operation-results-461903
- https://pkg.go.dev/os
- https://docs.bearer.com/reference/rules/go_gosec_filesystem_tempfile/
- https://pkg.go.dev/go.mway.dev/x/os/tempdir
- https://github.com/golang/go/issues/19695
- https://documentation.help/Golang/os.htm
- https://gist.github.com/thiagozs/85f93d58e4f5aebc71f7f95033206829