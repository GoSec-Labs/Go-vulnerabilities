A Path Traversal vulnerability, also known as Directory Traversal, is a critical security flaw that allows attackers to access files and directories stored outside the intended web root folder. By manipulating variables that reference files with "dot-dot-slash" (`../`) sequences or absolute file paths, an attacker can potentially access sensitive information, leading to data breaches or system compromise.

### **Vulnerability Title:** Path Traversal

### **Severity Rating:** High🟠 to Critical🔴

### **Description**

Path Traversal attacks exploit insufficient security validation or sanitization of user-supplied input that is used in file system operations. An attacker can craft a malicious file path to navigate the file system and access restricted files and directories. This can include application source code, configuration files containing credentials, and sensitive operating system files.

### **Technical Description (for security pros)**

This vulnerability occurs when an application concatenates user-provided input directly into a file path without proper neutralization. Attackers use path traversal sequences like `../` to move up in the directory hierarchy. For instance, if a web application uses a URL parameter to serve files (e.g., `https://example.com/view?file=report.pdf`), an attacker might change the `file` parameter to `../../../../etc/passwd` to access the system's password file. The success of this attack depends on the web server's and application's handling of file paths and the privileges of the user running the application.

-----

### **Common Mistakes That Cause This**

  * **Directly using user input in file paths:** The most common mistake is directly concatenating unsanitized user input into a file path.
  * **Improper path sanitization:** Relying on simple string replacement for `../` is often insufficient, as attackers can use various encodings (e.g., URL encoding `%2e%2e%2f`) or nested sequences to bypass filters.
  * **Not validating the final path:** Failing to verify that the fully resolved, canonical path is within the intended base directory.
  * **Misuse of `path/filepath.Join`:** While `filepath.Join` is helpful for constructing OS-agnostic paths, it does not inherently prevent path traversal. It will clean paths (e.g., resolve `../`), but it doesn't restrict them to a specific directory.
  * **Ignoring symlinks:** Attackers can use symbolic links to redirect file access to unauthorized locations, bypassing path validation checks.

### **Exploitation Goals**

  * **Read sensitive files:** Access configuration files (`.env`, `config.json`), source code, or system files (`/etc/passwd`, `/etc/shadow`).
  * **Write or modify files:** In some cases, an attacker might be able to upload or modify files, potentially leading to Remote Code Execution (RCE).
  * **Information disclosure:** Gain insights into the application's structure, dependencies, and underlying operating system.

-----

### **Affected Components or Files**

Any part of a Go application that handles file I/O based on user-controllable input can be vulnerable. This includes:

  * File upload and download functionality.
  * Functions that read or include files from the local system (e.g., templates, language files).
  * Modules that interact with the filesystem, such as `os`, `io/ioutil` (now part of `io` and `os` in Go 1.16+), and `path/filepath`.

### **Vulnerable Code Snippet**

Here's an example of vulnerable Go code that serves files based on a URL path:

```go
package main

import (
    "net/http"
    "path/filepath"
)

func main() {
    http.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
        // Unsafe: Directly using user-provided path
        filePath := r.URL.Path[len("/files/"):]
        // The file path is not properly sanitized and validated
        http.ServeFile(w, r, filePath)
    })
    http.ListenAndServe(":8080", nil)
}
```

In this snippet, an attacker could request `http://localhost:8080/files/../../../../etc/passwd` to access the password file.

-----

### **Detection Steps**

1.  **Static Analysis (SAST):** Use security scanners to analyze the source code for patterns of unsafe file path handling. Look for direct usage of user input in functions like `os.Open`, `http.ServeFile`, and `ioutil.ReadFile`.
2.  **Dynamic Analysis (DAST):** Actively probe the running application with various path traversal payloads in input fields and URL parameters.
3.  **Manual Code Review:** Carefully inspect any code that constructs file paths from user input. Ensure that robust validation and sanitization are in place.

### **Proof of Concept (PoC)**

For the vulnerable code snippet above, a simple `curl` command can demonstrate the vulnerability:

```bash
curl --path-as-is http://localhost:8080/files/../../../../../../../../etc/passwd
```

If the server responds with the contents of the `/etc/passwd` file, the vulnerability is confirmed. The `--path-as-is` flag is crucial to prevent `curl` from normalizing the URL before sending the request.

-----

### **Risk Classification**

  * **CVSS Score:** Typically ranges from 7.5 (High) to 9.8 (Critical), depending on the impact.
  * **Confidentiality:** High (sensitive data can be read).
  * **Integrity:** Low to High (files may be modified or created).
  * **Availability:** Low to High (denial of service could occur).

### **Fix & Patch Guidance**

To fix a path traversal vulnerability in Go, you should:

1.  **Define a secure base directory:** Explicitly specify the directory from which files should be served.
2.  **Clean and validate the user-provided path:** Use `filepath.Clean` to canonicalize the path.
3.  **Join the base directory with the cleaned path:** Use `filepath.Join` to construct the full, intended file path.
4.  **Verify the final path is within the base directory:** Use `strings.HasPrefix` to ensure the final path starts with the secure base directory.

Here's a patched version of the vulnerable code:

```go
package main

import (
    "net/http"
    "path/filepath"
    "strings"
)

func main() {
    http.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
        baseDir := "/var/www/static"
        requestedPath := r.URL.Path[len("/files/"):]

        // Clean the path to prevent directory traversal
        cleanedPath := filepath.Clean(requestedPath)

        // Construct the full path and ensure it's within the base directory
        fullPath := filepath.Join(baseDir, cleanedPath)

        // Security check: ensure the final path is still within the intended directory
        if !strings.HasPrefix(fullPath, baseDir) {
            http.Error(w, "Invalid file path", http.StatusBadRequest)
            return
        }

        http.ServeFile(w, r, fullPath)
    })
    http.ListenAndServe(":8080", nil)
}
```

-----

### **Scope and Impact**

A successful path traversal attack can have a severe impact, potentially leading to:

  * **Complete system compromise:** If an attacker can read sensitive credentials or upload and execute a malicious script.
  * **Significant data breaches:** Exfiltration of customer data, intellectual property, or other sensitive information.
  * **Reputational damage and financial loss.**

### **Remediation Recommendation**

  * **Never trust user input:** Treat all input from users as potentially malicious.
  * **Use whitelisting for file access:** If possible, only allow access to a predefined list of files.
  * **Implement the principle of least privilege:** Run your Go application with the minimum necessary file system permissions.
  * **Stay updated:** Keep your Go version and all dependencies up to date to benefit from the latest security patches.
  * **Use dedicated libraries:** For more complex scenarios, consider using security-focused libraries that provide robust protection against path traversal.

-----

### **Summary**

Path traversal is a serious vulnerability in Go applications that arises from improperly handling user-supplied input in file system operations. It can be mitigated by rigorously sanitizing and validating all user-provided paths to ensure they do not access unauthorized files or directories. By following secure coding practices, developers can significantly reduce the risk of this type of attack.

### **References**

  * [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
  * [Go Documentation: path/filepath](https://pkg.go.dev/path/filepath)
  * [Mitigating Path Traversal Vulnerabilities](https://www.google.com/search?q=https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html)