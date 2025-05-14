# **Vulnerability Analysis Report: Commented Code Leftover**

## **Vulnerability Title**

Commented Code Leftover (CWE-615: Inclusion of Sensitive Information in Source Code Comments)

## **Severity Rating**

The severity of Commented Code Leftover is **variable**, ranging from **Low🟢 to Critical🔴**. It is highly dependent on the nature of the information exposed within the comments and the context of the application.

- **Low🟢:** Comments revealing non-sensitive internal details, old non-functional code snippets, or vague developer notes.
- **Medium🟡:** Comments exposing internal file paths, outdated API endpoints, or hints about application logic that could aid reconnaissance.
- **High🟠:** Comments containing functional but deprecated code with known vulnerabilities, sensitive configuration details, or partial credentials/keys.
- **Critical🔴:** Comments directly exposing active credentials, private API keys, PII, or detailed instructions for bypassing security controls.

The OWASP Web Security Testing Guide (WSTG) highlights that comments can reveal internal information not intended for attackers, and the review of such comments is crucial to determine if information leakage is occurring. The actual impact, and thus severity, is realized when an attacker can leverage the disclosed information.

## **Description**

Commented Code Leftover refers to a vulnerability where developers leave remarks, old code segments, or sensitive data within source code comments that are then deployed to testing, staging, or, most critically, production environments. While comments are essential for code maintainability and collaboration during development, those containing sensitive details or inactive code can become a significant security risk if exposed. This vulnerability is not about an executable flaw in the code itself, but rather an information disclosure that can aid attackers in understanding the system, finding other vulnerabilities, or directly gaining unauthorized access.

Developers might leave such comments for various reasons: as reminders (e.g., "TODO: Fix this later"), for debugging purposes, to temporarily disable a feature, or as an informal way of versioning code snippets. If these comments are not removed or sanitized before deployment, they can be accessed by anyone who can view the source code, particularly in client-side files like HTML, JavaScript, and CSS, or if server-side code is inadvertently exposed.

## **Technical Description (for security pros)**

Technically, CWE-615 (Inclusion of Sensitive Information in Source Code Comments) arises when comments embedded within application source code (e.g., HTML, JavaScript, CSS, server-side scripts, configuration files) contain information that could be leveraged by an attacker. This information is not intended for public consumption and can include:

- **Credentials:** Usernames, passwords, API keys, database connection strings.
- **Internal Infrastructure Details:** IP addresses, server names, internal network paths, hidden URLs or endpoints.
- **Application Logic and Design:** Details about algorithms, deprecated functionalities, known bugs, or security workarounds.
- **Sensitive Data Structures:** Information about database schemas, session management details, or PII handling.
- **Debugging Information:** Test parameters, temporary values, or developer notes that reveal system behavior.
- **Outdated or Vulnerable Code Snippets:** Commented-out code that might contain old vulnerabilities which, if understood, could provide clues to similar flaws in active code or be inadvertently re-activated.

The exposure typically occurs when client-side code is delivered to a user's browser, as comments in HTML, JavaScript, or CSS are directly viewable. For server-side code, exposure might happen through other vulnerabilities like source code disclosure, Local File Inclusion (LFI), or misconfigured repositories. Even if the commented-out code itself is not executable, the information it contains can be invaluable for an attacker during reconnaissance, potentially lowering the effort required to find exploitable flaws or directly providing means for unauthorized access. The risk is amplified because this information is often left unintentionally, under the assumption that comments are benign or will be stripped by build processes, which may not always be the case or may be misconfigured.

## **Common Mistakes That Cause This**

This vulnerability primarily stems from human oversight and inadequate development/deployment processes. Common mistakes include:

1. **Forgetting to Remove Debug Comments:** Developers often insert comments with sensitive data (e.g., test credentials, internal IP addresses, debug flags) during development or troubleshooting and forget to remove them before committing code or deploying.
    
2. **Using Comments for Temporary Code Disabling:** Instead of using version control branches for experimental features or temporarily disabling code, developers might comment out large blocks of code, sometimes including sensitive logic or old vulnerabilities.

3. **Informal Version Control:** Leaving old versions of functions or logic commented out as a quick way to revert, rather than relying on robust version control systems like Git. This practice clutters the codebase and increases the risk of exposing outdated, potentially insecure, logic.
    
4. **Lack of Thorough Code Reviews:** Code review processes that do not specifically scrutinize comments for sensitive information or large blocks of dead code can allow these issues to pass into production.
    
5. **Misconfigured Build/Minification Tools:** Over-reliance on build tools to strip comments. While many tools do this for client-side code, they might be misconfigured, or not all file types (e.g., server-side scripts, config files) undergo such processing. Developers might assume comments are "safe" because they believe they will be removed.

6. **Insufficient Developer Awareness/Training:** Developers may not be fully aware of the security implications of leaving certain types of information in comments, especially in code that might become publicly accessible.
    
7. **Copy-Pasting Code with Comments:** Developers might copy code snippets from internal documentation, older projects, or online sources that contain sensitive example comments, and inadvertently leave them in.
8. **"TODO" or "FIXME" Comments Containing Sensitive Context:** Comments like `//TODO: Remove hardcoded admin password after demo` or `//FIXME: This bypasses auth for testing` are clear indicators of sensitive information being present.
    
9. **Comments Explaining Security Flaws or Workarounds:** Detailed comments about why a certain piece of (perhaps insecure) code exists, or how a security measure was implemented (or bypassed for a test), can give attackers precise targets.

These mistakes are often exacerbated in fast-paced development environments where deadlines can lead to shortcuts. The underlying cause is typically a failure to treat comments as part of the deliverable code that requires the same level of security scrutiny as executable statements.

## **Exploitation Goals**

An attacker leveraging information found in commented-out code typically aims to achieve one or more of the following goals:

1. **Reconnaissance and Information Gathering:**
    - Map application architecture, identify technologies used, and understand internal structures, file names, or hidden directories.
        
    - Discover internal IP addresses, server names, or non-public API endpoints.
        
    - Identify developer names, email patterns, or internal project codenames, which can be used for social engineering.
2. **Unauthorized Access:**
    - Obtain hardcoded credentials (usernames, passwords, API keys, session tokens) to directly access user accounts, administrative interfaces, databases, or third-party services.
    - Discover or reconstruct logic for bypassing authentication or authorization mechanisms if such logic was commented out or described.
3. **Vulnerability Identification:**
    - Find clues about existing vulnerabilities (e.g., comments like `// Temporary fix for SQLi, need to sanitize properly`).
    - Analyze commented-out old code that might contain known vulnerabilities, potentially indicating similar patterns or reusable exploit logic in the current codebase.

    - Understand data validation processes (or lack thereof) from commented logic.
4. **Exploitation of Other Vulnerabilities:**
    - Use disclosed information (e.g., database table/column names, parameter names) to craft more effective payloads for other attacks like SQL Injection or Cross-Site Scripting (XSS).
        
    - Leverage knowledge of internal system configurations or error handling to refine attack vectors.
5. **Intellectual Property Theft:**
    - Gain insights into proprietary algorithms, business logic, or upcoming features if detailed in comments.
        
6. **Disruption or Defacement:**
    - If comments reveal administrative functionalities or misconfigurations, an attacker might use this to disrupt services or alter content.
7. **Elevation of Privileges:**
    - Information about user roles, permission structures, or administrative functions could be used to escalate privileges if an initial low-privileged foothold is gained through other means.

The ultimate goal is to reduce the effort and time needed for a successful attack by using the "free" information provided by the developers themselves within the comments. Even seemingly innocuous comments can contribute to a larger picture when aggregated.

## **Affected Components or Files**

Commented Code Leftover vulnerabilities can manifest in a wide variety of files and components across the software development lifecycle. The risk is present in any human-readable text file that supports comments and might be inadvertently exposed or deployed. Key affected components include:

- **Client-Side Code:** These are the most common and directly accessible sources.
    - **HTML Files (`.html`, `.htm`):** Comments `` can expose structural information, developer notes, credentials, or links to internal resources.

    - **JavaScript Files (`.js`):** Comments `//` or `/* */` may contain API keys, old logic, debug information, or sensitive endpoint details. Modern JavaScript frameworks often involve transpilation and bundling; misconfigurations in these build tools can lead to source comments persisting in production bundles.
        
    - **CSS Files (`.css`):** Comments `/* */` are less likely to contain highly sensitive data but can sometimes reveal notes about application structure or old styles related to hidden features.
    - **Source Map Files (`.map`):** If deployed, these can expose original source code, including comments, even if the bundled JavaScript is minified.

- **Server-Side Code (if leaked or accessible through other vulnerabilities):**
    - **Scripting Languages:** Python (`.py` - `#`), PHP (`.php` - `//, /* */, #`), Ruby (`.rb` - `#`), Perl (`.pl` - `#`), Node.js (JavaScript on the server).
    - **Compiled Languages (source files):** Java (`.java` - `//, /* */`), C# (`.cs` - `//, /* */`), Go (`.go` - `//, /* */`), C/C++ (`.c`, `.cpp` - `//, /* */`). While compiled code is typically deployed, the source files containing comments are the primary concern if they are improperly managed in version control or accessible through misconfigurations.
- **Configuration Files (if leaked or accessible):**
    - XML (`.xml` - ``), JSON (JSON itself doesn't support comments, but often embedded in JS or other formats that do, or developers use workarounds like `"_comment": "..."`), YAML (`.yml`, `.yaml` - `#`), `.ini` files (`;` or `#`). These can contain commented-out credentials, old settings, or infrastructure details.
- **Build Scripts & CI/CD Pipeline Definitions (if exposed):**
    - Files like `Jenkinsfile` (Groovy comments `//, /* */`), `Dockerfile` (`#`), `gitlab-ci.yml` (YAML comments `#`), `build.gradle` (Groovy/Kotlin comments), `pom.xml` (XML comments). These can contain comments with sensitive details about the build, test, or deployment process, including temporary credentials or environment specifics.
        
- **Database Schema Files & Migration Scripts (if exposed):**
    - SQL files (`.sql` - `-, /* */`) can have comments detailing table structures, old queries, or developer notes.
- **Infrastructure as Code (IaC) Templates (if exposed):**
    - Terraform (`.tf` - `# // /* */`), CloudFormation (JSON/YAML comments). Comments here might reveal assumptions about security configurations or sensitive default values.

The common thread is that any file processed or read by humans during development that also makes its way into a deployed or accessible environment without proper sanitization of comments is a potential vector. Client-side files present the most immediate risk due to their inherent exposure to the end-user's browser. However, the leakage of server-side code or configuration files, often through unrelated vulnerabilities or misconfigurations, can expose comments with even more critical internal information.

## **Vulnerable Code Snippet**

Below are illustrative examples of commented-out code that reveal different types of sensitive information. These are synthetic but based on common patterns observed in real-world scenarios.

**Example 1: HTML - Credentials and Internal Information**

```HTML

<div class="login-form">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
</div>
```

- **Information Leaked:** Internal URL for an admin panel, staging environment credentials, an old database connection string (revealing internal IP, username, password, and database name pattern), and an internal team email address.
- **Attacker Utility:** An attacker could attempt to access the internal admin panel, use the staging credentials if they find a way to access the staging environment or if the credentials are reused. The database string provides valuable reconnaissance for targeting the database if internal access is gained. The email can be used for social engineering.
    

**Example 2: JavaScript - API Key and Deprecated Logic**

```JavaScript

// function initializeMap() {
//     // Old API key - Do not use, has been revoked.
//     // var oldApiKey = "AIzaSy***************************";
//     // var map = new google.maps.Map(document.getElementById('map'), {
//     //    center: {lat: -34.397, lng: 150.644},
//     //    zoom: 8,
//     //    apiKey: oldApiKey // THIS WAS THE PROBLEM
//     // });
// }

// Current API key is loaded from server-side config.
// console.log("Map API Key: " + serverConfig.googleMapsApiKey); // Debug line, remove!

/*
function oldSubmitUserData(userData) {
    // This version had a vulnerability, directly posted to /api/v1/user_unsafe_submit
    // It didn't validate user input properly.
    // $.ajax({
    //    type: "POST",
    //    url: "/api/v1/user_unsafe_submit",
    //    data: userData,
    //    success: function(response) { console.log("Old submit success"); }
    // });
}
*/
var currentApiEndpoint = "/api/v2/user_secure_submit";
// console.log("Current secure endpoint for user data: " + currentApiEndpoint);
```

- **Information Leaked:** An old (potentially still monitored or pattern-revealing) API key, a debug `console.log` that might expose the current API key if `serverConfig` is accessible client-side, details about a deprecated API endpoint (`/api/v1/user_unsafe_submit`), and a hint about past input validation vulnerabilities.
- **Attacker Utility:** The old API key might still be informative. The debug line, if active, could directly leak the current key. Information about the old vulnerable endpoint and its flaws can guide an attacker to look for similar weaknesses in the current API or understand how the application evolved its security. The presence of "TODO", "FIXME", or "TEMP" in comments, or explicit mentions of credentials or debugging, often signals high-value targets for attackers.
    

**Example 3: Server-Side (Python/Django) - Revealing Old Vulnerability & Logic**

```Python
# models.py
class Product(models.Model):
    name = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    # description = models.TextField() # Old field, removed in v2.3

    # def get_price_for_user_DEPRECATED(self, user_role):
    #    # This had a bug where 'guest' users could see internal pricing
    #    # if user_role == 'admin' or user_role == 'staff':
    #    #    return self.internal_price
    #    # elif user_role == 'partner':
    #    #    return self.price * 0.8 # 20% discount for partners
    #    # else: # This was the bug, should have checked for specific public role
    #    #    return self.price # Oops, guests saw partner price if internal_price not set!
    #    #
    #    # Replaced with role-based pricing via PricingRule model. See services.py.
    #    pass

    def get_current_price(self, pricing_rules):
        # Current logic applies rules from PricingRule model
        #... (complex pricing logic)...
        return calculated_price
```

- **Information Leaked:** Details about a deprecated field (`description`), a significant past business logic flaw related to user roles and pricing (guests potentially seeing internal or partner prices), and a hint towards the current pricing mechanism (`PricingRule` model, `services.py`).
- **Attacker Utility:** Understanding past vulnerabilities can help an attacker probe for similar logic errors in the current system or in other modules. Knowing about the `PricingRule` model and `services.py` gives them specific areas to target for further investigation if they gain access to more code or can infer API interactions. This demonstrates that the vulnerability is language-agnostic and is fundamentally a human/process failing.

These snippets illustrate how seemingly harmless comments can provide attackers with a wealth of information, ranging from direct credentials to subtle clues about system architecture and past weaknesses.

## **Detection Steps**

Detecting commented code leftovers requires a multi-faceted approach, combining manual review with automated tooling. The goal is to identify comments that expose sensitive information or large blocks of inactive code.

1. **Manual Code Review:**
    - **Client-Side Inspection:** Thoroughly inspect all client-side code (HTML, JavaScript, CSS) delivered to the browser. Use the browser's "View Page Source" functionality and Developer Tools (especially the "Sources" or "Debugger" tab for JavaScript).
        
    - **Server-Side Inspection:** If access to server-side source code is available (e.g., during a white-box assessment, or if source code is leaked), review these files meticulously.
    - **Focus Areas:** Pay close attention to comments near authentication mechanisms, data handling routines, sensitive functions, configuration settings, and API integrations.
    - **Keyword Searching:** Look for common comment syntaxes (e.g., `` in HTML; `//` and `/* */` in JavaScript, Java, C#, Go; `#` in Python, Ruby, shell scripts, YAML). Search for indicative keywords within comments such as "TODO", "FIXME", "TEMP", "HACK", "debug", "password", "key", "secret", "admin", "internal", "database", "connstr", specific API provider names (e.g., "aws_key", "google_api"), or internal project codenames. Tools like `tickgit` or `todocheck` can assist in managing and reviewing TODO-style comments.
        
    - **Source Map Files:** If JavaScript is minified/uglified, check for the presence of source map files (`.map`). These files can allow reconstruction of the original source code, including comments, and are often inadvertently deployed to production.
        
2. **Automated Static Analysis (SAST):**
    - Utilize SAST tools to scan the application's codebase. Many SAST tools can identify hardcoded secrets, including those within comments, and can be configured with custom rules or regex patterns to detect specific keywords or sensitive data formats.
        
    - Tools like SonarLint can provide real-time feedback within the IDE as developers write code.
        
    - The effectiveness of SAST for this specific weakness is generally considered high.
        
3. **Secrets Detection Tools:**
    - Employ specialized tools like `gitleaks`, `truffleHog`, or commercial equivalents. These tools are designed to scan repositories (including entire Git history) for secrets and can often detect them even if they are within comments. This is particularly useful for finding secrets that were once committed and then perhaps removed from the active code but remain in history.
4. **Browser Developer Tools:**
    - Beyond viewing source, the "Network" tab can show all loaded resources. The "Elements" tab shows the live DOM, which might include dynamically generated comments. The "Console" can reveal output from `console.log` statements left for debugging, which sometimes includes sensitive variable contents mentioned in nearby comments.
5. **Web Proxy Tools (e.g., Burp Suite, OWASP ZAP):**
    - These tools capture all HTTP/S traffic, including all client-side files. Their search functionalities can be used to scan all responses for comment tags and keywords. Some extensions or scripts can automate parts of this search.
6. **Linters and Custom Scripts:**
    - Configure linters for various languages to flag excessive commenting or specific patterns. Custom scripts (e.g., using `grep` with regex) can be used for targeted searches in a codebase or deployment package.

A combination of these methods provides the most comprehensive coverage. Attackers often start with simple browser-based "View Source" or `grep` commands, making easily accessible client-side comments particularly risky. Effective detection must be integrated into the Software Development Lifecycle (SDLC), such as SAST scans in CI pipelines and mandatory, focused code reviews before merging code, rather than being an activity solely performed post-deployment.

## **Proof of Concept (PoC)**

The following scenario illustrates how an attacker might discover and conceptually exploit information found in commented code. This PoC focuses on demonstrating the potential impact of the information disclosure.

**Scenario: Discovery and Exploitation of Debug Endpoint and Credentials**

1. Discovery:
    
    An attacker is performing reconnaissance on a web application, https://www.example-app.com. While inspecting the JavaScript files loaded by the login page (login.js), the attacker finds the following commented-out block:

    ```JavaScript
    /*
    // --- DEBUG MODE ---
    // For internal QA testing on dev server (192.168.1.50) only.
    // To enable, set localStorage.setItem('debugUser', 'qa_admin');
    // and localStorage.setItem('debugToken', 'DEBUG_TOKEN_STRING_12345');
    // This will bypass MFA and use the /api/v1/auth_debug endpoint.
    // REMEMBER TO REMOVE THIS ENTIRE BLOCK BEFORE PRODUCTION!!!
    // Last test: 2024-10-15 - John Doe
    */
    
    // function normalLogin(username, password) {
    //    //... regular login logic...
    // }
    ```
    
2. Information Analysis:
    
    The comment reveals several critical pieces of information:
    
    - The existence of a "debug mode."
    - An internal IP address (`192.168.1.50`), likely a development server.
    - Specific `localStorage` keys and values (`debugUser: qa_admin`, `debugToken: DEBUG_TOKEN_STRING_12345`) used to activate this mode.
    - The fact that debug mode bypasses Multi-Factor Authentication (MFA).
    - A specific debug authentication endpoint: `/api/v1/auth_debug`.
    - A developer's name (`John Doe`) and a recent test date, which could be useful for social engineering or understanding update cycles.
3. **Hypothesis & Attempted Exploitation:**
    - **Hypothesis 1:** The debug mode logic, including the endpoint and token check, might have been mistakenly left active in the production environment.
    - **Attempt (Client-Side):**
        - The attacker opens the browser's developer console on `https://www.example-app.com`.
        - They execute the following commands:
        
            ```JavaScript
            
            localStorage.setItem('debugUser', 'qa_admin');
            localStorage.setItem('debugToken', 'DEBUG_TOKEN_STRING_12345');
            ```
            
        - They refresh the login page or attempt an action that would trigger authentication.
    - **Hypothesis 2:** The debug endpoint `/api/v1/auth_debug` might be directly callable, perhaps expecting the token in a header or parameter.
    - **Attempt (Direct API Call):**
        - Using a tool like `curl` or Postman, the attacker crafts a request to `https://www.example-app.com/api/v1/auth_debug`.
        - They might try sending the `debugUser` and `debugToken` as JSON body, query parameters, or custom headers (e.g., `X-Debug-User: qa_admin`, `X-Debug-Token: DEBUG_TOKEN_STRING_12345`).
4. **Potential Outcome & Impact Demonstration:**
    - **Successful MFA Bypass:** If Hypothesis 1 is correct and the client-side JavaScript still contains the logic to check these `localStorage` items and redirect/authenticate using the debug endpoint, the attacker might successfully log in as `qa_admin` with bypassed MFA, potentially gaining administrative privileges.
    - **Successful API Exploitation:** If Hypothesis 2 is correct, the attacker might receive a session token or direct access by calling the debug API endpoint with the correct debug credentials/token.
    - **Information Gain for Further Attacks:** Even if the debug mode is not fully functional in production, the knowledge of the endpoint, parameter names (`debugUser`, `debugToken`), internal IP, and credential patterns is valuable. This information can be used to:
        - Probe for the endpoint on other subdomains or related servers.
        - Attempt to use the credential pattern (`qa_admin`, `DEBUG_TOKEN_STRING_12345`) against other discovered interfaces.
        - Understand the application's authentication architecture better.

This PoC demonstrates that the primary exploit is the *use of the disclosed information*. The comment itself is not directly executable but provides the blueprint for a potential compromise. The severity of this particular find would be High to Critical due to the MFA bypass and potential admin access. The PoC highlights how a seemingly isolated information leak can become a critical step in an attack chain.

## **Risk Classification**

The risk associated with Commented Code Leftover (CWE-615) is not uniform; it varies significantly based on the sensitivity of the information disclosed within the comments and its potential utility to an attacker. The primary risk scope is **Confidentiality**, as the vulnerability leads to the unauthorized disclosure of information. However, if the leaked information facilitates further attacks, it can also impact **Integrity** and **Availability**.

According to CWE-615, a common consequence is the ability for an attacker to "Read Application Data," which has a high likelihood. This can allow an attacker to map the application's structure, expose hidden parts, and study code fragments to reverse engineer the application. This vulnerability can align with OWASP Top 10 categories such as A01:2021-Broken Access Control (if comments reveal ways to bypass controls), A02:2021-Cryptographic Failures (which absorbed Sensitive Data Exposure, if keys or sensitive data are in comments), or A05:2021-Security Misconfiguration (if comments reveal misconfigurations).

The following table provides a nuanced risk profile based on the type of information commonly found in leftover comments:

**Table: Risk Profile of Commented Code Leftover (Based on CWE-615)**

| **Type of Information Leaked in Comment** | **Potential Attacker Action** | **Primary Risk Scope(s)** | **Example Consequence** | **Typical Severity** |
| --- | --- | --- | --- | --- |
| General developer notes, non-sensitive old logic, code formatting | Understand code flow, identify developers/teams, code style | Reconnaissance | Minor information disclosure, aids social engineering | Low |
| Internal file paths, non-public URLs, old/test API endpoints | Attempt to access restricted areas, map application structure, probe deprecated endpoints | Information Disclosure, Reconnaissance | Discovery of hidden functionality, understanding of application architecture | Low to Medium |
| Old/alternative code logic (functional but not currently used) | Understand system evolution, identify deprecated flaws, infer current logic patterns | Reconnaissance, Potential Vulnerability Identification | Insight into past weaknesses that might still exist or be reintroduced | Medium |
| Database structure details, partial query logic, data model information | Craft targeted database queries (e.g., SQLi), understand data relationships | Information Disclosure, Reconnaissance | Facilitate other attacks (e.g., SQL Injection), data exfiltration if combined with SQLi | Medium |
| Full database queries (especially with sensitive table/column names) | Directly attempt query manipulation if an injection point is found | Information Disclosure, Integrity | More precise SQL injection, potential data enumeration | Medium to High |
| Configuration details (e.g., timeout values, feature flags, paths) | Exploit misconfigurations, understand system behavior under specific conditions | Information Disclosure, Reconnaissance | Denial of service, bypass of certain features, targeted exploitation | Medium to High |
| API keys (for non-critical or test services), session token examples | Unauthorized access to limited third-party services, session hijacking attempts | Confidentiality, Integrity | Abuse of test services, potential for limited unauthorized actions | High |
| Active API keys (for critical services), full credentials, private keys | Unauthorized access to critical systems/data, data breach, financial loss | Confidentiality, Integrity, Availability | Full account/system compromise, significant data loss or manipulation | Critical |
| Explicit security bypass logic, hardcoded backdoors (commented out) | Attempt to reactivate or replicate bypass | Confidentiality, Integrity, Availability | Complete compromise of security controls | Critical |

The ease of discovery also plays a crucial role in assessing likelihood. Comments in publicly accessible client-side files (HTML, JavaScript) are more likely to be found than those in server-side code that requires a separate breach to be exposed. The risk is not static; information from old comments can still be relevant if it provides clues about current system patterns, such as password policies or architectural designs. Therefore, effective risk classification demands not just the identification of the comment but a contextual understanding of the information's value to an attacker.

## **Fix & Patch Guidance**

The primary remediation for Commented Code Leftover is the proactive removal of unnecessary and sensitive comments, along with the code they pertain to, before deployment to any environment accessible beyond local development. This involves a combination of process changes, developer practices, and automated checks.

1. **Thorough Code Reviews:**
    - Implement mandatory code reviews as a gate before merging code into main/development branches or deploying.
    - Reviewers must specifically look for:
        - Large blocks of commented-out code.
        - Comments containing credentials, API keys, internal IP addresses, hostnames, sensitive file paths, PII, or any other potentially sensitive operational or business data.
        - Debug statements, temporary workarounds, or comments with keywords like "TODO", "FIXME", "HACK", "TEMP", "password", "key", "admin", "debug", "secret".
        - Comments that describe application logic or security mechanisms in excessive detail.
2. **Version Control System (VCS) Hygiene:**
    - Utilize the VCS (e.g., Git) as the definitive source for code history, experimental features (using branches), and reverting changes. Discourage the use of comments within active code files for these purposes.

    - Train developers to remove or refactor commented-out code and sensitive comments *before* committing changes. If a temporary comment is necessary for a work-in-progress commit on a feature branch, ensure it is addressed before a merge request is created.
3. **Automated Tooling in CI/CD:**
    - **Static Application Security Testing (SAST):** Integrate SAST tools into the CI/CD pipeline. Configure these tools to scan for secrets (API keys, passwords, etc.) within all code files, including comments. Many SAST tools can also flag overly long comments or specific keywords.

    - **Linters and Custom Scripts:** Employ linters that can identify and flag commented-out code blocks or specific comment patterns. Custom scripts (e.g., using `grep` with regular expressions) can be added as a build step to search for forbidden keywords or patterns in comments.
    - **Secret Scanners:** Use tools like `gitleaks` or `truffleHog` in pre-commit hooks or CI pipelines to detect secrets before they are permanently recorded in version control or deployed.
4. **Build and Minification Processes:**
    - For client-side code (JavaScript, CSS), ensure that build and minification tools are correctly configured to strip all comments from production bundles.
    - **Caution:** Do not rely solely on this. Server-side code comments, comments in configuration files not processed by these tools, or misconfigurations in the build process itself can still lead to exposure. The primary defense is removal at the source.
5. **Developer Education and Awareness:**
    - Conduct regular training sessions to educate developers on the security risks associated with leaving sensitive information or dead code in comments.

    - Establish clear secure coding guidelines that explicitly address commenting practices.
6. **Incident Response for Discovered Leftovers:**
    - If sensitive information is found in comments in a production system:
        - Immediately remove the offending comments and redeploy.
        - If credentials or API keys were exposed, revoke them and issue new ones.
        - Analyze the potential impact of the exposure.
        - Review version control history to determine when the information was introduced and if it was present in previous versions. Consider procedures for cleaning sensitive data from Git history if deemed necessary (though this is complex and has its own risks).

The most effective "patch" is prevention through disciplined development practices and automated checks. This vulnerability is less about a flaw in a software library that needs a version update and more about maintaining a high standard of code hygiene throughout the development lifecycle.

## **Scope and Impact**

The scope of Commented Code Leftover is broad, potentially affecting any component of an application or system where developers can insert comments. This includes client-side code (HTML, JavaScript, CSS), server-side application logic, configuration files, build scripts, and even database schemas or Infrastructure as Code (IaC) templates. The impact is primarily **Information Disclosure**, but the consequences can cascade, facilitating more severe attacks.

**Scope:**

- **Application-Wide:** Can occur in any text-based file that is part of the application stack.
- **Environment-Specific:** Comments might expose details specific to development, staging, or production environments if care is not taken to manage configurations and comments appropriately for each.
- **Interconnected Systems:** Leaked information, such as API keys or credentials for shared services, can extend the impact beyond the immediate application to other systems within an organization's ecosystem.

**Impact:**

The impact of this vulnerability is directly proportional to the sensitivity of the information disclosed and the criticality of the affected system.

- **Direct Impacts:**
    - **Confidentiality Breach (Information Disclosure):** This is the most direct impact. Attackers can gain access to :

        - **Technical Details:** Internal IP addresses, server names, file paths, directory structures, software versions, database table/column names, API endpoints.
        - **Credentials & Secrets:** Usernames, passwords, API keys, session tokens, encryption keys, database connection strings.
        - **Business Logic:** Proprietary algorithms, internal processes, deprecated features, known bugs, security workarounds.
        - **PII Hints or Metadata:** While direct PII is less common in comments, notes about data handling or fields can provide clues.
- **Indirect Impacts:**
    - **Facilitation of Other Attacks:** This is often the most significant consequence. The disclosed information acts as a stepping stone :
        - **Reconnaissance Enhancement:** Provides attackers with a detailed map of the application and infrastructure, reducing their effort and increasing the effectiveness of targeted attacks.
        - **Exploitation of Other Vulnerabilities:** Knowledge of parameter names, data types, or internal logic can help in crafting precise payloads for SQL injection, XSS, command injection, or insecure deserialization.
        - **Authentication/Authorization Bypass:** Leaked credentials or details about debug modes or backdoors can lead to direct unauthorized access or privilege escalation.
    - **Reputational Damage:** Public exposure of sensitive internal information, poor coding practices, or embarrassing developer commentary can damage an organization's reputation and erode customer trust.
        
    - **Financial Loss:** Direct financial loss can occur if leaked credentials are used for fraudulent transactions. Indirect losses can arise from incident response costs, regulatory fines, and loss of business.

    - **Intellectual Property (IP) Theft:** Disclosure of proprietary algorithms or unique business logic can lead to competitors gaining an unfair advantage.

    - **Compliance Violations:** If comments expose PII or data regulated by standards like GDPR, HIPAA, or PCI DSS, the organization can face significant fines and legal repercussions.

    - **Increased Attack Surface Understanding:** Attackers gain a clearer view of potential weaknesses and entry points, making future attacks easier to plan and execute.

    - **Reduced Time and Effort for Attackers:** The information effectively provides attackers with "insider" knowledge, saving them considerable time that would otherwise be spent on probing and discovery.

The impact is not always from a single revelatory comment. Often, it is the aggregation of multiple, seemingly minor pieces of information from various comments that provides an attacker with a comprehensive understanding of the target system. A comment revealing an old password pattern, for instance, might not grant immediate access but can inform brute-force strategies against current accounts. The impact extends beyond the application itself, as leaked developer information or common credential patterns could be used to target other organizational assets or in social engineering campaigns.

## **Remediation Recommendation**

Addressing the "Commented Code Leftover" vulnerability requires a combination of immediate corrective actions for existing codebases and long-term preventative strategies integrated into the Software Development Lifecycle (SDLC). The goal is to eliminate current instances and prevent future occurrences.

**I. Immediate Actions (for existing codebases):**

1. **Comprehensive Code Audit:**
    - Conduct a thorough audit of all active codebases, prioritizing client-facing applications and publicly exposed code (HTML, JavaScript, CSS).
    - Employ both manual review techniques and automated tools (SAST, secret scanners) as detailed in the "Detection Steps" section to identify all instances of commented-out code and sensitive information within comments.
    - Pay special attention to comments containing keywords like "TODO", "FIXME", "password", "key", "API", "internal", "debug", etc.
2. **Prioritized Removal:**
    - Remove all identified sensitive information from comments.
    - Remove large blocks of commented-out functional code. If the code represents a previous state or an experimental feature, ensure it is properly managed in the version control system (e.g., in a separate branch or accessible through commit history).

    - Redeploy cleaned applications immediately.
3. **Credential Rotation & Access Review:**
    - If active credentials, API keys, or other secrets are found, revoke them immediately and issue new ones.
    - Review access logs for any signs of misuse of the exposed secrets.
4. **Version Control History Review:**
    - Scan version control history (e.g., Git history) for sensitive information that might have been committed in comments previously and subsequently removed from the active codebase.
    - If highly sensitive data is found in commit history, evaluate the need and feasibility of purging it (e.g., using `git filter-repo` or BFG Repo-Cleaner). This process is complex and should be undertaken with caution as it rewrites history.

**II. Long-Term Prevention Strategies:**

1. **Establish Clear Coding and Commenting Policies:**
    - Develop and enforce strict coding standards that explicitly forbid:
        - Storing any sensitive information (credentials, keys, PII, internal infrastructure details) in comments.
        - Leaving large blocks of unused or experimental code commented out in production-bound branches.
    - Mandate the use of the version control system for managing code history, feature experimentation (via branches), and temporary code changes. Comments should explain *why* code does something, not *what* it used to do or contain secrets.
2. **Mandatory Secure Code Reviews:**
    - Integrate mandatory, thorough code reviews into the pre-merge/pre-deployment process.
        
    - Provide reviewers with a checklist that specifically includes looking for sensitive comments, commented-out code, debug statements, and temporary workarounds.
3. **Integrate Automated Scanning into CI/CD Pipelines:**
    - **SAST Tools:** Embed SAST tools into the CI/CD pipeline to automatically scan code (including comments) for hardcoded secrets, sensitive keywords, and patterns indicative of information disclosure. Configure these tools to fail the build or flag issues for review if such items are detected.
        
    - **Secret Scanning Tools:** Implement repository-wide secret scanning that runs regularly and on new commits/PRs.
    - **Linters:** Configure linters to flag excessive commented code or specific unwanted comment patterns.
4. **Pre-Commit / Pre-Push Hooks:**
    - Encourage or enforce the use of client-side pre-commit hooks that scan staged files for common secret patterns or "TODO" comments that might contain sensitive context before they are even committed.
5. **Developer Training and Awareness Programs:**
    - Conduct regular security awareness training for all development staff.
        
    - Specifically educate developers on the risks of information disclosure through comments, secure commenting practices, proper use of version control, and the organization's policies regarding code hygiene.
    - Share examples of how seemingly innocuous comments have led to security incidents.
6. **Configuration Management for Build Tools:**
    - Ensure that any build tools, minifiers, or bundlers used for client-side code are correctly configured to strip comments for production builds. However, reiterate that this is a secondary defense, not a replacement for removing sensitive comments at the source.
7. **Foster a Security-Conscious Culture:**
    - Promote a culture where developers take ownership of the security of their code, including its non-executable parts like comments.
    - Encourage the proactive deletion of unneeded code and comments to maintain a clean, maintainable, and secure codebase.

Effective remediation is not a one-off activity but a continuous process of vigilance, automation, and education. By integrating these recommendations, organizations can significantly reduce the risk of sensitive information exposure through commented code leftovers, leading to improved overall code quality and security posture.

## **Summary**

Commented Code Leftover, identified as CWE-615 (Inclusion of Sensitive Information in Source Code Comments), is an information disclosure vulnerability that arises when developers inadvertently leave sensitive data, debugging information, or inactive code segments within comments that are then deployed to accessible environments. This is primarily a human oversight issue, often occurring due to rushed development, improper use of comments for versioning or temporary disabling of code, or inadequate code review processes.

The risks associated with this vulnerability are significant and multifaceted. While not directly executable, the information contained in comments can provide attackers with critical insights into application architecture, internal infrastructure, credentials, API keys, or deprecated logic. This information greatly aids attacker reconnaissance, can directly lead to unauthorized access if credentials are exposed, and facilitates the exploitation of other vulnerabilities by providing context or revealing weaknesses. The severity of the vulnerability is highly contextual, ranging from low for benign developer notes to critical if active credentials or sensitive operational details are leaked.

Detection involves a combination of meticulous manual code reviews, especially of client-side code, and the use of automated tools such as SAST and specialized secret scanners integrated into the SDLC. The primary remediation strategy is the diligent removal of such comments and commented-out code before deployment. This should be supported by robust code review practices, leveraging version control systems for historical code management rather than comments, and continuous developer training on secure coding and commenting hygiene.

Ultimately, Commented Code Leftover underscores the principle that all components of a codebase, including non-executable comments, require security scrutiny. Addressing this vulnerability is a fundamental aspect of secure software development, contributing not only to enhanced security but also to cleaner, more maintainable code.

## **References**

- CWE-615: Inclusion of Sensitive Information in Source Code Comments. MITRE. Available: https://cwe.mitre.org/data/definitions/615.html
    
- OWASP Foundation. Web Security Testing Guide (WSTG) - WSTG-INFO-05 - Review Web Page Content for Information Leakage. Available:(https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage)
    
- OWASP Foundation. Secure Coding Practices - Quick Reference Guide. Available: https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist
    
- OWASP Foundation. Developer Guide - 12.2.1 Secure environment. Available: https://devguide.owasp.org/12-appendices/02-verification-dos-donts/01-secure-environment/

- PortSwigger. Web Security Academy - Information disclosure. Available: https://portswigger.net/web-security/information-disclosure

- Acunetix. "What is Cross-site Scripting (XSS): prevention and fixes". Available: https://www.acunetix.com/websitesecurity/cross-site-scripting/  (Referenced for context on how comments might be involved in other vulnerabilities).

- Beagle Security. "Source code disclosure". Available: https://beaglesecurity.com/blog/vulnerability/source-code-disclosure.html

    
- Securityium. "Understanding Information Disclosure Vulnerabilities: Risks & Fixes". Available: https://www.securityium.com/understanding-information-disclosure-vulnerabilities-risks-fixes/
    