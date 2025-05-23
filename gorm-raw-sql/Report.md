# GORM Raw SQL Misuse Leading to SQL Injection (CWE-89)

## 1. Vulnerability Title

GORM Raw SQL Misuse Leading to SQL Injection (CWE-89)

This title precisely identifies the core vulnerability: the improper utilization of GORM's raw SQL functionalities, which directly results in SQL Injection vulnerabilities. SQL Injection is a well-documented class of vulnerability, formally categorized under CWE-89 (Improper Neutralization of Special Elements used in an SQL Command). GORM, as an Object-Relational Mapper (ORM) for Golang, aims to simplify and secure database interactions. However, when its features allowing for raw SQL execution are not handled with appropriate caution—particularly concerning user-supplied input—the protections typically afforded by the ORM can be bypassed, reintroducing classic SQL Injection risks. The designation "gorm-raw-sql" specifically pinpoints this scenario where the ORM's raw SQL capabilities are the vector for the vulnerability.

The specificity of "GORM Raw SQL Misuse" underscores a common pitfall: developers may erroneously assume that all operations performed through an ORM are inherently secure. This assumption can be particularly dangerous when developers deviate from standard, abstracted ORM methods to employ raw SQL for complex queries or performance optimizations. ORMs generally provide safety by default for their structured methods, often through automatic parameterization of inputs. GORM, for instance, offers methods like `Raw()` and `Exec()` for executing custom SQL. If developers use these methods but abandon the secure practice of parameterization—a practice the ORM might otherwise handle implicitly—they expose the application to SQL Injection. It is critical to understand that the vulnerability, in this context, does not typically lie within GORM itself but rather in its *misuse* when these specific raw SQL features are employed. This distinction is vital, as highlighted by observations that misusing GORM by passing untrusted user input where GORM expects trusted SQL fragments constitutes a vulnerability in the application, not in GORM. Consequently, security awareness and practices for GORM users must emphasize that the ORM's safety net is significantly reduced when using raw SQL, making secure SQL coding practices, such as robust input validation and consistent parameterization, paramount.

## 2. Severity Rating

High🟠 to Critical🔴 (CVSS Base Score typically 7.5 - 9.8 for SQL Injection)

SQL Injection vulnerabilities are consistently classified with a high impact severity. The Common Vulnerability Scoring System (CVSS) base score for SQL Injection vulnerabilities, including those arising from GORM raw SQL misuse, generally falls within the range of 7.5 (High) to 9.8 (Critical). For instance, documented SQL injection vulnerabilities in various systems have received CVSS scores such as 9.0, 7.5, 9.1, and 8.8. The precise score is contingent upon several factors, including the attack vector (e.g., network, local), attack complexity, privileges required for exploitation, necessity of user interaction, and the resultant impact on the confidentiality, integrity, and availability of data and systems.

The high severity rating stems from the extensive potential for damage, which can include complete database compromise, unauthorized data access and modification, and denial of service. While GORM is a Golang library designed to abstract database interactions, the fundamental severity of SQL Injection remains undiminished if user input is allowed to directly influence raw SQL queries without proper sanitization or parameterization. The presence of an ORM layer does not inherently reduce the *potential impact* of an SQL Injection vulnerability if its protective mechanisms are bypassed through the misuse of raw SQL features.

The rationale for this high severity is rooted in the power of SQL itself. SQL Injection allows an attacker to directly manipulate database queries. Given that databases are often the repositories for an application's most critical assets—such as Personally Identifiable Information (PII), financial details, and authentication credentials—a successful SQLi can lead to severe consequences. These include theft of sensitive data (violating Confidentiality), unauthorized alteration or deletion of data (compromising Integrity), and disruption of application or database services (affecting Availability). The CVSS framework inherently assigns high scores to scenarios involving such impacts. Misuse of GORM's raw SQL capabilities directly exposes the application to these high-impact outcomes. Therefore, any GORM raw SQL vulnerability should be treated with the same level of urgency as any other high-severity SQL Injection flaw, and the use of an ORM should not lead to a false sense of security or a downplaying of the associated risks.

## 3. Description

A GORM raw SQL misuse vulnerability materializes when an application leverages GORM's functionalities for executing raw SQL queries—such as the `Raw()` or `Exec()` methods—by directly embedding or concatenating user-supplied input into the SQL query string without adequate sanitization or, more importantly, parameterization. This practice allows malicious actors to inject arbitrary SQL fragments into the query. These injected fragments can alter the intended logic of the SQL statement, potentially leading to unauthorized access to data, modification or deletion of records, execution of administrative database operations, or other forms of exploitation.

This vulnerability is a specific instance of SQL Injection (CWE-89) , occurring within the context of applications built using the GORM library. While ORMs like GORM are designed to provide an abstraction layer over SQL and often include built-in protections against SQL Injection for their standard query-building methods, these protections can be circumvented if raw SQL features are used improperly. The core of the issue lies in the failure to treat user-supplied data as data only; instead, due to insecure concatenation, it is interpreted by the database as part of the SQL command itself.

The vulnerability is not inherent to the existence of raw SQL execution features in GORM but rather stems from a specific, insecure pattern of their use. GORM provides these tools for flexibility, for instance, to execute complex queries that might be cumbersome to express through the standard ORM query builder. However, when developers construct the SQL strings for these raw methods by directly incorporating untrusted input (e.g., data from HTTP requests, API calls, or other external sources), they are essentially manually crafting SQL queries with potentially hostile external data. This manual construction often bypasses the default parameterization mechanisms that GORM might apply to its more abstracted methods (e.g., `db.Where("column =?", value)`). Consequently, the vulnerability manifests as a classic SQL Injection, merely facilitated through an ORM's interface intended for raw query execution. This underscores a shared responsibility: GORM provides the functionality, but developers are responsible for employing it securely, particularly by ensuring that any user-supplied components of a raw SQL query are correctly parameterized.

## 4. Technical Description (for security pros)

This vulnerability is a manifestation of CWE-89, Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'), specifically within applications utilizing the GORM library for Golang. The vulnerability arises when GORM's methods designed to execute raw SQL statements, such as `Raw()` and `Exec()`, are supplied with SQL query strings constructed through the concatenation or direct embedding of unsanitized user-provided input. This improper construction fails to neutralize SQL metacharacters (e.g., single quotes (`'`), double quotes (`"`), semicolons (`;`), comment markers (`--`, `/* */`)) present in the input. As a result, these special characters are interpreted by the database as part of the SQL command syntax rather than literal data values.

For example, an attacker can submit input such as `' OR '1'='1` or `'; DROP TABLE users; --`. If an application constructs a query like `query := "SELECT * FROM products WHERE id = '" + userInput + "'"` and then executes it using `db.Raw(query).Scan(&result)`, and `userInput` is `' OR '1'='1'`, the effective SQL query sent to the database becomes `SELECT * FROM products WHERE id = '' OR '1'='1'`. This modified logic typically bypasses the intended filtering condition, potentially returning all records from the `products` table.

The fundamental issue is the database interpreter's inability to differentiate between legitimate, developer-intended SQL code and attacker-injected SQL commands when queries are dynamically assembled with untrusted data in this unsafe manner. When GORM's `Raw()` method (or `Exec()`) is used with such a concatenated string, it typically passes the constructed query string to the underlying database driver "as-is." The driver then transmits this malformed query to the database server, leading to the execution of the injected SQL commands.

The attack surface is precisely at the point where developer-controlled string construction, incorporating external input, meets the GORM API call that accepts a raw SQL string. The vulnerability is not typically due to a flaw in GORM's SQL generation for its standard, abstracted query methods (which generally use parameterization correctly). Instead, it occurs when the developer effectively overrides GORM's standard, safer behavior by providing a hand-crafted SQL string that is already tainted with unescaped, malicious input. GORM, in this scenario of misuse, acts merely as a conduit for the malformed SQL query; it does not, and cannot easily, parse the arbitrarily complex concatenated string to distinguish the developer's intended SQL from the user-injected SQL before passing it to the database driver. Security reviews must, therefore, meticulously scrutinize the *construction process* of strings passed to `Raw()` and `Exec()`. The mere presence of these methods is a flag for deeper inspection, but the vulnerability hinges on *how* their string arguments are formed.

## 5. Common Mistakes That Cause This

Several common mistakes made by developers when using GORM's raw SQL capabilities can lead to SQL Injection vulnerabilities:

- **Direct String Concatenation or Formatting:** The most prevalent error is the direct construction of SQL query strings by concatenating user-supplied input using the `+` operator or by embedding it using string formatting functions like `fmt.Sprintf`. This practice injects the raw user input into the SQL statement without any sanitization or escaping, making it vulnerable.
    - *Example:* `userInput := r.URL.Query().Get("id")query := fmt.Sprintf("SELECT * FROM items WHERE item_id = '%s'", userInput)db.Raw(query).Scan(&item)`
    This pattern is highly susceptible if `userInput` contains SQL metacharacters.
- **Misunderstanding or Neglecting GORM's Parameterization for Raw SQL:** Developers might be unaware that GORM's `Raw()` and `Exec()` methods support parameterization (using `?` as placeholders or named arguments like `@name`) or may incorrectly assume that GORM automatically sanitizes any string passed to these methods. The safe parameterization feature is not automatic if a single, fully-formed (but insecurely constructed) string is passed; it requires the developer to use placeholders and provide the corresponding values as separate arguments.
    - *Incorrect Assumption:* Believing `db.Raw("SELECT * FROM users WHERE name = '" + userName + "'")` is somehow safer than raw SQL outside an ORM.
    - *Correct Usage (Ignored):* Failing to use `db.Raw("SELECT * FROM users WHERE name =?", userName)`.
- **False Sense of Security from ORM Usage:** A common cognitive bias is the belief that employing an ORM like GORM provides inherent protection against all forms of SQL Injection, even when utilizing low-level features like raw SQL execution. This can lead to complacency and the neglect of secure coding practices when raw SQL is deemed necessary.
- **Inadequate Input Validation and Sanitization:** While parameterized queries are the primary defense against SQL Injection, insufficient server-side input validation and sanitization serve as a contributing factor. Relying solely on client-side validation, or having weak server-side checks for data type, format, length, or character sets, means that malicious input is more likely to reach the point of SQL query construction. Although not a substitute for parameterization, robust validation is a crucial layer in defense-in-depth.
- **Incorrect Usage of `Exec()` vs. `Raw().Scan()` or Other Finisher Methods:** Developers might misunderstand the operational differences and requirements of GORM's raw SQL methods. For instance, `db.Raw()` by itself typically prepares a `gorm.DB` instance but does not execute the query until a "finisher" method like `Scan()`, `Rows()`, or `Error` is called. If complex string building is performed for a query intended for `Exec()` (which is usually for DML statements not returning rows, like `UPDATE` or `DELETE`, and executes immediately), the same concatenation vulnerabilities apply. Confusion about when execution occurs or how results are handled can sometimes distract from the primary concern of secure query construction.

A recurring theme in these mistakes is the disconnect between the abstraction and convenience offered by the ORM for standard operations, and the developer's understanding when they step "outside" this abstraction to use raw SQL. The ORM's typical safety mechanisms (like implicit parameterization in `db.Where("id =?", id)`) might lead to incorrect assumptions about how raw SQL strings are handled. Developers are taking full control of the SQL statement when they pass a complete string to `Raw()`; if they then apply the same mental model of "the ORM handles security" to the *construction* of that string (e.g., by using `fmt.Sprintf` with untrusted input), they introduce the vulnerability. The mistake is essentially a misapplication of the ORM's safety model to a feature explicitly designed to allow more direct, and thus potentially less automatically safeguarded, database interaction. Developer education must clearly delineate between GORM's abstracted query-building methods and its raw SQL execution methods, emphasizing that the latter require explicit and correct parameterization by the developer.

## 6. Exploitation Goals

Attackers who successfully exploit GORM raw SQL misuse vulnerabilities, which manifest as SQL Injection, pursue a variety of malicious objectives, mirroring the goals of general SQL Injection attacks. The ORM context does not inherently limit the attacker's capabilities once they can inject and execute arbitrary SQL commands. These goals primarily include:

- **Data Exfiltration (Loss of Confidentiality):** The most common goal is to retrieve sensitive information from the database. This can range from specific targeted data to entire tables containing user credentials, personal identifiable information (PII), financial records, intellectual property, or critical application configuration data. Attackers might use `UNION`based SQL Injection or manipulate `WHERE` clauses to broaden query results.
- **Data Manipulation (Loss of Integrity):** Attackers may aim to modify, insert, or delete data within the database. This could involve altering user account details (e.g., changing passwords or escalating privileges), manipulating financial transactions, defacing website content, or corrupting or deleting critical business data. Injected `UPDATE`, `INSERT`, or `DELETE` statements are common vectors.
- **Unauthorized Access and Privilege Escalation (Authentication/Authorization Bypass):** SQL Injection can be used to circumvent authentication mechanisms, allowing attackers to log in as legitimate users (including administrators) without valid credentials. They might also alter authorization controls within the database to grant themselves or other accounts elevated privileges. This is often achieved by injecting conditions like `' OR '1'='1` into login queries.
- **Denial of Service (DoS) (Loss of Availability):** Attackers can disrupt the availability of the application or database. This can be achieved by deleting critical data, dropping tables, or executing resource-intensive queries (e.g., complex joins on large tables, computationally heavy functions) that exhaust server resources (CPU, memory, disk I/O), leading to a slowdown or complete shutdown of the database service.
- **Remote Code Execution (RCE) / Server Compromise:** Depending on the database management system (DBMS) in use, its configuration, and the privileges of the database account compromised via SQL Injection, attackers may be able to escalate their access to execute commands on the underlying operating system of the database server. This can lead to a full compromise of the server, providing a persistent foothold in the victim's network. Certain DBMS functionalities (e.g., `xp_cmdshell` in SQL Server, UDFs in MySQL/PostgreSQL) can be abused for this purpose.

The exploitation goals for GORM raw SQL misuse are identical to those of general SQL Injection because the underlying vulnerability mechanism—the ability to directly manipulate SQL commands executed by the database—is the same. The database interprets the injected SQL based on its syntax and the permissions of the application's database user. Therefore, the defense strategy must assume the worst-case scenario regarding attacker intent. Implementing the principle of least privilege for the database user account that GORM connects with becomes a critical mitigating factor, as it can limit the scope and severity of what an attacker can achieve even if an injection vulnerability is present.

## 7. Affected Components or Files

The components and files affected by GORM raw SQL misuse vulnerabilities are primarily within the application's own codebase, rather than the GORM library itself or underlying database drivers (assuming these are not independently flawed). The vulnerability is one of implementation, specifically how the application code utilizes GORM's raw SQL features.

Key affected areas include:

- **Go Source Code Files (`.go` files):** Any Go file within the application's project that contains code utilizing GORM's raw SQL execution methods. The most commonly implicated methods are `db.Raw()` and `db.Exec()`.
- **Specific Functions or Methods:** Within these `.go` files, the vulnerability resides in functions or methods where SQL query strings are constructed by directly incorporating data derived from external, untrusted sources. Such sources include, but are not limited to:
    - HTTP request parameters (query strings, form data, path variables)
    - HTTP request headers or cookies
    - User-provided payloads in API requests (JSON, XML, etc.)
    - Data read from files or other external systems if that data can be influenced by an attacker.
    The critical factor is the construction of the SQL string using concatenation or unsafe string formatting (like `fmt.Sprintf`) with this untrusted input, *without* leveraging GORM's secure parameterization mechanisms (i.e., `?` placeholders or named arguments with subsequent value arguments).
- **Modules or Packages for Database Interaction:** Custom modules, packages, or layers within the application responsible for database interactions, often referred to as Data Access Layers (DALs), repositories, or services. If these components build and execute raw SQL queries using GORM in an unsafe manner, they become affected components.
- **Utility Functions or Templates:** Any utility functions or templating mechanisms that might dynamically generate SQL fragments, which are then concatenated and passed to GORM's raw SQL methods, can also be a source of vulnerability if the inputs to these generators are not properly handled.

It is crucial to reiterate that the affected components are parts of the application's codebase that *misuse* GORM. GORM provides the `Raw()` and `Exec()` functionalities for flexibility; the vulnerability arises from an insecure implementation pattern adopted by the developer. Therefore, security audits and code scanning tools should be configured to flag all usages of these GORM methods for careful manual review, with a specific focus on how the SQL string argument is constructed from external inputs. The presence of these methods signals a point where the developer takes on more direct responsibility for SQL security.

## 8. Vulnerable Code Snippet

The following Go code snippet demonstrates a common way GORM's raw SQL functionality can be misused, leading to an SQL Injection vulnerability.

```Go

package main

import (
    "fmt"
    "net/http"

    "gorm.io/gorm"
    // Ensure you have a GORM driver imported, e.g.:
    // "gorm.io/driver/sqlite" 
    // "gorm.io/driver/postgres"
)

// User defines a simple user model
type User struct {
    ID   uint
    Name string
    Age  int
    // other fields
}

// db is a global variable for the GORM database instance.
// In a real application, this would be initialized appropriately.
var db *gorm.DB 

// InitDB initializes the database connection (example setup)
// func InitDB() {
//     var err error
//     // Example for SQLite:
//     // db, err = gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
//     // if err!= nil {
//     //     panic("failed to connect database")
//     // }
//     // db.AutoMigrate(&User{})
// }

// GetUserByName retrieves a user by their name from an HTTP request.
// This function contains the vulnerable raw SQL usage.
func GetUserByName(w http.ResponseWriter, r *http.Request) {
    // Assume 'db' is initialized elsewhere and available.
    // if db == nil {
    //     http.Error(w, "Database not initialized", http.StatusInternalServerError)
    //     return
    // }

    userName := r.URL.Query().Get("name") // User input from query parameter
    var user User

    // VULNERABLE: User input is directly concatenated into the raw SQL query string
    // using fmt.Sprintf without parameterization.
    // Example of malicious input for 'userName': ' OR '1'='1
    // This would change the query to:
    // SELECT * FROM users WHERE name = '' OR '1'='1'
    rawQuery := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userName)
    
    // Execute the raw query
    result := db.Raw(rawQuery).Scan(&user)
    if result.Error!= nil {
        if result.Error == gorm.ErrRecordNotFound {
            http.Error(w, fmt.Sprintf("User '%s' not found", userName), http.StatusNotFound)
            return
        }
        http.Error(w, "Database query error", http.StatusInternalServerError)
        return
    }

    if result.RowsAffected == 0 {
         http.Error(w, fmt.Sprintf("User '%s' not found (no rows affected)", userName), http.StatusNotFound)
         return
    }

    fmt.Fprintf(w, "User Found: ID=%d, Name=%s, Age=%d", user.ID, user.Name, user.Age)
}

// main function to set up the HTTP server (example)
// func main() {
//     InitDB() // Initialize DB connection
//     http.HandleFunc("/user", GetUserByName)
//     fmt.Println("Server starting on port 8080...")
//     log.Fatal(http.ListenAndServe(":8080", nil))
// }
```

**Explanation of Vulnerability:**

In the `GetUserByName` function, the `userName` variable is fetched directly from an HTTP GET request's query parameter (`r.URL.Query().Get("name")`). This input is then embedded into the `rawQuery` string using `fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userName)`. This method of string construction does not sanitize the `userName` input nor does it utilize GORM's built-in parameterization capabilities for raw SQL queries.

If an attacker provides a malicious string such as `' OR '1'='1` as the value for the `name` query parameter, the `rawQuery` string becomes:
`SELECT * FROM users WHERE name = '' OR '1'='1'`

When GORM executes this query via `db.Raw(rawQuery).Scan(&user)`, the SQL `WHERE` clause `name = '' OR '1'='1'` will evaluate to true for every row in the `users` table. This effectively bypasses the intended filter that was supposed to retrieve a user by a specific name. Depending on how `Scan()` handles multiple results when scanning into a single struct, it might return the first user from the table, or an error if types don't match as expected. More sophisticated SQL injection payloads could be used to extract other data, modify records, or cause a denial of service.

The simplicity of using `fmt.Sprintf` for dynamic query construction can be deceptive. Developers, especially those under tight deadlines or less familiar with the nuances of SQL injection and ORM raw SQL security, might opt for this method due to its apparent straightforwardness. This is particularly risky if they are already using `db.Raw()` for legitimate reasons, such as executing a query whose structure is too complex for GORM's standard query builders. This example highlights a critical anti-pattern: combining `fmt.Sprintf` (or direct string concatenation) with `db.Raw()` for incorporating user-supplied data into SQL queries is a direct path to SQL Injection.

## 9. Detection Steps

Detecting GORM raw SQL misuse vulnerabilities requires a combination of manual and automated techniques, focusing on identifying how raw SQL queries are constructed and executed with user-supplied data.

- **Manual Code Review:**
    - **Targeted Inspection:** Systematically review all Go source code files for instances where GORM's raw SQL execution methods are used. These primarily include `db.Raw()` and `db.Exec()`, but any other custom or library function that ultimately passes a string to GORM for raw execution should also be scrutinized.
    - **Query Construction Analysis:** For each identified use of raw SQL, meticulously analyze how the SQL query string is constructed. The primary red flag is the use of string concatenation (e.g., using the `+` operator) or string formatting functions (e.g., `fmt.Sprintf`) to embed variables derived from untrusted external sources directly into the SQL string.
    - **Parameterization Check:** Verify that if raw SQL methods are used with dynamic values, GORM's secure parameterization mechanism is correctly implemented. This involves looking for the use of `?` as placeholders in the SQL string, with the corresponding values passed as subsequent arguments to the `Raw()` or `Exec()` method (e.g., `db.Raw("SELECT... WHERE id =?", userID)`). Also, check for the correct use of named arguments if that pattern is employed.
- **Static Application Security Testing (SAST):**
    - **Tool Utilization:** Employ SAST tools that are capable of analyzing Go code. Configure these tools with rules specifically designed to detect unsafe patterns of raw SQL construction with GORM.
    - **Data Flow Analysis:** Effective SAST tools can perform data flow analysis to trace data from untrusted input sources (e.g., HTTP request parameters, API inputs) to the arguments of GORM's raw SQL methods. If the data flows into a string that is then concatenated or formatted into the SQL query without passing through a parameterization mechanism, the tool should flag it.
    - **Verification of Findings:** SAST tools can generate false positives or miss vulnerabilities in complex code. All findings should be manually verified by a security analyst or developer to confirm their validity and context.
- **Dynamic Application Security Testing (DAST):**
    - **Automated Probing:** Use DAST tools to actively test the running application. These tools send crafted inputs, including common SQL injection payloads (e.g., single quotes, boolean-based conditions, time-based delays, `UNION` statements), to all accessible input fields, URL parameters, headers, etc..
    - **Behavioral Analysis:** DAST observes the application's responses (errors, changes in content, response times) to identify anomalous behavior indicative of successful SQL injection.
    - **Confirmation of Exploitability:** DAST can confirm whether identified injection points are practically exploitable. However, DAST tools typically cannot pinpoint the exact vulnerable line of code in the source, requiring further investigation often guided by SAST or manual review.
- **Security Linters for Go:**
    - Integrate Go-specific security linters, such as `gosec`, into the development workflow and CI/CD pipelines. `gosec` includes checks for hardcoded SQL and can often detect obviously unsafe uses of `fmt.Sprintf` or other string formatting functions in the construction of SQL queries passed to database functions, including GORM's `Raw()`/`Exec()`.
- **Logging and Monitoring (Indirect Detection):**
    - While not a direct method for finding code flaws, robust logging of database queries (if feasible and secure) and monitoring database server logs for unusual, malformed, or excessively long/complex queries can sometimes provide indicators of attempted or successful SQL injection attacks. This is more of an incident detection and response measure but can lead to the discovery of underlying vulnerabilities.

Effective detection necessitates a multi-layered strategy. SAST offers the advantage of early detection during development by identifying risky code patterns. DAST validates exploitability in a running environment. Manual code review remains crucial for understanding context, verifying tool findings, and identifying subtle vulnerabilities that automated tools might miss, especially given that GORM raw SQL misuse is fundamentally an incorrect implementation pattern. Training developers to recognize these vulnerable patterns also serves as a proactive "detection" mechanism by preventing the introduction of such flaws.

## 10. Proof of Concept (PoC)

This Proof of Concept demonstrates how a GORM raw SQL misuse vulnerability, as shown in the vulnerable code snippet (Section 8), can be exploited.

**Scenario:**
The application has a web endpoint, for instance, `/user`, which accepts a `name` query parameter to search for a user. The backend Go code uses GORM's `db.Raw()` method with `fmt.Sprintf` to construct the SQL query, making it vulnerable.

**Vulnerable Code Reference (from Section 8):**

```Go

//...
userName := r.URL.Query().Get("name")
rawQuery := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userName)
db.Raw(rawQuery).Scan(&user) 
//...
```

**Attacker's Goal:**
To bypass the intended filter (searching by a specific name) and retrieve information about users they are not supposed to see, or to confirm the SQL injection vulnerability.

**PoC 1: Boolean-Based SQL Injection to Retrieve Data**

- **Malicious Input:** The attacker crafts a URL targeting the vulnerable endpoint:
`http://localhost:8080/user?name=' OR '1'='1`
- **Execution Flow:**
    1. The `GetUserByName` handler in the Go application receives the `name` parameter with the value `' OR '1'='1`.
    2. The line `rawQuery := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userName)` constructs the SQL query string as:
    `"SELECT * FROM users WHERE name = '' OR '1'='1'"`
    The initial single quote from the input closes the string literal for `name = '`, and the rest of the input is appended as SQL logic.
    3. GORM's `db.Raw(rawQuery).Scan(&user)` method executes this maliciously crafted SQL query against the database.
    4. The `WHERE` clause `name = '' OR '1'='1'` evaluates to `TRUE` for every row in the `users` table because `'1'='1'` is always true.
- **Outcome:**
Instead of returning a specific user matching a benign name or a "User not found" error, the query will attempt to retrieve all users. If `user` is a single `User` struct, `db.Scan(&user)` will typically populate `user` with the data from the first row returned by the query `SELECT * FROM users`. The HTTP response would then display the details of this first user, confirming the vulnerability and exfiltrating unintended data.

**PoC 2: UNION-Based SQL Injection for Data Extraction (Illustrative)**

This PoC is more advanced and its success depends on the attacker knowing or guessing table/column names and the number of columns in the original `SELECT` statement. Assume the `users` table (queried by `SELECT *`) has columns like `id`, `name`, `age`, `email`, `password_hash`.

- **Malicious Input:** The attacker crafts a URL:
`http://localhost:8080/user?name=' UNION SELECT NULL,cc_number,expiry_date,cvv,NULL FROM credit_cards--`
(Assuming a `credit_cards` table exists with `cc_number`, `expiry_date`, `cvv` columns, and the original query selects 5 columns implicitly with ).
- **Potentially Injected Query:**`SELECT * FROM users WHERE name = '' UNION SELECT NULL,cc_number,expiry_date,cvv,NULL FROM credit_cards--'`
The `-` at the end comments out any remaining part of the original query, like a trailing single quote if `fmt.Sprintf` added one.
- **Execution Flow:**
    1. The `userName` input is substituted into `rawQuery`.
    2. The `UNION SELECT` statement is appended to the original query.
    3. If the number of columns in the `UNION SELECT` matches the original `SELECT * FROM users`, and data types are compatible or coercible, the database will execute the combined query.
- **Outcome:**
The query could return results from the `credit_cards` table, mapped into the fields of the `User` struct being scanned. For example, `cc_number` might appear in the `user.Name` field in the response if the column order and types align or are cast appropriately by the database/driver. This demonstrates exfiltration of data from an entirely different table.

These PoCs illustrate that GORM raw SQL misuse vulnerabilities are exploited using standard SQL Injection techniques. The ORM layer, when its raw SQL features are used insecurely with string concatenation, does not offer protection against these classic attack vectors. The primary focus for security testers is to identify these injection points where user input directly forms part of the SQL command.

## 11. Risk Classification

The risk associated with GORM raw SQL misuse leading to SQL Injection is classified as **High to Critical**. This classification is derived using the OWASP Risk Rating Methodology, which considers both the Likelihood of exploitation and the Impact of a successful exploit.

**Likelihood Factors Assessment:**

| Likelihood Factor | Assessment for GORM Raw SQL Misuse | Score (0-9) |
| --- | --- | --- |
| **Ease of Discovery** | Medium to High. Vulnerable patterns like `fmt.Sprintf` with `db.Raw()` can be identified by SAST tools, DAST tools using common payloads, or manual code review. | 7 |
| **Ease of Exploit** | High. Standard SQL injection techniques and widely available automated tools apply directly once the injection point is found. | 9 |
| **Awareness** | High. SQL Injection is a perennially top-ranked vulnerability (e.g., OWASP Top 10) and is well-understood by attackers. | 9 |
| **Intrusion Detection** | Low to Medium. Basic SQLi attempts might be logged by generic WAFs or IDS, but sophisticated or targeted attacks can evade detection without specialized database activity monitoring or robust application logging. Often, logging is insufficient or not reviewed. | 8 |
| **Overall Likelihood** | **High** (Average score: (7+9+9+8)/4 = 8.25) |  |

**Impact Factors Assessment:**

| Impact Factor | Assessment for GORM Raw SQL Misuse | Score (0-9) |
| --- | --- | --- |
| **Loss of Confidentiality** | High to Critical. Complete disclosure of sensitive data (PII, financial, credentials) stored in the database is possible. | 9 |
| **Loss of Integrity** | High to Critical. Unauthorized modification, creation, or deletion of data, potentially leading to fraud, impersonation, or data corruption. | 9 |
| **Loss of Availability** | Medium to High. Database services can be disrupted or made entirely unavailable through data deletion, table drops, or resource exhaustion attacks. | 7 |
| **Loss of Accountability** | Medium to High. Attacker actions might be untraceable or misattributed if identities are spoofed or logs are tampered with. | 7 |
| **Overall Impact** | **High** (Average score: (9+9+7+7)/4 = 8.0) |  |

**Overall Risk Calculation:**
Based on the OWASP methodology (Risk = Likelihood x Impact), with both Likelihood and Impact assessed as High, the overall risk is **High to Critical**.

**CVSS Vector (Illustrative Example for a common remote exploitation scenario):**
A typical CVSS 3.1 vector for a remotely exploitable SQL injection vulnerability that requires no authentication and leads to high impact on confidentiality, integrity, and availability would be:
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
This vector yields a **CVSS Base Score of 9.8 (Critical)**. Variations can occur based on specific context (e.g., if privileges are required, or if user interaction is needed), but the potential for severe impact generally keeps the score high. For instance, CVE-2019-15562, related to GORM allowing SQL injection via incomplete parentheses (though noted as application misuse), points to the reality of such issues.

The consistently high risk classification arises because SQL injection is a well-understood attack vector with readily available tools and techniques for exploitation. Once an application exposes a raw SQL interface to unparameterized user input, the protective abstractions of the ORM are effectively nullified for that specific query. The database becomes as vulnerable as if no ORM were in use for that interaction. Therefore, any finding of GORM raw SQL misuse should be treated as a significant security flaw requiring prompt and thorough remediation.

## 12. Fix & Patch Guidance

The primary and most effective method to fix and prevent GORM raw SQL misuse vulnerabilities is to ensure that all dynamic user input incorporated into raw SQL queries is handled via parameterization.

- **Prioritize Parameterized Queries (Prepared Statements):**
This is the cornerstone of SQL injection prevention. When using GORM's `Raw()` or `Exec()` methods with dynamic input, always use `?` as placeholders in the SQL query string. The actual values for these placeholders should then be passed as subsequent arguments to the GORM method. GORM, in conjunction with the underlying database driver, will handle the necessary escaping and sanitization to ensure that the input is treated as data, not executable SQL code.
    - **Secure Example for `db.Raw()`:**

        ```Go
        userName := r.URL.Query().Get("name")
        email := r.URL.Query().Get("email")
        var user User
        // Secure: Using '?' placeholders for user input
        db.Raw("SELECT * FROM users WHERE name =? AND email =?", userName, email).Scan(&user)
        ```
        
    - **Secure Example for `db.Exec()`:

        ```Go
        newName := "updatedUser"
        userID := 123
        // Secure: Using '?' placeholders for DML operations
        db.Exec("UPDATE users SET name =? WHERE id =?", newName, userID)
        ```
        
    - **Named Arguments:** GORM also supports named arguments using `sql.NamedArg`, `map[string]interface{}`, or structs, which provide another safe way to parameterize queries.
        - *Example:* `db.Raw("SELECT * FROM users WHERE name = @name", sql.Named("name", "jinzhu")).Scan(&user)`.
- **Strictly Avoid String Concatenation/Formatting for Queries:**
Under no circumstances should SQL queries be constructed by directly concatenating (using `+`) or formatting (using `fmt.Sprintf` or similar functions) user-supplied input into the query string. This is the primary cause of the vulnerability.
    - **Anti-Pattern (Vulnerable):** `rawQuery := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userName)`
- **Implement Robust Server-Side Input Validation and Sanitization:**
As a crucial defense-in-depth measure, rigorously validate all user inputs on the server side before they are used in any operation, including database queries. This includes checking for expected data types, formats (e.g., regex for emails or specific IDs), lengths, and character sets. While parameterization is the main defense against SQLi, input validation can prevent a broader range of issues and reduce the likelihood of malformed data reaching the database layer. Sanitization (actively removing or escaping potentially dangerous characters) should be considered a secondary measure and generally not relied upon as the sole defense against SQLi if parameterization is available.
- **Prefer GORM's Standard Query Builders:**
Whenever possible, use GORM's chainable query builder methods (e.g., `db.Where()`, `db.Find()`, `db.First()`, `db.Create()`, `db.Updates()`). These higher-level abstractions are designed to use parameterization correctly by default and reduce the risk of accidental SQL injection. Raw SQL should be reserved for genuinely complex queries or performance-critical operations that cannot be efficiently or easily expressed through the standard builders.
- **Adhere to the Principle of Least Privilege (Database User):**
Ensure that the database user account configured for the GORM application has only the minimum necessary permissions required for its intended operations. For example, if the application only needs to read data, the user should not have `UPDATE`, `DELETE`, or `DROP` privileges. This will not prevent an SQL injection attempt but can significantly limit the potential damage if an attacker successfully exploits a vulnerability.
- **Keep GORM, Go, and Database Drivers Updated:**
Regularly update the GORM library, the Go runtime, and any underlying database drivers (e.g., `go-sql-driver/mysql`, `lib/pq`) to their latest stable versions. This ensures that the application benefits from the latest security patches and bug fixes, although for GORM raw SQL misuse, the primary vulnerability lies in application code, not typically in the library itself.

The most effective and direct fix involves developers consistently applying parameterization when using GORM's raw SQL features. The tools for secure implementation are readily available within GORM; the challenge lies in ensuring developers are aware of and correctly use these mechanisms.

## 13. Scope and Impact

**Scope:**

The scope of GORM raw SQL misuse vulnerabilities can be extensive, potentially affecting any part of an application where GORM is used to execute raw SQL queries constructed with untrusted, dynamically incorporated input. This includes:

- **Application Codebase:** Any Go source files (`.go`) containing functions or methods that utilize `db.Raw()` or `db.Exec()` with concatenated or unsafely formatted user input.
- **Data Access Logic:** Data Access Layers (DALs), repository patterns, or service layers responsible for database interactions are common locations for such vulnerabilities if they resort to raw SQL for specific operations.
- **API Endpoints:** Backend API endpoints that process user-supplied data (e.g., filters, identifiers, search terms from query parameters, request bodies, or headers) and use this data to construct raw SQL queries are directly in scope.
- **Administrative Interfaces:** Internal or administrative sections of an application that might allow more complex querying or data manipulation, if built using raw SQL, can also be vulnerable.
- **Batch Processes or Background Jobs:** Any backend process that ingests external data and uses it to form raw SQL queries.
- **Database Schema:** The entire database schema accessible to the GORM instance is potentially within scope. The extent of data an attacker can access or modify is limited by the permissions granted to the database user account that GORM uses to connect to the database. A single vulnerable query can potentially lead to compromise of multiple tables or even the entire database if permissions are overly broad.

**Impact:**

A successful exploitation of a GORM raw SQL injection vulnerability can have severe and multifaceted impacts:

- **Confidentiality Breach:** This is often the most significant impact. Attackers can exfiltrate sensitive data, including but not limited to:
    - Personally Identifiable Information (PII) of users (names, addresses, contact details, national IDs).
    - Authentication credentials (usernames, password hashes, API keys).
    - Financial information (credit card numbers, bank account details, transaction histories).
    - Proprietary business data, intellectual property, or application secrets stored within the database.
- **Integrity Compromise:** Attackers can alter, insert, or delete data in the database, leading to:
    - Data corruption or destruction.
    - Financial fraud (e.g., modifying account balances, creating fraudulent transactions).
    - User impersonation or unauthorized privilege escalation (e.g., changing user roles, modifying access rights).
    - Manipulation of application logic that relies on database state.
- **Availability Disruption:** The application or database service can be rendered unavailable through:
    - Deletion of critical data or entire tables (`DROP TABLE`).
    - Execution of resource-intensive queries that overload the database server (CPU, memory, disk I/O), causing it to become unresponsive or crash.
    - Locking database resources, preventing legitimate access.
- **Business Impact:** Beyond the direct technical consequences, the business can suffer:
    - **Reputational Damage:** Loss of customer trust and public confidence.
    - **Financial Losses:** Costs associated with incident response, forensic investigation, data recovery, customer notification, credit monitoring for affected users, and potential loss of business.
    - **Regulatory Fines and Legal Liabilities:** Non-compliance with data protection regulations (e.g., GDPR, CCPA, HIPAA) can result in substantial fines. Legal action from affected parties is also possible.
- **System Compromise:** In the most severe cases, depending on the specific database management system, its configuration, and the privileges of the compromised database account, SQL injection can be escalated to achieve remote code execution (RCE) on the database server. This could lead to a full compromise of the underlying operating system, allowing the attacker to establish a persistent presence, pivot to other systems within the network, or deploy ransomware.

The scope is directly proportional to the pervasiveness of insecure raw SQL usage and the breadth of permissions assigned to the application's database user. Even a single vulnerable raw SQL call can have catastrophic consequences if it allows access to critical data or administrative database functions. The principle of least privilege is therefore a vital mitigating control to limit the potential blast radius should an injection occur.

## 14. Remediation Recommendation

A comprehensive remediation strategy for GORM raw SQL misuse vulnerabilities involves immediate fixes, preventative measures, and process improvements to ensure long-term security.

- **Prioritize and Mandate Parameterized Queries:**
    - The foremost recommendation is the mandatory use of parameterized queries for all GORM `Raw()` and `Exec()` calls that involve any form of dynamic input. Utilize `?` placeholders for positional parameters or named parameters (e.g., `sql.Named("name", value)` or `map[string]interface{}{"name": value}`). This should be a non-negotiable standard in development guidelines.
    - **Action:** Review and refactor all existing raw SQL queries to use parameterization.
- **Comprehensive Developer Training and Awareness:**
    - Conduct regular, targeted training sessions for developers on secure coding practices, with a specific focus on SQL injection vulnerabilities and the secure usage of GORM, particularly its raw SQL features.
    - Ensure developers understand the risks of string concatenation/formatting for SQL queries and are proficient in implementing parameterized queries. Highlight that ORM usage does not grant immunity when raw SQL is employed.
- **Robust Code Review and Automated Security Testing:**
    - **Security-Focused Code Reviews:** Implement a mandatory code review process that specifically scrutinizes all database interaction code, especially new or modified uses of `db.Raw()` and `db.Exec()`. Reviewers should verify correct parameterization.
    - **SAST Integration:** Integrate Static Application Security Testing (SAST) tools into the CI/CD pipeline. Configure SAST to detect patterns of GORM raw SQL misuse, such as direct string concatenation of user input into queries.
    - **DAST Integration:** Perform regular Dynamic Application Security Testing (DAST) scans on running applications in test/staging environments to identify and confirm exploitable SQL injection vulnerabilities from an external perspective.
- **Promote Use of GORM's Standard Query Builders:**
    - Encourage developers to default to GORM's standard, type-safe query builder methods (e.g., `db.Where()`, `db.Find()`, `db.Select()`) whenever the required query can be expressed through them. These methods typically handle parameterization safely by default. Raw SQL should be treated as an exception for truly complex scenarios, not the default approach.
- **Consider a Centralized Data Access Layer (DAL):**
    - If raw SQL is frequently required for complex operations, consider abstracting these queries into a dedicated, well-vetted DAL. This allows for centralized enforcement of secure practices and makes security reviews more focused and manageable.
- **Enforce the Principle of Least Privilege (Database Accounts):**
    - Configure the database user account that the Go application uses to connect to the database with the absolute minimum set of permissions necessary for its legitimate operations. Avoid using highly privileged accounts (e.g., `root`, `dbo`, `admin`). This limits the potential damage if an SQL injection vulnerability is exploited.
- **Regular Security Audits and Penetration Testing:**
    - Schedule periodic security audits and penetration tests conducted by qualified third-party security professionals. These assessments can help identify SQL injection vulnerabilities and other security weaknesses that internal processes might miss.
- **Vigilant Dependency Management:**
    - Keep GORM, the Go language runtime, and all database drivers updated to their latest stable and secure versions. Subscribe to security advisories for these components to be aware of any discovered vulnerabilities.

Remediation is not merely about fixing individual instances of vulnerable code; it requires establishing systemic changes in development culture, tools, and processes. A defense-in-depth approach, incorporating these recommendations, is essential for managing the risk of GORM raw SQL misuse effectively and sustainably.

## 15. Summary

Misuse of GORM's raw SQL functionalities, particularly the `Raw()` and `Exec()` methods, by directly concatenating or formatting un-sanitized user-supplied input into SQL query strings, is a primary cause of SQL Injection (CWE-89) vulnerabilities in Go applications. This vulnerability is consistently rated as High to Critical severity due to its potential to allow attackers to exfiltrate sensitive data, manipulate or delete database records, disrupt application services, or, in severe cases, achieve full compromise of the database server.

Despite GORM being an Object-Relational Mapper designed to simplify and secure database interactions, its raw SQL features inherently bypass some of the ORM's standard protective mechanisms if not used with explicit, developer-implemented security measures. The core issue is the failure to distinguish between executable SQL code and literal data when user input is unsafely embedded in queries. Effective detection of such vulnerabilities relies on a combination of meticulous manual code reviews, Static Application Security Testing (SAST) to identify risky patterns, and Dynamic Application Security Testing (DAST) to confirm exploitability.

The most critical remediation strategy is the consistent and correct use of parameterized queries for all raw SQL operations involving dynamic data. GORM supports this through `?` placeholders or named arguments, ensuring that user input is treated strictly as data. This technical fix must be complemented by comprehensive developer training on secure GORM usage, robust security testing integrated into the development lifecycle, and adherence to security best practices such as the principle of least privilege for database accounts. Ultimately, while ORMs like GORM offer significant advantages, developers must remain vigilant and understand the boundaries of these tools' protections, especially when utilizing features that allow for more direct control over SQL execution.

## 16. References

- https://afine.com/sql-injection-in-the-age-of-orm-risks-mitigations-and-best-practices/
- https://dev.to/dzungnt98/preventing-sql-injection-with-raw-sql-and-orm-in-golang-5dhn
- https://gorm.io/docs/sql_builder.html
- https://gorm.io/docs/connecting_to_the_database.html
- https://owasp.org/www-community/attacks/SQL_Injection
- https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
- https://www.veracode.com/security/java/cwe-89/
- https://documentation.blackduck.com/bundle/remediation/page/CWE-89_java.html
- https://wiliamvj.com/en/posts/sql-injection-golang/
- https://www.youtube.com/watch?v=E2XqDHJj_gY
- https://neon.tech/guides/golang-gorm-postgres
- https://gorm.io/docs/query.html
- https://www.aikido.dev/blog/sast-vs-dast-what-you-need-to-now
- https://checkmarx.com/glossary/sql-injection/
- https://gorm.io/docs/error_handling.html
- https://stackoverflow.com/questions/73451662/gorm-raw-sql-not-getting-executed
- https://cqr.company/web-vulnerabilities/sql-injection-union-attack/
- https://www.first.org/cvss/v3-1/examples
- https://scm.cms.hu-berlin.de/safeguarding/cvelistV5/-/blob/cve_2023-03-15_1700Z/preview_cves/2019/15xxx/CVE-2019-15562.json?ref_type=tags
- https://afine.com/sql-injection-in-the-age-of-orm-risks-mitigations-and-best-practices/
- https://cwe.mitre.org/data/definitions/89.html
- https://dev.to/dzungnt98/preventing-sql-injection-with-raw-sql-and-orm-in-golang-5dhn
- https://owasp.org/www-community/attacks/SQL_Injection
- https://cwe.mitre.org/data/definitions/89.html