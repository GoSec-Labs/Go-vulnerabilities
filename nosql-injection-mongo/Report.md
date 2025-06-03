# Vulnerability Title

MongoDB NoSQL Injection (nosql-injection-mongo)

## Severity Rating

**High🟠**

This vulnerability can lead to unauthorized data access, data manipulation, authentication bypass, and potentially remote code execution or denial of service, depending on the application's configuration and the database's capabilities.

## Description

MongoDB NoSQL Injection is a type of injection vulnerability that occurs when an application constructs MongoDB queries using unsanitized user-supplied input. While MongoDB does not use SQL, it supports query operators and, in some cases, JavaScript expressions within queries. An attacker can inject malicious operators or JavaScript code into the query, altering its intended logic or executing arbitrary commands on the database or even the underlying application.

## Technical Description (for security pros)

NoSQL injection in MongoDB typically arises when user input is directly concatenated into query strings or when input is passed without proper validation and type-checking into query objects (e.g., `bson.M` in Go). Attackers can leverage MongoDB's query operators (ee.g., `$gt`, `$lt`, `$ne`, `$regex`, `$where`, `$eval`) to bypass authentication, enumerate data, or execute arbitrary JavaScript code on the server if server-side JavaScript execution is enabled.

In Go, this often manifests when dynamic query structures (like `bson.M` or `map[string]interface{}`) are populated directly from untrusted user input (e.g., JSON request bodies) without strict schema validation or sanitization. If the application expects a simple string but receives a BSON object containing a malicious operator, the MongoDB driver might interpret it as a legitimate query instruction.

## Common Mistakes That Cause This

  * **Directly using user input in queries:** Concatenating user-controlled strings directly into query filters or using `bson.M` maps populated directly from unvalidated user input.
  * **Lack of input validation and sanitization:** Failing to strictly validate the type and content of user input before it's used in database operations. For instance, expecting a string but allowing an object or a different data type.
  * **Using `$where` or `$eval` with user input:** MongoDB's `$where` operator allows JavaScript evaluation within queries. If user input flows into this operator, it's highly susceptible to code injection. The `db.eval()` command is also dangerous if used with untrusted input.
  * **Over-privilege database users:** Using a database user with excessive permissions (e.g., admin rights) for application operations.
  * **Outdated MongoDB drivers/versions:** Older drivers or MongoDB versions might have known vulnerabilities or less robust protection mechanisms.

## Exploitation Goals

  * **Authentication Bypass:** Log in as any user (e.g., administrator) without knowing credentials.
  * **Information Disclosure:** Retrieve sensitive data from the database (e.g., user records, financial information) that the attacker is not authorized to access.
  * **Data Manipulation:** Modify or delete arbitrary data in the database.
  * **Denial of Service (DoS):** Inject payloads that consume excessive resources (e.g., infinite loops with `$where`) to make the database or application unresponsive.
  * **Remote Code Execution (RCE):** If server-side JavaScript execution is enabled and `$where` or `db.eval()` is used with unsanitized input, an attacker might execute arbitrary code on the database server.

## Affected Components or Files

  * Application code (Go source files) responsible for handling user input and constructing MongoDB queries.
  * Database interaction layers, particularly functions that build query filters or update documents based on user-supplied parameters.
  * API endpoints that receive JSON or form data that is then directly used in MongoDB queries.

## Vulnerable Code Snippet (Golang)

```go
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var client *mongo.Client

func main() {
	// Connect to MongoDB
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	var err error
	client, err = mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to MongoDB!")

	router := gin.Default()
	router.POST("/login", loginHandler)
	router.Run(":8080")
}

// Vulnerable login handler
func loginHandler(c *gin.Context) {
	var user User
	// Directly binds the incoming JSON to a bson.M map, representing a MongoDB query.
	// This allows an attacker to inject MongoDB operators.
	var query bson.M 
	if err := c.ShouldBindJSON(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	collection := client.Database("testdb").Collection("users")
	
	// The unsanitized 'query' (bson.M) is directly used in the FindOne operation.
	var result User
	err := collection.FindOne(context.TODO(), query).Decode(&result)
	
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "user": result.Username})
}
```

## Detection Steps

1.  **Code Review:** Manually inspect code for direct concatenation of user input into MongoDB query strings or unvalidated assignment of user input to `bson.M` or similar query objects. Look for usage of operators like `$where`, `$eval`, `$regex` with untrusted input.
2.  **Dynamic Application Security Testing (DAST):** Use DAST tools (e.g., Burp Suite, OWASP ZAP) to send specially crafted payloads to application endpoints.
      * **Error-based detection:** Inject characters or operators that would cause a MongoDB error if processed improperly (e.g., `"username": {"$ne": []}` where a string is expected).
      * **Boolean-based blind injection:** Inject logical operators (e.g., `{"password": {"$ne": "dummy"}}`) and observe differences in application responses (e.g., success/failure, presence/absence of data) to infer true/false conditions.
      * **Time-based blind injection:** Inject sleep functions (if `$where` is enabled) and measure response times to confirm injection.
3.  **Static Application Security Testing (SAST):** Use SAST tools to analyze source code for patterns indicative of NoSQL injection vulnerabilities, such as `bson.M` population from `c.ShouldBindJSON` or `c.BindJSON` followed by direct use in `Find` or `FindOne` operations without intervening validation/sanitization.

## Proof of Concept (PoC)

Given the vulnerable Go code for `/login`:

**Authentication Bypass PoC:**

1.  **Request:**
    ```
    POST /login HTTP/1.1
    Host: localhost:8080
    Content-Type: application/json
    Content-Length: 42

    {
        "username": {"$ne": null},
        "password": {"$ne": null}
    }
    ```
2.  **Expected Outcome (Vulnerable):** The application would likely return "Login successful" and potentially the first user found in the database, effectively bypassing authentication, assuming there's at least one user. The `$ne` (not equal) operator makes both conditions (`username != null` AND `password != null`) true for any existing user.

**Data Enumeration (if applicable and if a search endpoint exists):**

Suppose there's a search endpoint that takes a `query` parameter directly into a `Find` operation:

```go
func searchHandler(c *gin.Context) {
    var searchQuery bson.M
    if err := c.ShouldBindJSON(&searchQuery); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    collection := client.Database("testdb").Collection("products")
    cursor, err := collection.Find(context.TODO(), searchQuery)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    defer cursor.Close(context.TODO())

    var products []bson.M
    if err = cursor.All(context.TODO(), &products); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"results": products})
}
```

1.  **Request to `/search`:**
    ```
    POST /search HTTP/1.1
    Host: localhost:8080
    Content-Type: application/json
    Content-Length: 20

    {
        "price": {"$gt": 0}
    }
    ```
2.  **Expected Outcome (Vulnerable):** Instead of searching for a specific price, this query would return all products with a price greater than 0, potentially disclosing product data that the user shouldn't see.

## Risk Classification

  * **Confidentiality:** High (sensitive data exposure)
  * **Integrity:** High (data manipulation/deletion)
  * **Availability:** Medium to High (DoS potential)
  * **Accountability:** Low (logs might not distinguish between legitimate and malicious queries easily if the injection is successful)

## Fix & Patch Guidance

The primary fix for NoSQL injection is **strict input validation and sanitization**.

1.  **Use strongly-typed structs for input:** Instead of `bson.M` for user-supplied data, define Go structs with explicit field types and use `c.ShouldBindJSON` (or `json.Unmarshal`) to parse incoming JSON into these structs. This ensures that the structure and types of the input are as expected, and any attempts to inject operators as field values will fail (e.g., `{"username": {"$ne": null}}` will fail to bind to a `string` field).

    **Corrected Go Code Snippet:**

    ```go
    package main

    import (
    	"context"
    	"log"
    	"net/http"

    	"github.com/gin-gonic/gin"
    	"go.mongodb.org/mongo-driver/bson"
    	"go.mongodb.org/mongo-driver/mongo"
    	"go.mongodb.org/mongo-driver/mongo/options"
    )

    type User struct {
    	Username string `json:"username" binding:"required"` // Added binding:"required" for validation
    	Password string `json:"password" binding:"required"` // Added binding:"required" for validation
    }

    var client *mongo.Client

    func main() {
    	// Connect to MongoDB
    	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
    	var err error
    	client, err = mongo.Connect(context.TODO(), clientOptions)
    	if err != nil {
    		log.Fatal(err)
    	}
    	err = client.Ping(context.TODO(), nil)
    	if err != nil {
    		log.Fatal(err)
    	}
    	log.Println("Connected to MongoDB!")

    	router := gin.Default()
    	router.POST("/login", loginHandler)
    	router.Run(":8080")
    }

    // Secure login handler
    func loginHandler(c *gin.Context) {
    	var input User // Use a strongly-typed struct for input
    	if err := c.ShouldBindJSON(&input); err != nil {
    		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
    		return
    	}

    	collection := client.Database("testdb").Collection("users")

    	// Construct the query explicitly using the validated input fields
    	query := bson.M{
    		"username": input.Username,
    		"password": input.Password, // In a real app, hash and compare passwords securely!
    	}

    	var result User
    	err := collection.FindOne(context.TODO(), query).Decode(&result)

    	if err != nil {
    		if err == mongo.ErrNoDocuments {
    			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
    			return
    		}
    		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
    		return
    	}

    	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "user": result.Username})
    }
    ```

2.  **Avoid `$where`, `$eval`, `mapReduce` with user input:** If possible, disable server-side JavaScript execution in MongoDB by setting `javascriptEnabled: false` in `mongod.conf`. If it's absolutely necessary to use these features, ensure that any user-controlled input used within them is meticulously escaped and validated, and ideally, only allow pre-defined, safe scripts.

3.  **Principle of Least Privilege:** Ensure that the MongoDB user account used by the application has only the necessary permissions (e.g., read-only for public data, read/write for specific collections, but no admin privileges).

4.  **Keep MongoDB and drivers updated:** Regularly update to the latest stable versions of MongoDB and its Go driver to benefit from security fixes and improvements.

5.  **Utilize validation libraries:** For complex input scenarios, consider using Go validation libraries to enforce expected data types, formats, and ranges before data reaches the database layer.

## Scope and Impact

This vulnerability affects applications that interact with MongoDB databases, particularly those that process user-supplied input to construct queries. The impact ranges from unauthorized data access and manipulation to complete compromise of the database server or application, depending on the severity of the injection and the attacker's skill. Authentication bypass is a common and severe impact.

## Remediation Recommendation

Immediately review all code paths that interact with MongoDB and process user input. Implement strict input validation and type checking for all data used in query construction. Prioritize using strongly-typed Go structs for incoming data and explicitly building query objects using these validated fields. Avoid using `bson.M` directly from user input without validation. Disable server-side JavaScript execution in MongoDB if not strictly required by the application.

## Summary

MongoDB NoSQL injection is a critical vulnerability arising from improper handling of user input in applications interacting with MongoDB. Attackers can leverage this to bypass authentication, steal or manipulate data, or even achieve remote code execution. The most effective defense is strict input validation and sanitization, ensuring that user-supplied data is always treated as data and never as executable code or query logic. Implementing strong typing for input parameters in Go applications and explicitly constructing MongoDB queries are essential steps to mitigate this risk.

## References

  * OWASP Top 10 - A03:2021 – Injection: [https://owasp.org/Top10/A03\_2021\_Injection/](https://www.google.com/search?q=https://owasp.org/Top10/A03_2021_Injection/)
  * What is NoSQL Injection? - Infosec: [https://www.infosecinstitute.com/resources/application-security/what-is-nosql-injection/](https://www.infosecinstitute.com/resources/application-security/what-is-nosql-injection/)
  * What Is NoSQL Injection? | MongoDB Attack Examples - Imperva: [https://www.imperva.com/learn/application-security/nosql-injection/](https://www.imperva.com/learn/application-security/nosql-injection/)
  * How to scan for MongoDB injection vulnerabilities – and how to fix them | Invicti: [https://www.invicti.com/blog/docs-and-faqs/scan-fix-mongodb-injection-vulnerabilities/](https://www.invicti.com/blog/docs-and-faqs/scan-fix-mongodb-injection-vulnerabilities/)
  * MongoDB Security Best Practices: [https://www.mongodb.com/docs/manual/administration/security-best-practices/](https://www.mongodb.com/docs/manual/administration/security-best-practices/)