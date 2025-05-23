# Vulnerability Report: GraphQL Introspection Leakage in Golang Applications

## 1. Vulnerability Title

GraphQL Introspection Leakage (graphql-introspection-leak).
Alternative names for this vulnerability include GraphQL Introspection Enabled and GraphQL Introspection Query Exposure.

## 2. Severity Rating

The severity of GraphQL Introspection Leakage is typically rated as **Low🟢**. For instance, one security assessment identified "GraphQL Introspection Query Exposure" with a CVSS (Common Vulnerability Scoring System) score of 2.3, based on the vector `AV:A/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`. This particular vector implies an attack originating from an adjacent network, requiring high attack complexity, and resulting in a low impact on confidentiality. However, a more generalized CVSS 3.x vector, such as `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`, which assumes network access, low attack complexity, no privileges required, no user interaction, unchanged scope, low confidentiality impact, and no integrity or availability impact, would yield a score of 5.3.

It is crucial to understand that while the direct act of information disclosure through introspection might be classified as "Low" severity, its true risk often lies in its role as a facilitator for other, potentially more severe attacks. The exposed schema can serve as a detailed map for attackers, guiding them to understand the API's structure, identify sensitive data, and pinpoint other vulnerabilities. For example, knowledge of the schema can help an attacker find insecure direct object references or craft queries to exploit injection vulnerabilities. Therefore, a "Low" numerical rating should not lead to complacency, as the ease of exploitation and the strategic value of the disclosed information make introspection leakage a significant finding that warrants remediation.

## 3. Description

GraphQL introspection is a built-in feature of the GraphQL specification that allows clients to query a GraphQL server for detailed information about its schema. This metadata includes descriptions of supported types, fields, queries (operations for fetching data), mutations (operations for changing data), and directives (instructions to the GraphQL executor). Introspection is a powerful tool for developers, facilitating schema exploration, enabling the auto-generation of API documentation, and powering developer tools such as GraphiQL and GraphQL Playground, which provide interactive environments for writing and testing queries.

GraphQL introspection leakage occurs when this introspection capability is left enabled and accessible in environments where it is not intended, particularly in production systems that are exposed to untrusted users. The vulnerability arises because most GraphQL server libraries enable introspection by default as a convenience for development. If this default setting is not explicitly overridden or restricted for production deployments, the API inadvertently exposes its entire structure.

The nature of GraphQL introspection is that it is an intentional design feature, integral to GraphQL's philosophy of discoverability and ease of use for developers. The "vulnerability" aspect does not stem from a flaw in the GraphQL protocol itself but rather from a common security misconfiguration: the failure to disable or adequately restrict a powerful development and diagnostic tool in a live, potentially hostile environment. This aligns with security misconfiguration categories such as OWASP API8:2023.

## 4. Technical Description (for security pros)

GraphQL introspection is performed by clients sending specific queries that target reserved fields within the GraphQL schema. The primary fields used for introspection are `__schema`, which allows querying for schema-wide information (like all available types or query/mutation entry points), and `__type`, which provides details about a specific named type within the schema. These introspection queries are standard GraphQL queries, typically sent via HTTP POST requests to the GraphQL endpoint, although some servers may also accept them via GET requests. A common example of an introspection query is `query { __schema { types { name kind } } }`, which retrieves the names and kinds (e.g., OBJECT, SCALAR, INTERFACE) of all types defined in the schema.

When introspection is enabled, a wealth of information about the API's structure is exposed. This includes:

- **Full API Schema:** The names and detailed structures of all object types, input types, enums, unions, and interfaces.
- **Queries:** All available query operations, including their names, arguments (with types), and return types.
- **Mutations:** All available mutation operations, their arguments, and return types.
- **Subscriptions:** Details of any available subscription operations for real-time updates.
- **Fields:** For each type, the names, data types, arguments (if any), and descriptions of all its fields.
- **Directives:** Information about custom directives supported by the server, which can modify query execution behavior.
- **Descriptions:** Developer-written descriptions for types, fields, and arguments. These descriptions, intended for documentation, can sometimes inadvertently leak internal information, implementation details, or hints about functionality.

A critical aspect contributing to this vulnerability is the default behavior of most GraphQL server implementations. Many libraries, including popular choices for Golang, enable introspection by default to facilitate ease of development. For example, in the Golang ecosystem:

- The `gqlgen` library, when using `handler.NewDefaultServer()`, includes introspection capabilities by default.
- The `graph-gophers/graphql-go` library enables introspection unless explicitly disabled through schema options, such as `graphql.DisableIntrospection()`.

This default enablement, while beneficial for development, can become a significant liability. The exposure of the entire schema through introspection can also complicate API versioning and evolution strategies. GraphQL's design encourages evolving a single schema rather than versioning entire API endpoints. If introspection is publicly available, it reveals the *entire* current state of the schema. This includes fields or types that might be experimental, intended for internal use only, part of a phased rollout, or even deprecated but not yet removed. Attackers can leverage this to identify and potentially abuse these non-public or unstable parts of the API, which may lack the same level of security scrutiny or stability as publicly documented features. This undermines controlled feature releases and can lead to unexpected interactions if attackers utilize features that are not yet officially supported or fully secured.

## 5. Common Mistakes That Cause This

The GraphQL introspection leakage vulnerability typically arises from several common mistakes and oversights during development and deployment:

- **Leaving Introspection Enabled in Production:** This is the most prevalent error. Developers may deploy their applications to production environments using the default GraphQL server configurations, which often have introspection enabled.
- **Lack of Environment-Specific Configurations:** A failure to differentiate configurations between development, staging, and production environments is a significant contributor. While introspection is highly useful and often desired in development and staging, it poses an unnecessary risk in production.
- **Misunderstanding GraphQL Library Defaults:** Developers may not be fully aware that the Golang GraphQL library they are using (e.g., `gqlgen` with its `NewDefaultServer` helper, or `graph-gophers/graphql-go` without specific disabling options) enables introspection by default. This lack of awareness means they don't take proactive steps to disable it for production.
- **Belief in "Security Through Obscurity":** Some teams might disable introspection but fail to address other potential schema leakage vectors, such as verbose error messages that provide field suggestions. They might incorrectly assume that disabling the main introspection query effectively hides the schema.
- **Publicly Accessible Development/Staging Environments:** In some cases, development or staging environments, where introspection might be legitimately enabled for testing and development purposes, are inadvertently exposed to the public internet without adequate access controls (e.g., IP restrictions, authentication).

Many of these mistakes stem from a violation of the "default secure" principle in the design of some GraphQL libraries. Secure software design principles advocate for defaults that are inherently secure, requiring explicit actions to enable less secure features. However, many GraphQL libraries enable introspection by default to enhance developer convenience and speed up the initial setup. This convenience in development environments becomes a security liability in production if developers are unaware of the default behavior or forget to override it. This shifts the onus of security onto the developer to remember to disable such features for production, a step that is unfortunately often missed.

## 6. Exploitation Goals

Attackers exploit GraphQL introspection leakage with several key objectives in mind, primarily centered around comprehensive reconnaissance and preparation for further attacks:

- **Schema Discovery and Enumeration:** The foremost goal is to obtain a complete and detailed map of the GraphQL API. This includes discovering all available types (objects, inputs, scalars, enums, etc.), fields within those types, queries, mutations, subscriptions, and their interrelationships. This detailed schema acts as a "treasure map" or "floorplan" of the application's data layer, revealing its structure and capabilities.
- **Identification of Sensitive Data:** Attackers meticulously analyze the exposed schema to find fields or types that might contain, handle, or provide access to sensitive information. This could include Personally Identifiable Information (PII) like names and email addresses, financial data such as payment instrument details, credentials, internal system notes, or private API keys. Real-world examples include the exposure of `customerPaymentInstruments` and `privateMetafields` in Shopify's case, or `internalNotes` and `projectSecrets` at GitLab.
- **Discovery of Hidden or Deprecated Functionality:** The introspection query can reveal unlinked, experimental, or deprecated queries, mutations, or fields. These elements might not be part of the public API documentation and could lack proper security controls, making them attractive targets for abuse.
- **Understanding Business Logic:** By examining the schema, including type relationships, query/mutation arguments, and field descriptions, attackers can infer how the application processes data and what operations are permissible. This understanding can help them devise more sophisticated attacks that exploit specific business logic flaws.
- **Reconnaissance for Further Attacks:** The information gathered through introspection is invaluable for planning and executing subsequent attacks. Specifically, it helps to:
    - Identify potential injection points, such as arguments in queries or mutations, for attacks like SQL injection, NoSQL injection, or OS command injection.
    - Discover patterns that might lead to Insecure Direct Object References (IDOR) or Broken Object Level Authorization (BOLA) vulnerabilities by understanding how objects are identified and fetched.
    - Craft Denial-of-Service (DoS) attacks by identifying queries that are likely to be complex or resource-intensive.
    - Find other vulnerabilities that are specific to the application's unique GraphQL implementation and business domain.

The availability of GraphQL introspection significantly accelerates the attacker's lifecycle. Without introspection, an attacker would need to engage in laborious and time-consuming activities like blindly probing endpoints, guessing field and type names, and meticulously analyzing error messages to gradually map out the API. This process could take days or even weeks. With introspection enabled, a complete and structured schema can often be retrieved in minutes using a single query. This allows attackers to bypass much of the discovery work and proceed directly to identifying and exploiting vulnerabilities, effectively lowering the barrier to entry for sophisticated attacks and making them quicker to execute.

## 7. Affected Components or Files

The GraphQL introspection leakage vulnerability primarily affects the following components within a Golang application environment:

- **GraphQL API Endpoints:** The most direct component affected is the GraphQL endpoint itself. This is the URL to which GraphQL queries are sent (e.g., `/graphql`, `/api`, `/api/graphql`, `/query`). If this endpoint processes and responds to introspection queries, it is vulnerable.
- **GraphQL Server Configuration (Golang Application Code):** The server-side code responsible for initializing and configuring the GraphQL server is critical. In Golang applications, this configuration dictates whether introspection is enabled or disabled.
    - For applications using the `99designs/gqlgen` library, the vulnerability often lies in how the GraphQL handler is created. Using `handler.NewDefaultServer(es)` enables introspection by default. A custom setup using `handler.New(es)` might also be vulnerable if `extension.Introspection{}` is unconditionally added.
    - For applications using `github.com/graph-gophers/graphql-go`, the vulnerability depends on the options passed during schema parsing (e.g., `graphql.ParseSchema` or `graphql.MustParseSchema`). If the `graphql.DisableIntrospection()` option is omitted, introspection remains enabled.
- **Golang GraphQL Libraries:** The specific Golang libraries used to implement the GraphQL server play a crucial role, as their default behaviors and available configuration options determine the application's susceptibility. Key libraries include:
    - `github.com/99designs/gqlgen`
    - `github.com/graph-gophers/graphql-go` (Note: some sources might generically refer to `graphql-go`, but `graph-gophers/graphql-go` is a distinct and popular implementation with specific options like `DisableIntrospection()`).
    - `github.com/graphql-go/graphql` (another library, for which disabling field suggestions has been a discussed issue).
- **GraphQL Gateway Configurations:** If a GraphQL gateway (e.g., GraphQL Hive Gateway) is used in front of the Golang service, its configuration might also manage introspection settings, potentially overriding or complementing the application-level settings.

In typical Golang GraphQL applications, the HTTP handler that receives incoming HTTP requests and routes them to the GraphQL execution engine serves as a critical control point for introspection. When an HTTP request arrives at a designated GraphQL path (e.g., `/graphql`), a router directs it to a specific GraphQL handler. This handler (such as `relay.Handler` for `graph-gophers/graphql-go` or handlers provided by `99designs/gqlgen/graphql/handler`) is responsible for parsing the query, validating it against the schema, and invoking the resolvers. It is typically at the stage of schema initialization (parsing the schema definition and resolvers) or handler setup that introspection capabilities are defined. For instance, `gqlgen`'s `NewDefaultServer` conveniently bundles introspection, while a more manual setup with `handler.New(es)` requires explicitly adding the introspection extension, ideally conditionally for development environments only. Similarly, `graph-gophers/graphql-go` uses schema parsing options like `DisableIntrospection()` to control this feature. Therefore, developers must scrutinize the initialization and configuration of their GraphQL schema parsing and HTTP handlers as these are the primary locations for managing and mitigating introspection leakage.

## 8. Vulnerable Code Snippet (Conceptual Golang Example)

The following conceptual Golang code snippets illustrate how GraphQL introspection leakage might occur due to default library behaviors or common setup patterns. These are not direct exploits but demonstrate vulnerable configurations.

**Using `github.com/99designs/gqlgen` (Default Behavior):**

```go
// File: server.go
package main

import (
    "log"
    "net/http"
    "os"

    "github.com/99designs/gqlgen/graphql/handler"
    "github.com/99designs/gqlgen/graphql/playground"
    "your_project/graph" // Assuming 'graph' contains generated.go and resolver.go from gqlgen init
)

const defaultPort = "8080"

func main() {
    port := os.Getenv("PORT")
    if port == "" {
        port = defaultPort
    }

    // handler.NewDefaultServer() includes introspection support by default.
    // If this server is deployed to production without further configuration to disable
    // introspection for the production environment, the /query endpoint will be vulnerable.
    // This is a common helper function that prioritizes ease of development.
    srv := handler.NewDefaultServer(graph.NewExecutableSchema(graph.Config{Resolvers: &graph.Resolver{}})) // Ref: [15, 17]

    // The GraphQL Playground also relies on introspection and is often enabled by default with NewDefaultServer.
    http.Handle("/", playground.Handler("GraphQL playground", "/query"))
    http.Handle("/query", srv)

    log.Printf("GraphQL server with introspection (and playground) running on http://localhost:%s/", port)
    log.Fatal(http.ListenAndServe(":"+port, nil))
}
```

**Explanation:** The `handler.NewDefaultServer()` function provided by `gqlgen` is a convenience constructor that sets up a GraphQL server with several features enabled by default, including introspection and often a GraphQL Playground interface. While this accelerates development, deploying such a configuration to a production environment without explicitly disabling introspection for that environment will expose the schema via the `/query` endpoint.

**Using `github.com/graph-gophers/graphql-go` (Default Behavior):**

```go
// File: server.go
package main

import (
    "log"
    "net/http"
    // "context" // If needed for resolvers

    graphql "github.com/graph-gophers/graphql-go"
    "github.com/graph-gophers/graphql-go/relay"
)

// Assume schemaString is your GraphQL schema definition
var schemaString = `
    type Query {
        hello: String!
    }
`

// Assume RootResolver is your root resolver struct
type RootResolver struct{}

func (r *RootResolver) Hello() string {
    return "Hello, introspection-enabled world!"
}

func main() {
    // When parsing the schema with graphql.MustParseSchema (or graphql.ParseSchema),
    // introspection is enabled by default unless graphql.DisableIntrospection()
    // is passed as a schema option.
    opts :=graphql.SchemaOpt{} // No graphql.DisableIntrospection() present
    schema := graphql.MustParseSchema(schemaString, &RootResolver{}, opts...) // Ref: [19] (schema options)

    http.Handle("/query", &relay.Handler{Schema: schema})

    log.Println("GraphQL server with introspection enabled, listening on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

**Explanation:** The `graphql.MustParseSchema` (and `graphql.ParseSchema`) functions from the `graph-gophers/graphql-go` library enable introspection by default. If the `graphql.DisableIntrospection()` option is not included in the `opts` slice passed to this function, the resulting GraphQL schema will support introspection queries, making the `/query` endpoint vulnerable in a production setting.

These examples highlight a common trade-off in library design: "helper" functions or default constructors (like `gqlgen`'s `NewDefaultServer`) offer ease of use and rapid development by bundling common features. However, this convenience can obscure underlying security implications if developers are not fully aware of what these defaults entail. Using such helpers in production without careful review can lead to vulnerabilities like introspection leakage. A more explicit configuration approach, while potentially requiring more boilerplate code (e.g., using `handler.New(es)` in `gqlgen` and conditionally adding extensions like `srv.Use(extension.Introspection{})` only for development environments ), generally leads to more secure and understandable production deployments. Developers should be cautious with "default" or "easy setup" functionalities and always verify which security-sensitive features are enabled by default, opting for more explicit and granular configurations for production builds.

## 9. Detection Steps

Detecting GraphQL introspection leakage can be achieved through several methods, ranging from manual querying to automated scanning and code review:

- **Sending Standard Introspection Queries:** This is the most direct method.
    - Use a GraphQL client tool (e.g., Postman, Insomnia, GraphiQL, Altair, or even cURL) to send specially crafted introspection queries to the target GraphQL endpoint.
    - **Basic Probe:** A simple query like `{"query": "{__schema{queryType{name}}}"}` can quickly determine if introspection is enabled. If the server responds with data (e.g., the name of the root query type), introspection is active.
    - **Full Introspection Query:** A more comprehensive query can be used to attempt to retrieve the entire schema, including all types, fields, queries, mutations, and directives. Examples of such queries are available in security resources.
    - **Target Common Endpoints:** Test against common GraphQL endpoint paths, as these are not standardized. Examples include `/graphql`, `/api`, `/api/graphql`, `/graphql/api`, `/query`, `/graphiql`, `/playground`, `/v1/graphql`.
- **Using Automated Security Scanning Tools:**
    - **Burp Suite:** The Burp Scanner, particularly in its Professional version, can automatically test for GraphQL introspection during its scans. If enabled, it will report a "GraphQL introspection enabled" issue. Burp Suite can also assist in generating various introspection queries.
    - **`vulnapi`:** This tool can specifically scan for GraphQL introspection using a command like `vulnapi scan graphql [url] --scans graphql.introspection_enabled`.
    - **Other GraphQL-specific Security Tools:** Tools such as GraphSpecter are designed to check if introspection is enabled and export the schema. While tools like Clairvoyance are primarily known for reconstructing schemas when introspection is *disabled* (by exploiting field suggestions), their underlying principles of schema discovery are relevant.
- **Checking Server Configurations (White-box Analysis):**
    - If access to the source code is available, review the Golang application code where the GraphQL server and schema are initialized.
    - For `gqlgen` implementations: Look for the use of `handler.NewDefaultServer()` without conditional logic to disable introspection in production. Also, check if `extension.Introspection{}` is added unconditionally to a custom server setup (e.g., `handler.New(es).Use(extension.Introspection{})`).
    - For `graph-gophers/graphql-go` implementations: Verify if `graphql.DisableIntrospection()` is absent from the schema parsing options provided to `graphql.ParseSchema` or `graphql.MustParseSchema`.
- **Observing Exposed GraphQL IDEs:** If a GraphQL IDE like GraphiQL or GraphQL Playground is accessible in a production environment, it is a strong indicator that introspection is also enabled, as these tools heavily rely on introspection to function.

While basic detection of introspection by sending a standard query is straightforward, more sophisticated setups might attempt to block common introspection query patterns (e.g., via a Web Application Firewall - WAF) or might only enable introspection for authenticated or specifically authorized users, or based on certain request headers. Therefore, if an initial unauthenticated query fails, it does not definitively mean introspection is fully disabled for all possible contexts. Comprehensive testing should consider these possibilities, potentially testing from different network locations or with different privilege levels if feasible, to avoid false negatives.

## 10. Proof of Concept (PoC)

This Proof of Concept demonstrates how an attacker can retrieve schema information from a vulnerable GraphQL endpoint using a standard introspection query.

- **Objective:** To confirm that GraphQL introspection is enabled and to retrieve a list of all type names defined in the schema.
- **Tool:** cURL (command-line tool for transferring data with URLs) or any GraphQL client like Postman or Insomnia.
- **Target GraphQL Endpoint (Example):** `http://vulnerable-app.com/graphql`
- **Introspection Query (to fetch all type names and their kinds):**
The query asks the `__schema` for all `types`, and for each type, its `name` and `kind` (e.g., OBJECT, SCALAR, INPUT_OBJECT).GraphQL
    
    ```graphql
    query IntrospectionQuery {
      __schema {
        types {
          name
          kind
        }
      }
    }
    ```
    
- **Execution using cURL:**
The query is sent as a JSON payload in the body of an HTTP POST request.Bash
    
    ```bash
    curl -X POST \
         -H "Content-Type: application/json" \
         --data '{"query": "query IntrospectionQuery { __schema { types { name kind } } }"}' \
         http://vulnerable-app.com/graphql
    ```
    
- **Expected Vulnerable Response (Illustrative):**
If introspection is enabled, the server will respond with a JSON object containing the requested schema information within the `data` field.JSON
    
    ```json
    {
      "data": {
        "__schema": {
          "types":
        }
      }
    }
    ```
    
- **Expected Non-Vulnerable Response (Introspection Disabled):**
If introspection is properly disabled, the server should return an error message. The exact error message varies depending on the GraphQL server implementation and configuration. For example, AWS AppSync, when introspection is disabled, might return an error like : JSON
    
    ```json
    {
      "errors":
    }
    ```
    
    Other servers might return more generic "Cannot query field `__schema` on type `Query`" or similar validation errors.
    

The simplicity of this PoC underscores the ease with which an attacker can exploit an introspection leakage. No complex exploit code or specialized tools are strictly necessary; standard HTTP clients and knowledge of the GraphQL specification's introspection mechanism are sufficient. The output—the schema itself—provides immediate and actionable intelligence for an attacker, making this a practical and readily exploitable vulnerability.

## 11. Risk Classification

GraphQL introspection leakage is primarily classified under the following industry-standard weakness and vulnerability categories:

- **CWE (Common Weakness Enumeration):**
    - **CWE-200: Exposure of Sensitive Information to an Unauthorized Actor.** This is the most direct and fitting classification. GraphQL introspection, when enabled in an unauthorized context (like a public production environment), leaks the API schema. The schema itself, detailing the structure, types, fields, and operations of the API, is considered sensitive information from a security perspective because it can aid attackers. The definition of CWE-200 includes scenarios where "the code explicitly inserts sensitive information into resources or messages that are intentionally made accessible to unauthorized actors, but should not contain the information" or "the code manages resources that intentionally contain sensitive information, but the resources are unintentionally made accessible to unauthorized actors". Enabled introspection fits these descriptions perfectly.
- **OWASP API Security Top 10:**
    - **API8:2023 - Security Misconfiguration.** Leaving GraphQL introspection enabled in production environments is a classic example of a security misconfiguration. This category addresses failures to properly implement or harden security controls and configurations. Many GraphQL server libraries enable introspection by default for development convenience; failing to change this default for production is a misconfiguration.

While CWE-200 and API8:2023 are the primary classifications for the act of leaking the schema itself, the *impact* of this leakage often extends to facilitating the exploitation of other vulnerabilities. The information gained from an exposed schema can significantly aid an attacker in identifying and exploiting issues that fall under other OWASP API Security Top 10 categories, such as:

- **API1:2023 - Broken Object Level Authorization (BOLA):** The schema reveals how objects are structured and queried, potentially highlighting ID parameters or query patterns that could be tested for BOLA.
- **API2:2023 - Broken Authentication:** The schema might inadvertently expose details about authentication mechanisms or user-related types and fields that could be probed.
- **API3:2023 - Broken Object Property Level Authorization:** By revealing all properties of an object, introspection helps attackers identify if any sensitive properties lack proper access controls.
- **API5:2023 - Broken Function Level Authorization:** The full list of queries and mutations allows attackers to discover all available operations, including potentially administrative or privileged functions that might lack sufficient authorization checks.
.

Thus, introspection leakage serves as a crucial reconnaissance tool. The direct flaw is the information exposure (CWE-200) resulting from a security misconfiguration (API8:2023). However, an attacker then uses this exposed schema to more easily discover and exploit other weaknesses, such as a BOLA vulnerability where a query for a specific resource does not adequately check if the requester is authorized to access that particular resource. In such a scenario, the introspection leakage did not *cause* the BOLA, but it made the BOLA vulnerability significantly easier to find and exploit. This dual nature—being a vulnerability in itself and an enabler for others—underscores its importance despite a potentially "Low" direct severity rating.

## 12. Fix & Patch Guidance

Addressing GraphQL introspection leakage involves a combination of disabling the feature in production, hardening configurations, and adopting secure development practices.

**General Principles:**

- **Disable Introspection in Production Environments:** This is the most critical and effective mitigation. GraphQL introspection queries (`__schema`, `__type`) should be disabled for all publicly accessible production environments. Introspection should only be enabled in controlled development and testing environments where access is strictly limited.
- **Restrict Access to Introspection (If Enabled in Non-Prod):** If introspection is deemed necessary in staging or other non-production environments that are network-accessible, access must be strictly controlled. This can be achieved through methods like IP address whitelisting, requiring VPN access, or enforcing strong authentication and authorization (e.g., allowing introspection only for administrative roles).
- **Disable Field Suggestions in Production:** Even if introspection queries are disabled, GraphQL servers often provide helpful error messages that suggest valid field names when a typo is made in a query (e.g., "Did you mean 'fieldName'?"). Attackers can abuse this feature with tools like Clairvoyance to reconstruct parts of the schema. Therefore, it is strongly recommended to also disable these field suggestions in production environments. This often involves custom error formatting or middleware to strip or generalize such suggestions.

**Golang Specifics:**

The exact method for disabling introspection and field suggestions depends on the Golang GraphQL library being used.

- **For `github.com/99designs/gqlgen`:**
    - **Introspection:** Avoid using `handler.NewDefaultServer(es)` in production code, as this helper function enables introspection by default. Instead, create a bare server instance using `srv := handler.New(es)`. Introspection can then be added conditionally, typically for development environments only
    Introspection can also be controlled on a per-request basis using middleware, for example, by checking user authentication or roles :
        
        ```go
        // Conceptual example for gqlgen
        import (
            "os"
            "github.com/99designs/gqlgen/graphql/handler"
            "github.com/99designs/gqlgen/graphql/handler/extension"
            // "github.com/99designs/gqlgen/graphql/playground" // For playground
            // "your_project/graph" // Your generated schema
            // "context"
            // "github.com/99designs/gqlgen/graphql"
        )
        
        // es := graph.NewExecutableSchema(graph.Config{Resolvers: &graph.Resolver{}}) // Your executable schema
        // srv := handler.New(es)
        // srv.AddTransport(transport.POST{}) // Add necessary transports
        
        // if os.Getenv("APP_ENV") == "development" {
        //     srv.Use(extension.Introspection{}) // Enable introspection queries
        //     // http.Handle("/", playground.Handler("GraphQL playground", "/query")) // Enable playground
        // }`
        
        `// Conceptual example for gqlgen middleware
        // srv.AroundOperations(func(ctx context.Context, next graphql.OperationHandler) graphql.ResponseHandler {
        //     opCtx := graphql.GetOperationContext(ctx)
        //     // Implement your logic, e.g., based on user role from context
        //     // if!isUserAdmin(ctx) {
        //     //    opCtx.DisableIntrospection = true
        //     // }
        //     return next(ctx)
        // })
        ```
        
    - **Field Suggestions:** `gqlgen` does not appear to offer a direct, top-level configuration option to disable field suggestions based on the provided information. This would likely require custom error formatting logic or middleware to intercept GraphQL errors and remove or sanitize the suggestion part of the messages, similar to approaches discussed for other frameworks.
- **For `github.com/graph-gophers/graphql-go`:**
    - **Introspection:** Use the `graphql.DisableIntrospection()` schema option when parsing or creating the schema.Go
    Alternatively, `graphql.RestrictIntrospection(fn func(ctx context.Context) bool)` provides more granular control for conditional disabling, where `DisableIntrospection()` is a shorthand for a function that always returns `false`.
        
        `// Conceptual example for graph-gophers/graphql-go
        import graphql "github.com/graph-gophers/graphql-go"
        
        // schemaString := "..." // Your schema definition
        // rootResolver := &YourRootResolver{}
        // opts :=graphql.SchemaOpt{graphql.DisableIntrospection()}
        // schema := graphql.MustParseSchema(schemaString, rootResolver, opts...)`
        
    - **Field Suggestions:** Direct configuration for disabling field suggestions is not explicitly detailed for this library in the provided materials. Similar to `gqlgen`, custom error handling might be necessary. A GitHub issue  for `graphql-go/graphql` (a related but distinct library project) indicates a desire for this feature in the broader Go GraphQL ecosystem.
- **For `github.com/graphql-go/graphql`:**
    - **Introspection:** Control is typically managed during schema setup; specific options should be verified in the library's documentation.
    - **Field Suggestions:** A GitHub issue was raised in January 2024 requesting the ability to disable field suggestions. The function `UndefinedFieldMessage` in `graphql/rules.go` is responsible for generating these suggestions. At the time of the issue, no native configuration option was readily available, suggesting that custom error handling or patching might be required.
- **Using a GraphQL Gateway (e.g., GraphQL Hive Gateway):**
If a gateway manages the GraphQL API, it might offer centralized controls. For example, GraphQL Hive Gateway allows disabling introspection via `disableIntrospection: { disableIf: () => true }` and blocking field suggestions with `blockFieldSuggestions: true` in its configuration.

**Summary Table: Golang GraphQL Library Introspection & Field Suggestion Controls**

| Library | Default Introspection Status | How to Disable Introspection | Field Suggestion Control |
| --- | --- | --- | --- |
| `99designs/gqlgen` | Enabled with `NewDefaultServer` | Use `handler.New(es)`; conditionally add `extension.Introspection{}` via `srv.Use()` or use `AroundOperations` for context-based disabling. | No direct config in available data; likely requires custom error handling/middleware. |
| `graph-gophers/graphql-go` | Enabled | Pass `graphql.DisableIntrospection()` or `graphql.RestrictIntrospection(fn)` as a `SchemaOpt` during schema parsing. | No direct config in available data; likely requires custom error handling. |
| `graphql-go/graphql` | Enabled (Assumed, typical) | Check library documentation for specific schema options. | No direct config in available data; GitHub issue  (Jan 2024) requested this. Likely requires custom error handling or patching `rules.go`. |
| `graphql-hive/gateway` (if used) | Enabled (depends on config) | `gatewayConfig.disableIntrospection.disableIf`, `gatewayConfig.blockFieldSuggestions: true` | `blockFieldSuggestions: true` |

Simply disabling the main introspection queries (targeting `__schema` and `__type`) might not be a complete solution if other information leakage vectors remain. GraphQL servers, in their effort to be developer-friendly, often return detailed error messages that include suggestions for misspelled field names or types. For instance, if a query contains `query { user { nam } }`, the server might respond with an error like, "Cannot query field 'nam' on type 'User'. Did you mean 'name'?". This "field suggestion" inadvertently leaks the existence and correct spelling of the 'name' field. Attackers can systematically exploit these suggestions, often with automated tools like Clairvoyance and a dictionary of common field names, to reconstruct significant portions of the GraphQL schema even when direct introspection is disabled. This underscores the importance of disabling field suggestions in production environments as a crucial defense-in-depth measure, making schema discovery much more challenging for attackers.

## 13. Scope and Impact

The scope of GraphQL introspection leakage directly involves the exposure of the API's structural definition, and its impact can range from simple information disclosure to facilitating severe, targeted attacks.

- **Information Disclosure:**
    - The primary and immediate impact is the complete exposure of the API schema. This includes all defined types (objects, inputs, enums, etc.), queries, mutations, subscriptions, fields within types, arguments for fields and operations, and any custom directives.
    - This exposure can reveal sensitive data structures, internal implementation details, and data relationships. If naming conventions are consistent between the API and underlying data stores (e.g., database tables or columns), introspection might inadvertently reveal parts of the database schema.
    - Descriptions associated with schema elements (types, fields, arguments), intended for developer documentation, can also be retrieved. If these descriptions contain sensitive contextual information, internal notes, or hints about unstated functionality, this further exacerbates the information leak.
- **Increased Attack Surface:**
    - The exposed schema provides attackers with a detailed roadmap of the API, making it significantly easier for them to understand the available operations and data structures. This knowledge allows them to identify and probe for other vulnerabilities more effectively and efficiently.
    - Attackers can use the schema to discover hidden, deprecated, or less-tested parts of the API. These components might have weaker security controls or known vulnerabilities that were not anticipated to be discoverable.
- **Facilitation of Targeted Attacks:**
    - With full knowledge of available queries and mutations, attackers can craft precise requests to extract data, particularly if authorization mechanisms are weak or improperly implemented.
    - The schema helps identify parameters and input types, which can be targeted for injection attacks such as SQL injection, NoSQL injection, or OS command injection, if the backend resolvers do not properly sanitize these inputs.
    - Exposed business logic, inferred from the schema, can be abused. For example, understanding how discounts or credits are applied might allow an attacker to manipulate these systems.
- **Real-World Examples of Impact:**
The potential impact is not merely theoretical. Several high-profile incidents demonstrate the risks:
    - **GitLab (2018):** An exposed GraphQL schema revealed hidden fields such as `internalNotes` and `projectSecrets`, which were not intended for public consumption.
    - **Shopify (2020):** Accidental enablement of introspection exposed fields like `customerPaymentInstruments` (containing payment details) and `privateMetafields` (holding confidential store data).
    - **Facebook (2017):** During its early adoption of GraphQL, Facebook's implementation inadvertently exposed internal user data through introspection, serving as a significant learning experience for the industry regarding API security.
    These cases highlight how a vulnerability often rated as "Low" in isolation can quickly escalate in severity when it leads to the exposure of sensitive data or critical functionality.
- **Regulatory and Compliance Risks:**
If the exposed schema reveals fields related to Personally Identifiable Information (PII)—such as email addresses, dates of birth, physical addresses, or other regulated data categories—this can contribute to breaches of data privacy regulations like GDPR, CCPA, HIPAA, etc. Such breaches can lead to substantial fines, legal action, and significant reputational damage.

The exposed schema can be likened to a "blueprint for burglary." It provides an attacker with a detailed plan of the application's data layer: where valuable data (like user emails or financial details) is likely stored, how it can be accessed (via which queries or mutations), and what potential weak points might exist in its defenses. Without this blueprint, an attacker would be operating with much less information, significantly increasing their effort and the likelihood of detection. Introspection leakage hands them this critical intelligence on a platter.

## 14. Remediation Recommendation

A defense-in-depth strategy is essential for mitigating the risks associated with GraphQL introspection leakage and protecting the overall API. No single measure is foolproof, but a combination of controls significantly enhances security.

- **Primary Action: Disable Introspection in Production:** This is the most critical and direct remediation step. GraphQL introspection queries (`__schema`, `__type`) must be disabled for all publicly accessible production environments.
    - In Golang applications, achieve this by using environment variables or build flags to differentiate configurations between development/staging and production builds, ensuring that the code paths or options that enable introspection are not active in production. (Refer to Section 12 for library-specific guidance).
- **Secondary Action: Disable Field Suggestions in Production:** As a crucial secondary defense, disable or sanitize field suggestions in GraphQL error messages in production environments. This prevents attackers from reconstructing the schema using tools like Clairvoyance if introspection is (or is mistakenly believed to be) disabled. This typically involves custom error formatters or middleware.
- **Implement Strong Authentication and Authorization:** Fundamentally, all GraphQL queries, mutations, and even individual fields (where appropriate) should be protected by robust authentication (verifying the user's identity) and fine-grained authorization (verifying the user's permissions for the requested data or action) mechanisms. This limits what an attacker can achieve even if they somehow obtain the schema.
- **Regular Security Audits and Automated Testing:**
    - Periodically audit GraphQL endpoint configurations to confirm that introspection and field suggestions remain disabled as intended in all production environments.
    - Integrate security scanning tools (as mentioned in Section 9, "Detection Steps") into CI/CD pipelines or conduct regular automated security assessments to detect any accidental exposure of introspection or other schema-leaking behaviors.
- **Adhere to the Principle of Least Privilege in Schema Design:** When designing the GraphQL schema itself, avoid exposing overly sensitive or unnecessary data fields to the public API layer. Review the schema to ensure that only data explicitly intended for client consumption is included. This minimizes the potential damage even if introspection were to be inadvertently enabled.
- **Strict Environment Segregation and Access Controls:** Maintain rigorous separation and distinct access controls for development, staging, and production environments. If staging or development environments require introspection to be enabled for testing, ensure these environments are not publicly accessible. Protect them with strong credentials, IP address restrictions, or VPN access.
- **Educate Development Teams:** Ensure that all developers working with GraphQL are aware of the security implications of introspection, the default behaviors of the Golang GraphQL libraries they use, and the importance of secure configurations for production deployments.

This layered approach ensures that even if one control fails or is bypassed, other mechanisms are in place to protect the API and its data. Disabling introspection is a key layer, but it is most effective as part of a comprehensive security strategy.

## 15. Summary

GraphQL introspection leakage, also known as GraphQL Introspection Enabled or GraphQL Introspection Query Exposure, is a common information disclosure vulnerability (CWE-200: Exposure of Sensitive Information to an Unauthorized Actor). It is often assigned a "Low" severity rating based on its direct impact. However, this rating can be misleading, as the vulnerability can significantly facilitate more severe attacks by providing attackers with a complete blueprint of the API's structure and capabilities. The issue arises when GraphQL's built-in schema discovery feature, designed for development convenience, is left accessible in production environments. This is frequently due to default configurations in GraphQL server libraries, including those commonly used in Golang applications.

The primary risk associated with this vulnerability is that it equips attackers with detailed knowledge of the API, including all types, fields, queries, and mutations. This information accelerates reconnaissance, enabling attackers to identify sensitive data, discover hidden or deprecated functionality, understand business logic, and pinpoint other vulnerabilities such as injection flaws or authorization bypasses. Real-world security incidents at prominent companies like GitLab, Shopify, and Facebook have demonstrated the tangible dangers of exposed GraphQL schemas, leading to the potential leakage of sensitive project data, customer payment details, and internal user information.

The core remediation strategy is to **disable GraphQL introspection in all production environments**. For Golang applications, this requires specific configuration adjustments depending on the GraphQL library in use (e.g., `99designs/gqlgen`, `graph-gophers/graphql-go`). Developers must be aware of library defaults and proactively secure their production deployments.

Additional critical measures include **disabling field suggestions in error messages** in production to prevent alternative schema reconstruction techniques. Furthermore, implementing **strong, fine-grained authentication and authorization** for all GraphQL operations is fundamental, as is conducting **regular security audits and automated testing** to ensure these controls remain effective. Adherence to the principle of least privilege in schema design and strict environment segregation also contribute to a robust defense.

In conclusion, while GraphQL introspection is an invaluable tool during the development lifecycle, its unintentional exposure in production environments poses an unnecessary and significant security risk. This risk can be effectively mitigated through diligent configuration management, developer awareness, and a defense-in-depth security posture.

## 16. References

**Official GraphQL Documentation:**

- GraphQL Introspection:
- GraphQL Validation:
- GraphQL Best Practices (including security):

**Security Advisories and Information:**

- PortSwigger - GraphQL Introspection Enabled:
- PortSwigger - GraphQL API Vulnerabilities:
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor:
- OWASP API Security Top 10 (General Context):
- VulnAPI - GraphQL Introspection Enabled:
- Akto - GraphQL Introspection Mode Enabled:

**Golang GraphQL Libraries & Tools Documentation/Issues:**

- `99designs/gqlgen`:
    - General:
    - Introspection Handling:
    - CORS (related server setup):
- `graph-gophers/graphql-go` (often referred to as `graphql-go`):
    - General:
    - Introspection Handling (`DisableIntrospection` option):
- `graphql-go/graphql` (distinct from `graph-gophers`):
    - Field Suggestion Issue:
    - Introspection Internals:
- GraphQL Hive Gateway (Security Features):
- GraphSpecter (Tool for auditing GraphQL):

**Security Articles and Blogs Discussing GraphQL Introspection:**

- Hacken Report Snippet:
- CyberChief - GraphQL Security (Introspection & Suggestions):
- TravisaSM - Hidden Dangers of GraphQL Introspection (Real-world cases):
- Imperva - GraphQL Vulnerabilities (Introspection Attack):
- DeepStrike - GraphQL API Vulnerabilities (Bypassing disabled introspection, Clairvoyance):
- YesWeHack - Hacking GraphQL Endpoints (Field Suggestions):
- Wallarm - Disabling Introspection Query:
- HackerOne - GraphQL Bug & Auth Bypass (Introspection as enabler):
- ArXiv - GraphQLer (Context-Aware Security Testing, mentions Clairvoyance):
- Escape.tech - GraphQL Field Suggestions Security:
- Ariadne - Hiding Field Suggestions:
- Hygraph - GraphQL Introspection Overview:
- Contentful - GraphQL Introspection Queries:
- AWS AppSync - Configuring Introspection:
- Black Hat GraphQL (Book Snippet, Mentions Clairvoyance):
- WunderGraph - Scaling GraphQL Observability (Mentions Clairvoyance contextually):
- Aptori - OWASP GraphQL Security Cheat Sheet: