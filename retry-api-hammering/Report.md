# Retry Logic Hammering Public APIs

## Vulnerability Title
Aggressive API Retry Logic Leading to Distributed Denial of Service (DDoS)

## Severity Rating
**Medium🟡 to High🟠** (CVSS 3.1: 7.5)
- Can escalate to Critical when multiple instances participate in the attack

## Description
This vulnerability occurs when Go applications implement overly aggressive retry logic for failed API calls without proper backoff strategies, rate limiting, or jitter. When multiple instances of the application encounter errors simultaneously (such as during an API outage), they can inadvertently create a thundering herd effect, overwhelming the target API with exponentially increasing requests.

## Technical Description (for security pros)
The vulnerability manifests when retry implementations use tight loops, linear backoff, or synchronized retry intervals across distributed systems. Go's lightweight goroutines make it trivial to spawn thousands of concurrent retry attempts. Without proper circuit breakers, exponential backoff with jitter, or rate limiting, applications can amplify a temporary API failure into a sustained DDoS attack. The issue is exacerbated in containerized environments where auto-scaling can spawn additional instances, each contributing to the retry storm.

## Common Mistakes That Cause This
- Using simple `for` loops with `time.Sleep()` for retries
- Implementing linear or no backoff between retry attempts
- Missing jitter in exponential backoff calculations
- Absence of circuit breaker patterns
- No global rate limiting across application instances
- Retrying on 4xx errors that won't succeed
- Infinite retry loops without maximum attempt limits
- Not respecting `Retry-After` headers from APIs

## Exploitation Goals
- Cause service degradation or outage of target APIs
- Trigger rate limiting that affects legitimate users
- Exhaust API quotas leading to service interruption
- Create cascading failures in dependent services
- Generate excessive costs for pay-per-request APIs

## Affected Components or Files
- HTTP client implementations
- API client libraries
- Background job processors
- Message queue consumers
- Webhook handlers
- Health check implementations

## Vulnerable Code Snippet
```go
// VULNERABLE: Tight retry loop with no backoff
func callAPI(url string) (*http.Response, error) {
    maxRetries := 10
    client := &http.Client{Timeout: 5 * time.Second}
    
    for i := 0; i < maxRetries; i++ {
        resp, err := client.Get(url)
        if err == nil && resp.StatusCode == 200 {
            return resp, nil
        }
        
        // Bad: Fixed sleep, no backoff
        time.Sleep(100 * time.Millisecond)
    }
    
    return nil, fmt.Errorf("max retries exceeded")
}

// ALSO VULNERABLE: Linear backoff without jitter
func callAPIWithLinearBackoff(url string) (*http.Response, error) {
    client := &http.Client{}
    
    for attempt := 1; attempt <= 5; attempt++ {
        resp, err := client.Get(url)
        if err == nil && resp.StatusCode < 500 {
            return resp, nil
        }
        
        // Bad: Linear backoff causes synchronized retries
        time.Sleep(time.Duration(attempt) * time.Second)
    }
    
    return nil, errors.New("API call failed")
}
```

## Detection Steps
1. Monitor outbound request rates during API failures
2. Check for exponential increase in request volume during incidents
3. Analyze application logs for retry patterns
4. Review code for retry implementations lacking:
   - Exponential backoff
   - Jitter mechanisms
   - Circuit breakers
   - Rate limiters
5. Load test retry behavior with simulated API failures
6. Monitor for synchronized request spikes across instances

## Proof of Concept (PoC)
```go
// Simulate API failure scenario
func demonstrateRetryHammering() {
    // Mock API server that always returns 500
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        atomic.AddInt64(&requestCount, 1)
        w.WriteHeader(http.StatusInternalServerError)
    }))
    defer server.Close()
    
    // Launch multiple goroutines simulating distributed instances
    var wg sync.WaitGroup
    instances := 100
    
    for i := 0; i < instances; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            callAPI(server.URL) // Using vulnerable retry logic
        }()
    }
    
    wg.Wait()
    fmt.Printf("Total requests generated: %d\n", atomic.LoadInt64(&requestCount))
    // Result: Thousands of requests from just 100 instances
}
```

## Risk Classification
- **Availability Impact**: High
- **Integrity Impact**: None
- **Confidentiality Impact**: None
- **Exploitability**: Medium
- **Business Impact**: High (service disruption, API quota exhaustion, increased costs)

## Fix & Patch Guidance
```go
// SECURE: Proper retry with exponential backoff and jitter
func callAPISecure(url string) (*http.Response, error) {
    client := &http.Client{Timeout: 10 * time.Second}
    maxRetries := 5
    maxBackoff := 32 * time.Second
    
    for attempt := 0; attempt < maxRetries; attempt++ {
        resp, err := client.Get(url)
        
        // Don't retry on client errors
        if err == nil && resp.StatusCode < 500 {
            return resp, nil
        }
        
        if attempt == maxRetries-1 {
            return nil, fmt.Errorf("max retries exceeded: %v", err)
        }
        
        // Exponential backoff with jitter
        backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
        if backoff > maxBackoff {
            backoff = maxBackoff
        }
        
        // Add jitter (±25%)
        jitter := backoff / 4
        backoff = backoff + time.Duration(rand.Int63n(int64(jitter))) - jitter/2
        
        time.Sleep(backoff)
    }
    
    return nil, errors.New("unreachable")
}

// BETTER: With circuit breaker
import "github.com/sony/gobreaker"

var cb *gobreaker.CircuitBreaker

func init() {
    cb = gobreaker.NewCircuitBreaker(gobreaker.Settings{
        Name:        "API",
        MaxRequests: 3,
        Interval:    60 * time.Second,
        Timeout:     30 * time.Second,
        ReadyToTrip: func(counts gobreaker.Counts) bool {
            failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
            return counts.Requests >= 3 && failureRatio >= 0.6
        },
    })
}
```

## Scope and Impact
- Affects all external API integrations
- Can cascade to partner services and third-party providers
- May violate API terms of service leading to account suspension
- Potential financial impact from pay-per-use APIs
- Reputation damage from being source of DDoS

## Remediation Recommendation
1. **Immediate Actions**:
   - Implement exponential backoff with jitter
   - Add circuit breakers to all external API calls
   - Set reasonable retry limits and timeouts
   - Implement per-service rate limiting

2. **Long-term Solutions**:
   - Use established retry libraries (e.g., `github.com/avast/retry-go`)
   - Implement distributed rate limiting with Redis
   - Add observability for retry behavior
   - Create API client abstractions with built-in protection
   - Implement bulkhead patterns to isolate failures

3. **Configuration Guidelines**:
   - Initial retry delay: 1-2 seconds
   - Maximum retries: 3-5 attempts
   - Backoff multiplier: 2x
   - Maximum backoff: 30-60 seconds
   - Jitter range: ±25% of backoff time

## Summary
Retry logic hammering is a common vulnerability in Go applications that can transform minor API hiccups into major outages. The combination of Go's concurrency features and inadequate retry strategies creates perfect conditions for accidental DDoS attacks. Proper implementation requires exponential backoff with jitter, circuit breakers, and rate limiting. Organizations should audit all API integrations and standardize on well-tested retry patterns to prevent becoming an unwitting participant in distributed denial of service attacks.

## References
- Google SRE Book - Chapter 22: Addressing Cascading Failures
- AWS Architecture Blog: Exponential Backoff and Jitter
- Circuit Breaker Pattern - Martin Fowler
- Go Concurrency Patterns: Timing out, moving on
- Building Resilient Services with Go - GopherCon Talk
- RFC 7231 Section 7.1.3: Retry-After Header