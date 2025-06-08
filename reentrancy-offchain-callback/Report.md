# Potential Reentrancy using Timeout Callbacks

## Vulnerability Title
Reentrancy via Goroutine Timeout Callbacks in Concurrent Go Applications

## Severity Rating
**Medium to High** (CVSS 3.1: 7.5 - 8.5 depending on context)

## Description
This vulnerability occurs when timeout callbacks in Go applications can trigger unexpected reentrancy, causing functions to be called recursively while still processing. This can lead to race conditions, state corruption, or security bypasses when timeout handlers modify shared state or trigger operations that weren't designed for concurrent execution.

## Technical Description (for security pros)
In Go, timeout callbacks implemented using `time.After()`, `time.AfterFunc()`, or context deadlines can create reentrancy vulnerabilities when:
- Callback functions modify shared state without proper synchronization
- Timeout handlers trigger operations that call back into the original function
- Multiple goroutines interact with timeout-protected resources
- Cleanup operations in deferred functions race with timeout callbacks

The asynchronous nature of Go's runtime scheduler can cause timeout callbacks to execute at unexpected points, potentially interrupting critical sections or causing double-execution of sensitive operations.

## Common Mistakes That Cause This
- Not using proper mutex protection around timeout callback handlers
- Assuming timeout callbacks won't execute if operation completes successfully
- Failing to cancel timers/contexts after successful completion
- Using shared state in timeout handlers without synchronization
- Not considering that timeout callbacks run in separate goroutines
- Mixing channel operations with timeout callbacks incorrectly

## Exploitation Goals
- **State Corruption**: Manipulate shared data structures during partial updates
- **Double Spending**: Trigger duplicate transactions or operations
- **Authentication Bypass**: Exploit race conditions in auth timeout handlers
- **Resource Exhaustion**: Create resource leaks through repeated timeouts
- **Logic Bypass**: Skip security checks by triggering timeouts at specific moments

## Affected Components or Files
- HTTP server timeout handlers
- Database connection pool managers
- Authentication/session timeout implementations
- Rate limiting mechanisms
- Circuit breaker patterns
- Any code using `context.WithTimeout()` or `time.After()`

## Vulnerable Code Snippet
```go
type Service struct {
    mu       sync.Mutex
    balance  int
    pending  map[string]bool
}

func (s *Service) ProcessPayment(id string, amount int) error {
    // Vulnerable: timeout callback can cause reentrancy
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    go func() {
        <-ctx.Done()
        if ctx.Err() == context.DeadlineExceeded {
            // This runs in separate goroutine without proper locking
            s.revertPayment(id, amount)
        }
    }()
    
    s.mu.Lock()
    if s.balance < amount {
        s.mu.Unlock()
        return errors.New("insufficient funds")
    }
    s.balance -= amount
    s.pending[id] = true
    s.mu.Unlock()
    
    // Process payment...
    if err := processExternalPayment(id, amount); err != nil {
        s.revertPayment(id, amount)
        return err
    }
    
    return nil
}

func (s *Service) revertPayment(id string, amount int) {
    // Race condition: multiple goroutines can call this
    s.mu.Lock()
    if s.pending[id] {
        s.balance += amount
        delete(s.pending, id)
    }
    s.mu.Unlock()
}
```

## Detection Steps
1. **Static Analysis**: Search for patterns combining timeout mechanisms with state modifications
2. **Code Review**: Identify timeout callbacks that access shared resources
3. **Runtime Analysis**: Use Go's race detector (`go run -race`)
4. **Pattern Matching**: Look for `context.WithTimeout` followed by goroutines accessing parent scope
5. **Trace Analysis**: Monitor goroutine execution patterns during timeout scenarios

## Proof of Concept (PoC)
```go
package main

import (
    "context"
    "fmt"
    "sync"
    "time"
)

type VulnerableService struct {
    mu      sync.Mutex
    counter int
    active  bool
}

func (vs *VulnerableService) VulnerableOperation() {
    ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
    defer cancel()
    
    // Timeout callback without proper synchronization
    go func() {
        <-ctx.Done()
        fmt.Println("Timeout triggered")
        vs.cleanup() // Reentrancy vulnerability
    }()
    
    vs.mu.Lock()
    vs.active = true
    vs.counter++
    currentCount := vs.counter
    vs.mu.Unlock()
    
    // Simulate work
    time.Sleep(150 * time.Millisecond)
    
    vs.mu.Lock()
    if vs.active && vs.counter == currentCount {
        fmt.Printf("Operation completed: %d\n", vs.counter)
    }
    vs.active = false
    vs.mu.Unlock()
}

func (vs *VulnerableService) cleanup() {
    vs.mu.Lock()
    if vs.active {
        vs.counter-- // Race condition
        vs.active = false
    }
    vs.mu.Unlock()
}

func main() {
    service := &VulnerableService{}
    
    // Trigger race condition
    var wg sync.WaitGroup
    for i := 0; i < 5; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            service.VulnerableOperation()
        }()
    }
    wg.Wait()
    
    fmt.Printf("Final counter (should be 0): %d\n", service.counter)
}
```

## Risk Classification
- **Likelihood**: Medium (common pattern in production code)
- **Impact**: High (can lead to financial loss, data corruption)
- **Exploitability**: Medium (requires timing control)
- **Overall Risk**: Medium-High

## Fix & Patch Guidance
```go
// Secure implementation
func (s *Service) SecureProcessPayment(id string, amount int) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    
    // Use channel to coordinate cleanup
    done := make(chan bool, 1)
    
    go func() {
        select {
        case <-ctx.Done():
            if ctx.Err() == context.DeadlineExceeded {
                s.safeRevert(id, amount, done)
            }
        case <-done:
            // Operation completed successfully
            cancel()
        }
    }()
    
    s.mu.Lock()
    if s.balance < amount {
        s.mu.Unlock()
        done <- true
        return errors.New("insufficient funds")
    }
    s.balance -= amount
    s.pending[id] = true
    s.mu.Unlock()
    
    if err := processExternalPayment(id, amount); err != nil {
        done <- true
        s.safeRevert(id, amount, nil)
        return err
    }
    
    done <- true
    s.markComplete(id)
    return nil
}

func (s *Service) safeRevert(id string, amount int, done chan bool) {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    if s.pending[id] {
        s.balance += amount
        delete(s.pending, id)
        if done != nil {
            select {
            case done <- true:
            default:
            }
        }
    }
}
```

## Scope and Impact
- **Affected Systems**: Any Go application using timeout callbacks with shared state
- **Data Impact**: Potential corruption of financial data, user states, or counters
- **Business Impact**: Transaction inconsistencies, service reliability issues
- **Security Impact**: Possible exploitation for financial gain or DoS

## Remediation Recommendation
1. **Immediate**: Audit all timeout callback implementations for reentrancy issues
2. **Short-term**: Implement proper synchronization using channels or mutexes
3. **Long-term**: Adopt safe concurrency patterns and timeout handling libraries
4. **Best Practices**:
   - Always cancel contexts/timers on successful completion
   - Use channels for coordination between goroutines
   - Avoid shared state in timeout callbacks
   - Implement idempotent operations where possible
   - Use atomic operations for simple counters

## Summary
Reentrancy vulnerabilities through timeout callbacks represent a subtle but serious security issue in Go applications. The concurrent nature of timeout handlers combined with improper synchronization can lead to race conditions, state corruption, and security bypasses. Developers must carefully design timeout mechanisms with proper coordination between goroutines and ensure that cleanup operations are idempotent and thread-safe.

## References
- [Go Concurrency Patterns](https://go.dev/blog/pipelines)
- [Context Package Documentation](https://pkg.go.dev/context)
- [Go Memory Model](https://go.dev/ref/mem)
- [Effective Go - Concurrency](https://go.dev/doc/effective_go#concurrency)
- [Go Race Detector](https://go.dev/blog/race-detector)
- [Common Go Concurrency Mistakes](https://go101.org/article/concurrent-common-mistakes.html)