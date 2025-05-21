# **Zombie Processes from Bad Signal Handling in Golang (zombie-processes-signal-misuse)**

## **Severity Rating**

**Overall Severity: Medium🟡 to High🟠**

**CVSS 3.1 Base Score: 6.2 (Medium)**

- **Vector:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H
    - **Attack Vector (AV): Local (L):** The vulnerability typically requires local access to the system where the Go application is running or the ability to trigger specific process creation functionalities within the application remotely, which then manifests locally.
    - **Attack Complexity (AC): Low (L):** The conditions to exploit are often straightforward, stemming from common coding errors in process management rather than complex system interactions.
    - **Privileges Required (PR): Low (L):** Exploitation generally does not require high privileges. The Go application's own privilege level is usually sufficient to create child processes that can become zombies.
    - **User Interaction (UI): None (N):** No user interaction is typically needed for an attacker to trigger the vulnerability once a vulnerable code path is executed.
    - **Scope (S): Unchanged (U):** The exploit's impact is generally confined to the security scope of the vulnerable component (the application or the container it runs in).
    - **Confidentiality (C): None (N):** This vulnerability does not typically lead to direct disclosure of sensitive information.
    - **Integrity (I): None (N):** This vulnerability does not typically lead to direct modification of data.
    - **Availability (A): High (H):** The primary impact is a denial of service (DoS) due to resource exhaustion (e.g., Process IDs), which can render the application or even the container/system unresponsive.

The CVSS score represents a baseline. The actual severity can escalate, particularly if the Go application operates as Process ID 1 (PID 1) within a containerized environment, where its failure to manage processes can affect the entire container's stability.

**Severity Breakdown (OWASP Risk Rating Methodology Context)**

To further understand the severity, an OWASP-based risk rating approach can be applied, considering likelihood and impact factors.

| **Factor** | **Level (Score 0-9)** | **Justification for "Zombie Processes" Context** |
| --- | --- | --- |
| **Threat Agent Factors** |  |  |
| Skill Level | Low-Medium (3-5) | Exploiting often requires understanding Go process management and identifying the flawed pattern, but not necessarily elite hacking skills. |
| Motive | Medium (4) | Primary motive is typically disruption (DoS) rather than direct financial gain or data theft, though impact can be significant. |
| Opportunity | Medium (4-7) | Depends on accessibility of the vulnerable code path. If exposed via an API that spawns processes, opportunity increases. |
| Size | Medium (4-6) | Could be exploited by internal developers making mistakes, or external actors if the vulnerable functionality is exposed. |
| **Vulnerability Factors** |  |  |
| Ease of Discovery | Medium (3-7) | Code review can identify missing `Wait()` calls. Dynamic analysis by observing zombie processes or PID exhaustion also works. |
| Ease of Exploit | Medium (5) | Once the vulnerable pattern is identified and can be triggered (e.g., via API call that spawns a process), exploitation is straightforward. |
| Awareness | Medium (4-6) | The concept of zombie processes is known, but its specific manifestation in Go due to `os/exec` misuse might be less universally understood. |
| Intrusion Detection | Low-Medium (3-8) | Basic system monitoring might detect high PID usage or defunct processes. Application-specific logging for process management failures might be absent. |
| **Technical Impact** |  |  |
| Loss of Confidentiality | None (0) | Does not directly lead to data exposure. |
| Loss of Integrity | None (0) | Does not directly lead to data modification. |
| Loss of Availability | High (7-9) | Can lead to application DoS, container DoS, or even system-wide DoS if PID exhaustion occurs. This is the primary impact.|
| Loss of Accountability | Low (1-3) | Actions leading to zombie creation might be logged by the application, but the exploit itself doesn't inherently obscure attacker actions more than other DoS vectors. |

Context Dependency of Severity:

The severity of this vulnerability is not static; it is highly dependent on the operational context of the Go application.

A standalone Go application creating zombie processes primarily impacts its own operational stability and resource consumption within its allocated system limits. However, the situation changes dramatically when the Go application runs as PID 1 within a container, a common pattern in Dockerized environments.1 In a Linux environment, PID 1 is special; it is the "init" process, responsible for starting other processes and, crucially, for "adopting" and "reaping" any orphaned processes within its namespace. An orphaned process is one whose original parent has terminated. If the Go application, now acting as PID 1, fails to handle signals like SIGCHLD correctly and call wait() for its own mismanaged child processes, it will almost certainly also fail to reap other unrelated orphaned processes that it adopts within the container. This leads to a much faster accumulation of zombie processes from various sources, potentially exhausting the container's PID limit or available memory more rapidly. Consequently, the impact escalates from an application-specific DoS to a container-wide DoS, significantly increasing the effective severity.

Silent Failure Leading to Cascading Issues:

Zombie processes, in their defunct state, are individually benign and consume very few resources—primarily a slot in the process table.1 The danger arises from their accumulation. As they build up, the system may exhaust available PIDs, preventing any new processes from starting, which is a direct and severe impact.1 Less directly, but also consequentially, the gradual consumption of process table slots or associated kernel memory might lead to broader system resource starvation. This starvation can cause other, seemingly unrelated components of the application or even other applications on the system to behave erratically or fail. For instance, a database client might fail to establish new connections, or network services might become unresponsive, not because of a direct issue with those services, but because the underlying system cannot allocate necessary resources due to PID exhaustion caused by zombies. This makes diagnosis challenging, as the immediate error messages (e.g., "cannot connect to Redis" as noted in one account 1) often act as red herrings, obscuring the true root cause of zombie process accumulation.

## **Description**

A "Zombie Process from Bad Signal Handling" vulnerability in Golang applications arises when a parent Go program initiates child processes, typically utilizing the `os/exec` package, but subsequently fails to manage their lifecycle correctly. Specifically, the vulnerability manifests if the parent process does not wait for its child processes to terminate and thereby fails to "reap" their exit status. This oversight causes the terminated child processes to enter a "zombie" or "defunct" state. While an individual zombie process consumes minimal system resources (primarily a process table entry), their unchecked accumulation can lead to the exhaustion of critical system resources, most notably Process IDs (PIDs), and potentially contribute to memory depletion. Such resource exhaustion ultimately results in a Denial of Service (DoS), preventing new processes from being created and potentially destabilizing the application or the entire system. This issue is commonly rooted in the improper handling of the `SIGCHLD` signal (implicitly or explicitly) or the misuse of process management functions such as `cmd.Process.Kill()` without a corresponding and necessary call to `cmd.Wait()` to clean up the child process entry.**1**

## **Technical Description**

Understanding this vulnerability requires a grasp of Unix process lifecycle management and how Go's `os/exec` package interacts with these underlying mechanisms.

Process Lifecycle (Unix):

In Unix-like systems, new processes are typically created using the fork() system call, which creates a new process (child) that is a near-identical copy of the calling process (parent). The child process can then use one of the exec() family of system calls to replace its memory space with a new program.5 When a child process terminates, it sends a SIGCHLD signal to its parent process. The parent is then expected to call one of the wait() family functions (e.g., wait(), waitpid()) to retrieve the child's exit status. This wait() call allows the kernel to remove the terminated child's entry from the process table, effectively "reaping" the child.4

Zombie State:

If the parent process does not call wait() (or does not do so in a timely manner) after a child terminates, the child process enters a "zombie" state. In this state, the process has released most of its resources (memory, file descriptors), but its entry in the system's process table remains. This entry, often marked as <defunct> or Z in process listings, holds the child's exit status and PID.1 It exists solely for the parent to eventually collect its exit status. If the parent never collects this status, the zombie persists until the parent itself exits, at which point the zombie (if still present) would be reparented to the init process (PID 1) or an appropriate subreaper, which would then be responsible for reaping it.

Golang os/exec Package:

Go's standard os/exec package provides the primary interface for running external commands.

- `cmd.Start()`: This method initiates the specified command but does not wait for its completion. This is an asynchronous operation. It is then the developer's responsibility to explicitly call `cmd.Wait()` on the `exec.Cmd` object at a later point. `cmd.Wait()` waits for the command to exit and reaps the associated process resources. Failure to call `cmd.Wait()` after the child process has terminated is a direct cause of zombie processes.

    
- `cmd.Run()`: This method is a convenience function that calls `cmd.Start()` and then immediately calls `cmd.Wait()`. For simple, synchronous command execution where the program needs to wait for completion, `cmd.Run()` is generally safer concerning zombie creation because it handles the `Wait()` call internally.
    
- `cmd.Process.Kill()`: This method sends a `SIGKILL` signal (by default on Unix) to the process, causing it to terminate abruptly. Importantly, `Kill()` only terminates the process; it does *not* reap it. `cmd.Wait()` must still be called on the `exec.Cmd` object to clean up the process entry and retrieve its exit status (which will reflect the kill). A common misconception is that `Kill()` is sufficient for complete process cleanup.
    
- `cmd.Process.Signal()`: This allows sending an arbitrary signal to the process, offering finer control but carrying the same responsibilities regarding process reaping.

Signal Handling in Go:

Go's runtime manages signals for its internal operations and goroutines. However, when a Go program spawns external child processes using os/exec, the responsibility for reaping those specific children falls to the Go code that initiated them, primarily through the cmd.Wait() method. While the os/signal package allows a Go program to listen for and handle OS signals like SIGCHLD 7, this is not automatically set up to reap children started by os/exec unless cmd.Wait() is used for each child. The default behavior of a Go program regarding SIGCHLD from its external children is that the signal is delivered, but if cmd.Wait() is not called, the zombie state persists.

PID 1 Problem in Containers (Docker):

A critical scenario arises when a Go application is designated to run as PID 1 within a Docker container (or other container types). In Linux, PID 1 is the init process, which has special responsibilities, including adopting and reaping any orphaned processes within its process namespace.1 If a Go application running as PID 1 is not specifically designed to fulfill these init duties (i.e., it doesn't have a robust mechanism to handle SIGCHLD from any child and call waitpid() or equivalent for all terminated children, including those it adopts), then any orphaned processes, in addition to its own mismanaged children, will become zombies. This can rapidly lead to PID exhaustion within the container.

A subtle aspect here is the potential misunderstanding of Go's `os/exec` abstraction. Developers might assume that the package handles all low-level process lifecycle details automatically, similar to how some higher-level scripting languages manage child processes. However, the explicit requirement to call `cmd.Wait()` to reap child processes is a direct consequence of the underlying Unix process model, over which Go's `os/exec` provides a relatively thin, albeit convenient, abstraction. The Go runtime itself does not automatically reap `os/exec` children if `cmd.Wait()` is omitted by the application code. This gap between the perceived level of abstraction and the underlying OS mechanics is a frequent source of this vulnerability.

Furthermore, while the kernel sends `SIGCHLD` upon child termination, the default disposition of `SIGCHLD` in many Unix systems is to be ignored if not explicitly handled. Go programs can use `os/signal.Notify` to catch `SIGCHLD`. However, unless the Go program is specifically coded to act as an init process (if it's PID 1) and has a general `SIGCHLD` handler that calls `waitpid(-1,...)` to reap *any* child (including adopted orphans), these signals may not result in the necessary reaping action for all potential zombies. The `cmd.Wait()` call handles reaping for the specific child associated with the `Cmd` object, but a PID 1 process needs a broader reaping strategy.

## **Common Mistakes That Cause This**

Several common programming and deployment errors can lead to the creation of zombie processes in Go applications:

- **Neglecting `cmd.Wait()` after `cmd.Start()`:** The most frequent mistake is calling `cmd.Start()` to execute a child process asynchronously but failing to subsequently call `cmd.Wait()` on that `exec.Cmd` object. `cmd.Wait()` is essential for the parent to acknowledge the child's termination and allow the system to remove its process table entry.

    
- **Misunderstanding `cmd.Process.Kill()`:** Assuming that `cmd.Process.Kill()` is sufficient to terminate and clean up a child process. While `Kill()` does terminate the process (usually with `SIGKILL`), it does not reap it. `cmd.Wait()` must still be called afterwards to collect the exit status and free the process table entry.
    
- **Improper Use of `cmd.Process.Release()`:** Calling `cmd.Process.Release()` without first ensuring `cmd.Wait()` has completed. `Release()` is intended to free resources associated with the `os.Process` object in the parent, but only after the child process has been reaped by `Wait()`.
- **Failure to Wait in Loops:** In applications that spawn numerous short-lived child processes in a loop or concurrently, failing to call `cmd.Wait()` for each one in a timely and reliable manner will lead to an accumulation of zombies.
- **Orphaning Processes on Parent Exit:** If the main Go application exits (gracefully or due to a crash) without ensuring all its spawned child processes are terminated and waited for, these children can become orphaned. If the new parent process (e.g., PID 1 in a container, if it's not a proper init system) doesn't reap them, they become zombies.
    
- **PID 1 Mismanagement in Containers:**
    - Running a Go application as PID 1 in a Docker container without implementing a `SIGCHLD` handler that robustly calls `waitpid` (or an equivalent system call) to reap all terminated child processes (both its own direct children and any it adopts as orphans).
        
    - Not utilizing a dedicated init system like Tini or Docker's `-init` flag when the Go application is PID 1. These tools are designed to handle zombie reaping correctly.
        
- **Incorrect Process Group Management:** If a child process spawned by the Go application itself spawns further children (grandchildren to the Go app), simply killing and waiting for the direct child might not affect these grandchildren. If the direct child exits without properly managing its own children, they can become orphaned and subsequently zombies if not reaped by an init process. The issue described in , where `npm run start` spawns `next start`, highlights this, and using process groups was part of the solution to manage the entire process tree.
    

A subtle error can occur with **goroutine mismanagement for `cmd.Wait()`**. Because `cmd.Start()` is non-blocking, developers often launch `cmd.Wait()` in a separate goroutine to avoid blocking the main application flow. If this "waiter" goroutine is not properly managed—for instance, if it panics due to an unhandled error, if it's not started due to a logical flaw, or if the main program exits without ensuring these waiter goroutines complete their work (e.g., through `sync.WaitGroup`)—the `cmd.Wait()` call can be missed, leading to a zombie process.

Another area of complexity is the **"killing" of an entire process tree**. `os.Process.Kill()` only sends a signal to the immediate process identified by `cmd.Process.Pid`. If this process has spawned its own children, they are unaffected by this direct kill signal. Upon the termination of `cmd.Process.Pid`, its children become orphaned and are reparented, typically to PID 1. The Go application, by calling `cmd.Wait()` on the original `Cmd` object, only reaps its direct child. It has no built-in mechanism via `cmd.Wait()` to find and reap these "grandchildren." This can lead to an accumulation of orphaned grandchildren if PID 1 is not a proper init system. Managing such scenarios effectively often requires setting process group IDs and signaling the entire process group, as discussed in.

## **Exploitation Goals**

The primary objectives of exploiting a zombie process vulnerability are typically centered around causing disruption and instability:

- **Denial of Service (DoS):** This is the most common goal. By forcing the creation of numerous zombie processes, an attacker aims to exhaust system resources.
    - **PID Exhaustion:** Every process, including a zombie, occupies a Process ID (PID). PIDs are a finite resource on any Unix-like system (the maximum is defined by `/proc/sys/kernel/pid_max`). If enough zombie processes accumulate, the system can run out of available PIDs, preventing new processes from being created. This effectively denies service for any application or system utility that needs to spawn a new process.
        
    - **Memory Exhaustion:** While individual zombie processes consume very little memory (as their address space is deallocated), the process table entry itself and any associated kernel structures do consume some memory. In extreme cases of a very large number of zombies, or if there are subtle kernel memory leaks associated with unreaped processes over a long period, this could contribute to overall system memory pressure, potentially slowing down or crashing the application or system.
        
- **System Instability:** Beyond a clear DoS, the resource strain can lead to general system instability. Applications might behave erratically, crash unexpectedly, or suffer performance degradation. This is particularly true in containerized environments where resource limits are often tighter.

An attacker might pursue **targeted resource starvation**. Instead of a full system or container crash, the goal could be to subtly starve a specific, critical co-located service of PIDs or other related kernel resources. The vulnerable Go application acts as the vector, generating zombies that consume PIDs from a shared pool (system-wide or container-namespace-wide). Another critical application on the same system or in the same container, which needs to spawn new processes or threads (which also consume PIDs), may then fail when it attempts to do so because no PIDs are available. This causes the targeted critical service to malfunction or crash, even if the vulnerable Go application itself remains partially functional.

In **microservice architectures**, the impact can be amplified. If the Go service prone to creating zombies is a central component that other microservices rely upon for tasks involving process creation (e.g., a service that spawns workers for image processing or data transformation), its failure due to zombie accumulation can trigger a cascading failure. As the vulnerable service becomes unable to spawn new processes, requests from dependent microservices will begin to fail or time out, leading to a broader degradation of the entire system, extending far beyond the initially compromised service.

## **Affected Components or Files**

The vulnerability primarily involves the interaction between Go application code and the underlying operating system's process management:

- **Go Application Code:** Any part of a Go application that utilizes the `os/exec` package to create and manage child processes, especially functions like `cmd.Start()`, is a potential site for this vulnerability if `cmd.Wait()` is not correctly implemented.
    
- **Go Standard Library `os/exec`:** This package is the component being misused. It provides the functionality to run external commands, but requires careful handling by the developer to prevent zombie processes.
- **Operating System Process Table:** This kernel structure is where process entries (including those of zombies) are stored. The exhaustion of available slots in this table (manifesting as PID exhaustion) is the direct impact.
- **Container Runtime Environment (e.g., Docker):** If the Go application is running as PID 1 within a container without a proper init system (like Tini), the container environment itself is affected, as the Go application fails in its inherited init responsibilities.
    

## **Vulnerable Code Snippet**

The following Go code illustrates the common mistake of calling `cmd.Start()` without a corresponding `cmd.Wait()`, leading to zombie processes:

```Go

package main

import (
	"log"
	"os/exec"
	"time"
)

func vulnerableStartProcess() {
	// Example: uses "sleep 1" as a short-lived child process
	cmd := exec.Command("sleep", "1")
	err := cmd.Start() // Start the process asynchronously
	if err!= nil {
		log.Printf("Failed to start process: %v", err)
		return
	}
	log.Printf("Process started with PID: %d", cmd.Process.Pid)

	// CRITICAL MISTAKE: cmd.Wait() is not called here.
	// If this function is called repeatedly, and the 'sleep 1' processes
	// terminate, they will become zombie processes because the parent (this Go program)
	// has not waited for them to collect their exit status.
}

func main() {
	log.Println("Starting to create potential zombies...")
	for i := 0; i < 5; i++ {
		vulnerableStartProcess()
		// Brief pause to allow the 'sleep' process to potentially finish
		// and become a zombie if not waited upon by its parent.
		time.Sleep(1500 * time.Millisecond)
	}
	log.Println("Completed spawning processes. Check process list for defunct 'sleep' processes (e.g., using 'ps aux | grep defunct' or 'ps aux | grep Z').")
	// Keep the main program alive for a short period to allow observation of zombie processes.
	time.Sleep(10 * time.Second)
	log.Println("Exiting PoC.")
}
```

A second example, inspired by the scenario described in section -, demonstrates the misuse of `cmd.Process.Kill()` without a subsequent `cmd.Wait()`:

```Go

package main

import (
	"log"
	"os/exec"
	"time"
	"syscall" // Required for specific signal checks if any
)

// stopProcessIncorrectly attempts to kill a process but doesn't reap it.
// Based on the problematic pattern discussed in.[1]
func stopProcessIncorrectly(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		log.Println("Process is nil, cannot kill.")
		return nil // Or an error indicating process not started
	}
	log.Printf("Sending SIGKILL to process %d", cmd.Process.Pid)
	err := cmd.Process.Kill() // Sends SIGKILL (on Unix)
	if err!= nil {
		log.Printf("Failed to send SIGKILL to process %d: %v", cmd.Process.Pid, err)
		return err
	}
	log.Printf("SIGKILL sent to process %d.", cmd.Process.Pid)
	// CRITICAL MISTAKE: cmd.Wait() is not called after killing.
	// The process will terminate, but its entry will remain in the
	// process table as a zombie.
	return nil
}

func main() {
	// Start a long-running command (e.g., sleep for 60 seconds)
	cmd := exec.Command("sleep", "60")
	err := cmd.Start()
	if err!= nil {
		log.Fatalf("Failed to start command: %v", err)
	}
	log.Printf("Process %d started.", cmd.Process.Pid)

	// Allow the process to run for a short duration
	time.Sleep(2 * time.Second)

	// Attempt to stop the process incorrectly
	err = stopProcessIncorrectly(cmd)
	if err!= nil {
		// This error would be from cmd.Process.Kill() itself
		log.Printf("Error from stopProcessIncorrectly: %v", err)
	}

	// At this point, the 'sleep' process has been sent SIGKILL. It will terminate.
	// However, because cmd.Wait() is not called, it will become a zombie.
	// To correctly reap it, one would call:
	// waitMsg, waitErr := cmd.Wait()
	// if waitErr!= nil {
	//    if exitErr, ok := waitErr.(*exec.ExitError); ok {
	//        if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signal() == syscall.SIGKILL {
	//            log.Printf("Process %d killed and reaped successfully. Exit status: %s", cmd.Process.Pid, waitMsg)
	//        } else {
	//            log.Printf("Process %d reaped with error: %v. Exit status: %s", cmd.Process.Pid, waitErr, waitMsg)
	//        }
	//    } else {
	//        log.Printf("cmd.Wait() error for process %d: %v. Exit status: %s", cmd.Process.Pid, waitErr, waitMsg)
	//    }
	// } else {
	//    log.Printf("Process %d reaped successfully. Exit status: %s", cmd.Process.Pid, waitMsg)
	// }

	log.Printf("Process %d has been 'killed'. Check system for zombie 'sleep' process. PoC will exit in 15s.", cmd.Process.Pid)
	time.Sleep(15 * time.Second) // Keep main alive to observe zombies
	log.Println("Exiting PoC.")
}
```

In the first snippet, `vulnerableStartProcess` starts a child but omits `cmd.Wait()`. If called multiple times, `sleep` processes will terminate and become zombies. In the second snippet, `stopProcessIncorrectly` sends `SIGKILL` via `cmd.Process.Kill()` but, crucially, `cmd.Wait()` is not subsequently called in `main` to reap the now-terminated child process, thus leading to a zombie. The commented-out `cmd.Wait()` block shows how one might correctly reap it and check its exit status.

## **Detection Steps**

Identifying the presence of zombie process vulnerabilities involves a combination of system monitoring, log analysis, and code review:

- **Manual Process Inspection:** On Unix-like systems, the most direct way to detect existing zombie processes is by using command-line tools. Commands like `ps aux | grep defunct` or `ps aux | grep 'Z'` will list all processes currently in the zombie (defunct) state. The output should be examined to see if any of these zombies are child processes spawned by the Go application in question.
    
- **Monitoring PID Usage:** Keep track of the total number of Process IDs (PIDs) in use on the system or within the container. The maximum number of PIDs can be found (on Linux) via `cat /proc/sys/kernel/pid_max`. A consistent and unexplained increase in the number of active PIDs, especially if it trends towards the `pid_max` limit, can be an indicator of a zombie process leak. This often precedes errors related to inability to fork new processes.
- **Memory Monitoring:** While individual zombie processes consume very little memory, monitoring overall system or container memory usage is still advisable. Sometimes, unexplained memory growth that correlates with high rates of process spawning activity might indirectly point to issues, although zombies themselves are typically not the primary memory consumers. However, as noted in , memory spikes were observed before crashes, potentially due to the system struggling with resource limits or associated kernel structures not being fully reclaimed.

- **Application and System Logs:** Scrutinize application logs for errors related to process creation failures. Messages such as "fork: retry: no child processes," "resource temporarily unavailable," or "too many processes" can occur when the PID limit is reached due_to_zombie accumulation. System logs (e.g., kernel logs via `dmesg` or `/var/log/syslog`) might also contain warnings about PID exhaustion or excessive process creation.
- **Container-Specific Monitoring:** If the Go application is running within a Docker container, tools like `docker stats <container_id>` can show resource usage, including PID counts (if the Docker version and configuration expose this metric). A rising PID count for a container whose application is PID 1 and spawns processes could indicate mismanagement.
- **Static Code Analysis and Code Review:** Thoroughly review the Go source code, specifically looking for all instances where `os/exec.Command(...).Start()` is used. For each such call, verify that `cmd.Wait()` is eventually called in all possible execution paths, including normal completion, error handling, and within any goroutines used for asynchronous waiting. Pay special attention to signal handling logic if the application is intended to run as PID 1 or manages complex process trees.
- **Dynamic Analysis/Tracing:** Tools like `strace` (on Linux) can be attached to the Go process to observe system calls. Filtering for `clone` (or `fork`), `execve`, `wait4` (or `waitpid`), and signal-related calls can reveal if child processes are being started but not waited for.

## **Proof of Concept (PoC)**

The vulnerable code snippet provided in Section 8 (the first example focusing on `cmd.Start()` without `cmd.Wait()`) can be used as a Proof of Concept to demonstrate the creation of zombie processes.

**Steps to Reproduce:**

1. **Save the Code:** Save the first vulnerable Go code snippet from Section 8 into a file named `zombie_poc.go`.
    
    ```Go
    
    package main
    
    import (
    	"log"
    	"os/exec"
    	"time"
    )
    
    func vulnerableStartProcess() {
    	cmd := exec.Command("sleep", "1")
    	err := cmd.Start()
    	if err!= nil {
    		log.Printf("Failed to start process: %v", err)
    		return
    	}
    	log.Printf("Process started with PID: %d", cmd.Process.Pid)
    	// Missing cmd.Wait() here.
    }
    
    func main() {
    	log.Println("Starting to create potential zombies...")
    	for i := 0; i < 5; i++ {
    		vulnerableStartProcess()
    		time.Sleep(1500 * time.Millisecond) // Allow 'sleep 1' to finish
    	}
    	log.Println("Check process list for defunct 'sleep' processes (e.g., 'ps aux | grep defunct').")
    	time.Sleep(10 * time.Second) // Keep main alive to observe zombies
        log.Println("Exiting PoC.")
    }
    ```
    
2. **Compile the Code:** Open a terminal and compile the Go program:
    
    ```Bash
    
    `go build zombie_poc.go`
    ```
    
3. **Run the PoC:** Execute the compiled binary. It's helpful to run it in the background to easily check the process list from the same terminal, or simply open a second terminal.

./zombie_poc

1. **Observe Zombie Processes:** While the `zombie_poc` program is running (specifically during its final 10-second `time.Sleep`), or immediately after the loop finishes if it were to exit quickly, open another terminal window (if not already open) and execute one of the following commands:
    
    ```Bash
    
    `ps aux | grep defunct`
    ```
    
    or
    
    ```Bash
    
    `ps aux | grep 'Z'`
    ```
    
    or, to specifically look for the `sleep` commands:
    
    ```Bash
    
    `ps aux | grep sleep`
    ```
    
    **Expected Outcome:** You should see output indicating one or more `sleep` processes with a status flag of `Z` (for zombie) or listed as `<defunct>`. The log output from `zombie_poc` will show the PIDs of the processes it started, which can be correlated with the `ps` output. Each `sleep 1` command will have terminated after approximately 1 second, but because `cmd.Wait()` was not called by `vulnerableStartProcess`, their process table entries will persist as zombies. The main `zombie_poc` process acts as their parent. Once `zombie_poc` exits after its final sleep, these zombies will be re-parented to PID 1 and typically reaped shortly thereafter by the system's init process (if `zombie_poc` itself is not PID 1).
    

This PoC demonstrates the core mechanism of the vulnerability: starting a child process and failing to reap it with `cmd.Wait()`, leading to the creation of zombie processes.

## **Risk Classification**

The "Zombie Processes from Bad Signal Handling" vulnerability in Golang can be classified using standard vulnerability taxonomies:

- **CWE-404: Improper Resource Shutdown or Release:** This is the most direct Common Weakness Enumeration (CWE) classification. The parent Go process fails to properly "release" the child process resource—specifically, its process table entry and associated kernel data structures—by not calling `wait()` or an equivalent function. This leaves the child process in a zombie state, where it has executed but its termination has not been acknowledged and finalized by the parent.
    
- **CWE-400: Uncontrolled Resource Consumption:** This CWE describes the consequence of repeated instances of CWE-404. The accumulation of zombie processes (which are unreleased resources) leads to the consumption of a finite system resource: Process IDs (PIDs). As PIDs are exhausted, the system can no longer create new processes, resulting in a denial of service.
    

OWASP Risk Rating Context:

Following the OWASP Risk Rating Methodology, the overall risk is assessed as Medium to High.

- **Likelihood:** This can range from Low to Medium. The likelihood depends on factors such as the prevalence of the faulty `os/exec` usage pattern within the codebase, the frequency with which these vulnerable code paths are exercised during application operation, and the attacker's ability to trigger such paths.
- **Impact:** The impact is primarily on **Availability**, which can range from Medium (application-specific Denial of Service) to High (system-wide or container-wide Denial of Service). This is especially true if the Go application is running as PID 1 in a container, where its failure to reap processes can affect the entire container's operation. Confidentiality and Integrity are generally not directly impacted.

The interplay between CWE-404 and CWE-400 is crucial: CWE-404 (Improper Resource Shutdown or Release) is the *cause*—the failure of the parent process to call `wait()` on its terminated child. CWE-400 (Uncontrolled Resource Consumption) is the *effect*—the depletion of available PIDs as zombie processes accumulate due to repeated instances of CWE-404.

Implicitly, running a Go application as PID 1 in a container without a dedicated init system or without the application itself being designed with robust init capabilities can be viewed as a form of **Security Misconfiguration** (related to OWASP A05:2021). This configuration places the application in the role of an init process, a role it is typically not equipped to handle securely by default regarding comprehensive zombie reaping.**1** This misconfiguration significantly elevates the potential impact of any zombie process creation bugs within the application.

## **Fix & Patch Guidance**

Addressing the zombie process vulnerability in Go applications requires careful management of child processes spawned via `os/exec` and appropriate configuration in containerized environments.

- Always Call cmd.Wait():
    
    The fundamental fix is to ensure that for every exec.Cmd object on which cmd.Start() is invoked, the cmd.Wait() method is subsequently called. This call should occur after the child process has finished its execution or has been signaled to terminate. cmd.Wait() reaps the child process, allowing the operating system to remove its entry from the process table and free associated resources.4
    
    ```Go
    
    package main
    
    import (
    	"log"
    	"os/exec"
    )
    
    func correctProcessHandling() {
    	cmd := exec.Command("sleep", "1")
    	err := cmd.Start()
    	if err!= nil {
    		log.Printf("Failed to start process: %v", err)
    		return
    	}
    	log.Printf("Process %d started, waiting for it to finish...", cmd.Process.Pid)
    
    	// Crucially, call cmd.Wait() to reap the process
    	err = cmd.Wait()
    	if err!= nil {
    		// Handle potential errors from Wait, e.g., non-zero exit status
    		log.Printf("Process %d finished with error: %v", cmd.Process.Pid, err)
    	} else {
    		log.Printf("Process %d finished successfully and was reaped.", cmd.Process.Pid)
    	}
    }
    
    func main() {
    	correctProcessHandling()
    }
    ```
    
- Proper Goroutine Management for cmd.Wait():
    
    If cmd.Wait() is called within a separate goroutine to allow asynchronous execution, this goroutine must be managed correctly. Ensure it runs to completion and handles errors. If the main program might exit before these "waiter" goroutines complete, use synchronization primitives like sync.WaitGroup.4
    
- Killing Process Groups for Entire Trees:
    
    If a child process spawned by Go might create its own children (forming a process tree), simply killing and waiting for the direct child is insufficient to terminate the entire tree. To manage this, the direct child should be started in a new process group. Signals can then be sent to the entire process group to terminate all its members. cmd.Wait() is still required for the direct child.1
    
    ```Go
    
    package main
    
    import (
    	"log"
    	"os"
    	"os/exec"
    	"syscall"
    	"time"
    )
    
    func manageProcessGroup() {
    	// Example: a script that starts its own background children
    	// Create a dummy script for demonstration
    	scriptContent := "#!/bin/bash\n" +
    		"echo \"Parent script PID: $$\"\n" +
    		"sleep 5 &\n" + // grandchild 1
    		"sleep 5 &\n" + // grandchild 2
    		"wait\n" +      // wait for its own children (good practice for the script)
    		"echo \"Parent script exiting\"\n"
    	scriptPath := "./test_script.sh"
    	_ = os.WriteFile(scriptPath,byte(scriptContent), 0755)
    	defer os.Remove(scriptPath)
    
    	cmd := exec.Command(scriptPath)
    	// Set Setpgid to true to create a new process group for the child.
    	// The child's PGID will be the same as its PID.
    	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
    
    	err := cmd.Start()
    	if err!= nil {
    		log.Fatalf("Failed to start process: %v", err)
    	}
    	log.Printf("Process group leader %d started.", cmd.Process.Pid)
    
    	// Let it run for a little
    	time.Sleep(1 * time.Second)
    
    	// To kill the entire process group:
    	if cmd.Process!= nil {
    		// Get the PGID (which is same as PID for the group leader started this way)
    		pgid := cmd.Process.Pid
    		log.Printf("Attempting to kill process group %d", pgid)
    		// Send SIGKILL to the entire process group (note the negative pgid)
    		err = syscall.Kill(-pgid, syscall.SIGKILL)
    		if err!= nil {
    			log.Printf("Failed to kill process group %d: %v", pgid, err)
    		} else {
    			log.Printf("Successfully sent SIGKILL to process group %d", pgid)
    		}
    	}
    
    	// Still need to wait for the direct child process
    	err = cmd.Wait()
    	if err!= nil {
    		log.Printf("Process group leader %d finished with error: %v", cmd.Process.Pid, err)
    	} else {
    		log.Printf("Process group leader %d finished successfully.", cmd.Process.Pid)
    	}
    }
    
    func main() {
    	manageProcessGroup()
    }
    ```
    
- Using context.Context for Cancellation:
    
    The exec.CommandContext function allows associating a command with a context.Context. Canceling the context will typically send SIGKILL to the process. However, cmd.Wait() must still be called to reap the process and handle its exit status.13
    
- **Running as PID 1 in Containers (Docker):**
    - **Use an Init System (Recommended):** The most robust solution is to use a minimal init system like Tini. This can be done by adding Tini to the Docker image and setting it as the `ENTRYPOINT`, or by using Docker's `-init` flag (e.g., `docker run --init myimage`), which transparently uses Tini. Kubernetes often handles this through the container runtime or allows specifying an init process.

        
        - Example Dockerfile with Tini: `ENTRYPOINT ["/usr/bin/tini", "--"] CMD ["/app/mygoapp"]`
    - **Implement Custom `SIGCHLD` Handling (Advanced, Not Recommended for Most Cases):** If an init system cannot be used and the Go application *must* run as PID 1, it needs to implement comprehensive `SIGCHLD` signal handling. This involves using `os/signal.Notify` to listen for `syscall.SIGCHLD`. The signal handler must then loop, calling `syscall.Wait4(-1, &status, syscall.WNOHANG, nil)` (or similar `waitpid` variants with appropriate flags like `WNOHANG` in a loop, or blocking `waitpid` in a dedicated reaping goroutine) to reap *any* child process that has terminated, including adopted orphans. This is significantly more complex than just calling `cmd.Wait()` for direct children and is prone to errors.  notes a SIGCHLD handler "ought to be relatively trivial," but a subsequent comment by Historical-Subject11 in  correctly points out the added complexity for adopted orphans, making a generic init system preferable.
    
        

**Comparison of Fix/Remediation Techniques**

| **Technique** | **Description** | **How it Prevents Zombies** | **Pros** | **Cons** | **Typical Use Case** |
| --- | --- | --- | --- | --- | --- |
| `cmd.Wait()` after `cmd.Start()` | Explicitly wait for a specific child process to exit and reap its resources. **4** | Parent collects exit status, OS removes process table entry. | Direct control, standard Go practice. | Blocking call; requires careful management in async scenarios (goroutines). | Asynchronous execution of a single child process. |
| `cmd.Run()` | Combines `Start()` and `Wait()` for synchronous execution. **4** | `Wait()` is called internally. | Simple for synchronous tasks, less error-prone for basic cases. | Blocks until command completion; not suitable for concurrent child processes without goroutines. | Simple, synchronous execution of a command. |
| Process Groups + `syscall.Kill(-pgid)` | Start child in a new process group, signal entire group for termination. `Wait()` still needed. **1** | Allows terminating an entire process tree. Parent reaps direct child via `Wait()`. | Effective for managing complex child process hierarchies. | Unix-specific (`syscall.Setpgid`, `syscall.Kill` with negative PGID); more complex to implement correctly. | Go app spawning children that themselves spawn more processes. |
| `exec.CommandContext` + `cmd.Wait()` | Use context for cancellation; `Wait()` still mandatory. **13** | Context cancellation signals process; `Wait()` reaps it. | Integrates with Go's context pattern for cancellation and timeouts. | `Wait()` is still required and often forgotten; cancellation signal is `SIGKILL` by default. | Long-running child processes that need to be cancellable. |
| Tini / `docker --init` | Use a minimal init system as PID 1 in containers. **1** | Init system handles `SIGCHLD` and reaps all orphaned/zombie processes in the container. | Robust, simple to configure for containers, handles adopted orphans. | Adds a small dependency (Tini); specific to containerized environments. | Any Go application running as PID 1 in a Docker/OCI container. |
| Custom `SIGCHLD` Handler (as PID 1) | Go app as PID 1 listens for `SIGCHLD` and calls `syscall.Wait4` to reap any child. **1** | Go app acts as init, reaping its own children and adopted orphans. | Full control within the Go application, no external init dependency (if implemented correctly). | Complex, error-prone, easy to miss edge cases (especially with adopted orphans), generally not recommended. | Highly specialized scenarios where an external init system is absolutely not an option. |

One important consideration is **defense in depth**. For critical applications, especially those running in containers, relying on a single fix might not be sufficient. Combining techniques, such as ensuring correct `cmd.Wait()` usage within the Go application logic *and* employing an init system like Tini when the application is PID 1 in a container, provides more robust protection. The Go application handles its direct children correctly, and Tini acts as a safety net for any adopted orphans or if a bug in the Go app leads to a direct child being orphaned upon the Go app's unexpected exit.

Another point is **portability concerns with signal handling**. While `os/exec` and `cmd.Wait()` are designed to be cross-platform, deeper Unix-specific mechanisms like process groups (`syscall.Setpgid`) and signaling specific PIDs/PGIDs (`syscall.Kill`) are not portable to non-Unix environments such as Windows, which has a fundamentally different process model. Zombie processes and `SIGCHLD` are Unix-specific concepts. Developers must be mindful of these constraints if their Go application needs to run on multiple operating systems. Container-level solutions like Tini abstract some of these OS differences but the underlying problem they solve is rooted in Unix process management.

## **Scope and Impact**

Scope:

The vulnerability's scope can range from the Go application itself to the entire container or even the host system, depending on the deployment scenario.

- **Application Level:** If the Go application is not PID 1, mismanaged child processes primarily affect the resources available to that specific Go application.
- **Container Level:** If the Go application runs as PID 1 in a container without a proper init system, its failure to reap zombies impacts the entire container. All processes within that container share the same PID namespace, and exhaustion can prevent any new process from starting within the container.
    
    
- **Host Level (Less Common but Possible):** If the Go application is running directly on a host (not containerized) and creates a very large number of zombies, it could theoretically consume PIDs from the host's global pool, impacting other applications on the same host. This is more likely in resource-constrained environments or with extremely high rates of zombie creation.

**Impact:**

- **Denial of Service (DoS):** The most direct impact is the inability to create new processes once PIDs are exhausted. This can render the application, the container, or even the system unresponsive as essential tasks requiring new processes fail.

    
- **Resource Exhaustion:**
    - **PID Depletion:** The primary resource consumed is PIDs from the finite pool available to the OS or container namespace.

    - **Memory Consumption (Secondary):** While individual zombies are small, their entries in the process table and associated kernel structures consume some memory. A massive number of zombies could contribute to memory pressure or, in some cases, trigger kernel-level memory leaks related to unreaped processes.
        
- **Cascading Failures:** The inability to create new processes can cause other services or components (both within the Go application and other applications on the system/container) to fail if they rely on spawning helper processes or threads. This leads to a ripple effect where the initial zombie problem triggers failures in seemingly unrelated areas.
- **Increased Debugging Complexity:** Symptoms of PID exhaustion (e.g., "resource temporarily unavailable," failures in unrelated services) can be misleading and may not immediately point to zombie processes as the root cause. This can significantly prolong investigation and resolution times, as seen with the Redis errors example in  which turned out to be a red herring.

## **Remediation Recommendation**

A prioritized approach is recommended to remediate and prevent zombie process vulnerabilities in Golang applications:

1. **Priority 1 (Code-Level Best Practices - Universal):**
    - **Rigorous `cmd.Wait()` Usage:** Conduct a thorough review of all code sections utilizing `os/exec`. For every instance of `cmd.Start()`, ensure that `cmd.Wait()` is called and that its execution is guaranteed (e.g., within a `defer` statement if the child process's lifecycle is tied to the function scope, or as the final step in a goroutine dedicated to managing that child process, with robust error handling).
        
    - **Prefer `cmd.Run()` for Synchronous Tasks:** For simple cases where the Go program needs to execute an external command and wait for its completion before proceeding, prefer `cmd.Run()`. This method internally handles calling `cmd.Start()` followed by `cmd.Wait()`, reducing the chance of error.
        
2. **Priority 2 (Containerized Environments - Essential for PID 1):**
    - **Employ an Init System:** If the Go application is deployed in a Docker (or other OCI) container and might run as PID 1, **always** use a minimal init system. The simplest ways are:
        - Modify the Dockerfile to include Tini and use it as the `ENTRYPOINT`: `ENTRYPOINT ["/usr/bin/tini", "--"] CMD ["/app/your-go-app"]`.
        - Use the `-init` flag when running the Docker container: `docker run --init your-image`. Kubernetes and other orchestrators often provide similar mechanisms or handle this via the container runtime.
        This is the most robust way to ensure all orphaned processes (including any zombies inadvertently created by the Go app itself if it's not PID 1 but its parent dies) are correctly reaped.
            
3. **Priority 3 (Complex Process Tree Management):**
    - **Implement Process Group Signaling:** If the Go application spawns child processes that are known to spawn their own children (grandchildren), and the entire tree needs to be managed (e.g., terminated together), implement process group management. This involves setting `cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}` when starting the direct child, and then using `syscall.Kill(-pgid, signal)` to signal the entire process group. `cmd.Wait()` must still be called for the direct child.
        
4. **Priority 4 (Monitoring and Alerting):**
    - **Implement System Monitoring:** Set up monitoring for system-level metrics such as total PID usage (and percentage of `pid_max`), and specifically for the count of zombie (`Z` or `defunct`) processes.
    - **Configure Alerts:** Create alerts that trigger when these metrics exceed predefined thresholds. This allows for early detection of potential zombie process leaks before they lead to a full denial of service.
5. **Priority 5 (Custom PID 1 Implementation - Advanced & Discouraged):**
    - **Robust `SIGCHLD` Handling:** In the rare and generally discouraged scenario where a Go application *must* run as PID 1 without an external init system, it must implement a comprehensive and flawless `SIGCHLD` signal handler. This handler needs to listen for `syscall.SIGCHLD` (via `os/signal.Notify`) and then enter a loop calling `syscall.Wait4(-1, &status, syscall.WNOHANG, nil)` (or equivalent `waitpid` calls) to reap *all* terminated children (both its own direct offspring and any adopted orphans) until no more reapable children exist. This is a complex task, prone to subtle errors, and should be avoided if an init system can be used.

By following these prioritized recommendations, developers can significantly reduce the risk of zombie process accumulation and the associated denial-of-service vulnerabilities in their Go applications.

## **Summary**

The "Zombie Processes from Bad Signal Handling" vulnerability in Golang applications (identified as `zombie-processes-signal-misuse`) occurs when parent processes, typically using the `os/exec` package, fail to properly wait for their child processes to terminate. This oversight prevents the operating system from removing the child's entry from the process table, leading to the child becoming a "zombie" or "defunct" process. Key causes include omitting `cmd.Wait()` after `cmd.Start()`, or misusing `cmd.Process.Kill()` without a subsequent `cmd.Wait()`.

While individual zombies consume minimal resources, their accumulation can exhaust the system's finite pool of Process IDs (PIDs) and potentially contribute to memory pressure, resulting in a Denial of Service (DoS). This is classified under CWE-404 (Improper Resource Shutdown or Release) as the cause, and CWE-400 (Uncontrolled Resource Consumption) as the consequence. The severity is Medium to High, escalating significantly if the Go application runs as PID 1 in a container without a proper init system, as it then fails to reap adopted orphans in addition to its own mismanaged children.

Effective remediation strategies are crucial. Developers must ensure `cmd.Wait()` is always called for processes started with `cmd.Start()`. For applications running as PID 1 in containers, employing an init system like Tini (e.g., via Docker's `--init` flag) is the most reliable solution. For complex scenarios involving process trees, managing them via process groups and appropriate signaling is necessary. Proactive monitoring for zombie processes and PID consumption aids in early detection.

## **References**

- `https://www.reddit.com/r/golang/comments/1k0knpu/slaying_zombie_processes_in_a_go_docker_setup_a/`
- `https://github.com/advisories/GHSA-3c94-ghvc-4j26`
- `https://www.cvedetails.com/cwe-details/400/Uncontrolled-Resource-Consumption.html`
- `https://www.cvedetails.com/cwe-details/404/Improper-Resource-Shutdown-or-Release.html`
- `https://feedly.com/cve/cwe/404`
- `https://en.wikipedia.org/wiki/Fork%E2%80%93exec`
- `https://www.scribd.com/document/618544730/PROCESS-CONTROL`
- `https://mezhenskyi.dev/posts/go-linux-processes/`
- `https://stackoverflow.com/questions/46293435/golang-exec-command-cause-a-lot-of-defunct-processes`
- `https://pkg.go.dev/os/signal`
- `https://pkg.go.dev/github.com/moby/sys/signal`
- Referenced implicitly via  (Docker's `-init` flag discussion).
    
- `https://pkg.go.dev/os/signal`
    
    
- `https://github.com/golang/go/issues/9896`
- `https://labex.io/tutorials/go-how-to-securely-execute-external-commands-in-go-431338`
- `https://mezhenskyi.dev/posts/go-linux-processes/`
    
    
- `https://owasp.org/www-community/OWASP_Risk_Rating_Methodology`
- `https://secumantra.com/owasp-top-ten-risk-rating/`
- `https://owasp.org/www-community/OWASP_Risk_Rating_Methodology`
