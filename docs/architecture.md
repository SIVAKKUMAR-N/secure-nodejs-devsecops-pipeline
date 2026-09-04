# Architecture

## Overview

This project demonstrates a security-focused DevSecOps pipeline built around a Node.js CRUD application.

The architecture separates the application, security scanning, policy configuration, security enforcement, CI automation, and reporting responsibilities.

Security controls are executed automatically during the CI process, and the final decision is made by a centralized Security Gate.

---

## High-Level Architecture

```text
                         ┌──────────────────────┐
                         │      Developer       │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Feature Branch     │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │    Pull Request      │
                         │    Target: main      │
                         └──────────┬───────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │       GitHub Actions CI       │
                    └───────────────┬───────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         │                          │                          │
         ▼                          ▼                          ▼
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│    Gitleaks     │       │    npm Tests    │       │     NoVuln      │
│ Secret Scanning │       │ Application Test│       │      SAST       │
└────────┬────────┘       └────────┬────────┘       └────────┬────────┘
         │                         │                          │
         └─────────────────────────┼──────────────────────────┘
                                   │
                                   ▼
                       ┌────────────────────────┐
                       │       npm Audit        │
                       │ Dependency Scanning    │
                       └────────────┬───────────┘
                                    │
                                    ▼
                       ┌────────────────────────┐
                       │      Docker Build      │
                       │   Container Image      │
                       └────────────┬───────────┘
                                    │
                                    ▼
              ┌────────────────────────────────────────┐
              │        CycloneDX SBOM Generation       │
              │           Software Inventory           │
              └───────────────────┬────────────────────┘
                                  │
                                  ▼
                       ┌────────────────────────┐
                       │         Trivy          │
                       │ Container Vulnerability│
                       │        Scanning        │
                       └────────────┬───────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │       SECURITY GATE v3        │
                    │                               │
                    │  Policy Evaluation            │
                    │  Exception Processing         │
                    │  Expiry Validation            │
                    │  Security Score               │
                    │  Policy Integrity Hash        │
                    │  Scanner Version Tracking     │
                    │  Final PASS / FAIL Decision   │
                    └───────────────┬───────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
                    ▼                               ▼
          ┌──────────────────┐            ┌──────────────────┐
          │      FAIL ❌      │            │      PASS ✅      │
          │ Merge Blocked    │            │ Merge Allowed    │
          └──────────────────┘            └────────┬─────────┘
                                                   │
                                                   ▼
                                           ┌───────────────┐
                                           │     main      │
                                           └───────────────┘
```

---

## Application Architecture

The application is a Node.js CRUD application using Express.js and MongoDB.

```text
                    Client
                       │
                       ▼
                ┌──────────────┐
                │   Express.js │
                │   Application│
                └──────┬───────┘
                       │
           ┌───────────┼───────────┐
           │           │           │
           ▼           ▼           ▼
      Controllers     Routes      Models
           │                         │
           └────────────┬────────────┘
                        │
                        ▼
                  ┌──────────┐
                  │ MongoDB  │
                  └──────────┘
```

The application is containerized using Docker and scanned as part of the CI security pipeline.

---

## CI Pipeline Architecture

The CI pipeline is triggered when a Pull Request targets the `main` branch.

```text
Feature Branch
      │
      ▼
Pull Request
      │
      ▼
GitHub Actions Workflow
      │
      ▼
┌─────────────────────────────┐
│ Security Validation Stage   │
├─────────────────────────────┤
│ Gitleaks                    │
│ Tests                       │
│ NoVuln                      │
│ npm Audit                   │
│ Docker Build                │
│ CycloneDX SBOM              │
│ Trivy                       │
└──────────────┬──────────────┘
               │
               ▼
       Security Gate v3
               │
               ▼
        Policy Decision
               │
        ┌──────┴──────┐
        │             │
        ▼             ▼
      FAIL           PASS
        │             │
        ▼             ▼
  Merge Blocked   Merge Allowed
```

The security scanners produce findings independently. The Security Gate centralizes policy evaluation and determines the final result.

---

## Security Gate Architecture

The Security Gate is the policy enforcement component of the architecture.

It receives security reports generated by the pipeline and evaluates them against the configured security policy.

```text
                         Security Reports
                                │
                                ▼
                ┌──────────────────────────────┐
                │       Security Gate v3       │
                └───────────────┬──────────────┘
                                │
                ┌───────────────┴───────────────┐
                │                               │
                ▼                               ▼
      Security Policy                    Exception Policy
                │                               │
                └───────────────┬───────────────┘
                                │
                                ▼
                    Policy Configuration Validation
                                │
                                ▼
                         Parse Reports
                                │
                                ▼
                     Apply Valid Exceptions
                                │
                                ▼
                    Evaluate Policy Thresholds
                                │
                                ▼
                      Calculate Security Score
                                │
                                ▼
                       Generate Policy Hash
                                │
                                ▼
                      Collect Build Metadata
                                │
                                ▼
                     Collect Scanner Versions
                                │
                                ▼
                       Generate Final Reports
                                │
                                ▼
                          PASS / FAIL
```

---

## Policy Architecture

Security rules are stored outside the Security Gate implementation.

```text
┌──────────────────────────────────┐
│    security-policy.json          │
├──────────────────────────────────┤
│ Scanner Thresholds               │
│ Severity Limits                  │
│ SBOM Requirements                │
│ Security Score Weights           │
└───────────────┬──────────────────┘
                │
                ▼
       Security Gate v3
                │
                ▼
       Policy Evaluation
```

This design separates security policy from application logic.

Policy changes can therefore be made without rewriting the Security Gate implementation.

The Security Gate validates the policy before using it.

Invalid policy configurations cause the gate to fail rather than silently continuing with unreliable configuration.

---

## Exception Architecture

Security exceptions are maintained separately from the main security policy.

```text
┌──────────────────────────────────┐
│ security-exceptions.json         │
└───────────────┬──────────────────┘
                │
                ▼
          Load Exceptions
                │
                ▼
       Validate Exception Data
                │
        ┌───────┴────────┐
        │                │
        ▼                ▼
 Invalid Expiry       Valid Expiry
        │                │
        ▼                ▼
 Warning + Ignore   Check Expiration
                         │
                  ┌──────┴──────┐
                  │             │
                  ▼             ▼
               Expired       Active
                  │             │
                  ▼             ▼
              Ignore      Apply Exception
```

Malformed expiry values are not silently accepted.

Invalid exceptions are ignored and warnings are generated.

Expired exceptions are also not applied.

---

## Security Findings Architecture

The pipeline generates multiple security reports.

```text
NoVuln
   │
   ├── Source Code Findings
   │
   ▼
NoVuln Report
                   ┐
npm Audit          │
   │               │
   ├── Dependency  │
   │    Findings   │
   ▼               │
audit.json         │
                   ├──► Security Gate
Trivy              │
   │               │
   ├── Container   │
   │    Findings   │
   ▼               │
trivy-report.json  │
                   │
SBOM               │
   │               │
   ▼               │
sbom.json          ┘
```

The Security Gate keeps scanner findings separate and evaluates them according to their configured policy thresholds.

The gate does not attempt to identify individual findings as the specific findings responsible for exceeding a threshold.

**For example:**

- Policy HIGH Threshold: `5`
- Scanner HIGH Findings: `7`

Result:

```
Total Findings:      7
Allowed Threshold:   5
Threshold Exceeded:  Yes
```

The policy violation determines the gate decision.

---

## Docker Security Architecture

The application uses a multi-stage Docker build.

```text
                    Source Code
                         │
                         ▼
              ┌─────────────────────┐
              │ Dependency Stage    │
              │                     │
              │ npm ci --omit=dev   │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │ Production Stage    │
              │                     │
              │ node_modules        │
              │ Application Code    │
              │ Non-root User       │
              └──────────┬──────────┘
                         │
                         ▼
                   Docker Image
                         │
                         ▼
                     Trivy Scan
```

The runtime container runs the application using a non-root user.

---

## SBOM Architecture

CycloneDX generates a Software Bill of Materials for the application.

```text
package.json
package-lock.json
        │
        ▼
    CycloneDX
        │
        ▼
    sbom.json
        │
        ▼
  Security Gate
```

The SBOM provides a machine-readable inventory of software dependencies.

---

## Build Metadata Architecture

The Security Gate records CI metadata when running inside GitHub Actions.

```text
GitHub Actions Environment
            │
            ▼
    ┌───────────────────────┐
    │ Build Metadata        │
    ├───────────────────────┤
    │ Repository            │
    │ Workflow              │
    │ Job                   │
    │ Runner                │
    │ Run ID                │
    │ Run Number            │
    │ Commit SHA            │
    │ Git Reference         │
    └───────────┬───────────┘
                │
                ▼
       Security Gate Report
```

When metadata is unavailable outside GitHub Actions, unavailable fields are stored as `null`.

---

## Policy Integrity Architecture

The loaded security policy is hashed using SHA-256.

```text
security-policy.json
        │
        ▼
    SHA-256
        │
        ▼
    Policy Hash
        │
        ▼
Security Gate Report
```

The policy hash provides traceability by recording which security policy configuration was used during a pipeline execution.

---

## Scanner Version Architecture

The Security Gate records versions of the security tools and runtime.

```text
NoVuln ─────┐
Trivy ──────┤
npm ────────┼──► Scanner Versions ──► Security Report
Node.js ────┘
```

If a version cannot be determined, the report stores `unknown`.

This improves build traceability.

---

## Reporting Architecture

Security reports generated by the pipeline are preserved as GitHub Actions artifacts.

```text
Security Pipeline
        │
        ▼
┌─────────────────────┐
│ Generated Reports   │
├─────────────────────┤
│ audit.json          │
│ sbom.json           │
│ trivy-report.json   │
│ report.json         │
│ summary.json        │
└──────────┬──────────┘
           │
           ▼
GitHub Actions Artifact
           │
           ▼
 Security Review
```

This allows security results to be reviewed after the pipeline execution.

---

## Branch Protection Architecture

The `main` branch is intended to be protected through GitHub rules.

```text
Developer
    │
    ├── Direct Push to main ─────────────► BLOCKED ❌
    │
    ▼
Feature Branch
    │
    ▼
Pull Request
    │
    ▼
Required Security Checks
    │
    ├── FAIL ────────────────────────────► Merge Blocked ❌
    │
    └── PASS ────────────────────────────► Merge Allowed ✅
                                              │
                                              ▼
                                            main
```

The intended controls include:

- Pull Request requirement
- Required security status checks
- Force push prevention
- Optional branch update requirements

---

## Current Security Architecture Summary

The current project architecture consists of five main layers.

```text
┌──────────────────────────────────────┐
│           APPLICATION LAYER          │
│                                      │
│ Node.js + Express.js + MongoDB       │
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│          CONTAINERIZATION LAYER      │
│                                      │
│ Docker Multi-Stage Build             │
│ Non-Root Runtime                     │
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│          SECURITY SCANNING LAYER     │
│                                      │
│ Gitleaks                            │
│ NoVuln                              │
│ npm Audit                           │
│ CycloneDX                           │
│ Trivy                               │
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│          POLICY ENFORCEMENT LAYER    │
│                                      │
│ Security Gate v3                     │
│ Security Policy                      │
│ Exception Policy                     │
│ Threshold Evaluation                 │
│ Security Score                       │
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│            CI GOVERNANCE LAYER       │
│                                      │
│ GitHub Actions                       │
│ Pull Requests                        │
│ Branch Protection                    │
│ Required Status Checks               │
└──────────────────────────────────────┘
```

---

## Deployment Architecture

Deployment is not yet implemented as part of the current architecture.

The intended future flow is:

```text
Feature Branch
      │
      ▼
Pull Request
      │
      ▼
Security Pipeline
      │
      ▼
Security Gate
      │
      ▼
PASS
      │
      ▼
Merge to main
      │
      ▼
Deployment Pipeline
      │
      ▼
Deployment Environment
```

Deployment should only occur after the security validation and merge process succeeds.

Future deployment controls may include:

- Separate deployment workflow
- Environment protection
- Deployment approval
- Cloud infrastructure
- Container registry
- Post-deployment security validation

---

This `architecture.md` is intentionally detailed, so your main README can stay much shorter and link to it:

```md
For detailed architecture information, see [Architecture Documentation](docs/architecture.md).
```
