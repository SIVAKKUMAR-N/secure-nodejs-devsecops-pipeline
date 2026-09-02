# Security Policy

## Overview

The Security Policy defines the security requirements enforced by the Security Gate.

The policy is stored externally in:

```text
policy/security-policy.json
```

The Security Gate loads this configuration during execution and evaluates security findings against the configured thresholds.

This separation allows security requirements to be changed without modifying the Security Gate implementation.

## Policy Architecture

```text
Security Scanners
      │
      ▼
Security Findings
      │
      ▼
Security Gate
      │
      ├── Load Security Policy
      │
      ├── Validate Policy
      │
      ├── Evaluate Findings
      │
      └── Generate PASS / FAIL Decision
      │
      ▼
Security Decision
```

The policy defines acceptable security limits.

The scanners identify security findings.

The Security Gate compares the scanner findings against the policy.

## Policy File

The security policy is stored in:

```text
policy/security-policy.json
```

The exact policy format used by the project must remain compatible with the Security Gate implementation.

A typical policy contains configuration for:

- NoVuln
- npm Audit
- Trivy
- SBOM requirements
- Security score weights

### Example Policy Structure

The following example illustrates the policy structure used by the Security Gate:

```json
{
  "version": "1.0.0",

  "novuln": {
    "critical": 0,
    "high": 0,
    "medium": 3,
    "low": 10,
    "unknown": 9999
  },

  "audit": {
    "critical": 0,
    "high": 0,
    "medium": 5,
    "low": 20,
    "unknown": 9999
  },

  "trivy": {
    "critical": 0,
    "high": 0,
    "medium": 5,
    "low": 25,
    "unknown": 9999
  },

  "sbom": {
    "required": true
  },

  "scoreWeights": {
    "critical": 25,
    "high": 15,
    "medium": 7,
    "low": 2,
    "unknown": 0,
    "accepted": 1
  }
}
```

The actual values should be chosen according to the project's risk tolerance.

## Policy Version

Example:

```json
{
  "version": "1.0.0"
}
```

The version identifies the security policy configuration.

Policy versioning helps track changes to security requirements over time.

For example:

```text
1.0.0
  │
  ├── Initial Policy
  │
  ▼
1.1.0
  │
  ├── Updated Medium Threshold
  │
  ▼
2.0.0
  │
  └── Major Policy Changes
```

The policy version should be updated when meaningful policy changes are made.

## Severity Levels

The Security Gate evaluates findings using severity levels.

Supported severity categories include:

- Critical
- High
- Medium
- Low
- Unknown

Conceptually:

```text
Critical
   │
   ▼
High
   │
   ▼
Medium
   │
   ▼
Low
   │
   ▼
Unknown
```

The policy defines the maximum allowed number of findings for each severity.

## Threshold Evaluation

A threshold represents the maximum allowed number of findings.

Example:

```json
{
  "high": 5
}
```

This means:

```text
Maximum Allowed HIGH Findings = 5
```

If the scanner reports:

```text
HIGH Findings = 3
```

The threshold is satisfied.

```text
3 <= 5

PASS
```

If the scanner reports:

```text
HIGH Findings = 7
```

The threshold is exceeded.

```text
7 > 5

FAIL
```

### Accurate Threshold Reporting

The Security Gate evaluates the total number of findings against the allowed threshold.

Example:

**Policy:**

```text
HIGH threshold = 5
```

**Scanner result:**

```text
HIGH findings = 7
```

The Security Gate reports:

```text
Total Findings:      7
Allowed Threshold:   5
Threshold Exceeded:  Yes
```

The gate does not attempt to identify specific findings as the individual findings that caused the threshold violation.

The policy violation is based on the aggregate count.

## NoVuln Policy

The NoVuln policy defines acceptable findings produced by Static Application Security Testing.

Example:

```json
{
  "novuln": {
    "critical": 0,
    "high": 0,
    "medium": 3,
    "low": 10,
    "unknown": 9999
  }
}
```

Example interpretation:

```text
Critical Findings Allowed: 0
High Findings Allowed:     0
Medium Findings Allowed:   3
Low Findings Allowed:      10
Unknown Findings Allowed:  9999
```

If a configured threshold is exceeded, the Security Gate records a policy violation.

## npm Audit Policy

The npm Audit policy controls acceptable dependency vulnerabilities.

Example:

```json
{
  "audit": {
    "critical": 0,
    "high": 0,
    "medium": 5,
    "low": 20,
    "unknown": 9999
  }
}
```

Example interpretation:

```text
Critical Dependency Vulnerabilities Allowed: 0
High Dependency Vulnerabilities Allowed:     0
Medium Dependency Vulnerabilities Allowed:   5
Low Dependency Vulnerabilities Allowed:      20
```

The Security Gate compares the vulnerability counts in `audit.json` against these thresholds.

## Trivy Policy

The Trivy policy controls acceptable vulnerabilities detected in the container image.

Example:

```json
{
  "trivy": {
    "critical": 0,
    "high": 0,
    "medium": 5,
    "low": 25,
    "unknown": 9999
  }
}
```

The Security Gate evaluates the vulnerability counts reported by Trivy.

Example:

```text
Trivy HIGH Findings: 2
Policy HIGH Threshold: 0
```

Result:

```text
Threshold Exceeded
Policy Violation
```

## SBOM Policy

The policy can define whether an SBOM is required.

Example:

```json
{
  "sbom": {
    "required": true
  }
}
```

When enabled:

```text
SBOM Required
      │
      ▼
Does sbom.json exist?
      │
 ┌────┴────┐
 │         │
 ▼         ▼
Yes        No
 │         │
 ▼         ▼
Continue   FAIL
```

If the SBOM is required but missing, the Security Gate fails the build.

## Security Score Weights

The policy defines severity weights used to calculate the security score.

Example:

```json
{
  "scoreWeights": {
    "critical": 25,
    "high": 15,
    "medium": 7,
    "low": 2,
    "unknown": 0,
    "accepted": 1
  }
}
```

Each severity contributes a configured penalty to the security score.

Example:

```text
Critical Finding
      │
      ▼
Critical Weight × Finding Count
      │
      ▼
Security Score Penalty
```

### scoreWeights Validation

The Security Gate validates `scoreWeights` before calculating the security score.

Requirements:

```text
scoreWeights
    │
    ├── Must exist
    │
    ├── Must be an object
    │
    ├── Every configured weight must be numeric
    │
    └── Every configured weight must be >= 0
```

Example of an invalid configuration:

```json
{
  "scoreWeights": {
    "critical": "high"
  }
}
```

This must be rejected because the value is not numeric.

Another invalid example:

```json
{
  "scoreWeights": {
    "critical": -10
  }
}
```

This must be rejected because score weights cannot be negative.

## Security Score Concept

The Security Score provides a summary of the security findings.

Example:

```text
Initial Score: 100
```

Given:

```text
Critical Findings: 1
High Findings:     2
Medium Findings:   3
Low Findings:      4
```

And weights:

```text
Critical: 25
High:     15
Medium:   7
Low:      2
```

The penalties are calculated according to the Security Gate implementation.

The score is included as additional security information.

The final gate decision is based on policy enforcement rather than using the score alone.

## Policy Validation

The policy must be valid before security findings are evaluated.

The Security Gate validates:

- Required policy configuration
- Scanner threshold configuration
- Threshold values
- SBOM configuration
- Score weight configuration

Invalid policy configurations are rejected.

This prevents accidental weakening of security controls through malformed configuration.

## Fail-Closed Policy Behavior

The Security Gate follows a fail-closed model.

```text
Can the policy be safely validated?
              │
       ┌──────┴──────┐
       │             │
       ▼             ▼
      Yes            No
       │             │
       ▼             ▼
Evaluate Policy     FAIL
```

The gate does not assume that an invalid policy means security checks should be ignored.

Instead, invalid policy configuration prevents reliable security enforcement and should result in failure.

## Policy Integrity

The Security Gate generates a SHA-256 hash of the loaded security policy.

```text
security-policy.json
        │
        ▼
     SHA-256
        │
        ▼
    policyHash
        │
        ▼
Security Gate Report
```

Example:

```json
{
  "policyHash": "8ab472d0..."
}
```

The hash helps identify exactly which policy content was used during a pipeline execution.

This improves:

- Traceability
- Auditing
- Build reproducibility
- Security investigation

## Updating the Security Policy

Security policy changes should be treated as security-relevant changes.

Recommended workflow:

```text
Update security-policy.json
          │
          ▼
Create Feature Branch
          │
          ▼
Commit Policy Change
          │
          ▼
Open Pull Request
          │
          ▼
Security Pipeline
          │
          ▼
Review Policy Change
          │
          ▼
Merge
```

Policy changes should not be made casually because changing thresholds can directly change what the Security Gate allows.

### Recommended Policy Change Practices

When modifying the security policy:

- Document why the policy is changing
- Review changes through Pull Requests
- Avoid increasing thresholds without justification
- Use temporary exceptions instead of permanently weakening policy
- Track policy versions
- Review exception expiry dates
- Test policy changes in CI

## Policy vs Exceptions

The security policy defines the general security requirements.

Exceptions define approved deviations from those requirements.

```text
Security Policy
      │
      ▼
Default Security Requirements
      │
      ▼
Security Finding
      │
      ▼
Valid Exception?
      │
 ┌────┴────┐
 │         │
 ▼         ▼
No        Yes
 │         │
 ▼         ▼
Apply      Apply
Policy     Exception
```

The policy should remain strict where possible.

Exceptions should be used for controlled and documented risk acceptance.

## Example Evaluation

Consider the following policy:

```json
{
  "audit": {
    "critical": 0,
    "high": 0,
    "medium": 5,
    "low": 20,
    "unknown": 9999
  }
}
```

Scanner results:

```text
Critical: 0
High:     1
Medium:   4
Low:      10
```

Evaluation:

```text
Critical: 0 <= 0  → PASS
High:     1 >  0  → FAIL
Medium:   4 <= 5  → PASS
Low:      10 <= 20 → PASS
```

Final result:

```text
Policy Violation Detected

Security Gate: FAIL
```

Even though most thresholds are satisfied, a single configured policy violation can cause the Security Gate to fail.

## Current Policy Components

The current security policy supports:

- ✓ Policy Version
- ✓ NoVuln Thresholds
- ✓ npm Audit Thresholds
- ✓ Trivy Thresholds
- ✓ Optional SBOM Requirement
- ✓ Security Score Weights
- ✓ Policy Validation
- ✓ SHA-256 Policy Integrity Hash

## Design Principle

The policy follows the principle:

```text
Security Findings
       +
Security Requirements
       =
Security Decision
```

Security scanners provide evidence.

The Security Policy defines acceptable risk.

The Security Gate evaluates the evidence against the policy and produces the final decision.

## Documentation Structure

For your documentation structure, you will now have:

```text
README.md
│
├── docs/
│   ├── architecture.md
│   ├── security-gate.md
│   └── security-policy.md
│
├── policy/
│   ├── security-policy.json
│   └── security-exceptions.json
```
