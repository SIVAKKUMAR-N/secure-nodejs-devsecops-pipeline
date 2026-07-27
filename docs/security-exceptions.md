# Security Exception Register

## Exception ID

SE-001

## Title

Vulnerabilities in Node.js Base Image (npm Runtime)

## Scanner

Trivy

## Affected Components

- tar
- brace-expansion
- sigstore

## Root Cause

These vulnerabilities originate from the npm installation bundled with the official `node:22-alpine` Docker base image (`npm@10.9.8`).

The application's production dependencies do not directly include these vulnerable package versions. Verification using `npm ls` confirmed that the vulnerable versions are part of the runtime tooling provided by the base image.

## Impact Assessment

- The vulnerabilities are inherited from the official upstream Docker image.
- No application code depends directly on the affected packages.
- The project uses the latest available official Node.js Alpine image at the time of assessment.
- No patched upstream image containing the required package versions was available during testing.

## Mitigation

- Rebuild images regularly using the latest official Node.js Docker image.
- Continuously scan container images with Trivy in CI/CD.
- Monitor Node.js Docker image releases for patched npm versions.
- Upgrade the base image when fixes become available.

## Risk Decision

Risk Accepted (Temporary)

This exception will be reviewed whenever a newer Node.js base image is released or when Trivy reports fixed package versions.

## Evidence

- Trivy Scan Report
- Security Gate Result
- Docker Image Scan Logs

## Review Status

Open