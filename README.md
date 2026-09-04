# Secure Node.js DevSecOps Pipeline

A Node.js CRUD application integrated with an automated DevSecOps pipeline that performs security scanning, policy-based enforcement, container security analysis, SBOM generation, and CI governance through GitHub Actions.

The project demonstrates how security controls can be integrated directly into the software delivery lifecycle instead of being performed as a separate manual activity.

---

## Overview

The application is a Node.js CRUD application backed by MongoDB. The project extends the application with a DevSecOps pipeline that automatically performs security validation when a Pull Request targets the `main` branch.

The pipeline includes:

- Secret scanning
- Automated testing
- Static Application Security Testing
- Dependency vulnerability scanning
- Docker image building
- Software Bill of Materials generation
- Container vulnerability scanning
- Policy-based security enforcement
- Security exception handling
- Security scoring
- Build metadata collection
- Security report generation

A custom Security Gate acts as the centralized policy enforcement component and determines whether the build passes or fails.

---

## Architecture

The high-level workflow is:

```text
Developer
    |
    v
Feature Branch
    |
    v
Pull Request
    |
    v
GitHub Actions
    |
    +--> Gitleaks
    |
    +--> Tests
    |
    +--> NoVuln
    |
    +--> npm Audit
    |
    +--> Docker Build
    |
    +--> CycloneDX SBOM
    |
    +--> Trivy
    |
    v
Security Gate
    |
    +--> Security Policy
    |
    +--> Security Exceptions
    |
    +--> Policy Evaluation
    |
    +--> Security Score
    |
    v
PASS / FAIL
    |
    +--> PASS: Merge Allowed
    |
    +--> FAIL: Merge Blocked
```

For detailed architecture documentation, see: [Architecture Documentation](docs/architecture.md)

---

## Security Pipeline

The GitHub Actions workflow runs when a Pull Request targets the `main` branch.

The pipeline performs the following stages:

```text
Checkout Repository
        |
        v
Setup Node.js
        |
        v
Gitleaks Secret Scan
        |
        v
Install Dependencies
        |
        v
Run Tests
        |
        v
NoVuln SAST Scan
        |
        v
npm Audit
        |
        v
Build Docker Image
        |
        v
Generate CycloneDX SBOM
        |
        v
Trivy Container Scan
        |
        v
Security Gate
        |
        v
Upload Security Reports
```

The Security Gate evaluates the generated reports against the configured security policy and produces the final build decision.

---

## Security Controls

| Security Control | Tool | Purpose |
|---|---|---|
| Secret Scanning | Gitleaks | Detect exposed secrets and credentials |
| Application Testing | npm test | Validate application functionality |
| SAST | NoVuln | Identify potential source code security issues |
| Dependency Scanning | npm Audit | Detect known dependency vulnerabilities |
| Container Build | Docker | Build the application container image |
| SBOM Generation | CycloneDX | Generate software dependency inventory |
| Container Scanning | Trivy | Detect vulnerabilities in the Docker image |
| Policy Enforcement | Security Gate v3 | Evaluate findings against security policy |

---

## Security Gate

The custom Security Gate is the central policy enforcement component of the project.

It provides:

- External security policy support
- External security exception support
- Exception expiry validation
- Invalid expiry detection
- NoVuln evaluation
- npm Audit evaluation
- Trivy evaluation
- Optional SBOM validation
- Security score calculation
- Policy validation
- scoreWeights validation
- Fail-closed behavior
- Accurate threshold evaluation
- Scanner execution timing
- Scanner version tracking
- SHA-256 policy integrity hash
- GitHub Actions metadata collection
- GitHub Step Summary support
- Machine-readable JSON reports
- ANSI console output
- Final PASS or FAIL decision

The Security Gate evaluates aggregate findings against policy thresholds.

For example:

```text
Policy HIGH Threshold: 5
Scanner HIGH Findings: 7

Total Findings:      7
Allowed Threshold:   5
Threshold Exceeded:  Yes
```

The gate does not attempt to identify specific individual findings as "blocking" findings. The final decision is based on policy violations.

For detailed documentation, see: [Security Gate Documentation](docs/security-gate.md)

---

## Security Policy

Security thresholds are stored externally from the Security Gate implementation.

This allows security requirements to be modified without rewriting the gate logic.

The policy controls:

- NoVuln thresholds
- npm Audit thresholds
- Trivy thresholds
- SBOM requirements
- Security score weights

The Security Gate validates the policy before using it.

Invalid policy configurations result in failure rather than allowing the pipeline to continue with unreliable security configuration.

The loaded policy is also hashed using SHA-256 and recorded in the security report.

For detailed documentation, see: [Security Policy Documentation](docs/security-policy.md)

---

## Security Exceptions

The project supports external security exceptions.

Exceptions allow approved security risk to be managed separately from the main security policy.

The exception system supports:

- External exception configuration
- Exception validation
- Expiry dates
- Expired exception rejection
- Invalid expiry warnings

Malformed expiry dates are not silently accepted.

If an exception contains an invalid expiry value, the Security Gate ignores the exception, prints a warning, and continues processing.

---

## Docker Security

The application is containerized using Docker.

The Docker configuration includes:

- Multi-stage dependency handling
- Production dependency installation (`npm ci --omit=dev`)
- Non-root application user
- Separation of dependency and runtime stages

The generated Docker image is scanned using Trivy during the CI pipeline.

Build the image locally:

```bash
docker build -t simple-crud-app:latest .
```

Run the container:

```bash
docker run -p 3000:3000 simple-crud-app:latest
```

---

## SBOM

The project generates a Software Bill of Materials using CycloneDX.

The generated SBOM provides a machine-readable inventory of project dependencies.

Generate the SBOM locally:

```bash
npx @cyclonedx/cyclonedx-npm --output-file sbom.json
```

The generated file is:

```text
sbom.json
```

The Security Gate can validate whether the SBOM is required according to the configured security policy.

---

## CI/CD Governance

The project uses GitHub Actions for CI automation.

The intended branch workflow is:

```text
Developer
    |
    v
Feature Branch
    |
    v
Pull Request
    |
    v
Security Pipeline
    |
    +--> FAIL
    |       |
    |       v
    |   Merge Blocked
    |
    +--> PASS
            |
            v
       Merge Allowed
            |
            v
           main
```

The `main` branch is intended to use branch protection with:

- Pull Request requirement
- Required status checks
- Security pipeline validation
- Force push prevention
- Branch deletion protection

This ensures that code is reviewed and validated by the security pipeline before merging.

---

## Security Reports

The pipeline generates security-related reports including:

- `audit.json`
- `sbom.json`
- `trivy-report.json`
- `report.json`
- `summary.json`

The reports are uploaded as GitHub Actions artifacts.

These reports can be used for:

- Security review
- Build investigation
- Policy verification
- Future security dashboards
- Historical analysis

---

## Project Structure

```text
.
├── .github/
│   └── workflows/
│       ├──feature-pipeline.yml
│       └──main.pipeline.yml
│
├── routes/
│   └── product.route.js
│
├── docs/
│   ├── architecture.md
│   ├── security-gate.md
│   └── security-policy.md
│
├── policy/
│   ├── security-policy.json
│   └── security-exceptions.json
│
├── screenshots/
│   ├── pipeline-success.png
│   ├── security-gate-pass.png
│   ├── github-summary.png
│   └── branch-protection.png
│
├── scripts/
│   └── security-gate.js
│
├── tests/
│   ├── app.test.js
│   └── product.controller.test.js
│
├── app.js
├── Dockerfile
├── package.json
├── package-lock.json
├── README.md
└── server.js
```

The exact application file structure may vary depending on the CRUD application implementation.

---

## Running the Project Locally

### Clone the Repository

```bash
git clone https://github.com/SIVAKKUMAR-N/simple-crud-app.git
cd simple-crud-app
```

### Install Dependencies

```bash
npm ci
```

### Configure Environment Variables

Configure the required MongoDB connection environment variable.

Example:

```text
MONGODB_URI=your_mongodb_connection_string
```

Do not commit secrets or environment files containing credentials to the repository.

### Run the Application

```bash
node server.js
```

---

## Running Security Checks Locally

### NoVuln

```bash
npx -p novuln-backend novuln scan . --ci
```

### npm Audit

```bash
npm audit --json > audit.json
```

### Docker Build

```bash
docker build -t simple-crud-app:latest .
```

### Trivy

```bash
trivy image --format json --output trivy-report.json simple-crud-app:latest
```

### Generate SBOM

```bash
npx @cyclonedx/cyclonedx-npm --output-file sbom.json
```

### Security Gate

After generating the required reports:

```bash
node scripts/security-gate.js
```

---

## Pipeline Screenshots

**Successful Pipeline**

**Security Gate Result**

Additional screenshots and technical evidence can be added to the `screenshots/` directory.

---

## Documentation

Detailed technical documentation is available in the `docs` directory:

- [Architecture](docs/architecture.md)
- [Security Gate v3](docs/security-gate.md)
- [Security Policy](docs/security-policy.md)

---

## Current Architecture

The project currently consists of five primary layers:

```text
Application Layer
        |
        v
Containerization Layer
        |
        v
Security Scanning Layer
        |
        v
Policy Enforcement Layer
        |
        v
CI Governance Layer
```

### Application Layer

- Node.js
- Express.js
- MongoDB
- Mongoose

### Containerization Layer

- Docker
- Production dependencies
- Non-root runtime

### Security Scanning Layer

- Gitleaks
- NoVuln
- npm Audit
- CycloneDX
- Trivy

### Policy Enforcement Layer

- Security Gate v3
- External security policy
- Security exceptions
- Threshold evaluation
- Security scoring

### CI Governance Layer

- GitHub Actions
- Pull Requests
- Required status checks
- Branch protection

---

## Future Improvements

The current project focuses on CI security and policy enforcement.

Potential future improvements include:

- Automated deployment after successful security validation
- Separate deployment workflow
- Cloud deployment
- Container registry integration
- Deployment environments
- Environment protection rules
- Deployment approval gates
- Infrastructure as Code scanning
- Dynamic Application Security Testing
- API security testing
- Security dashboards
- Historical security trend analysis
- Security notifications

The intended future workflow is:

```text
Feature Branch
      |
      v
Pull Request
      |
      v
Security Pipeline
      |
      v
Security Gate
      |
      v
PASS
      |
      v
Merge to main
      |
      v
Deployment Pipeline
      |
      v
Deployment Environment
```

Deployment is not currently implemented and is planned as the next major stage of the project.

---

## Key DevSecOps Concepts Demonstrated

This project demonstrates:

- Shift-left security
- CI security automation
- Secret scanning
- Static Application Security Testing
- Dependency vulnerability management
- Container security
- Software supply chain visibility
- SBOM generation
- Policy-as-code concepts
- Security exception management
- Exception expiry
- Risk acceptance tracking
- Fail-closed validation
- Policy-based security gates
- CI artifact reporting
- Branch protection and governance

---

## Author

**Sivakkumar N**

Cybersecurity Student focused on Application Security and DevSecOps.

GitHub: [https://github.com/SIVAKKUMAR-N](https://github.com/SIVAKKUMAR-N)

---

## License

This project is intended for educational and portfolio purposes.

---

## Project Objective

The objective of this project is to demonstrate the integration of security controls directly into the software delivery lifecycle.

The development workflow follows:

```text
Code
  |
  v
Test
  |
  v
Scan
  |
  v
Analyze
  |
  v
Apply Security Policy
  |
  v
Security Gate
  |
  v
PASS / FAIL
```

The project demonstrates that security can be integrated as an automated and enforceable part of software delivery rather than being treated as a final manual activity.
