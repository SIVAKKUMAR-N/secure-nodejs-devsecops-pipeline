const fs = require("fs");

console.log("========================================");
console.log("         SECURITY GATE");
console.log("========================================");

let failed = false;
let reasons = [];

// =====================================
// Load Security Policy
// =====================================

const POLICY = JSON.parse(
  fs.readFileSync("policy/security-policy.json", "utf8")
);

// =====================================
// Check Required Reports
// =====================================

const requiredFiles = [
  "summary.json",
  "audit.json",
  "trivy-report.json"
];

if (POLICY.sbom.required) {
  requiredFiles.push("sbom.json");
}

for (const file of requiredFiles) {
  if (!fs.existsSync(file)) {
    failed = true;
    reasons.push(`Missing required report: ${file}`);
  }
}

if (failed) {
  console.log("\n❌ SECURITY GATE FAILED\n");

  console.log("Reasons:");
  reasons.forEach((reason) => console.log(`- ${reason}`));

  process.exit(1);
}

// =====================================
// Read Reports
// =====================================

const summary = JSON.parse(
  fs.readFileSync("summary.json", "utf8")
);

const audit = JSON.parse(
  fs.readFileSync("audit.json", "utf8")
);

const trivy = JSON.parse(
  fs.readFileSync("trivy-report.json", "utf8")
);

// =====================================
// Parse npm Audit
// =====================================

const auditSummary = audit.metadata.vulnerabilities;

// =====================================
// Parse Trivy
// =====================================

const trivySummary = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0
};

for (const result of trivy.Results || []) {

  for (const vuln of result.Vulnerabilities || []) {

    switch (vuln.Severity) {

      case "CRITICAL":
        trivySummary.critical++;
        break;

      case "HIGH":
        trivySummary.high++;
        break;

      case "MEDIUM":
        trivySummary.medium++;
        break;

      case "LOW":
        trivySummary.low++;
        break;

    }

  }

}

// =====================================
// Print Scan Results
// =====================================

console.log("\n========== NoVuln ==========");
console.log(`Critical : ${summary.critical}`);
console.log(`High     : ${summary.high}`);
console.log(`Medium   : ${summary.medium}`);
console.log(`Low      : ${summary.low}`);

console.log("\n========== npm audit ==========");
console.log(`Critical : ${auditSummary.critical}`);
console.log(`High     : ${auditSummary.high}`);
console.log(`Moderate : ${auditSummary.moderate}`);
console.log(`Low      : ${auditSummary.low}`);

console.log("\n========== Trivy ==========");
console.log(`Critical : ${trivySummary.critical}`);
console.log(`High     : ${trivySummary.high}`);
console.log(`Medium   : ${trivySummary.medium}`);
console.log(`Low      : ${trivySummary.low}`);

console.log("\n========== CycloneDX ==========");
console.log("SBOM Generated : YES");

// =====================================
// Generic Policy Evaluation
// =====================================

function evaluate(toolName, result, policy) {

  for (const severity in policy) {

    if (severity === "required") continue;

    const found = result[severity] || 0;
    const allowed = policy[severity];

    if (found > allowed) {

      failed = true;

      reasons.push(
        `${toolName}: ${severity.toUpperCase()} = ${found} (Allowed: ${allowed})`
      );

    }

  }

}

evaluate("NoVuln", summary, POLICY.novuln);

evaluate(
  "npm audit",
  {
    critical: auditSummary.critical,
    high: auditSummary.high,
    moderate: auditSummary.moderate,
    low: auditSummary.low
  },
  POLICY.audit
);

evaluate("Trivy", trivySummary, POLICY.trivy);

// =====================================
// Final Decision
// =====================================

console.log("\n========================================");

if (failed) {

  console.log("❌ SECURITY GATE FAILED\n");

  console.log("Reason(s):");

  reasons.forEach((reason) => {
    console.log(`- ${reason}`);
  });

  process.exit(1);

}

console.log("✅ SECURITY GATE PASSED");

process.exit(0);