#!/usr/bin/env node
/**
 * =====================================================================
 * SECURITY GATE v3
 * =====================================================================
 *
 * DevSecOps pipeline gate that evaluates the output of:
 *   - NoVuln (custom SAST)        -> summary.json
 *   - npm audit                   -> audit.json
 *   - Trivy container scan        -> trivy-report.json
 *   - CycloneDX SBOM              -> sbom.json (optional, policy driven)
 *
 * Against:
 *   - policy/security-policy.json      (severity thresholds, scores, versions)
 *   - policy/security-exceptions.json  (accepted risk / dev-dep waivers with expiry)
 *
 * Produces:
 *   - A console summary (with ANSI colors)
 *   - A GitHub Actions step summary (if GITHUB_STEP_SUMMARY is set)
 *   - security-gate-result.json
 *
 * Exit code:
 *   - 0 on PASS or WARNING
 *   - 1 on FAIL (or on unrecoverable setup errors)
 * =====================================================================
 */

"use strict";

const fs = require("fs");
const crypto = require("crypto");
const { execSync } = require("child_process");

const START_TIME = Date.now();

// =====================================================================
// Constants
// =====================================================================

const POLICY_PATH = "policy/security-policy.json";
const EXCEPTIONS_PATH = "policy/security-exceptions.json";

const REPORT_FILES = {
  novuln: "summary.json",
  audit: "audit.json",
  trivy: "trivy-report.json",
  sbom: "sbom.json",
};

const RESULT_JSON_PATH = "security-gate-result.json";

const SEVERITIES = ["critical", "high", "medium", "low", "unknown"];

// npm audit reports "moderate" where the rest of the pipeline says "medium"
const AUDIT_SEVERITY_ALIASES = { moderate: "medium" };

const STATUS = { PASS: "PASS", WARNING: "WARNING", FAIL: "FAIL" };
const GATE_STATUS = { PASSED: "PASSED", WARNING: "WARNING", FAILED: "FAILED" };

const DEFAULT_SCORE_WEIGHTS = { critical: 25, high: 15, medium: 7, low: 2, unknown: 0, accepted: 1 };

// ANSI Color Codes for Console Output
const COLORS = {
  PASS: "\x1b[32m",    // Green
  WARNING: "\x1b[33m", // Yellow
  FAIL: "\x1b[31m",    // Red
  INFO: "\x1b[36m",    // Cyan
  RESET: "\x1b[0m"     // Reset
};

// =====================================================================
// Generic Helpers
// =====================================================================

class GateSetupError extends Error {}

/**
 * Checks if a file exists on the filesystem.
 * @param {string} file - Path to the file.
 * @returns {boolean} True if the file exists.
 */
function fileExists(file) {
  return fs.existsSync(file);
}

/**
 * Ensures a value is an array, falling back to an empty array.
 * @param {*} value - The value to check.
 * @returns {Array} The guaranteed array.
 */
function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

/**
 * Ensures a value is a valid finite number, falling back to a default.
 * @param {*} value - The value to cast.
 * @param {number} [fallback=0] - The default value if casting fails.
 * @returns {number} A valid finite number.
 */
function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

/**
 * Constrains a number between a minimum and maximum value.
 * @param {number} value - The number to clamp.
 * @param {number} min - The minimum allowed value.
 * @param {number} max - The maximum allowed value.
 * @returns {number} The clamped value.
 */
function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

/**
 * Returns an object with all tracked severities initialized to zero.
 * @returns {Object} Zero-initialized severity counts.
 */
function zeroCounts() {
  return { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
}

/**
 * Sums up all tracked severities in a count object.
 * @param {Object} counts - Object containing severity keys mapped to numbers.
 * @returns {number} The sum of all counts.
 */
function sumCounts(counts) {
  return SEVERITIES.reduce((sum, sev) => sum + (counts[sev] || 0), 0);
}

/**
 * Logs a standard formatted message for lifecycle phases.
 * @param {string} phaseName - The name of the phase being executed.
 */
function logPhase(phaseName) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${COLORS.INFO}[INFO] Phase: ${phaseName}${COLORS.RESET}`);
}

/**
 * Checks if an exception object has a valid, non-expired date.
 * If the date format is malformed, prints a warning and treats the exception as invalid.
 * @param {Object} exceptionObj - The exception configuration.
 * @param {string} contextName - Identifier for the exception (used in warnings).
 * @returns {boolean} True if valid and not expired, false otherwise.
 */
function isExceptionValid(exceptionObj, contextName) {
  if (!exceptionObj || !exceptionObj.expires) return true;
  
  const expiryDate = new Date(exceptionObj.expires);
  if (isNaN(expiryDate.getTime())) {
    console.log(`${COLORS.WARNING}⚠️  [WARNING] Exception for '${contextName}' has an invalid expiry date ('${exceptionObj.expires}'). Ignoring exception.${COLORS.RESET}`);
    return false; // Malformed expiry means we fail closed (ignore the exception)
  }
  
  // Set today's date to midnight for accurate expiration check
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  
  return today <= expiryDate;
}

/**
 * Collects build environment metadata, favoring GitHub Actions if present.
 * @returns {Object|null} Build metadata or a partial object if running locally.
 */
function getBuildMetadata() {
  const env = process.env;
  return {
    commit: env.GITHUB_SHA || null,
    branch: env.GITHUB_REF_NAME || null,
    runId: env.GITHUB_RUN_ID || null,
    runNumber: env.GITHUB_RUN_NUMBER || null,
    actor: env.GITHUB_ACTOR || null,
    repository: env.GITHUB_REPOSITORY || null,
    workflow: env.GITHUB_WORKFLOW || null,
    job: env.GITHUB_JOB || null,
    runner: env.RUNNER_NAME || null
  };
}

/**
 * Executes a shell command to extract scanner version numbers.
 * @param {Object} novulnReport - The parsed NoVuln report (may contain version).
 * @returns {Object} Object containing scanner versions.
 */
function getScannerVersions(novulnReport) {
  function getCmd(cmd, parseFn) {
    try {
      const out = execSync(cmd, { stdio: "pipe" }).toString().trim();
      return parseFn ? parseFn(out) : out.split("\n")[0];
    } catch {
      return "unknown";
    }
  }

  return {
    novuln: novulnReport?.version || "unknown",
    trivy: getCmd("trivy --version", (out) => {
      const match = out.match(/Version:\s*(v?\d+\.\d+\.\d+)/i);
      return match ? match[1] : "unknown";
    }),
    npm: getCmd("npm --version"),
    node: process.version
  };
}

// =====================================================================
// Policy & Exceptions Loading
// =====================================================================

/**
 * Validates the loaded security policy structure and constraints.
 * @param {Object} policy - The loaded policy object.
 * @throws {GateSetupError} If validation fails.
 */
function validatePolicy(policy) {
  if (!policy.version) {
    throw new GateSetupError("Policy validation failed: 'version' is missing.");
  }
  if (!policy.scoreWeights || typeof policy.scoreWeights !== "object") {
    throw new GateSetupError("Policy validation failed: 'scoreWeights' object is missing.");
  }

  for (const [key, val] of Object.entries(policy.scoreWeights)) {
    if (typeof val !== "number" || isNaN(val) || val < 0) {
      throw new GateSetupError(`Policy validation failed: 'scoreWeights.${key}' must be a number >= 0.`);
    }
  }

  const scanners = ["novuln", "audit", "trivy"];
  for (const scanner of scanners) {
    if (policy[scanner]) {
      if (typeof policy[scanner] !== "object") {
        throw new GateSetupError(`Policy validation failed: '${scanner}' threshold section must be an object.`);
      }
      for (const [sev, val] of Object.entries(policy[scanner])) {
        if (typeof val !== "number" || isNaN(val) || val < 0) {
          throw new GateSetupError(`Policy validation failed: Threshold for '${scanner}.${sev}' must be a number >= 0.`);
        }
      }
    }
  }
}

/**
 * Loads the security policy, computes its integrity hash, and validates it.
 * @returns {Object} The validated policy object with injected hash.
 * @throws {GateSetupError} If the file is missing or invalid.
 */
function loadPolicy() {
  logPhase("Loading policy");
  if (!fileExists(POLICY_PATH)) {
    throw new GateSetupError(`Security policy missing: ${POLICY_PATH}`);
  }

  let raw;
  let policy;
  try {
    raw = fs.readFileSync(POLICY_PATH, "utf8");
    policy = JSON.parse(raw);
  } catch (error) {
    throw new GateSetupError(`Security policy is malformed: ${error.message}`);
  }

  validatePolicy(policy);
  
  policy.scoreWeights = { ...DEFAULT_SCORE_WEIGHTS, ...policy.scoreWeights };
  policy._hash = crypto.createHash("sha256").update(raw).digest("hex");
  
  return policy;
}

/**
 * Loads the exception configuration file.
 * Fails closed if the file is present but malformed.
 * @returns {Object} Mapped exception objects.
 */
function loadExceptions() {
  logPhase("Loading exceptions");
  const emptyExceptions = {
    trivyCves: new Map(),
    auditPackages: new Map(),
    novulnRules: new Map(),
    ignoreDevDependencies: false
  };

  if (!fileExists(EXCEPTIONS_PATH)) {
    return emptyExceptions;
  }

  let rawExceptions;
  try {
    rawExceptions = JSON.parse(fs.readFileSync(EXCEPTIONS_PATH, "utf8"));
  } catch (error) {
    throw new GateSetupError(`security-exceptions.json is malformed.\n${error.message}`);
  }

  // Parse Trivy
  const trivyCves = new Map();
  for (const cve of safeArray(rawExceptions.trivy?.cves)) {
    if (typeof cve === "string") trivyCves.set(cve, { id: cve });
    else if (cve.id) trivyCves.set(cve.id, cve);
  }

  // Parse Audit
  const auditPackages = new Map();
  for (const pkg of safeArray(rawExceptions.audit?.packages)) {
    if (typeof pkg === "string") auditPackages.set(pkg, { name: pkg });
    else if (pkg.name) auditPackages.set(pkg.name, pkg);
  }

  // Parse NoVuln
  const novulnRules = new Map();
  for (const rule of safeArray(rawExceptions.novuln?.rules)) {
    if (typeof rule === "string") novulnRules.set(rule, { id: rule });
    else if (rule.id) novulnRules.set(rule.id, rule);
  }

  return {
    trivyCves,
    auditPackages,
    novulnRules,
    ignoreDevDependencies: Boolean(rawExceptions.audit?.ignoreDevDependencies)
  };
}

// =====================================================================
// Report Validation & Loading
// =====================================================================

/**
 * Builds the required report list based on policy.
 * @param {Object} policy - The security policy.
 * @returns {string[]} Array of required file paths.
 */
function requiredReportList(policy) {
  const required = [REPORT_FILES.novuln, REPORT_FILES.audit, REPORT_FILES.trivy];
  if (policy.sbom?.required) required.push(REPORT_FILES.sbom);
  return required;
}

/**
 * Validates that all required report files are present on disk.
 * @param {Object} policy - The security policy.
 * @returns {string[]} Array of missing file paths.
 */
function validateReports(policy) {
  logPhase("Validating reports");
  const required = requiredReportList(policy);
  const missing = [];

  console.log("\n========== REPORT VALIDATION ==========");
  for (const file of required) {
    const exists = fileExists(file);
    console.log(`${exists ? COLORS.PASS + "✅" : COLORS.FAIL + "❌"} ${file}${COLORS.RESET}`);
    if (!exists) missing.push(file);
  }

  return missing;
}

/**
 * Orchestrates parsing a single scanner report and evaluating it against thresholds.
 * @param {string} name - Scanner name.
 * @param {string} file - File path.
 * @param {Function} parserFn - Function to parse the specific tool's output.
 * @param {Object} policyThresholds - Threshold limits for this scanner.
 * @param {Object} exceptions - Security exceptions data.
 * @returns {Object} Evaluated scanner result payload.
 */
function loadAndEvaluateScanner(name, file, parserFn, policyThresholds, exceptions) {
  const startMs = Date.now();
  let report = {};
  
  logPhase(`Parsing ${name} report`);
  if (fileExists(file)) {
    try {
      report = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (error) {
      throw new GateSetupError(`Unable to parse ${file}\n${error.message}`);
    }
  }

  logPhase(`Evaluating policy for ${name}`);
  const parsed = parserFn(report, exceptions);
  const result = buildScannerResult(name, parsed, policyThresholds);
  
  result.executionTimeMs = Date.now() - startMs;
  return result;
}

// =====================================================================
// Trivy Parser
// =====================================================================

function parseTrivy(trivyReport, exceptions) {
  const counts = zeroCounts();
  const acceptedCounts = zeroCounts();
  const warningCounts = zeroCounts();
  const blocking = [];
  const accepted = [];

  for (const result of safeArray(trivyReport.Results)) {
    for (const vuln of safeArray(result.Vulnerabilities)) {
      const severity = (vuln.Severity || "unknown").toLowerCase();
      if (!(severity in counts)) continue; // Keep tracked severities

      const finding = {
        identifier: vuln.VulnerabilityID || "UNKNOWN",
        severity,
        package: vuln.PkgName || "unknown",
        installedVersion: vuln.InstalledVersion || "unknown",
        fixedVersion: vuln.FixedVersion || "none",
        target: result.Target || "unknown",
      };

      const exception = exceptions.trivyCves.get(finding.identifier);
      
      if (exception && isExceptionValid(exception, finding.identifier)) {
        finding.reason = exception.reason || "Accepted Risk";
        accepted.push(finding);
        acceptedCounts[severity]++;
      } else {
        blocking.push(finding);
        counts[severity]++;
      }
    }
  }

  return { counts, acceptedCounts, warningCounts, blockingItems: blocking, acceptedItems: accepted, warningItems: [] };
}

// =====================================================================
// npm Audit Parser
// =====================================================================

function parseAudit(auditReport, exceptions) {
  const rawVulns = auditReport.vulnerabilities || {};
  const ignoreDev = exceptions.ignoreDevDependencies;

  const counts = zeroCounts();
  const warningCounts = zeroCounts();
  const acceptedCounts = zeroCounts();
  
  const blocking = [];
  const warnings = [];
  const accepted = [];

  const hasDetailedFindings = Object.keys(rawVulns).length > 0;

  for (const [pkgName, entry] of Object.entries(rawVulns)) {
    const rawSeverity = entry.severity || "unknown";
    const severity = AUDIT_SEVERITY_ALIASES[rawSeverity] || rawSeverity;
    if (!(severity in counts)) continue;

    const developmentDependency = Boolean(entry.isDevDependency || entry.dev);
    
    const finding = {
      identifier: "N/A", // npm audit detailed advisories vary by format
      package: pkgName,
      severity,
      dependencyType: entry.isDirect ? "direct" : "transitive",
      isDevDependency: developmentDependency,
    };

    const exception = exceptions.auditPackages.get(pkgName);

    if (exception && isExceptionValid(exception, pkgName)) {
      finding.reason = exception.reason || "Accepted Risk";
      accepted.push(finding);
      acceptedCounts[severity]++;
    } else if (ignoreDev && developmentDependency) {
      finding.reason = "Development Dependency";
      warnings.push(finding);
      warningCounts[severity]++;
    } else {
      blocking.push(finding);
      counts[severity]++;
    }
  }

  let finalCounts = counts;
  if (!hasDetailedFindings && auditReport.metadata?.vulnerabilities) {
    const md = auditReport.metadata.vulnerabilities;
    finalCounts = {
      critical: safeNumber(md.critical),
      high: safeNumber(md.high),
      medium: safeNumber(md.moderate),
      low: safeNumber(md.low),
      unknown: safeNumber(md.info)
    };
  }

  return { counts: finalCounts, acceptedCounts, warningCounts, blockingItems: blocking, warningItems: warnings, acceptedItems: accepted };
}

// =====================================================================
// NoVuln Parser
// =====================================================================

function parseNoVuln(summary, exceptions) {
  const findings = safeArray(summary.findings || summary.issues);
  const counts = zeroCounts();
  const acceptedCounts = zeroCounts();
  const blocking = [];
  const accepted = [];

  if (findings.length === 0) {
    return {
      counts: {
        critical: safeNumber(summary.critical),
        high: safeNumber(summary.high),
        medium: safeNumber(summary.medium),
        low: safeNumber(summary.low),
        unknown: safeNumber(summary.unknown)
      },
      acceptedCounts,
      warningCounts: zeroCounts(),
      blockingItems: [],
      acceptedItems: [],
      warningItems: []
    };
  }

  for (const finding of findings) {
    const severity = (finding.severity || "unknown").toLowerCase();
    const ruleId = finding.rule || finding.ruleId || finding.id || "UNKNOWN";

    if (!(severity in counts)) continue;

    const exception = exceptions.novulnRules.get(ruleId);
    
    const standardFinding = {
      identifier: ruleId,
      severity,
      package: finding.file || finding.path || "N/A",
      ...finding
    };

    if (exception && isExceptionValid(exception, ruleId)) {
      standardFinding.reason = exception.reason || "Accepted Risk";
      accepted.push(standardFinding);
      acceptedCounts[severity]++;
    } else {
      blocking.push(standardFinding);
      counts[severity]++;
    }
  }

  return { counts, acceptedCounts, warningCounts: zeroCounts(), blockingItems: blocking, acceptedItems: accepted, warningItems: [] };
}

// =====================================================================
// Risk Engine & Score Computation
// =====================================================================

/**
 * Evaluates finding counts against configured policy thresholds.
 * @param {Object} counts - Discovered findings by severity.
 * @param {Object} policyThresholds - Policy limits.
 * @returns {Array} List of violations that exceeded policy.
 */
function evaluateThresholds(counts, policyThresholds) {
  const violations = [];
  for (const severity of SEVERITIES) {
    const allowed = policyThresholds?.[severity];
    if (allowed === undefined) continue;

    const found = counts[severity] || 0;
    if (found > allowed) {
      violations.push({ severity, found, allowed });
    }
  }
  return violations;
}

/**
 * Builds the final result object for a single scanner run,
 * tracking all non-excepted items as potential blockers.
 * @param {string} name - Scanner name.
 * @param {Object} parsed - Parsed output from the scanner.
 * @param {Object} policyThresholds - Relevant policy boundaries.
 * @returns {Object} Formatted scanner result.
 */
function buildScannerResult(name, parsed, policyThresholds) {
  const violations = evaluateThresholds(parsed.counts, policyThresholds || {});
  
  // As per requirements: All non-accepted findings are kept, without attempting
  // to slice them by threshold allowance limits.
  const trueBlockingItems = parsed.blockingItems;

  const blockingTotal = trueBlockingItems.length; // Will match sum of unaccepted items
  const acceptedTotal = sumCounts(parsed.acceptedCounts);
  const warningTotal = sumCounts(parsed.warningCounts);

  let scannerStatus = STATUS.PASS;
  // Status decision hinges entirely on overall threshold breaches.
  if (violations.length > 0) scannerStatus = STATUS.FAIL;
  else if (acceptedTotal > 0 || warningTotal > 0) scannerStatus = STATUS.WARNING;

  return {
    name,
    status: scannerStatus,
    blocking: blockingTotal,
    warnings: warningTotal,
    accepted: acceptedTotal,
    summary: {
      counts: parsed.counts,
      acceptedCounts: parsed.acceptedCounts,
      warningCounts: parsed.warningCounts,
    },
    violations,
    blockingItems: trueBlockingItems,
    acceptedItems: parsed.acceptedItems || [],
    warningItems: parsed.warningItems || []
  };
}

function buildSbomResult(policy) {
  if (!policy.sbom?.required) return null;
  logPhase("Evaluating policy for SBOM");
  
  const startMs = Date.now();
  const exists = fileExists(REPORT_FILES.sbom);
  const result = {
    name: "SBOM",
    status: exists ? STATUS.PASS : STATUS.FAIL,
    blocking: exists ? 0 : 1,
    warnings: 0,
    accepted: 0,
    summary: { counts: zeroCounts(), acceptedCounts: zeroCounts(), warningCounts: zeroCounts() },
    violations: exists ? [] : [{ severity: "n/a", found: 0, allowed: 0 }],
    blockingItems: [],
    acceptedItems: [],
    warningItems: [],
    executionTimeMs: Date.now() - startMs
  };
  return result;
}

function determineGateStatus(scannerResults) {
  if (scannerResults.some((s) => s.status === STATUS.FAIL)) return GATE_STATUS.FAILED;
  if (scannerResults.some((s) => s.status === STATUS.WARNING)) return GATE_STATUS.WARNING;
  return GATE_STATUS.PASSED;
}

function calculateSecurityScore(scannerResults, policyWeights) {
  let score = 100;
  
  for (const scanner of scannerResults) {
    const { counts, acceptedCounts } = scanner.summary;
    for (const severity of SEVERITIES) {
      score -= (counts[severity] || 0) * (policyWeights[severity] || 0);
      score -= (acceptedCounts[severity] || 0) * (policyWeights.accepted || 0);
    }
  }
  return clamp(Math.round(score), 0, 100);
}

// =====================================================================
// Console Output
// =====================================================================

function printSummary({ gateStatus, score, scannerResults, executionTime, policyVersion }) {
  logPhase("Generating summary");
  
  console.log(`\n${COLORS.INFO}=========================================
           SECURITY GATE
=========================================${COLORS.RESET}`);
  console.log(`Policy Version  : ${policyVersion}`);
  console.log(`Security Score  : ${score}/100`);
  console.log(`Execution Time  : ${executionTime}s\n`);

  console.log(`${COLORS.INFO}========== Scanner Results ==========${COLORS.RESET}`);
  
  for (const scanner of scannerResults) {
    let statColor = COLORS.PASS;
    if (scanner.status === STATUS.FAIL) statColor = COLORS.FAIL;
    else if (scanner.status === STATUS.WARNING) statColor = COLORS.WARNING;

    console.log(`${scanner.name.padEnd(23)} ${statColor}${scanner.status.padEnd(10)}${COLORS.RESET} (${scanner.executionTimeMs}ms)`);
  }

  const allViolations = scannerResults.flatMap(s => 
    s.violations.map(v => `- ${s.name}: ${v.severity.toUpperCase()} limit exceeded (found ${v.found}, allowed ${v.allowed})`)
  );

  console.log(`\n${COLORS.INFO}========== Policy Violations ==========${COLORS.RESET}`);
  if (allViolations.length > 0) {
    allViolations.forEach(v => console.log(v));
  } else {
    console.log("None");
  }

  const acceptedTotal = scannerResults.reduce((sum, s) => sum + s.accepted, 0);
  console.log(`\n${COLORS.INFO}========== Accepted Risks ==========${COLORS.RESET}`);
  if (acceptedTotal > 0) {
    console.log(`- ${acceptedTotal} total accepted risks`);
  } else {
    console.log("None");
  }

  console.log(`\n${COLORS.INFO}========== Final Decision ==========${COLORS.RESET}`);
  if (gateStatus === GATE_STATUS.FAILED) {
    console.log(`${COLORS.FAIL}❌ SECURITY GATE FAILED${COLORS.RESET}\n`);
  } else if (gateStatus === GATE_STATUS.WARNING) {
    console.log(`${COLORS.WARNING}⚠️  SECURITY GATE PASSED WITH WARNINGS${COLORS.RESET}\n`);
  } else {
    console.log(`${COLORS.PASS}✅ SECURITY GATE PASSED${COLORS.RESET}\n`);
  }
}

// =====================================================================
// GitHub Actions Step Summary
// =====================================================================

function writeGithubStepSummary({ gateStatus, score, blockingTotal, warningTotal, acceptedTotal, executionTime, scannerResults, policyVersion, buildMeta }) {
  if (!process.env.GITHUB_STEP_SUMMARY) return;

  const statusEmoji = { PASSED: "✅", WARNING: "⚠️", FAILED: "❌" }[gateStatus];
  let output = `
# Security Gate v3

**Status:** ${statusEmoji} ${gateStatus}
**Security Score:** ${score}/100
**Policy Version:** ${policyVersion}
**Execution Time:** ${executionTime}s
`;

  if (buildMeta && buildMeta.runId) {
    output += `\n**Run ID:** ${buildMeta.runId} | **Branch:** ${buildMeta.branch} | **Triggered by:** ${buildMeta.actor}\n`;
  }

  output += `
## Scanner Results
| Scanner | Status | Time |
|---|---|---|
`;

  for (const scanner of scannerResults) {
    output += `| ${scanner.name} | ${scanner.status} | ${scanner.executionTimeMs}ms |\n`;
  }

  output += `
## Vulnerability Summary
| Unaccepted Findings | Warnings | Accepted Risks |
|---|---|---|
| ${blockingTotal} | ${warningTotal} | ${acceptedTotal} |
`;

  const allBlocking = scannerResults.flatMap(s => s.blockingItems.map(item => ({ scanner: s.name, ...item })));

  if (allBlocking.length > 0) {
    output += `\n## Top Findings (Not Accepted)\n`;
    output += `| Scanner | Severity | Identifier | Package |\n`;
    output += `|---|---|---|---|\n`;
    
    const limit = Math.min(allBlocking.length, 20);
    for (let i = 0; i < limit; i++) {
      const item = allBlocking[i];
      output += `| ${item.scanner} | ${item.severity.toUpperCase()} | ${item.identifier} | ${item.package} |\n`;
    }
    
    if (allBlocking.length > 20) {
      output += `\n*...and ${allBlocking.length - 20} more findings.*\n`;
    }
  }

  output += `
### Decision
${statusEmoji} **${gateStatus}**
`;

  try {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, output);
  } catch (error) {
    console.log(`⚠️  Unable to write GITHUB_STEP_SUMMARY: ${error.message}`);
  }
}

// =====================================================================
// Result JSON
// =====================================================================

function writeResultJson({ gateStatus, score, blockingTotal, warningTotal, acceptedTotal, executionTime, scannerResults, missingReports, policy, buildMeta, scannerVersions }) {
  logPhase("Writing JSON report");
  
  const scanners = {};
  const allAccepted = [];
  const allBlocking = [];
  const scannerExecutionSummary = [];

  for (const scanner of scannerResults) {
    scanners[scanner.name] = {
      status: scanner.status,
      blocking: scanner.blocking,
      warnings: scanner.warnings,
      accepted: scanner.accepted,
      summary: scanner.summary,
    };
    
    scannerExecutionSummary.push({
      scanner: scanner.name,
      status: scanner.status,
      blocking: scanner.blocking,
      accepted: scanner.accepted,
      warnings: scanner.warnings,
      executionTime: `${scanner.executionTimeMs}ms`
    });

    scanner.acceptedItems.forEach(item => allAccepted.push({ scanner: scanner.name, ...item }));
    scanner.blockingItems.forEach(item => allBlocking.push({ scanner: scanner.name, ...item }));
  }

  const generatedAt = new Date().toISOString();
  const finalResult = {
    schemaVersion: "1.0",
    gateVersion: "3.2",
    policyVersion: policy.version || "unknown",
    policyHash: policy._hash || null,
    generatedAt,
    timestamp: generatedAt,
    status: gateStatus,
    securityScore: score,
    executionTime: `${executionTime}s`,
    buildMetadata: buildMeta,
    scannerVersions,
    blockingIssues: blockingTotal,
    warnings: warningTotal,
    acceptedRisks: acceptedTotal,
    scannerExecutionSummary,
    missingReports,
    scanners,
    acceptedFindings: allAccepted,
    blockingFindings: allBlocking,
    scannerResults
  };

  try {
    fs.writeFileSync(RESULT_JSON_PATH, JSON.stringify(finalResult, null, 2));
  } catch (error) {
    console.log(`${COLORS.WARNING}⚠️  Unable to write ${RESULT_JSON_PATH}: ${error.message}${COLORS.RESET}`);
  }

  return finalResult;
}

// =====================================================================
// Main
// =====================================================================

function main() {
  let policy;
  try {
    policy = loadPolicy();
  } catch (error) {
    console.log(`\n${COLORS.FAIL}ERROR:\n${error.message}\n\nSecurity Gate FAILED.${COLORS.RESET}`);
    process.exit(1);
    return;
  }

  const buildMeta = getBuildMetadata();
  let exceptions;
  
  try {
    exceptions = loadExceptions();
  } catch (error) {
    console.log(`\n${COLORS.FAIL}ERROR:\n${error.message}\n\nSecurity Gate FAILED.${COLORS.RESET}`);
    process.exit(1);
    return;
  }

  const missingReports = validateReports(policy);
  const executionTime = ((Date.now() - START_TIME) / 1000).toFixed(2);

  // Parse versions early for the metadata, though NoVuln payload is needed.
  let rawNoVulnReport = {};
  if (fileExists(REPORT_FILES.novuln)) {
    try { rawNoVulnReport = JSON.parse(fs.readFileSync(REPORT_FILES.novuln, "utf8")); } catch (e) {} // Ignored here, parsed later
  }
  const scannerVersions = getScannerVersions(rawNoVulnReport);

  if (missingReports.length > 0) {
    console.log(`\n${COLORS.FAIL}ERROR:\nMissing required reports: ${missingReports.join(", ")}\n\nSecurity Gate FAILED.${COLORS.RESET}`);
    
    logPhase("Decision");
    writeResultJson({
      gateStatus: GATE_STATUS.FAILED,
      score: 0,
      blockingTotal: missingReports.length,
      warningTotal: 0,
      acceptedTotal: 0,
      executionTime,
      scannerResults: [],
      missingReports,
      policy,
      buildMeta,
      scannerVersions
    });
    process.exit(1);
    return;
  }

  let scannerResults = [];
  try {
    scannerResults.push(loadAndEvaluateScanner("NoVuln", REPORT_FILES.novuln, parseNoVuln, policy.novuln, exceptions));
    scannerResults.push(loadAndEvaluateScanner("npm Audit", REPORT_FILES.audit, parseAudit, policy.audit, exceptions));
    scannerResults.push(loadAndEvaluateScanner("Trivy", REPORT_FILES.trivy, parseTrivy, policy.trivy, exceptions));
    
    const sbomResult = buildSbomResult(policy);
    if (sbomResult) scannerResults.push(sbomResult);
  } catch (error) {
    console.log(`\n${COLORS.FAIL}ERROR:\n${error.message}\n\nSecurity Gate FAILED.${COLORS.RESET}`);
    process.exit(1);
    return;
  }

  const gateStatus = determineGateStatus(scannerResults);
  const score = calculateSecurityScore(scannerResults, policy.scoreWeights);

  const blockingTotal = scannerResults.reduce((sum, s) => sum + s.blocking, 0);
  const warningTotal = scannerResults.reduce((sum, s) => sum + s.warnings, 0);
  const acceptedTotal = scannerResults.reduce((sum, s) => sum + s.accepted, 0);
  
  const finalExecutionTime = ((Date.now() - START_TIME) / 1000).toFixed(2);

  printSummary({ gateStatus, score, scannerResults, executionTime: finalExecutionTime, policyVersion: policy.version });

  writeGithubStepSummary({ gateStatus, score, blockingTotal, warningTotal, acceptedTotal, executionTime: finalExecutionTime, scannerResults, policyVersion: policy.version, buildMeta });

  logPhase("Decision");
  writeResultJson({
    gateStatus,
    score,
    blockingTotal,
    warningTotal,
    acceptedTotal,
    executionTime: finalExecutionTime,
    scannerResults,
    missingReports: [],
    policy,
    buildMeta,
    scannerVersions
  });

  process.exit(gateStatus === GATE_STATUS.FAILED ? 1 : 0);
}

main();