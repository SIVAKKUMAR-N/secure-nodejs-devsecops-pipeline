const fs = require("fs");
const path = require("path");

const startTime = Date.now();

console.log(`
========================================
          SECURITY GATE v2
========================================
`);


let failed = false;
let reasons = [];
let results = {};


// =====================================
// Helpers
// =====================================

function loadJSON(file) {

    try {

        return JSON.parse(
            fs.readFileSync(file, "utf8")
        );

    } catch (error) {

        failed = true;

        reasons.push(
            `Unable to read JSON: ${file}`
        );

        return {};

    }

}


function fileExists(file) {

    return fs.existsSync(file);

}


function status(ok){

    return ok ? "PASS" : "FAIL";

}


// =====================================
// Load Security Policy
// =====================================

const POLICY_PATH =
    "policy/security-policy.json";


if (!fileExists(POLICY_PATH)) {

    console.log(
        "❌ Security policy missing"
    );

    process.exit(1);

}


const POLICY = loadJSON(POLICY_PATH);



console.log("\n========== SECURITY POLICY ==========");

console.log(
    JSON.stringify(
        POLICY,
        null,
        2
    )
);



// =====================================
// Required Reports
// =====================================

const requiredFiles = [

    "summary.json",
    "audit.json",
    "trivy-report.json"

];


if (POLICY.sbom?.required) {

    requiredFiles.push(
        "sbom.json"
    );

}



console.log("\n========== REPORT VALIDATION ==========");


for (const file of requiredFiles) {


    if(fileExists(file)){

        console.log(
            `✅ ${file}`
        );

    }

    else{

        failed = true;

        reasons.push(
            `Missing report: ${file}`
        );


        console.log(
            `❌ ${file}`
        );

    }

}



if(failed){

    finish();

}



// =====================================
// Load Reports
// =====================================

const summary =
    loadJSON("summary.json");


const audit =
    loadJSON("audit.json");


const trivy =
    loadJSON("trivy-report.json");




// =====================================
// Parse npm audit
// =====================================


const auditSummary =
    audit.metadata?.vulnerabilities || {

        critical:0,
        high:0,
        moderate:0,
        low:0

    };




// =====================================
// Parse Trivy
// =====================================


const trivySummary = {

    critical:0,
    high:0,
    medium:0,
    low:0

};



for(const result of trivy.Results || []){


    for(const vuln of result.Vulnerabilities || []){


        const severity =
            vuln.Severity?.toLowerCase();


        if(trivySummary[severity] !== undefined){

            trivySummary[severity]++;

        }


    }


}




// =====================================
// Scanner Evaluation
// =====================================


function evaluateScanner(
    name,
    report,
    policy
){


    let scannerFailed = false;


    for(const severity in policy){


        if(
            severity === "required"
        ){

            continue;

        }


        const found =
            report[severity] || 0;


        const allowed =
            policy[severity];



        if(found > allowed){


            scannerFailed = true;


            reasons.push(

                `${name}: ${severity.toUpperCase()} found ${found}, allowed ${allowed}`

            );


        }


    }



    results[name] =
        status(!scannerFailed);



    if(scannerFailed){

        failed = true;

    }


}




evaluateScanner(

    "NoVuln",

    summary,

    POLICY.novuln

);



evaluateScanner(

    "npm Audit",

    {

        critical:auditSummary.critical,
        high:auditSummary.high,
        moderate:auditSummary.moderate,
        low:auditSummary.low

    },

    POLICY.audit

);



evaluateScanner(

    "Trivy",

    trivySummary,

    POLICY.trivy

);



if(POLICY.sbom?.required){

    results["SBOM"] =
        fileExists("sbom.json")
            ? "PASS"
            : "FAIL";

}



// =====================================
// Summary Table
// =====================================


console.log(`

========== SECURITY SUMMARY ==========

Scanner              Status
--------------------------------------

`);



for(const tool in results){

    console.log(

        `${tool.padEnd(20)} ${results[tool]}`

    );

}



console.log(
`
--------------------------------------
Violations: ${reasons.length}
`
);




// =====================================
// GitHub Actions Summary
// =====================================


function githubSummary(){


    if(!process.env.GITHUB_STEP_SUMMARY){

        return;

    }


    let output =
`
# Security Gate v2

| Scanner | Status |
|---|---|
`;


    for(const tool in results){

        output +=
        `| ${tool} | ${results[tool]} |\n`;

    }



    output +=
`
## Decision

${failed ? "❌ BLOCKED" : "✅ APPROVED"}

Violations:
${reasons.length}

`;



    fs.appendFileSync(

        process.env.GITHUB_STEP_SUMMARY,

        output

    );


}



githubSummary();



// =====================================
// Generate Result JSON
// =====================================


const executionTime =
    ((Date.now()-startTime)/1000)
    .toFixed(2);



const finalResult = {


    status:
        failed
        ? "FAILED"
        : "PASSED",


    violations:
        reasons.length,


    scanners:
        results,


    executionTime:
        `${executionTime}s`,


    timestamp:
        new Date().toISOString(),


    reasons

};



fs.writeFileSync(

    "security-gate-result.json",

    JSON.stringify(

        finalResult,

        null,

        2

    )

);





// =====================================
// Final Decision
// =====================================


function finish(){


    console.log(
`
========================================
`
    );


    if(failed){


        console.log(
            "❌ SECURITY GATE FAILED"
        );


        console.log("\nReasons:");

        reasons.forEach(r =>
            console.log(
                "- " + r
            )
        );


        process.exit(1);

    }



    console.log(
        "✅ SECURITY GATE PASSED"
    );


    process.exit(0);


}




finish();