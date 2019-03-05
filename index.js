#!/usr/bin/env node
'use strict';

const minimist = require('minimist');
const { spawn } = require('child_process');

const defaultLimits = {
    "critical": 0,
    "high": 0,
    "moderate": 0,
    "low": 0,
    "info": 0
};

let args = minimist(process.argv.slice(2), {
    alias: {
        v: 'version',
        c: 'critical',
        h: 'high',
        m: 'moderate',
        l: 'low',
        i: 'info'
    }
});

if(args.help) {
    console.log("Usage: `npm run audit-ignore-dev`");
    console.log("Options:");
    console.log("  --help       View this message");
    console.log("  --json       Output audit json minus devDependencies");
    console.log("  -c={Number}  Acceptable number of critical vulnerabilities");
    console.log("  -h={Number}  Acceptable number of high vulnerabilities");
    console.log("  -m={Number}  Acceptable number of moderate vulnerabilities");
    console.log("  -l={Number}  Acceptable number of low vulnerabilities");
    console.log("  -i={Number}  Acceptable number of info vulnerabilities");
    process.exit(0);
}

const consoleLogIfNotJson = (consoleArgs) => {
    if (!args.json) {
        console.log(...consoleArgs);
    }
}

let audit = spawn('npm', ['audit', '--json']);

let auditOutput = '';

audit.stdout.on('data', (data) => {
  auditOutput += data
});

audit.stderr.on('data', (data) => {
  console.log(`stderr: ${data}`);
});

audit.on('close', (code) => {
    const auditParsed = JSON.parse(auditOutput);
    let newAudit = JSON.parse(auditOutput);

    const vulnerabilities = {
        "critical": auditParsed.metadata.vulnerabilities.critical,
        "high": auditParsed.metadata.vulnerabilities.high,
        "moderate": auditParsed.metadata.vulnerabilities.moderate,
        "low": auditParsed.metadata.vulnerabilities.low,
        "info": auditParsed.metadata.vulnerabilities.info,
    }

    consoleLogIfNotJson(['\x1b[35m%s\x1b[0m', 'Analyzing vulnerabilities from `npm audit` and ignoring those under devDependencies\n']);

    consoleLogIfNotJson(['\x1b[35m%s\x1b[0m', 'Vulnerabilities before analysis:\n']);
    for(let vuln of Object.keys(vulnerabilities)) {
        vulnerabilities[vuln] > 0 ? consoleLogIfNotJson(['%s: \x1b[31m%s\x1b[0m', vuln, vulnerabilities[vuln]]) : consoleLogIfNotJson(['%s: \x1b[32m%s\x1b[0m', vuln, vulnerabilities[vuln]]);
    }

    for(let advisoryNumber of Object.keys(auditParsed.advisories)) {
      for(let finding of auditParsed.advisories[advisoryNumber].findings) {
        if(finding.dev) {
          vulnerabilities[auditParsed.advisories[advisoryNumber].severity] -= finding.paths.length;
          for(let vulnPath of finding.paths) {
            const actionIndex = newAudit.actions.findIndex(action => action.module === auditParsed.advisories[advisoryNumber].module_name);
            if (actionIndex !== -1) {
                const resolveIndex = newAudit.actions[actionIndex].resolves.findIndex(resolve => resolve.path === vulnPath);
                if (resolveIndex !== -1) {
                    newAudit.actions[actionIndex].resolves.splice(resolveIndex, 1);
                }
            }
          }
        }
      }
    }

    newAudit.metadata.vulnerabilities = vulnerabilities;

    consoleLogIfNotJson(['\x1b[35m%s\x1b[0m', '\nVulnerabilities after analysis:\n']);
    for(let vuln of Object.keys(vulnerabilities)) {
        vulnerabilities[vuln] > 0 ? consoleLogIfNotJson(['%s: \x1b[31m%s\x1b[0m', vuln, vulnerabilities[vuln]]) : consoleLogIfNotJson(['%s: \x1b[32m%s\x1b[0m', vuln, vulnerabilities[vuln]]);
    }

    if(args.json) {
        console.log(JSON.stringify(newAudit, null, 2));
    }

    for(let vuln of Object.keys(vulnerabilities)) {
        if(vulnerabilities[vuln] > (args[vuln] ? args[vuln] : defaultLimits[vuln])) {
            consoleLogIfNotJson(['\x1b[31m%s\x1b[0m', '\nMaximum allowed ' + vuln + ' vulnerabilities exceeded! Run `npm audit` for details.\n']);
            process.exit(1);
        }
    }

    consoleLogIfNotJson(['\x1b[32m%s\x1b[0m', '\nNo vulnerabilities exceeded the allowed amount!\n']);

    process.exit(0);     
});