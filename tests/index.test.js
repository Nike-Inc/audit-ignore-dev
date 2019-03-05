const { spawn } = require('child_process');

describe('Audit Ignore Dev tests', () => {
    it('Pretty print outputs to console as expected', async (done) => {
        let script = spawn('node', ['index.js']);

        let scriptOutput = '';

        script.stdout.on('data', (data) => {
          scriptOutput += data
        });

        script.stderr.on('data', (data) => {
          console.log(`stderr: ${data}`);
          fail(1);
        });

        script.on('close', (code) => {
            expect(scriptOutput).toContain("\x1b[35mVulnerabilities before analysis:\n\x1b[0m\n" + 
                                            "critical: \x1b[32m0\x1b[0m\n" + 
                                            "high: \x1b[32m0\x1b[0m\n" + 
                                            "moderate: \x1b[32m0\x1b[0m\n" + 
                                            "low: \x1b[31m1\x1b[0m\n" +         // low: 1
                                            "info: \x1b[32m0\x1b[0m"
                                            );
            expect(scriptOutput).toContain("\x1b[35m\nVulnerabilities after analysis:\n\x1b[0m\n" + 
                                            "critical: \x1b[32m0\x1b[0m\n" + 
                                            "high: \x1b[32m0\x1b[0m\n" + 
                                            "moderate: \x1b[32m0\x1b[0m\n" + 
                                            "low: \x1b[32m0\x1b[0m\n" +         // low: 0
                                            "info: \x1b[32m0\x1b[0m"
                                            );
            done();
        });
    });

    it('Json outputs to console as expected', async (done) => {
        let script = spawn('node', ['index.js', '--json']);

        let scriptOutput = '';

        script.stdout.on('data', (data) => {
          scriptOutput += data
        });

        script.stderr.on('data', (data) => {
          console.log(`stderr: ${data}`);
          fail(1);
        });

        script.on('close', (code) => {
            scriptJson = JSON.parse(scriptOutput);

            // The devDependency is removed from the resolves object
            expect(scriptJson.actions[0].resolves.length).toEqual(0);

            // The devDependency remains in the findings object
            expect(scriptJson.advisories["785"].findings.length).toEqual(1);

            //The metadata is updated to remove any devDependencies
            expect(scriptJson.metadata.vulnerabilities.low).toEqual(0);
            
            done();
        });
    });
})