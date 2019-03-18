# audit-ignore-dev
This package allows you to ignore `devDependencies` while running `npm audit`. You can replace `npm audit` in your CI pipeline directly by using the following:

## Global
##### Installation
    npm install -g audit-ignore-dev
    
##### Usage
    audit-ignore-dev
    
This command will produce output based on the `package.json` file in your current directory.

## Save to current package
##### Installation
    npm install --save-dev audit-ignore-dev

##### Usage
    ./node_modules/audit-ignore-dev/index.js

## Run tests
Clone this repo locally, then run

    npm install
    npm test


### Options:

Optionally, you can provide arguments for the acceptable amount of vulnerabilities in your `dependencies`:

    audit-ignore-dev -c 0 -h 0 -m 2 -l 10 -i 1000 --json
    
`--help`: View these options

`--json`: If this flag is present, output a new json object with the vulnerabilities from `devDependencies` removed from the `metadata.vulnerabilities` and from the `actions[actionNumber].resolves`.

`-c {Number}` or `---critical {Number}`: Amount of acceptable critical vulnerabilities in your `dependencies`

`-h {Number}` or `--high {Number}`: Amount of acceptable high vulnerabilities in your `dependencies`

`-m {Number}` or `--moderate {Number}`: Amount of acceptable moderate vulnerabilities in your `dependencies`

`-l {Number}` or `--low {Number}`: Amount of acceptable low vulnerabilities in your `dependencies`

`-i {Number}` or `--info {Number}`: Amount of acceptable info vulnerabilities in your `dependencies`

## Author
Nathanial Myers

nathanial.myers@nike.com

