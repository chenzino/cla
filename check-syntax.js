#!/usr/bin/env node
// Quick syntax checker for index.html - catches JS errors before they go live
const fs = require('fs');
const { execSync } = require('child_process');
const file = '/home/ubuntu/cla/public/index.html';

const html = fs.readFileSync(file, 'utf8');
const regex = /<script[^>]*>([\s\S]*?)<\/script>/g;
let match, blockNum = 0, errors = 0;

while ((match = regex.exec(html)) !== null) {
  blockNum++;
  const code = match[1];
  if (code.trim().length < 10) continue;

  const tmpFile = `/tmp/syntax_check_${blockNum}.js`;
  fs.writeFileSync(tmpFile, code);

  try {
    execSync(`node --check ${tmpFile}`, { stdio: 'pipe' });
    console.log(`  ✓ Script block ${blockNum} OK`);
  } catch (e) {
    errors++;
    const stderr = e.stderr.toString();
    // Extract line number from error
    const lineMatch = stderr.match(new RegExp(tmpFile.replace(/\//g, '\\/') + ':(\\d+)'));
    const errLine = lineMatch ? lineMatch[1] : '?';
    const msgMatch = stderr.match(/SyntaxError: (.+)/);
    const errMsg = msgMatch ? msgMatch[1] : 'Unknown syntax error';
    console.log(`  ✗ Script block ${blockNum} ERROR at line ${errLine}: ${errMsg}`);

    // Show context
    if (lineMatch) {
      const lines = code.split('\n');
      const ln = parseInt(lineMatch[1]) - 1;
      for (let i = Math.max(0, ln - 2); i <= Math.min(lines.length - 1, ln + 2); i++) {
        console.log(`    ${i === ln ? '>>>' : '   '} ${i + 1}: ${lines[i].substring(0, 100)}`);
      }
    }
  }
}

if (errors > 0) {
  console.log(`\n  ✗ ${errors} syntax error(s) found!`);
  process.exit(1);
} else {
  console.log(`\n  ✓ All ${blockNum} script blocks clean`);
  process.exit(0);
}
