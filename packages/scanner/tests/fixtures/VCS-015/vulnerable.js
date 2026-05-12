const { exec, execSync } = require("child_process");
const vm = require("vm");

function deploy(branch) {
  exec(`git pull origin ${branch}`);
}

function listFiles(path) {
  return execSync(`ls -la ${path}`).toString();
}

function parseExpr(input) {
  return eval(input);
}

function runIsolated(code) {
  return vm.runInNewContext(code);
}

function fnFromString(body) {
  return new Function(body);
}
