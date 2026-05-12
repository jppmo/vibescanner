const { spawn, execFile } = require("child_process");

function deploy(branch) {
  return spawn("git", ["pull", "origin", branch]);
}

function listFiles(path) {
  return execFile("ls", ["-la", path]);
}

function parseExpr(input) {
  return JSON.parse(input);
}
