#!/usr/bin/env node
"use strict";

const { spawnSync } = require("child_process");

function hasPython() {
  for (const cmd of ["python3", "python"]) {
    try {
      const result = spawnSync(cmd, ["--version"], { encoding: "utf8" });
      if (result.status === 0) return cmd;
    } catch {}
  }
  return null;
}

function hasPip(pythonCmd) {
  try {
    const result = spawnSync(pythonCmd, ["-m", "pip", "--version"], {
      encoding: "utf8",
    });
    return result.status === 0;
  } catch {
    return false;
  }
}

function hasVibescan(pythonCmd) {
  try {
    const result = spawnSync(pythonCmd, ["-m", "vibescan_cli", "--version"], {
      encoding: "utf8",
      stderr: "pipe",
    });
    return result.status === 0;
  } catch {
    return false;
  }
}

const pythonCmd = hasPython();

if (!pythonCmd) {
  console.warn(
    "\nvibescan: Python 3.10+ is required but was not found.\n" +
      "Install Python from https://python.org and then run:\n" +
      "  pip install vibescan-scanner\n"
  );
  process.exit(0);
}

if (!hasPip(pythonCmd)) {
  console.warn(
    "\nvibescan: pip not found. Install pip and then run:\n" +
      "  pip install vibescan-scanner\n"
  );
  process.exit(0);
}

if (hasVibescan(pythonCmd)) {
  process.exit(0);
}

console.log("vibescan: installing Python package...");
const result = spawnSync(
  pythonCmd,
  ["-m", "pip", "install", "vibescan-scanner", "--quiet"],
  { stdio: "inherit" }
);
if (result.status !== 0) {
  console.warn(
    "\nvibescan: pip install failed. Install manually with:\n" +
      "  pip install vibescan-scanner\n"
  );
}
