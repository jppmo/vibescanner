#!/usr/bin/env node
"use strict";

const { spawnSync } = require("child_process");

function findVibescan() {
  // Try the shell PATH first (covers pipx, uv tool, homebrew, system pip)
  for (const cmd of ["vibescan", "python3 -m vibescan_cli", "python -m vibescan_cli"]) {
    const parts = cmd.split(" ");
    const result = spawnSync(parts[0], [...parts.slice(1), "--version"], {
      encoding: "utf8",
      stderr: "pipe",
    });
    if (result.status === 0) return parts;
  }
  return null;
}

const args = process.argv.slice(2);

// Fast path: `vibescan` binary on PATH
const directResult = spawnSync("vibescan", args, { stdio: "inherit" });
if (directResult.error == null) {
  process.exit(directResult.status ?? 0);
}

// Fallback: invoke as Python module
for (const pythonCmd of ["python3", "python"]) {
  const result = spawnSync(
    pythonCmd,
    ["-m", "vibescan_cli", ...args],
    { stdio: "inherit" }
  );
  if (result.error == null) {
    process.exit(result.status ?? 0);
  }
}

console.error(
  "vibescan: could not find the vibescan Python package.\n" +
    "Run: pip install vibescan-cli"
);
process.exit(3);
