#!/usr/bin/env node
"use strict";

const childProcess = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const packageRoot = path.resolve(__dirname, "..");
const packageJson = JSON.parse(
  fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"),
);

const minimumPython = [3, 11];

function sanitizeName(value) {
  return value.replace(/[^A-Za-z0-9_.-]/g, "_");
}

function venvPythonPath(venvDir) {
  if (process.platform === "win32") {
    return path.join(venvDir, "Scripts", "python.exe");
  }
  return path.join(venvDir, "bin", "python");
}

function runQuiet(command, args, options = {}) {
  return childProcess.spawnSync(command, args, {
    cwd: options.cwd || packageRoot,
    env: options.env || process.env,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function runChecked(command, args, label, options = {}) {
  const result = runQuiet(command, args, options);
  if (result.error || result.status !== 0) {
    process.stderr.write(`\n[oh-my-misc] ${label} failed\n`);
    process.stderr.write(`command: ${command} ${args.join(" ")}\n`);
    if (result.error) {
      process.stderr.write(`${result.error.message}\n`);
    }
    if (result.stdout) {
      process.stderr.write(result.stdout);
    }
    if (result.stderr) {
      process.stderr.write(result.stderr);
    }
    process.exit(result.status || 1);
  }
  return result;
}

function pythonMeetsVersion(command) {
  const code = [
    "import sys",
    `ok = sys.version_info >= (${minimumPython[0]}, ${minimumPython[1]})`,
    "print(f'{sys.executable}\\t{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')",
    "raise SystemExit(0 if ok else 1)",
  ].join("; ");
  const result = runQuiet(command, ["-c", code]);
  return !result.error && result.status === 0;
}

function findPython() {
  const candidates = [];
  if (process.env.OH_MY_MISC_PYTHON) {
    candidates.push(process.env.OH_MY_MISC_PYTHON);
  }
  candidates.push("python3.13", "python3.12", "python3.11", "python3", "python");

  const seen = new Set();
  for (const candidate of candidates) {
    if (seen.has(candidate)) {
      continue;
    }
    seen.add(candidate);
    if (pythonMeetsVersion(candidate)) {
      return candidate;
    }
  }

  process.stderr.write(
    `[oh-my-misc] Python ${minimumPython.join(".")}+ is required. ` +
      "Set OH_MY_MISC_PYTHON=/path/to/python if it is installed in a custom location.\n",
  );
  process.exit(1);
}

function markerMatches(markerPath, pythonCommand) {
  if (process.env.OH_MY_MISC_NPM_REINSTALL === "1") {
    return false;
  }
  try {
    const marker = JSON.parse(fs.readFileSync(markerPath, "utf8"));
    return (
      marker.name === packageJson.name &&
      marker.version === packageJson.version &&
      marker.packageRoot === packageRoot &&
      marker.pythonCommand === pythonCommand
    );
  } catch (_) {
    return false;
  }
}

function ensurePythonEnvironment(pythonCommand) {
  const cacheRoot =
    process.env.OH_MY_MISC_NPM_CACHE ||
    path.join(os.homedir(), ".cache", "oh-my-misc", "npm");
  const envName = sanitizeName(`${packageJson.name}-${packageJson.version}`);
  const venvDir = path.join(cacheRoot, envName);
  const markerPath = path.join(venvDir, ".oh-my-misc-npm.json");
  const pythonPath = venvPythonPath(venvDir);

  if (fs.existsSync(pythonPath) && markerMatches(markerPath, pythonCommand)) {
    return pythonPath;
  }

  process.stderr.write(`[oh-my-misc] preparing Python environment in ${venvDir}\n`);
  fs.mkdirSync(cacheRoot, { recursive: true });
  fs.rmSync(venvDir, { recursive: true, force: true });

  runChecked(pythonCommand, ["-m", "venv", venvDir], "create virtualenv");
  runChecked(
    pythonPath,
    [
      "-m",
      "pip",
      "install",
      "--disable-pip-version-check",
      "--upgrade",
      packageRoot,
    ],
    "install oh-my-misc",
  );

  fs.writeFileSync(
    markerPath,
    JSON.stringify(
      {
        name: packageJson.name,
        version: packageJson.version,
        packageRoot,
        pythonCommand,
      },
      null,
      2,
    ),
  );
  return pythonPath;
}

function main() {
  const pythonCommand = findPython();
  const pythonPath = ensurePythonEnvironment(pythonCommand);
  const child = childProcess.spawnSync(
    pythonPath,
    ["-m", "oh_my_misc", ...process.argv.slice(2)],
    {
      cwd: process.cwd(),
      env: process.env,
      stdio: "inherit",
    },
  );
  if (child.error) {
    process.stderr.write(`[oh-my-misc] launch failed: ${child.error.message}\n`);
    process.exit(1);
  }
  process.exit(child.status === null ? 1 : child.status);
}

main();
