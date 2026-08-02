"use strict";

const vscode = require("vscode");
const cp = require("child_process");
const fs = require("fs");
const path = require("path");

let methodsByFile = new Map();
let decorationType;
let diagnosticCollection;
let output;
let statusBarItem;
let enabled = true;
let anomaliesEnabled = true;
let running = false;
let workspaceRunning = false;
let queuedFile = null;
let saveTimer;

const SEVERITY = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  hint: vscode.DiagnosticSeverity.Hint,
  info: vscode.DiagnosticSeverity.Information
};

function config() {
  return vscode.workspace.getConfiguration("autotype");
}

function workspaceRoot() {
  const folders = vscode.workspace.workspaceFolders;
  return folders && folders.length > 0 ? folders[0].uri.fsPath : undefined;
}

function cachePath(root) {
  return path.join(root, config().get("cacheFile", "tmp/autotype_cache.json"));
}

function normalizeKey(filePath) {
  return filePath.replace(/^\.\//, "").split(path.sep).join("/");
}

function relativePath(uri) {
  const root = workspaceRoot();
  if (!root || !uri) return null;
  return normalizeKey(path.relative(root, uri.fsPath));
}

function fileGlobs() {
  return config().get("fileGlobs", ["app/**/*.rb", "lib/**/*.rb", "config/**/*.rb"]);
}

function log(message) {
  if (output) output.appendLine(message);
}

function setStatus(text, loading = false) {
  if (!statusBarItem) return;
  statusBarItem.text = loading ? `$(sync~spin) Autotype: ${text}` : `$(ruby) Autotype: ${text}`;
  statusBarItem.show();
}

function loadCache() {
  const root = workspaceRoot();
  if (!root) return;
  try {
    const raw = fs.readFileSync(cachePath(root), "utf8");
    methodsByFile = new Map(Object.entries(JSON.parse(raw)).map(([key, value]) => [normalizeKey(key), value]));
    log(`loaded cache for ${methodsByFile.size} files`);
    decorateVisibleEditors();
    publishDiagnostics();
    updateStatusFromCache();
  } catch (_error) {
    log("no cache yet");
    setStatus("waiting…");
  }
}

function persistCache() {
  const root = workspaceRoot();
  if (!root) return;
  try {
    const file = cachePath(root);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    // Merge with entries written externally (CLI scans) since our last read,
    // so a single-file refresh never clobbers a full-workspace scan.
    let merged = {};
    try {
      merged = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (_error) {
      merged = {};
    }
    for (const [key, value] of methodsByFile.entries()) merged[key] = value;
    for (const [key, value] of Object.entries(merged)) {
      const normalized = normalizeKey(key);
      if (!methodsByFile.has(normalized)) methodsByFile.set(normalized, value);
    }
    fs.writeFileSync(file, JSON.stringify(merged));
  } catch (error) {
    log(`cache write failed: ${error.message}`);
  }
}

function ingestJson(json, label) {
  const parsed = JSON.parse(json);
  for (const [file, methods] of Object.entries(parsed)) {
    methodsByFile.set(normalizeKey(file), methods);
  }
  log(`${label}: ${Object.keys(parsed).length} file(s), ${methodsByFile.size} total cached`);
  persistCache();
  decorateVisibleEditors();
  publishDiagnostics();
  updateStatusFromCache();
}

function updateStatusFromCache() {
  let anomalies = 0;
  for (const methods of methodsByFile.values()) {
    for (const method of methods) anomalies += (method.anomalies || []).length;
  }
  if (anomalies > 0) setStatus(`${anomalies} anomal${anomalies === 1 ? "y" : "ies"}`);
  else setStatus(`${methodsByFile.size} files`);
}

function publishDiagnostics() {
  if (!diagnosticCollection) return;
  diagnosticCollection.clear();
  if (!anomaliesEnabled) return;

  const root = workspaceRoot();
  if (!root) return;

  for (const [relative, methods] of methodsByFile.entries()) {
    const uri = vscode.Uri.file(path.resolve(root, relative));
    const diagnostics = [];

    for (const method of methods) {
      for (const anomaly of method.anomalies || []) {
        const line = Math.max(0, method.line - 1);
        const endLine = Math.max(line, (method.end_line || method.line) - 1);
        const range = new vscode.Range(line, 0, endLine, 1);
        const diagnostic = new vscode.Diagnostic(
          range,
          `[${anomaly.code}] ${anomaly.message}`,
          SEVERITY[anomaly.severity] || SEVERITY.warning
        );
        diagnostic.source = "Autotype";
        diagnostic.code = anomaly.code;
        diagnostics.push(diagnostic);
      }
    }

    if (diagnostics.length > 0) diagnosticCollection.set(uri, diagnostics);
  }
}

function runCommand(shellCommand, label, onDone) {
  const root = workspaceRoot();
  if (!root) return;

  const shell = process.env.SHELL || "/bin/zsh";
  log(`[${new Date().toISOString()}] ${label}: ${shellCommand}`);

  cp.execFile(
    shell,
    ["-lc", shellCommand],
    { cwd: root, maxBuffer: 512 * 1024 * 1024, env: { ...process.env, BUNDLE_GEMFILE: path.join(root, "Gemfile") } },
    (runError, stdout, stderr) => {
      if (stderr && stderr.trim()) log(stderr.trim());
      if (runError) {
        log(`${label} failed: ${runError.message}`);
        vscode.window.showErrorMessage(`Autotype failed — open Output → Autotype for details`);
        setStatus("failed");
        if (onDone) onDone(runError);
        return;
      }
      try {
        ingestJson(stdout, label);
        if (onDone) onDone(null);
      } catch (parseError) {
        log(`${label} bad JSON: ${parseError.message}`);
        log(stdout.slice(0, 500));
        setStatus("bad JSON");
        if (onDone) onDone(parseError);
      }
    }
  );
}

function autotypeCommandPrefix() {
  return config().get("command", "autotype");
}

function refreshFile(relative) {
  if (!relative) return;
  if (running) {
    queuedFile = relative;
    return;
  }
  running = true;
  setStatus(path.basename(relative), true);

  const cmd = `${autotypeCommandPrefix()} "${relative}" --json`;
  runCommand(cmd, `file ${relative}`, () => {
    running = false;
    if (queuedFile) {
      const next = queuedFile;
      queuedFile = null;
      refreshFile(next);
    }
  });
}

function lookupMethods(uri) {
  if (!uri) return null;
  const root = workspaceRoot();
  const fsPath = normalizeKey(uri.fsPath);
  if (root) {
    const relative = normalizeKey(path.relative(root, uri.fsPath));
    if (methodsByFile.has(relative)) return methodsByFile.get(relative);
  }
  if (methodsByFile.has(fsPath)) return methodsByFile.get(fsPath);
  return null;
}

function refreshCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor || editor.document.languageId !== "ruby") return;
  const root = workspaceRoot();
  const fsPath = editor.document.uri.fsPath;
  let target = fsPath;
  if (root) {
    const relative = normalizeKey(path.relative(root, fsPath));
    if (relative && !relative.startsWith("..")) target = relative;
  }
  refreshFile(target);
}

function refreshWorkspace() {
  if (workspaceRunning) return;
  workspaceRunning = true;
  setStatus("workspace…", true);

  const globs = fileGlobs().map((glob) => `'${glob}'`).join(" ");
  const cmd = `${autotypeCommandPrefix()} $(git ls-files ${globs}) --json`;
  runCommand(cmd, "workspace", () => {
    workspaceRunning = false;
  });
}

function refresh() {
  refreshCurrentFile();
  if (config().get("workspaceRefresh", false)) refreshWorkspace();
}

function signatureSuffix(signature) {
  const separator = signature.indexOf(" : ");
  return separator === -1 ? signature : signature.slice(separator + 3);
}

function anomalyBadge(method) {
  const count = (method.anomalies || []).length;
  if (count === 0) return "";
  const errors = method.anomalies.filter((a) => a.severity === "error").length;
  return errors > 0 ? `  ⚠${count}` : `  ◦${count}`;
}

function hoverMarkdown(method) {
  const lines = ["```", method.signature, "```"];
  if (method.anomalies && method.anomalies.length > 0) {
    lines.push("**Anomalies**");
    for (const anomaly of method.anomalies) {
      lines.push(`- **${anomaly.code}** (${anomaly.severity}) ${anomaly.message}`);
    }
  }
  if (method.helpers && method.helpers.length > 0) {
    lines.push("**Universal types**");
    for (const helper of method.helpers) {
      const params = helper.parameters.length > 0 ? `<${helper.parameters.join(", ")}>` : "";
      lines.push(`- \`type ${helper.name}${params} = ${helper.definition}\``);
    }
  }
  if (method.constraints && method.constraints.length > 0) {
    lines.push("**Constraints**");
    for (const constraint of method.constraints) lines.push(`- \`${constraint}\``);
  }
  return new vscode.MarkdownString(lines.join("\n\n"));
}

function decorateEditor(editor) {
  if (!enabled || editor.document.languageId !== "ruby") return;
  const methods = lookupMethods(editor.document.uri);
  if (!methods) {
    editor.setDecorations(decorationType, []);
    return;
  }
  const decorations = [];
  for (const method of methods) {
    const line = method.line - 1;
    if (line < 0 || line >= editor.document.lineCount) continue;
    const hasError = (method.anomalies || []).some((a) => a.severity === "error");
    decorations.push({
      range: editor.document.lineAt(line).range,
      hoverMessage: hoverMarkdown(method),
      renderOptions: {
        after: {
          contentText: `  ⊢ ${signatureSuffix(method.signature)}${anomalyBadge(method)}`,
          color: new vscode.ThemeColor(hasError ? "editorWarning.foreground" : "editorCodeLens.foreground"),
          fontStyle: "italic"
        }
      }
    });
  }
  editor.setDecorations(decorationType, decorations);
}

function decorateVisibleEditors() {
  for (const editor of vscode.window.visibleTextEditors) decorateEditor(editor);
}

function findMethodAt(methods, line) {
  let best = null;
  for (const method of methods) {
    const start = method.line;
    const end = method.end_line || method.line;
    if (line < start || line > end) continue;
    if (!best || end - start < (best.end_line || best.line) - best.line) best = method;
  }
  return best;
}

function provideHover(document, position) {
  if (!enabled) return undefined;
  const methods = lookupMethods(document.uri);
  if (!methods) return undefined;

  const method = findMethodAt(methods, position.line + 1);
  if (method) {
    const line = method.line - 1;
    if (position.line === line) return new vscode.Hover(hoverMarkdown(method), document.lineAt(line).range);
  }

  const wordRange = document.getWordRangeAtPosition(position, /@?[a-zA-Z_][a-zA-Z0-9_]*[?!]?/);
  if (!wordRange || !method || !method.locals) return undefined;
  const word = document.getText(wordRange);
  const type = method.locals[word];
  if (!type) return undefined;

  const markdown = new vscode.MarkdownString();
  markdown.appendCodeblock(`${word} : ${type}`, "ruby");
  markdown.appendMarkdown(`in \`${method.name}\``);
  return new vscode.Hover(markdown, wordRange);
}

function clearAllDecorations() {
  for (const editor of vscode.window.visibleTextEditors) editor.setDecorations(decorationType, []);
}

function syncSettings() {
  anomaliesEnabled = config().get("anomalies.enabled", true);
}

function activate(context) {
  output = vscode.window.createOutputChannel("Autotype");
  decorationType = vscode.window.createTextEditorDecorationType({ isWholeLine: false });
  diagnosticCollection = vscode.languages.createDiagnosticCollection("autotype");
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = "autotype.refresh";
  statusBarItem.tooltip = "Click to refresh Autotype on the current file";
  syncSettings();

  context.subscriptions.push(
    output,
    decorationType,
    diagnosticCollection,
    statusBarItem,
    vscode.commands.registerCommand("autotype.refresh", refresh),
    vscode.commands.registerCommand("autotype.refreshWorkspace", refreshWorkspace),
    vscode.commands.registerCommand("autotype.toggle", () => {
      enabled = !enabled;
      if (enabled) decorateVisibleEditors();
      else clearAllDecorations();
      vscode.window.showInformationMessage(`Autotype ${enabled ? "enabled" : "disabled"}`);
    }),
    vscode.languages.registerHoverProvider({ language: "ruby" }, { provideHover }),
    vscode.window.onDidChangeVisibleTextEditors(decorateVisibleEditors),
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor && editor.document.languageId === "ruby") refreshCurrentFile();
    }),
    vscode.workspace.onDidOpenTextDocument((document) => {
      if (document.languageId === "ruby") refreshFile(relativePath(document.uri));
    }),
    vscode.workspace.onDidSaveTextDocument((document) => {
      if (document.languageId !== "ruby") return;
      clearTimeout(saveTimer);
      saveTimer = setTimeout(() => refreshFile(relativePath(document.uri)), 800);
    }),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("autotype")) {
        syncSettings();
        loadCache();
      }
    })
  );

  loadCache();
  refreshCurrentFile();
}

function deactivate() {
  if (diagnosticCollection) diagnosticCollection.dispose();
  if (statusBarItem) statusBarItem.dispose();
}

module.exports = { activate, deactivate };
