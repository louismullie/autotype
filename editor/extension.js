"use strict";

const vscode = require("vscode");
const cp = require("child_process");
const fs = require("fs");
const path = require("path");

let methodsByFile = new Map();
let decorationType;
let output;
let enabled = true;
let running = false;
let queued = false;
let saveTimer;

function config() {
  return vscode.workspace.getConfiguration("autotype");
}

function workspaceRoot() {
  const folders = vscode.workspace.workspaceFolders;
  return folders && folders.length > 0 ? folders[0].uri.fsPath : undefined;
}

function cacheFile(root) {
  return path.join(root, config().get("cacheFile", "tmp/autotype_cache.json"));
}

function fileGlobs() {
  return config().get("fileGlobs", ["app/**/*.rb", "lib/**/*.rb", "config/**/*.rb"]);
}

function loadCache() {
  const root = workspaceRoot();
  if (!root) return;
  try {
    const raw = fs.readFileSync(cacheFile(root), "utf8");
    methodsByFile = new Map(Object.entries(JSON.parse(raw)));
    output.appendLine(`loaded cached signatures for ${methodsByFile.size} files`);
    decorateVisibleEditors();
  } catch (_error) {
    output.appendLine("no signature cache yet; waiting for first typecheck");
  }
}

function writeCache(json) {
  const root = workspaceRoot();
  if (!root) return;
  try {
    const file = cacheFile(root);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, json);
  } catch (error) {
    output.appendLine(`could not write cache: ${error.message}`);
  }
}

function refresh() {
  const root = workspaceRoot();
  if (!root) return;
  if (running) {
    queued = true;
    return;
  }
  running = true;

  const commandName = config().get("command", "autotype");
  const globs = fileGlobs().map((glob) => `'${glob}'`).join(" ");
  const command = `${commandName} $(git ls-files ${globs}) --json`;
  output.appendLine(`[${new Date().toISOString()}] running ${commandName}...`);

  const shell = process.env.SHELL || "/bin/zsh";
  cp.execFile(
    shell,
    ["-lc", command],
    { cwd: root, maxBuffer: 512 * 1024 * 1024 },
    (runError, json) => {
      running = false;
      if (runError) {
        output.appendLine(`autotype failed: ${runError.message}`);
        return;
      }
      try {
        methodsByFile = new Map(Object.entries(JSON.parse(json)));
        output.appendLine(`loaded signatures for ${methodsByFile.size} files`);
        writeCache(json);
        decorateVisibleEditors();
      } catch (parseError) {
        output.appendLine(`bad JSON from autotype: ${parseError.message}`);
      }
      if (queued) {
        queued = false;
        refresh();
      }
    }
  );
}

function signatureSuffix(signature) {
  const separator = signature.indexOf(" : ");
  return separator === -1 ? signature : signature.slice(separator + 3);
}

function hoverMarkdown(method) {
  const lines = ["```", method.signature, "```"];
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
  const root = workspaceRoot();
  if (!root) return;
  const relative = path.relative(root, editor.document.uri.fsPath);
  const methods = methodsByFile.get(relative);
  if (!methods) {
    editor.setDecorations(decorationType, []);
    return;
  }
  const decorations = [];
  for (const method of methods) {
    const line = method.line - 1;
    if (line < 0 || line >= editor.document.lineCount) continue;
    decorations.push({
      range: editor.document.lineAt(line).range,
      hoverMessage: hoverMarkdown(method),
      renderOptions: {
        after: {
          contentText: `  ⊢ ${signatureSuffix(method.signature)}`,
          color: new vscode.ThemeColor("editorCodeLens.foreground"),
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
  const root = workspaceRoot();
  if (!root) return undefined;
  const relative = path.relative(root, document.uri.fsPath);
  const methods = methodsByFile.get(relative);
  if (!methods) return undefined;

  const wordRange = document.getWordRangeAtPosition(position, /@?[a-zA-Z_][a-zA-Z0-9_]*[?!]?/);
  if (!wordRange) return undefined;
  const word = document.getText(wordRange);

  const method = findMethodAt(methods, position.line + 1);
  if (!method || !method.locals) return undefined;
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

function activate(context) {
  output = vscode.window.createOutputChannel("Autotype");
  decorationType = vscode.window.createTextEditorDecorationType({ isWholeLine: false });

  context.subscriptions.push(
    output,
    decorationType,
    vscode.commands.registerCommand("autotype.refresh", refresh),
    vscode.commands.registerCommand("autotype.toggle", () => {
      enabled = !enabled;
      if (enabled) decorateVisibleEditors();
      else clearAllDecorations();
      vscode.window.setStatusBarMessage(`Autotype ${enabled ? "on" : "off"}`, 2000);
    }),
    vscode.languages.registerHoverProvider({ language: "ruby" }, { provideHover }),
    vscode.window.onDidChangeVisibleTextEditors(decorateVisibleEditors),
    vscode.workspace.onDidSaveTextDocument((document) => {
      if (document.languageId !== "ruby") return;
      clearTimeout(saveTimer);
      saveTimer = setTimeout(refresh, 1500);
    }),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("autotype")) loadCache();
    })
  );

  loadCache();
  refresh();
}

function deactivate() {}

module.exports = { activate, deactivate };
