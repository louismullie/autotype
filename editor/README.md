# Autotype editor extension

Inline inferred Ruby method signatures powered by the [autotype](https://github.com/doximity/autotype) gem.

## Install

From the gem repo:

```bash
cd editor
npx --yes @vscode/vsce package -o autotype.vsix
cursor --install-extension autotype.vsix
```

## Configuration

| Setting | Default | Description |
| --- | --- | --- |
| `autotype.command` | `autotype` | Inference command (use `bundle exec autotype` in Bundler projects) |
| `autotype.fileGlobs` | `app/**/*.rb`, … | Globs passed to `git ls-files` |
| `autotype.cacheFile` | `tmp/autotype_cache.json` | Workspace cache for fast startup |

## Commands

- **Autotype: Refresh** — re-run inference
- **Autotype: Toggle Inline Signatures** — show/hide ghost-text signatures
