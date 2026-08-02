# Autotype

Syntax-less Ruby type inference: analyze method bodies with [Prism](https://github.com/ruby/prism), accumulate send capabilities, and solve to fixed-point types without requiring source annotations.

## Install

```bash
gem install autotype
```

Or from source:

```bash
bundle exec rake native:compile
bundle exec rspec
```

## CLI

```bash
autotype app/**/*.rb --json
autotype lib/**/*.rb --html typedoc.html
```

Enable the native C solver priming pass:

```bash
AUTOTYPE_NATIVE=1 autotype app/**/*.rb --json
```

No config file is required. Autotype discovers actor port wiring, emit patterns, entity factories, and type file locations from your Ruby source.

## Optional overrides

When heuristics get something wrong, add `autotype.yml` (see `autotype.example.yml`):

```yaml
skip:
  - vendor/**

types:
  members:
    query: MyApp::Entities::Query   # only when name conventions fail
```

Set `AUTOTYPE_CONFIG` or pass `--config PATH` to point at a non-default location.

### What is discovered automatically

| Concern | How |
| --- | --- |
| Actor DSL | `input` / `output` / `option` calls at class level |
| Port handler | Instance method with `from:` (or `source:`) keyword — prefers `process` |
| Output emit | `emit(x, to: :port)`-style sends on actor classes |
| Options hash | Classes declaring `option` and reading `options` |
| Entity factories | `Entity.define`, `*::Entity.define`, `Data.define`, `Struct.new` |
| Entity file paths | Glob `{snake}.rb` under project root; match constant definition |
| Member / option types | Common field names (`name`, `step`, `base_url`, …) |
| Lifecycle methods | `on_*` methods on actor classes → `nil` return |
| Structured prefixes | Namespaces seen in port `type:` constants (e.g. `MyApp::Entities::`) |

Everything in the old verbose config (`dsl`, `wiring`, `pipeline`, `structured`, `locators`, `self_types`) is inferred unless you override it.

## Ruby API

```ruby
require "autotype"

Autotype.run(["app/models/user.rb", "--json"])
```

## Native extension

The optional C extension accelerates the builtin fixed-point solver. It compiles automatically on gem install via `ext/autotype/extconf.rb`, sharing sources with `native/autotype/`.

```bash
cd native/autotype && make test
```

## Editor extension

The Cursor / VS Code extension lives in `editor/`. It runs `autotype --json` and renders inline signatures.

```bash
cd editor
npm install
```

Configure workspace settings to point at the `autotype` executable on your PATH, or rely on the bundled `exe/autotype` via `bundle exec`.

## License

MIT
