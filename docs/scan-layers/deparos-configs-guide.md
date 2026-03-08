# Module Configuration Guide

Custom modules control discovery behavior based on path patterns. Configure what tasks to create, which directories to skip, and how to prioritize work.

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration Structure](#configuration-structure)
- [Pattern Types](#pattern-types)
  - [Path-Level Patterns](#path-level-patterns)
  - [Segment-Level Patterns](#segment-level-patterns)
  - [File-Level Patterns](#file-level-patterns)
  - [Pattern Options](#pattern-options)
- [Actions](#actions)
  - [Control Flow](#control-flow)
  - [Task Creation](#task-creation)
  - [Task Blocking](#task-blocking)
- [Wordlist Sources](#wordlist-sources)
- [Built-in Modules](#built-in-modules)
- [Module Execution Order](#module-execution-order)
- [Examples](#examples)
- [Usage](#usage)

---

## Quick Start

```yaml
modules:
  enabled: true
  built_in:
    - wildcard
  custom:
    - name: my-module
      enabled: true
      priority: 10
      patterns:
        - type: path_suffix
          value: /admin/
      actions:
        tasks:
          - wordlist: observed_names
            extensions: [php, asp]
            priority: 0
```

---

## Configuration Structure

```yaml
modules:
  enabled: true           # Enable/disable entire module system
  built_in:               # Built-in modules to enable
    - wildcard            # Currently only wildcard is available
  disabled: []            # Modules to explicitly disable (overrides built_in)
  custom: []              # User-defined modules (see below)
```

### Custom Module Definition

```yaml
custom:
  - name: module-name             # Required: unique identifier
    description: Human readable   # Optional: description
    enabled: true                 # Optional: enable/disable (default: true)
    priority: 10                  # Optional: execution order (lower = first)
    patterns: []                  # Required: at least 1 pattern
    actions: {}                   # Optional: actions when matched
```

---

## Pattern Types

13 pattern types organized into 3 categories:

### Path-Level Patterns

Match against the **full URL path** (e.g., `/api/v1/users/admin/`).

| Type | Description | Example Value | Matches | Does NOT Match |
|------|-------------|---------------|---------|----------------|
| `path_contains` | Substring anywhere in path | `admin` | `/foo/admin/bar`, `/administrator/` | `/adm/panel/` |
| `path_prefix` | Path starts with value | `/api/` | `/api/v1/users`, `/api/` | `/v1/api/users` |
| `path_suffix` | Path ends with value | `/admin/` | `/panel/admin/`, `/admin/` | `/admin/users/` |
| `path_exact` | Exact path match | `/admin/` | `/admin/` only | `/admin`, `/admin/users/` |
| `path_regex` | Regex pattern on full path | `^/api/v\d+/` | `/api/v1/`, `/api/v123/` | `/api/latest/` |

### Segment-Level Patterns

Match against **individual path segments** (parts between `/`).

Given path `/foo/mybackup/bar`:
- Segments are: `foo`, `mybackup`, `bar`

| Type | Description | Example Value | Matches | Does NOT Match |
|------|-------------|---------------|---------|----------------|
| `segment_exact` | Exact segment match | `backup` | `/foo/backup/bar` | `/mybackup/`, `/backups/` |
| `segment_contains` | Substring in any segment | `backup` | `/mybackup/`, `/data-backup/` | `/bak/file` |
| `segment_prefix` | Segment starts with value | `admin` | `/adminpanel/foo` | `/superadmin/` |
| `segment_suffix` | Segment ends with value | `backup` | `/mybackup/foo` | `/backup123/` |
| `segment_regex` | Regex match on any segment | `^old` | `/old/`, `/old-data/` | `/folder/`, `/myold/` |

**`segment_regex` Usage:**

```yaml
# Match segments starting with "old" (avoids matching "folder")
- type: segment_regex
  value: "^old"

# Match segments containing "admin" as a word (not "administrator")
- type: segment_regex
  value: "\\badmin\\b"
```

**Key Difference:**
- `path_contains: backup` matches `/backup` anywhere in path string
- `segment_contains: backup` matches only segments containing `backup`

### File-Level Patterns

Match against **filename or extension**.

| Type | Description | Example Value | Matches | Does NOT Match |
|------|-------------|---------------|---------|----------------|
| `file_extension` | File extension (case-insensitive) | `js` or `.js` | `/app.js`, `/App.JS` | `/app.jsx` |
| `file_name` | Exact filename match | `config.json` | `/any/path/config.json` | `/config.yaml` |
| `file_glob` | Glob pattern on filename | `*.min.js` | `/foo/app.min.js` | `/app.js` |

**Notes:**
- `file_extension` accepts both `js` and `.js` (normalized internally)
- `file_extension` is case-insensitive: `.JS` matches `.js`
- `filepath.Ext` only returns last extension: `/bundle.min.js` → `.js`

### Pattern Options

```yaml
patterns:
  - type: segment_contains
    value: backup
    negated: false      # Optional: invert match (default: false)
    match_files: false  # Optional: file patterns in directory context
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `negated` | bool | `false` | Invert the match. Pattern matches when value is NOT found. |
| `match_files` | bool | `false` | For file patterns (`file_extension`, `file_name`, `file_glob`), also apply during directory matching. |

**Negated Pattern Example:**

```yaml
# Match paths that do NOT contain "api"
- type: path_contains
  value: api
  negated: true
```

---

## Actions

Actions define what happens when a pattern matches.

```yaml
actions:
  stop_recursion: false       # Stop recursive discovery
  skip_default_logic: false   # Skip default task generation
  tasks: []                   # Tasks to create
  block_task_patterns: []     # Regex patterns to block tasks
```

### Control Flow

| Action | Type | Description |
|--------|------|-------------|
| `stop_recursion` | bool | Stop recursive discovery into matched directories. No further subdirectories explored. |
| `skip_default_logic` | bool | Skip default task generation. Module handles all task creation. |

```yaml
actions:
  stop_recursion: true      # Don't recurse into /images/
  skip_default_logic: true  # Don't generate default tasks
```

### Task Creation

Create explicit tasks when module matches. Each task specifies:
- **wordlist**: Where to get words from
- **extensions**: File extensions to test (required, empty `[]` = no extension)
- **priority**: Task priority 0-14 (optional, default 6)

```yaml
actions:
  tasks:
    - wordlist: observed_names
      extensions: [js, mjs, cjs]
      priority: 1
    - wordlist: short_files
      extensions: [php, asp]
      priority: 5
```

**Task Priority Values:**

| Value | Priority Level |
|-------|----------------|
| `0` | Highest (execute first) |
| `1-5` | High priority |
| `6` | Default |
| `7-10` | Normal |
| `11-14` | Low priority |

### Task Blocking

Block tasks matching regex patterns. Checked during `ShouldAddTask`.

```yaml
actions:
  block_task_patterns:
    - "/images/"      # Block any path containing /images/
    - "/fonts/"       # Block any path containing /fonts/
    - "\.css$"        # Block paths ending in .css
```

**Note:** These are regex patterns matched against task `BasePath`.

---

## Wordlist Sources

Available wordlist sources for task creation:

| Source | Description |
|--------|-------------|
| `observed_names` | Names discovered during scan (dynamic) |
| `observed_paths` | Paths discovered during scan (dynamic) |
| `short_files` | Short file wordlist from global config |
| `long_files` | Long file wordlist from global config |
| `short_dirs` | Short directory wordlist from global config |
| `long_dirs` | Long directory wordlist from global config |
| `custom` | Custom wordlist (file or inline) |

### Custom Wordlist

For `custom` wordlist, provide either `file` or `inline`:

```yaml
tasks:
  - wordlist: custom
    extensions: []
    priority: 0
    file: /path/to/wordlist.txt  # Path to wordlist file
```

```yaml
tasks:
  - wordlist: custom
    extensions: []
    priority: 0
    inline:                      # Inline word list
      - graphql
      - graphiql
      - playground
```

---

## Built-in Modules

### wildcard

Detects and handles wildcard prefix responses. When a server returns identical responses for `/admin`, `/adminxyz`, `/admin123`, it blocks further tasks with that prefix.

```yaml
built_in:
  - wildcard
```

**Features:**
- Prefix-based detection with fingerprint comparison
- Automatic queue cleanup (removes duplicate tasks, keeps one for recursion)
- Threshold-based confirmation (default: 3 paths with same prefix)

This is the only built-in module. Previous builtins (backup, js, static) are now available as YAML examples in `modules.yaml`.

---

## Module Execution Order

1. Modules execute in `priority` order (lower = first)
2. Multiple modules can match the same path
3. Results are merged:
   - Boolean flags: OR (any true → true)
   - Tasks: appended (all tasks from all modules collected)
   - Block patterns: appended

**Example execution for `/static/js/app.js`:**

| Order | Module | Priority | Matches? | Result |
|-------|--------|----------|----------|--------|
| 1 | wildcard | 5 | No | - |
| 2 | backup | 10 | No | - |
| 3 | static | 40 | Yes | stop_recursion=true |
| 4 | js | 50 | Yes | tasks=[{observed_names, js extensions}] |

Final: `stop_recursion=true`, tasks collected from js module

---

## Examples

### Backup Directories

Match directories containing backup keywords, create high-priority tasks with backup extensions.

```yaml
- name: backup
  description: Backup/archive directories
  priority: 10
  patterns:
    - type: segment_contains
      value: backup
    - type: segment_contains
      value: bak
    - type: segment_contains
      value: dump
    - type: segment_contains
      value: archive
  actions:
    tasks:
      - wordlist: observed_names
        extensions: [sql, tar, tar.gz, gz, zip, bak, dump]
        priority: 0
      - wordlist: short_files
        extensions: [sql, tar, gz, zip, bak]
        priority: 4
```

### JavaScript Directories

Match JS directories and files, test with JS-specific extensions.

```yaml
- name: js
  description: JavaScript directories and files
  priority: 50
  patterns:
    - type: path_suffix
      value: /js/
    - type: path_suffix
      value: /scripts/
    - type: file_extension
      value: js
  actions:
    tasks:
      - wordlist: observed_names
        extensions: [js, mjs, cjs, jsx, ts, tsx, min.js, bundle.js, map]
        priority: 1
```

### Static Assets (Block)

Block static asset directories entirely.

```yaml
- name: static
  description: Static asset directories - stop recursion
  priority: 40
  patterns:
    - type: path_suffix
      value: /images/
    - type: path_suffix
      value: /img/
    - type: path_suffix
      value: /fonts/
    - type: path_suffix
      value: /css/
  actions:
    stop_recursion: true
    skip_default_logic: true
    block_task_patterns:
      - "/images/"
      - "/img/"
      - "/fonts/"
      - "/css/"
```

### API Versioning

Match versioned API paths with regex.

```yaml
- name: api-versioned
  description: Versioned API endpoints
  priority: 15
  patterns:
    - type: path_regex
      value: ^/api/v\d+/
  actions:
    tasks:
      - wordlist: observed_names
        extensions: ["", json, xml]  # Empty string = no extension
        priority: 0
```

### Skip node_modules

Completely skip node_modules directories.

```yaml
- name: skip-node-modules
  description: Skip node_modules directories
  priority: 5
  patterns:
    - type: segment_exact
      value: node_modules
  actions:
    stop_recursion: true
    skip_default_logic: true
    block_task_patterns:
      - "node_modules"
```

### WordPress Detection

Target WordPress installations.

```yaml
- name: wordpress
  description: WordPress directories
  priority: 30
  patterns:
    - type: segment_contains
      value: wp-content
    - type: segment_contains
      value: wp-admin
  actions:
    tasks:
      - wordlist: observed_names
        extensions: [php, php~, php.bak, txt, log]
        priority: 1
```

### GraphQL with Custom Wordlist

Inline wordlist for GraphQL discovery.

```yaml
- name: graphql
  description: GraphQL endpoint discovery
  priority: 10
  patterns:
    - type: path_contains
      value: graphql
    - type: path_suffix
      value: /gql/
  actions:
    skip_default_logic: true
    tasks:
      - wordlist: custom
        extensions: []  # No extension
        priority: 0
        inline:
          - graphql
          - graphiql
          - playground
          - subscriptions
          - explorer
          - schema
```

### Negated Pattern Example

Match all paths EXCEPT those containing "api".

```yaml
- name: non-api
  description: Non-API endpoints
  priority: 100
  patterns:
    - type: path_contains
      value: api
      negated: true
  actions:
    tasks:
      - wordlist: observed_names
        extensions: [html, htm]
        priority: 6
```

---

## Usage

### CLI Flag

```bash
deparos -u http://target.com --module-config modules.yaml
```

### Main Config File

```yaml
target:
  url: http://target.com

modules:
  enabled: true
  built_in:
    - wildcard
  custom:
    - name: my-module
      enabled: true
      priority: 10
      patterns:
        - type: path_suffix
          value: /admin/
      actions:
        tasks:
          - wordlist: observed_names
            extensions: [php, asp]
            priority: 0
```

### Disable All Modules

```yaml
modules:
  enabled: false
```

### Only Custom Modules (No Built-in)

```yaml
modules:
  enabled: true
  built_in: []  # Empty = none enabled
  custom:
    - name: my-custom-module
      # ...
```
