# Changelog

## [Unreleased]

- **Debugger: `/output <file>` command** — echoes all input/output (results, queued commands, sent messages) to file with `[timestamp]` prefix. `/output` (no arg) shows current file. File is opened and closed per write (no persistent handle)
- **Debugger: browser polling timestamp** — `lastId` initialised to `Number(new Date)` instead of `-1` to avoid stale command replay on browser reconnect
- **Debugger: per-connection consumed tracking** — `_to_consumed_key()` keys consumed set by `{id}_{conn_name}` instead of bare id, preventing cross-browser command duplication
- **Debugger: consumed-at-poll-time** — consumed markers moved from result handler to poll handler; commands flagged consumed when polled rather than when result received
- **WebSocket: unknown opcode anomaly** — unknown opcodes (e.g. 0x3-0x7, 0xB-0xF) now fire an anomaly event

## [0.8.0] — 2026-05-22

- **Debugger encryption** (`--debugger-key`): AES-256-GCM-style via SHA-256 + XOR+MAC. Stdlib-only on server, pure-JS SHA-256 on browser (no WebCrypto dependency). Wire format: `base64(nonce).base64(ciphertext).base64(mac)`
- **Collection commands** (`/run`, `/load`): loadable JSON configs for reusable JS snippets. JSON schema validation, file resolution (debugger dir → CWD → absolute), positional arg substitution (`{0}`, `{1}`, ...)
- **Fix: debugger XOR decrypt error** — corrected decryption logic. The bug was in how `++u8array[i]` in a JavaScript Uint8Array returns 256 instead of wrapping around to 0 like in C. To be clear, it _does_ wrap around to 0, but the value returned by prefix increment is 256.
- **Flag rename**: `--ignore-common-headers` / `-i` replaced by `--show-common-headers`; common headers now hidden by default (inverted behavior). This is a breaking change.
- **File server nav**: upload form links back to file list and vice versa; `max_size` uses computed expression; JS template literal escaping cleaned up
- **Debugger result timestamps**: result display now shows `[timestamp]` prefix
- **Fix: request body handling** — resolved bug on requests with body > 8192 bytes due to Python socket file object's internal buffering. Also refactored `TimeoutBufferedReader`. By hand.

## [0.7.2] — 2026-05-20

- **Debugger TUI UX rewrite**: replace `rich.Console` with `prompt_toolkit` as it allows printing above the cursor; `/help`, `/conns`, `/target`, `/broadcast`, `/clear` internal commands; connection tracking via `_connections` dict; command targeting by browser name; `--hostname` for no-origin contexts

## [0.7.1] — 2026-05-14

- **Mixin variable management refactor** — `HttpMossServer` now directly inherits `ThreadingHTTPServer`; eliminated `setattr` field copy divergence; removed backward-compat aliases `self.server` and `self.instance`; removed `_run_http_server` classmethod
- **SSRF detector example** (`examples/cve_2026_21967.py`): per-target 32-hex correlation IDs, `--filter userid` for credential extraction, `--output FILE` for CSV, `--certfile`/`--keyfile` for HTTPS polyglot mode
- **File/upload merge**: separate `sfile` and `upload` extensions merged into single `file.py`; upload API example added

## [0.7.0] — 2026-05-13

- **Multiple filter support** (`--filter` accepts multiple patterns)
- **Pastebin fixes** — HTTPS warning hidden when `--https` not enabled; fixed subtlecrypto detection

## [0.6.5] — 2026-05-11

- **WebSocket OAST extension**: `-e websocket` enables WS without `--websockets` flag; `TimeoutBufferedReader.drain()` for pre-read bytes recovery; dedicated `handle_websocket` handler with `ws_event=True`; `--ws-path` restriction; WSS (TLS) support; WS tester HTML page (`--websocket-tester`)
- **WS bug fixes**: added missing `correlation_id` to WS `push_event()`; fixed `ws_event` field missing from JSONL output; caught `ConnectionAbortedError` in `handle()`
- **Interactive JS Debugger extension** (`debugger.py`): `GET /{debugger_path}` serves eval-able JS payload; browser polls `/pending` every 2s; TUI input thread at `debug [id]>` prompt; `--debugger-path` with `{RANDOM}` placeholder; `--debugger-no-input` for testing; CORS support; `--no-log` flag on server
- **Auth extension**: basic/bearer auth middleware
- **Pastebin: smart encryption fallback**: AES-GCM via `crypto.subtle`, falls back to AES-CBC via `aes.js`; HTTPS redirect for GCM pastes accessed over HTTP; conditional AES script loading
- **Pastebin: headless browser tests** via Playwright; sanity checks
- **`--pastebin-password`** flag for hardcoded password convenience mode (server-side encrypt/decrypt)
- **`--pastebin-store-password-in-browser`** for localStorage password saving
- **Server class merge**: merged `HttpMossServer` and `ThreadingHTTPServer` classes
- **Fixed HTML bug**: missing `</script>` tag in `pastebin.html`
- **`pastebin_max_size removed`** — covered by core `MAX_BODY_SIZE`

## [0.6.4] — 2026-05-08

- **Gzip MIME expansion**: added text/csv, text/xml, text/plain, application/javascript, application/json to gzip-compressible list
- **Buffer emptiness fix**: `is_buffer_empty()` corrected to reference `self._pastreadbuffer`/`self._buffer` instead of `self.rfile._pastreadbuffer`/`self.rfile._buffer`
- **Keep-alive fix** — better handling of persistent connections
- **Pastebin: AES-CBC encryption** via `crypto.subtle`; server-side XOR cipher for HTTP fallback
- **Pastebin: hardcoded password** (`--pastebin-password`) convenience mode
- **Pastebin: HTTP fallback** — warning when accessing via HTTP; crypto API disabled detection
