# MOSS (Modular Offensive Security Server)

A multifunctional server for all your offensive security testing: OAST, DLP/Exfiltration, Automation, Pastebin, Honeypot. (Sorry, no C2 stuff here. Yet.)

Cut time during engagements, exams, and bug bounty!

## Use Cases

- Out-of-Band (OOB) Application Security Testing (OAST) with a focus on HTTP
    - SSRF
    - Blind Attacks (XSS/SQLi/RCE)
- Automation and Exploit Development via a Programmatic Interface and Structured Output
- HTTP Honeypots (maybe), with socket-level reporting
- Additional use cases covered by extensions:
    - DLP/Exfiltration
    - Secure (End-to-End Encrypted) Pastebin
    - Browser-Based C2 Agent

The general intended use is to host this on a VPS or— in case you're testing an internal network— your own machine.

## Features

- [x] custom response
    - [x] customise status, headers, body
    - [x] gzip static files to save bandwidth and load stuff faster (`--gzip`)
- [x] OAST features
    - [x] match/filter interesting requests by regex (`--filter`)
    - [x] extract correlation ID by regex (`--correlation`)
- [x] comprehensive JSONL logging
- [x] cool network shenanigans:
    - [x] polyglot HTTP (supports both HTTP/HTTPS on the same port) (`--https`)
    - [x] log HTTP anomalies (unsupported method, bad version, potential port scan, and more)
    - [x] detects HTTP protocol variants (HTTP proxy, HTTP proxy over SSL, HTTPS tunnel proxy) (NOTE: currently only detects, but doesn't parse or follow through)
- [x] websocket OAST support (`-e websocket`)
- [x] modular extensions, include what you need
    - [x] send notifications to **Discord** webhook on match (`-e notify`)
    - [x] protect endpoints with **auth** middleware (basic, bearer) (`-e auth`)
    - [x] in-memory **pastebin** (with end-to-end encryption) (`-e pastebin`)
    - [x] robust **stealthy** exfiltration module customisable via a JSON DSL (`-e stealthnet`)
    - [x] serve/upload files (`-e file`)
    - [x] remote JS debugging, or in other words, a browser-based C2 agent (`-e debugger`)
- [x] store settings in a **config file** to keep your command line clean (`@config.txt`)
- [x] **blocks** nosy scanners to reduce noise
- [x] DoS protection (hopefully)

Additional Perks:

- [x] zero dependencies! (pure Python)[^deps]
- [x] core OAST comes in a single Python file; easy to setup, easy to configure, easy to hack(?)
- [x] pretty ANSI colours!

[^deps]: Zero dependencies... with the exception of some optional packages to enhance your experience. (Check pyproject.toml or noodle around to find out more.)

## Quick Start

> [!IMPORTANT]
> MOSS requires Python 3.10 or above.

### One-File, OAST

```shell
wget https://github.com/TrebledJ/moss/blob/main/moss.py
python3 moss.py
```

Done. This spins up a HTTP listener on port 8000, enough for simple OAST.

No hassle. Quick-n-dirty. Simple.

### pip

```shell
pip install git+https://github.com/TrebledJ/moss
moss -h
```

This installs MOSS as a Python package, and also conveniently supplies it as a command.

### CheatSheet

You may be interested in these other options:

**Basic**: Custom port

```shell
moss -p 80
```

**OpSec**: Override the default server header

```shell
moss --server Apache
```

**Basic**: Modify default response status, headers, and body

```shell
moss --status-code 404 -H 'X-Frame-Options: DENY' --body 'Hello world!'
```

**Basic**: Filter for specific requests

```shell
moss --filter /api/v1/callback
```

**Basic**: Simple logging (one line per event) and output JSONL

```shell
moss --simple --jsonl output.jsonl
```

**OpSec**: Enable HTTPS polyglot (see the section [HTTPS Support](#https-support) for guidance)

```shell
moss --https --certfile cert.pem --keyfile key.pem
```

**OpSec**: Protect other extensions with auth

```shell
moss -e auth file --basic-auth moss:isawesome
```

**Ext**: MOSS automatically looks for extensions under the pre-packaged `ext/` folder. You can also leave out the `.py` or load custom extensions!

```shell
moss -e auth file ./mycustomext.py --basic-auth moss:isawesome
```

**Ext**: Enable the pastebin extension and access it at `http://127.0.0.1:8000/pastebin`

```shell
moss -e pastebin
```

**Ext**: Enable the file/upload server extension and access it at `http://127.0.0.1:8000/upload`

```shell
moss -e file
```

**Ext**: Enable a file server with directory listing and access it at `http://127.0.0.1:8000/files/{YOUR_FILE}`

```shell
moss -e file -d optional/path/to/folder --file-index
```

**Ext**: Enable Discord notifications on filtered requests

```shell
moss -e notify --filter 'password=' --notify discord --notify-on match --webhook-url https://discord.com/api/webhooks/.../...
```

**Ext**: Enable a stealthy upload service and access it at `http://127.0.0.1:8000/sneakers`

```shell
moss -e stealthnet --file-index
```


## Options

Explore a plethora of options!

```
moss -e auth pastebin debugger file notify stealthnet websocket -h
usage: moss
       [-h] [--ext EXT [EXT ...]] [--version] [-v] [--bind HOST]    
       [--port PORT] [--host HOSTNAME] [--server SERVER_HEADER]     
       [--header HEADERS] [--minify-js] [--gzip]
       [--status-code DEFAULT_STATUS_CODE]
       [--mime-type DEFAULT_MIME_TYPE] [--body DEFAULT_BODY]        
       [--index] [--filter FILTER_REGEX]
       [--correlation CORRELATION_REGEX] [--output-all]
       [--ignore-common-headers] [--jsonl JSONL_FILE]
       [--no-anomaly] [--no-log] [--simple] [--https]
       [--https-only] [--certfile CERTFILE] [--keyfile KEYFILE]     
       [--block-scanners] [--token-auth TOKEN_AUTH]
       [--basic-auth BASIC_AUTH] [--pastebin-path PASTEBIN_PATH]    
       [--pastebin-fixed PASTEBIN_FIXED]
       [--pastebin-store-password-in-browser PASTEBIN_STORE_PASSWORD_IN_BROWSER]
       [--pastebin-password PASTEBIN_PASSWORD]
       [--debugger-path DEBUGGER_PATH] [--debugger-no-input]        
       [--debugger-id-length DEBUGGER_RANDOM_ID_LENGTH]
       [--debugger-minify-js]
       [--file-url-path FILESERVER_URL_PATH]
       [--file-directory DIRECTORY]
       [--upload-url-path UPLOAD_URL_PATH]
       [--upload-dir UPLOAD_DIR] [--max-size MAX_SIZE]
       [--file-index] [--stealth-path STEALTH_PATH]
       [--stealth-profile STEALTH_PROFILE_PATH]
       [--stealth-no-validate]
       [--stealth-upload-to STEALTH_UPLOAD_TO] [--ws-path WS_PATH]  
       [--websocket-tester WEBSOCKET_TESTER] [--notify {discord}]   
       [--notify-on {match,correlation,anomaly,all}]
       [--webhook-url WEBHOOK_URL] [--id IDENTIFIER]

Simple, modular offensive HTTP server by TrebledJ, v0.7.1

options:
  -h, --help            show this help message and exit
  --ext, -e EXT [EXT ...]
                        Load extensions (Python files). Works with  
                        bash file glob/expansion, e.g. -e
                        ext/file.py (default: [])
  --version, -V         show program's version number and exit      
  -v                    Verbosity. -v for INFO, -vv for DEBUG       
                        messages. (default: 0)
  --bind, -b HOST       Bind to this address (e.g. 0.0.0.0 to       
                        listen on all interfaces; 127.0.0.1 to      
                        listen only on localhost) (default:
                        0.0.0.0)
  --port, -p PORT
  --host, --hostname HOSTNAME
                        Hostname which resolves to the server       
                        (e.g. example.com). This is completely      
                        optional and used by some extensions to     
                        resolve the host (default: None)

response:
  --server SERVER_HEADER
                        Server header in response. Special values:  
                        random, none (default: moss
                        (https://github.com/TrebledJ/moss))
  --header, -H HEADERS  Headers to include in server output. You    
                        can specify multiple of these, e.g. -H      
                        'Set-Cookie: a=b' -H 'Content-Type:
                        application/json' (default: [])
  --minify-js           Enable minification on large JavaScript     
                        responses (default: False)
  --gzip                Enable gzip on static file extensions for   
                        lower network latency (default: False)      
  --status-code, -S DEFAULT_STATUS_CODE
                        The default status code to return
                        (default: 200)
  --mime-type, -M DEFAULT_MIME_TYPE
                        The default mime type to return (default:   
                        text/html)
  --body DEFAULT_BODY   The default content to return. This could   
                        be a file, which will be loaded (default:   
                        )
  --index               Enable an index page which lists the        
                        services enabled (default: False)

matching:
  --filter FILTER_REGEX
                        Match request line, headers, or body        
                        (supports multiple filters, OR'd)
                        (default: [])
  --correlation, -r CORRELATION_REGEX
                        Extract correlation ID based on regex,      
                        this works independently of the filter      
                        (default: )

logging:
  --output-all          Output all HTTP requests, including those   
                        that don't match the filter (default:       
                        False)
  --ignore-common-headers, -i
                        Exclude common request headers from
                        display. This does not affect jsonl output  
                        (default: False)
  --jsonl, -o JSONL_FILE
                        Output file path for JSONL logging (one     
                        JSON event per line). Use `--jsonl -` to    
                        output to stdout (default: None)
  --no-anomaly          Do not log anomalies (default: False)       
  --no-log              Do not log anything entirely (default:      
                        False)
  --simple              Use simple logging, one line per event      
                        (default: False)

https:
  --https               Enable HTTPS polyglot support (default:     
                        False)
  --https-only          Force HTTPS, ignore raw HTTP (default:      
                        False)
  --certfile CERTFILE   Public key (default: None)
  --keyfile KEYFILE     Private key (default: None)

security:
  --block-scanners      Enables automatic blocking of IPs which     
                        behave like scanners. To unblock, restart   
                        the server lol (default: False)

auth (ext/auth.py):
  --token-auth TOKEN_AUTH
                        Use the provided bearer token. Special      
                        values: generate (generates a token which   
                        will be printed to console or can be        
                        programmatically fetched via a method)      
                        (default: None)
  --basic-auth BASIC_AUTH
                        Basic authentication in the format
                        username:password (default: None)

pastebin (ext/pastebin.py):
  --pastebin-path PASTEBIN_PATH
                        HTTP path which accepts pastebin payloads   
                        (default: /pastebin)
  --pastebin-fixed PASTEBIN_FIXED
                        Write the pastebin to a fixed path
                        (default: None)
  --pastebin-store-password-in-browser PASTEBIN_STORE_PASSWORD_IN_BROWSER
                        Save the encryption password to browser     
                        localStorage in PLAIN TEXT. The string      
                        passed to this argument will be used as     
                        the localStorage key. NOTE: This option     
                        has been provided for convenience.
                        (default: )
  --pastebin-password PASTEBIN_PASSWORD
                        Hardcode a password for pastebin
                        encryption. NOTE: This option has been      
                        provided for convenience and essentially    
                        nullifies end-to-end encryption. (default:  
                        None)

debugger (ext/debugger.py):
  --debugger-path DEBUGGER_PATH
                        URL path for the interactive debugger JS    
                        payload. Use {RANDOM} to insert a random    
                        ID in the path (default:
                        /debugger/{RANDOM})
  --debugger-no-input   Disable the TUI input thread (for testing)  
                        (default: False)
  --debugger-id-length DEBUGGER_RANDOM_ID_LENGTH
                        The length of the random ID. Consider       
                        using the --block-scanners flag to
                        mitigate against brute-forcing. Set to 0    
                        to replace {RANDOM} with nothing (default:  
                        6)
  --debugger-minify-js  Minify the debugger JS payload using        
                        rjsmin (default: False)

fileserver (ext/file.py):
  --file-url-path FILESERVER_URL_PATH
                        The HTTP base path to access files. A base  
                        path of /static means files can be
                        accessed through
                        http://HOSTNAME:PORT/static (default:       
                        /files)
  --file-directory, -d DIRECTORY
                        The local directory to serve files from,    
                        or [[memory]] for in-memory mode (default:  
                        None)
  --upload-url-path UPLOAD_URL_PATH
                        HTTP path which accepts upload payloads     
                        (default: /upload)
  --upload-dir, -ud UPLOAD_DIR
                        Directory to store uploaded files
                        (default: same as --file-directory)
  --max-size MAX_SIZE   Max upload file size in bytes (default:     
                        10485760)
  --file-index          Enable an index page listing files within   
                        the directory (default: False)

stealthyupload (ext/stealthnet.py):
  --stealth-path STEALTH_PATH
                        HTTP path which accepts upload payloads     
                        (default: /sneakers)
  --stealth-profile STEALTH_PROFILE_PATH
                        The stealth profile to use (default:        
                        profile.json)
  --stealth-no-validate
                        Skip JSON schema validation. I too like to  
                        live dangerously. Note that passing this    
                        option does not suppress profile parsing    
                        errors, such as missing variables.
                        (default: False)
  --stealth-upload-to STEALTH_UPLOAD_TO
                        Store uploaded files in this directory      
                        (default: dest)

websocket (ext/websocket.py):
  --ws-path WS_PATH     Specific path for WebSocket connections     
                        (default: any path)
  --websocket-tester WEBSOCKET_TESTER
                        Serve the WebSocket tester HTML page at     
                        this path (e.g. /wstest). Default:
                        disabled (default: None)

notifications (ext/notify.py):
  --notify {discord}    Enable third-party notifications (default:  
                        None)
  --notify-on {match,correlation,anomaly,all}
                        You can pass multiple choices, for
                        example: `--notify-on match --notify-on     
                        anomaly`. "all" means notify on
                        match/correlation/anomaly. Default is all.  
                        (default: [])
  --webhook-url WEBHOOK_URL
                        Webhook URL (default: None)
  --id IDENTIFIER       An identifier which will be sent along      
                        with the notification, primarily to help    
                        you identify this instance in case you      
                        have multiple running. An id will be        
                        automatically generated if not provided     
                        (default: None)
                                                     
```


## Available Extensions

The `ext/` folder contains several extensions which double as examples to get you started on extension development.

- `ext/auth.py` - Safeguard your subsequent processors with simple authentication middleware (Basic or Bearer token).

    > [!CAUTION]
    > Note: You MUST specify this extension **before** the extensions you want to protect.
    > For instance, `-e auth file` will protect your file/upload endpoints with auth.
    > But `-e file auth` will not.
    
    You can also take advantage of this "ordering" feature to expose unauthenticated features.

- `ext/debugger.py` - Interactive JS debugging agent. Serves an eval-able JS payload that browses to, polls for pending commands, and POSTs results back. Randomised path support via `{RANDOM}` placeholder. CORS-enabled.
- `ext/file.py` - Combined file server and upload server with in-memory and on-disk
    storage. Supports file serving, uploads, and directory listing. Replaces the
    former sfile.py and upload.py extensions.
- `ext/notify.py` - Third-party webhook notifications, allowing basic filtering by event type. Currently supports Discord.
- `ext/pastebin.py` - End-to-end-encrypted pastebin service. Supports both browser-side (AES-GCM/AES-CBC via Web Crypto API) and server-side encryption fallback for HTTP access.
- `ext/stealthnet.py` - Stealthy upload service with a customisable JSON DSL profile. Chunkifies data and smuggles it out via HTTP requests; useful for bypassing DLP restrictions.
- `ext/websocket.py` - WebSocket OAST. Handles WS upgrade, logs incoming TEXT/BINARY frames as structured events through the standard pipeline. Supports WSS (TLS), path restriction via `--ws-path`, and a built-in tester page via `--websocket-tester`.

PRs are also welcome to contribute new extensions.

## Examples

The `examples/` folder contains standalone scripts that demonstrate common usage patterns using MOSS's programmatic API:

| File | Description |
|------|-------------|
| `example_extension.py` | Reference extension exercising every major MOSS API: Mixin (CLI flags, `__post_init__`), Processor (GET/POST/fallback dispatch), Handler (custom event consumption). Use `moss -e example_extension` to load. |
| `rce_curl.py` | RCE curl file exfiltration — starts MOSS with `-e file -d [[memory]]`, sends curl commands to a mock compromised target, captures uploaded files via `server.files`. |
| `xxe_exfil.py` | Blind XXE OOB detection — serves a malicious DTD via `serve_file()`, sends an XXE payload to target, waits for OOB callbacks. |
| `cve_2026_21967.py` | SSRF callback detector with per-target correlation IDs, `--hostname` for public callback URL, `--output FILE` for CSV export. |
| `mock_rce_target.py` | Mock RCE server for testing `rce_curl.py` — executes curl commands via `os.system` on a designated port. |
| `mock_xxe_server.py` | Mock XML parser endpoint that fetches external DTDs — used with `xxe_exfil.py`. |
| `mock_opera_server.py` | Mock server for testing Opera mini proxy detection. |

## Pastebin

Recommended Command:

```shell
moss -e auth pastebin \
    --basic-auth your:password \
    --simple --server random \
    --https --certfile ... --keyfile ...
```

<!-- TODO: screen record -->

Using the `pastebin` extension with `auth` provides two layers of password protection.

1. The first layer (`auth` module) is to protect against unauthorised access to the `/pastebin` URL.
2. The second layer (`pastebin`'s end-to-end encryption) is to protect against MITM whether it's malicious or blue team.
    
    By using a password which is not sent across the network, we ensure that eavesdroppers don't have access to the data. Of course, this only holds if the pastebin password is different from the auth password.

    This is important even when HTTPS is enabled. If you're in a red team engagement exfiltrating from a victim machine, there is the possibility deep packet inspection will pick up the goodies. Let me rephrase... Even in HTTPS, traffic can still be decrypted by those who hold the right keys/certificates. There is also the possibility of a [compromised/malicious CA](https://sslmate.com/resources/certificate_authority_failures) intercepting data.

## Stealthy Upload (StealthNet)

Recommended Command:

```shell
moss -e auth stealthnet file \
    --basic-auth your:password \
    --index --file-index -d dest \
    --stealth-profile profile.json \
    --simple --server random \
    --https --certfile ... --keyfile ...
```

<!-- TODO: screen record -->

Stealthnet is the working title of a stealthy upload module, which may come in handy for bypassing DLP restrictions, at the cost of slower upload speed. The file is broken down into multiple chunks, encoded, inserted into various parts of a HTTP request, then reassembled on the server. Larger files are broken down and sent separately across multiple requests.

The traffic is customisable by defining a *profile* using a JSON DSL (domain-specific language). The profile will be understood by both the frontend and backend, providing a common interface to specify requests and headers.

Some use cases:
- Deliver large files by chunking and using minimal delay
- Mimic and blend in with existing web traffic for stealthier exfiltration

MOSS pre-packages several profiles, which can be specified via `--stealth-profile FILE`:

- `profile.json` - default, resembles a web app with an API
- `chunk5kbget.json` - sends 5 KB per GET request, minimal delay
- `chunk100kb.json` - sends 100 KB per POST request, minimal delay

More details can be found in [ext/stealthnet/README.md](ext/stealthnet/README.md).

Sample profile:

```jsonc
{
    "metadata": {
        // Profile metadata goes here.
        "version": 20260101,
        "description": "Sample profile."
    },
    "encryption": {
        // Encrypt the data before sending. Currently only XOR encryption is offerred.
        "type": "xor",
        "key": "asldf01lk2nlk-EU9J1LJ3R'A-091;,91G[1.DUB81KENHjfog8lkn10)(JGjgoi"
    },
    "vars": [
        // Define variables to be substituted into requests.
        {
            "name": "api",
            "type": "cycle",
            "items": [
                "users",
                "comments",
                "posts",
                "author",
                "links"
            ]
        }
    ],
    "common": {
        // Define common headers here.
        "headers": {
            // State metadata (e.g. the index of the current chunk) can be substituted.
            // The server intelligently parses out the embedded substitutions.
            "X-Filename": "asdf${state:filename}vbnm",
            "X-Checksum": "${state:checksum}",
            "X-Range": "${state:currentIndex} - ${state:finalIndex} / ${state:retries}",
            // Common headers can also include data substitutions.
            // The server will automatically convert encoded data back to its original form.
            "X-Data": "${b64:400}"
        }
    },
    "intermittent": [
        // Requests here fire every X seconds.
        {
            "every": [
                5000,
                10000
            ],
            "req": 
                {
                    "method": "POST",
                    "url": "/telemetry",
                    "headers": {
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },
                    "body": "{\"action\":\"${var:uiAction}\",\"events\":\"${b64:20000:40000}\"}"
                }
            
        }
    ],
    "cycle": [
        // Requests here will fire sequentially.
        // You can specify a custom random delay between requests.
        {
            "count": [1, 1],
            "delay": [100, 500],
            "req": [
                {
                    "repeat": [4, 6],
                    "method": "GET",
                    "url": "/api/v1/${var:api}"
                },
                // ...
            ]
        }
    ]
}
```

## Notifications

Recommended Command:

```shell
moss -e notify \
    --filter youroastfilter \
    --notify discord --notify-on match \
    --webhook-url https://discord.com/api/webhooks/.../... \
    --server random \
    --https --certfile ... --keyfile ...
```

<!-- TODO: screen record -->

(Will add more documentation in the future)


## HTTPS Support

Polyglot support is mainly there for the tester's convenience. You only need to remember one port. Of course, if you want separate ports, you are free to spin up the servers to your liking.

Obtain certificates, e.g. via Let's Encrypt / certbot (ref: https://certbot.eff.org/instructions?ws=other&os=pip).

```shell
sudo python3 -m venv /opt/certbot/
sudo /opt/certbot/bin/pip install --upgrade pip
sudo /opt/certbot/bin/pip install certbot
sudo ln -s /opt/certbot/bin/certbot /usr/local/bin/certbot
sudo certbot certonly --standalone
```

Alternatively, you can generate self-signed certs like so:

```shell
openssl req -new -x509 -nodes -days 365 -out server.crt -keyout server.key -sha256
```

Then run like so:

```shell
moss.py --https --certfile /etc/letsencrypt/live/your.domain.com/fullchain.pem --keyfile /etc/letsencrypt/live/your.domain.com/privkey.pem
```

For LetsEncrypt, You may need to play around with permissions to get this to work.

```shell
sudo moss --https --certfile ... --keyfile ...

# or

cp /etc/letsencrypt/live/your.domain.com/{fullchain,privkey}.pem .
sudo chown $USER:$USER {fullchain,privkey}.pem
moss --https --certfile fullchain.pem --keyfile privkey.pem
```

## Extensions

MOSS is designed to be modular and extensible. Extension modules can be scripted in vanilla[^vanilla] Python to extend MOSS's CLI/API.

[^vanilla]: Vanilla, in this case, means code written purely with built-in Python modules, without the need to download additional modules or to import this project itself (i.e. no `import moss` is needed in extensions).

### Writing Extensions

(TODO: Diagram)

Extensions can declare classes to introduce new behaviour, HTTP processing, and event handling to MOSS. Classes named with these suffixes will be loaded:

- `*Mixin`: This extends the `HttpMossServer` class by exposing new APIs for automation and adds new fields to `req.server`. For instance, `ext/file.py` adds a `serve_file()` method, allowing you to dynamically serve a file, such as an XXE payload.
- `*Processor`: This processes requests, ideal for modifying request attributes and customising HTTP responses.
- `*Handler`: This handles events within a single thread. Examples of events are incoming requests, anomalies, or user-defined JSON. Useful for writing to files, logging, notifications, etc.

If none of this suits you, you could consider inheriting existing classes such as `MossRequestHandler` and override methods for further customisation.


## Programmatic API

For your custom scripts and automation ventures. See `examples/` for working scripts that use MOSS as a library.

Async API is in the works.

<!-- ## Motivation

My first draft was made in the middle of an exam, and I specifically wanted the OAST server to be controllable programmatically. That is, I run the script, and it will handle servers, craft payloads, and extract exfiltrated credentials within a single script. Later on I did a rewrite when I realised I wanted to handle the scale of hundreds of requests.

Core functionality such as OAST and logging are kept as a single file so that it is easy to download and copy around without having to wrestle with a package manager.

### Why not interactsh?

Interactsh allows self-hosting using interactsh-server.

### Why not webhook.site?

---

On one hand, you have mature OAST tools such as interactsh, Burp Collaborator, and online webhooks. Unfortunately, due to abuse by black hats, these free services are becoming increasingly signatured by firewalls/DLP/IDS which means it's hard to be confident that a negative is a True Negative.

On the other hand, if you want to test quick-n-dirty, you could set up a Python server (`python -m http.server`) or fire up a netcat port to receive HTTP in its raw glory. The problem with these is that it doesn't support HTTPS (encrypted HTTP). Or perhaps you want to test an SSRF within an air-gapped internal network. Online tools will not help here. You need to "self-host" on your machine.

### Why not just use interactsh-server?

Good question! It appears as if this project needlessly contends with an existing mature tool. Part of me is too lazy to setup golang whenever I need to quickly test something.


Now if you want to test quickly without the hassle of spinning up interactsh-server, its dependencies.

I have tried using interactsh-server in the past, but to me it seems very rigid. There is a fixed workflow (which is great in some cases! because you can reason about its behaviour more consistently), but it was not flexible enough for my use case.

Here's the normal way to use interactsh is:
- client requests a correlation ID from the server. This ID is unique, but the main point is that the ID is 
- client fires payload to target containing correlation ID
- server picks up correlation ID
- client is notified (e.g. by polling the server)

webhook.site is another contender which is open source and allows self-hosting. This one is more flexible in that the correlation ID is part of the URL path. There are still DNS and email hook options, which is nice to have.

To summarise my inane ramblings, I experienced pain in the following areas.
1. (interactsh) Correlation IDs are always placed as a subdomain, and the entire workflow is built on that. This is inflexible. Also I am poor and don't want to buy and manage domain. (Certain cloud providers allow you to configure a domain for a VPS, but no subdomains, and I wanted to use that.)
2. (interactsh) 
3. (raw netcat / Python http.server) No SSL support. Or need to restart on each new request. No features for filtering.

This does mean this tool comes with a few disadvantages, which should be acknowledged:
- Lack of direct support for other protocols (SMB/SMTP/LDAP/DNS), although you can certainly listen on those ports to identify connections
- 

I still use interactsh; it's a great tool boasting many integrations. But tools have a time and place, and it's nice to have a choice. You wouldn't use a hammer to cut an apple.
-->

## Warnings

> [!WARNING]
> While MOSS is hardened against security attacks, the implementation still shares similarities with Python's built-in `http.server` which is known to be *not intended* for production. Use at your own risk.

> [!WARNING]
> MOSS is not intended to be used with reverse proxies.

## Disclaimer

> [!WARNING]
> This tool is intended for authorised and ethical purposes only. The developers of this tool are not liable for any damages, legal consequences, or loss of data resulting from the use or misuse of this tool. Users are solely responsible for ensuring compliance with applicable laws and regulations.

> [!WARNING]
> This code is provided "as is" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software. Use at your own risk.


## TODOs

- [x] project: tests
- [ ] project: automation examples
- [ ] automation(correlation): issue server-to-client correlation IDs in HTTP response
- [ ] automation(correlation): register filters/matchers dynamically, and await for match
- [ ] automation: async programmatic API
- [ ] protocol: support ACAO in responses
- [x] protocol: receive and log incoming websocket messages
- [ ] protocol: support HTTP/2 requests
- [ ] protocol: support and comply with HTTP proxy
- [ ] protocol: support and comply with HTTPS Tunnel proxy
- [x] option: filter matches with regex
- [ ] ui: toggle detailed/compressed views with keyboard input
- [ ] ui: anchored status bar, displaying stats, e.g. number of filtered requests, number of anomalies
- [ ] misc: better structured reporting of anomalies and socket-level analysis?
- [ ] misc: encryption, throttling for debugger c2
- [ ] stealthnet: more TODOs in [ext/stealthnet/README.md](ext/stealthnet/README.md#roadmap)!

PRs welcome.
