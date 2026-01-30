# SimpleOAST

Multifunctional server for all your offensive testing: OAST, DLP/Exfiltration, Automation, Honeypot. (Sorry, no C2 stuff here.)

## Use Cases

- Out-of-Band (OOB) Application Security Testing (OAST) with a focus on HTTP
    - Blind Attacks (XSS/SQLi/RCE)
    - SSRF
- Automation and Exploit Development via Programmatic Interface and Structured Output
- HTTP Honeypots (maybe), with socket-level reporting
- Use it to cut time during engagements, exams, and bug bounty!

## Features

- [x] single Python file, easy to setup, easy to configure, easy to hack
- [x] custom response (status, headers, body)
- [x] robust matching/filtering
- [x] extract correlation ID by regex
- [x] pretty ANSI colours!
- [x] comprehensive JSONL logging
- [x] polyglot (supports both HTTP/HTTPS on the same port)
- [x] log HTTP anomalies (unsupported method, bad http version, potential port scan, etc.)
- [x] serve files (stores content in-memory for extra safety guarantees, at the expense of memory consumption)
- [x] detects HTTP protocol variants (websockets, websockets over SSL, HTTP proxy, HTTP proxy over SSL, HTTPS tunnel proxy) (NOTE: currently only detects, but doesn't parse or follow through on handshakes etc. That is planned for the future.)
- [x] send notifications to Discord webhook on match

## Setup

```shell
wget https://github.com/TrebledJ/simpleoast.py/blob/main/simpleoast.py
python3 simpleoast.py
```

Done. This spins up a HTTP listener on port 8000.

No hassle. Quick-n-dirty. Simple (oast).

## Motivation

My first draft was made in the middle of an exam, and I specifically wanted the OAST server to be controllable programmatically. That is, I run the script, and it will handle servers, craft payloads, and extract exfiltrated credentials. Later on I did a rewrite when I realised I wanted to handle the scale of hundreds of requests. (Also I lost the first draft, hehe, but found it later.)

I aim to keep this as a single file so that it is easy to download and copy around without having to wrestle with a package manager.

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



## Options

```
usage: simpleoast.py [-h] [--bind BIND] [--port PORT] [-v]
                     [--status-code STATUS_CODE] [--body BODY]
                     [--server SERVER] [--header HEADER]
                     [--directory DIRECTORY] [--base-path BASE_PATH]
                     [--filter FILTER] [--correlation-regex CORRELATION_REGEX]
                     [--jsonl JSONL] [--output-all] [--ignore-common-headers]
                     [--no-anomaly] [--https] [--certfile CERTFILE]
                     [--keyfile KEYFILE] [--websockets]

Dead simple HTTP OAST server by TrebledJ.

options:
  -h, --help            show this help message and exit
  --bind BIND, -b BIND  Bind to this address (default: 0.0.0.0)
  --port PORT, -p PORT
  -v                    Verbosity. -v for INFO, -vv for DEBUG messages.
                        (default: 0)

response:
  --status-code STATUS_CODE, -S STATUS_CODE
                        The default status code to return (default: 200)
  --body BODY           The default content to return. This could be a file,
                        which will be loaded (default: )
  --server SERVER       Server header in response. Special values: random,
                        none (default: SimpleOAST
                        (https://github.com/TrebledJ/simpleoast))
  --header HEADER, -H HEADER
                        Headers to include in server output. You can specify
                        multiple of these arguments (default: [])
  --directory DIRECTORY, -d DIRECTORY
                        The directory to serve files from. Files served from
                        this directory always return status code 200 (default:
                        None)
  --base-path BASE_PATH
                        The base path to "put" static files in. A base path of
                        /static means files can be accessed through
                        http://HOSTNAME:PORT/static (default: /static)

display/logging:
  --filter FILTER       Match request line and body (default: None)
  --correlation-regex CORRELATION_REGEX, -r CORRELATION_REGEX
                        Extract correlation ID based on regex, this works
                        independently of the filter (default: None)
  --jsonl JSONL         Output file path for JSONL logging (one JSON event per
                        line). Use `--jsonl -` to output to stdout (default:
                        None)
  --output-all, -f      Output all HTTP requests, including those that don't
                        match the filter (default: False)
  --ignore-common-headers, -i
                        Exclude common request headers from display. This does
                        not affect jsonl output (default: False)
  --no-anomaly          Do not log anomalies (default: False)

protocol:
  --https               Enable https polyglot support. (default: False)
  --certfile CERTFILE
  --keyfile KEYFILE
  --websockets, -ws     Enable websocket support. Limited support, currently
                        only detects the HTTP handshake (default: False)

```

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

Then run like so:

```shell
simpleoast.py --https --certfile /etc/letsencrypt/live/your.domain.com/fullchain.pem --keyfile /etc/letsencrypt/live/your.domain.com/privkey.pem
```

## Programmatic API

For your custom scripts and automation ventures.

Example:

```
TODO
+ share an example.py in repo
```

Async API is in the works.

## Warnings

- Implementation is based on Python's built-in HTTP Server which is known to be *not intended* for production use. My personal recommendation is to not keep this long running, and use it primarily for quick tests. Use at your own risk.

- Disclaimer: This tool is intended for authorised and ethical purposes only. The developers of this tool are not liable for any damages, legal consequences, or loss of data resulting from the use or misuse of this tool. Users are solely responsible for ensuring compliance with applicable laws and regulations.

## Roadmap (PRs welcome!)

- [ ] automation(correlation): issue server-to-client correlation IDs in HTTP response
- [ ] automation(correlation): register filters/matchers dynamically, and await for match
- [ ] automation: async programmatic API
- [ ] protocol: support ACAO in responses
- [ ] protocol: receive and log incoming websocket messages
- [ ] protocol: support HTTP/2 requests
- [ ] protocol: support and comply with HTTP proxy
- [ ] protocol: support and comply with HTTPS Tunnel proxy
- [ ] option/log: allow 'compressed' view, one line per event
- [ ] option: filter matches with regex
- [ ] ui: toggle detailed/compressed views with keyboard input
- [ ] ui: fixed status bar, displaying stats, e.g. number of filtered requests, number of anomalies
- [ ] misc: better structured reporting of anomalies and socket-level analysis?
- [ ] misc: config file support (toml)
