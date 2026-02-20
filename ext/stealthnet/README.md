# StealthNet

StealthNet is a MOSS module for covert uploads and is probably unrelated to whatever shows up in your search engine results.

## Specification

You can find the JSON schema in [stealthnet.py](../stealthnet.py#L719).

By default, profiles will be validated against this schema. (You can disable this validation using `--stealth-no-validate`, but I would not recommend doing that.)

## Terms and Definitions

- **Profile**: The JSON file defining the requests and communication patterns used
- **Server**: The MOSS Server
- **Client**: The browser which you're uploading files from
- **Variables**: See [Variables](#variables). Some custom strings which can be inserted into requests.
- **Patterns**: See [Patterns](#patterns). Some upload metadata that we want to include in the request. Some fields are required.

## Examples

You can find examples of profiles in the [ext/stealthnet/profiles](profiles) folder.

## Requests

Requests make up the meat of the profile. These are what the DLP, proxy, or traffic solution will see, so it's worth investing some time to customise what is being sent.

Requests are required to have the following fields:

- `[request].method`: The HTTP method of the request, e.g. GET, POST, PATCH, PUT, DELETE
- `[request].url`: The requestline path, may contain query and fragments
- `[request].headers`: (optional)
- `[request].body`: (optional)

On the client, a `Request` schema will be used to **format** `fetch()` arguments before sending.
On the server, a `Request` schema will be used to **match** against incoming requests.

Care should be taken to ensure the `method` and `url` do not overlap among requests.
If overlap occurs, it may obstruct parsing and delivery will fail.

For instance, this is bad:
```json
"req": [
    { "method": "GET", "url": "/api/v1/healthcheck", "headers": { "X-Abc": "${hex:64}" } },
    { "method": "GET", "url": "/api/v1/healthcheck", "headers": { "X-Def": "${hex:128}" } }
]
```
The above request cycle contains two `/api/v1/healthcheck` endpoints. Since parsing only looks at the `method` and `url`, the server will be unable to distinguish between the first and second requests.

### Cycle and Intermittent Requests

How do we define the order of sending requests?

There are two ways.

1. `$.cycle` requests will be sent sequentially (in order). After each request, the client will pause sending as specified in `$.cycle[].delay`. This is useful for bursts of data-fetching requests, login sequences, etc.
2. `$.intermittent` requests will be sent at regular intervals. The interval is defined in `$.intermittent[].every`. This is useful for requests such as keep-alive or telemetry.

```jsonc
"cycle": [
    { // A stage
        "count": [8, 12],   // send 8-12 requests in this stage
        "delay": [40, 100], // delay between 40-100 ms
        "maxRetries": 3,    // hint to retry at most 3 times
        "req": [ // The chain of requests to send
            {
                "method": "GET",
                "url": "/app/${var:jsfile}.${hex:4}.js"
            }
        ]
    }
]
```


### Substitutions

How do we embed data into the requests?

When writing the `url`, `headers`, and `body`, you can use special tokens which will substitute data.

Examples:

- `${b64:400:800}` - extract 400-800 bytes of data, then Base64-encode it
- `${hex:400:800}` - extract 400-800 bytes of data, then hex-encode it
- `${hex:100}` - extract 100 bytes of data, then hex-encode it
- `${uuid}` - extract 16 bytes of data, then encode it as a UUID
- `${uuids:10}` - extract 10-UUIDs worth of data, then format it as a JSON array of strings
- `${var:apipath}` - substitute from the `apipath` variable (see [variables](#variables))

### Status Codes as Directives

JSON Path: `[request].on.status`

Information is communicated via HTTP status codes.

By default, we have:
- `200`/`ok`
- `400`/`error`
- `429`/`retry`

And these are completely customisable.

The status codes work like so:

- The client (the browser) sends data to the server via a request.
- The server sees an incoming request.
- The server attempts to parse the data.
- The server attempts to validate the data.
    - If an error was found in the request (e.g. incorrect length or checksum), the server, by default, returns a HTTP `400 Bad Request` status. The client will see this and understand an error occurred. The client will assume this to be a proxy/firewall/DLP issue and then decide whether to resend data or stop everything (see [stats-based healthcheck](#statshealth)).
    - If an unexpected server-side error occurs, the server returns a HTTP `502` status.
- After all that, the server processes "application" stuff.
- If the profile and request allows `retries`, the server will roll a dice to determine if the response should be a `retry` or `ok`. It will then return an appropriate status code, along with content passed in `[request].on.template`.
- When the client receives a response, it will interpret the action/directive based on that status code.

Example `[request].on` field:

```json
"on": [
    { "status": [304, 429], "action": "retry" },
    { "status": 200, "action": "ok", "template": "$fakejs" }
]
```

In the above example, note that 2 `retry` status codes are provided (304 and 429). The server will choose one of these at random, if it does decide to `retry`.

There are also special templates, where content will be substituted by generated content. Currently, there is:
- `$fakejs` - attempts to generate some poor man's minified JS
- `$fakeapi` - attempts to generate some dumb JSON API-like response


#### Actions

JSON Path: `[request].on.action`

- `ok` - This action indicates the non-interesting case where all bytes were successfully
    received and validated.

- `retry` - This action allows the server to provide a hint to the frontend to send more data
    by issuing a similar request (with different bytes). This is used to randomise 
    Only `cycle` requests can be `retry`-ied, and this can be specified with the `$.cycle[].maxRetries` key.

- `error` - This indicates an error occurred while parsing the bytes.
    This possibly indicates data corruption (say, due to a proxy) or incorrect parsing.

Server-side issues should NOT return the `error` action, but should return the reserved status code `502`.

## Variables

JSON Path: `$.vars`

Variables work hand-in-hand with [substitution](#substitutions), and provide some static randomness to the traffic, allowing it to better blend in as a normal website.

Example:

```json
"vars": [
    {
        "name": "apipath",
        "type": "cycle",
        "items": ["value1", "value2", "value3"]
    },
    {
        "name": "name",
        "type": "random",
        "items": ["alice", "bob"]
    }
]
```

- `type: cycle` - chooses items in order
- `type: random` - chooses items randomly

For example, suppose a request uses the URL: `/en/home?lang=${var:apipath}`, then the next 4 calls to the request would fetch:

- `/en/home?lang=value1`
- `/en/home?lang=value2`
- `/en/home?lang=value3`
- `/en/home?lang=value1`

## Patterns

JSON Path: `$.patterns`

When dealing with chunkified data, we need to send metadata to ensure consistency and integrity. This formatting is described by the patterns field.

- `currentIndex` (integer)
- `finalIndex` (integer)
- `filename` (string) - some "simple obfuscation" is done for opsec
- `checksum` (integer)
- `chunkNo` (integer) (optional)
- `retries` (integer) (optional)

```json
"patterns": {
    "currentIndex": {
        "type": "header",
        "name": "X-RateLimit-No"
    },
    ...
```

## Encryption

JSON Path: `$.encryption`

We provide some rudimentary encryption. Currently, the following ciphers are available:

- `xor` (lol)

This is mostly to protect some simple plaintext from being picked up by dumb patterns.

But really, you are expected to compress your data prior to uploading it, ideally in a password-protected zip. Don't come to me bawling that forensics was able to reverse engineer the network traffic and found your silly xor password.

## Common

JSON Path: `$.common`

For common headers which will be included across all requests.


## Stats-Based Healthcheck
<a id="statshealth"></a>

This is mostly an implementation detail, but the purpose of this section is to shine some light on how it works.

When dealing with errors, we need to consider several cases:

- How long have we been running the loop?
- What endpoints are affected?
- Was the endpoint working before?

The current implementation is designed based on these different considerations.

When an error occurs which is likely to be caused by a proxy/firewall/DLP solution, the client will call `.queryContinue()` to check whether we should attempt to continue sending. If `true`, we attempt to resend by looping through a subarray of failed data. If `false`, we stop everything and notify the user.

## Roadmap

- [ ] Support stuffing patterns into cookies, query, and body
- [ ] Multiple profiles
- [ ] Encrypt/decrypt profiles over the network
- [ ] Minify JS
- [ ] Support stronger encryption, e.g. AES-CTR? Note that there are requirements for the cipher. Currently, encryption is implemented like so: Encryption, one-time, during init; Decryption, multiple times, immediately on arrival. As such, we currently require random access decryption.
- [ ] Final handshake - automate confirming the filehash, and any necessary error detection. This may be slightly difficult, especially when requests arrive out-of-order.
- [ ] Defensive programming: prevent multiple requests with the same `(method, url)` tuple.
- [ ] Improve fakejs generated output
