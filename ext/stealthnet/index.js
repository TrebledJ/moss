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

class PayloadTransformer {
    constructor(payload) {
        // Payload in Uint8Array.
        this.payload = payload;
        this.index = 0;
    }

    finished() {
        return this.index >= this.payload.length;
    }

    // next(nLo, nHi) {
    //     const rand = (nLo === nHi || !nHi) ? nLo : randomLoHi(nLo, nHi);
    //     this.index += rand;
    //     const buf = payload.subarray(this.index - rand, this.index);
    //     return buf;
    // }
    next(nLo, nHi) {
        const rand = (nLo === nHi || !nHi) ? nLo : randomLoHi(nLo, nHi);
        const remaining = this.payload.length - this.index;
        const take = Math.min(rand, remaining);
        const buf = this.payload.subarray(this.index, this.index + take);
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
        this.generators = {};
        for (const var_ of Object.keys(vars)) {
            const schema = vars[var_];
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
            this.generators[var_]  = gen;
        }
    }

    hasVariable(var_) {
        return Object.keys(this.generators).includes(var_);
    }

    generate(var_) {
        return this.generators[var_]();
    }
}

class Sequence {
    constructor(seq) {
        this.seq = seq;
    }

    generate() {
        let out = "";
        for (const f of this.seq)
            out += f();
        return out;
    }
}

class PayloadGenerator {
    constructor({ vgenerator, payloader }) {
        this.vgenerator = vgenerator;
        this.payloader = payloader;
        this.regex = /(\$\{(?:var|uuid|b64|hex)(?::[a-zA-Z0-9]+)?(?::[0-9]+)?\})/g;
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
        } else if (tag === 'b64' || tag === 'hex') {
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
            return () => this.vgenerator.generate(...args);
        } else if (tag === 'uuid') {
            return () => this.payloader.nextUuid(...args);
        } else if (tag === 'b64') {
            return () => this.payloader.nextB64(...args);
        } else if (tag === 'hex') {
            return () => this.payloader.nextHex(...args);
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
    constructor(gen, { url, method, headers, body, repeat }) {
        let bytes, expectedBytes = 0;
        [this.url, bytes] = gen.build(url);
        expectedBytes += bytes;
        
        this.method = method ?? 'GET';
        this.headers = [];
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
    }

    generate(common) {
        const { headers } = common;
        // Sort headers before generating.
        const sortedHeaders = [...headers, ...this.headers].sort(([a, _1], [b, _2]) => a.localeCompare(b, undefined, { sensitivity: 'base' }))
        // Return fetch arguments.
        return [
            this.url.generate(),
            {
                method: this.method,
                headers: Object.fromEntries([
                    ...sortedHeaders.map(([k, v]) => [k, `${v.generate()}`]),
                ]),
                body: this.body ? this.body.generate() : undefined,
                // "mode": "no-cors",
                // "credentials": "include",
            },
        ]
    }
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
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

async function actualSend(req, common, patterns, state) {
    let [url, options] = req.generate(common);
    state.finalIndex = state._finalIndex();

    // Add state patterns.
    for (const x of ['chunkNo', 'currentIndex', 'finalIndex', 'maxRetries', 'fnRev']) {
        if (patterns[x] !== undefined && state[x] !== undefined) {
            [url, options] = addPattern(url, options, patterns[x], state[x]);
        }
    }

    let actualRetry = 20, backoff = 1000;
    while (--actualRetry) {
        try {
            const resp = await fetch(url, options);
            if (!resp)
                throw new Error(`resp is ${resp}`);
            return resp;
        } catch (e) {
            // Retry on (network) error, but wait a bit first.
            console.error(`fetch error: ${e}, trying again in ${backoff}ms, ${actualRetry} retries left`);
            await delay(backoff);
            backoff = Math.min(backoff * 2, 60000); // At most 1min between waits.
        }
    }
}

class SequencedRequest {
    constructor(gen, requests, count, delay, maxRetries) {
        this.count = count ? (() => randomLoHi(...count)) : () => 1;
        this.delay = delay ? (() => randomLoHi(...delay)) : () => 5000;
        this.maxRetries = maxRetries ?? 0;
        this.requests = requests.map(r => new Request(gen, r));
    }

    async sendOneWithRetry(req, reqr) {
        let retries = this.maxRetries;
        while (true && retries >= 0) {
            if (reqr.finished())
                return;

            console.log(`>--> sequenced, chunk #${reqr.chunkNo}`);
            const state = {
                ...reqr.getState(),
                maxRetries: retries,
            };
            reqr.chunkNo++;
            retries -= 1;
            const resp = await actualSend(req, reqr.common, reqr.patterns, state);
            reqr.updateProgress();
            if (resp.status === 304) {
                // Sleep at most 100.
                await delay(Math.min(100, this.delay()));
                continue;
            }
            await delay(this.delay());
            if (resp.ok) {
                return; // Yippee!
            } else {
                throw new Error(`unexpected status code: ${resp.status}`);
            }
        }
    }

    async sendMany(reqr) {
        let nCount = this.count();
        let req_index = 0;
        while (nCount > 0) {
            if (reqr.finished())
                return;

            const req = this.requests[req_index];
            const repeat = req.repeat();
            for (let i = 0; i < repeat + 1; i++) {
                await this.sendOneWithRetry(req, reqr);
                nCount--;
                if (nCount <= 0)
                    return;
            }
            req_index = (req_index + 1) % this.requests.length; 
        }
    }
}

class Requester {
    constructor({ payloader, generator, patterns, intermittent, cycle, common, filename }) {
        this.payloader = payloader;
        this.generator = generator;
        this.filename = filename;
        this.common = { headers: [] };
        for (const hdr of Object.keys(common.headers)) {
            this.common.headers[hdr] = this.generator.build(common.headers[hdr]);
        }
        this.patterns = patterns;
        this.chunkNo = 0;
        this.running = false;

        if (!Array.isArray(intermittent)) {
            throw `expected intermittent to be Array, got ${typeof intermittent}`;
        }
        if (!Array.isArray(cycle)) {
            throw `expected cycle to be Array, got ${typeof cycle}`;
        }
        this.intermittent = intermittent.map(x => new IntermittentRequest(x.every, this.generator, x.req));
        this.cycle = cycle.map(c => new SequencedRequest(this.generator, c.req, c.count, c.delay, c.maxRetries))
        this.onprogress = () => {};
        this.startIntermittent();
    }

    startIntermittent() {
        this.intermittentIntervals = [];
        for (const iRequest of this.intermittent) {
            async function iRecursive() {
                if (this.finished())
                    return;
                console.log(`>--> intermittent, chunk #${this.chunkNo}`);
                const state = this.getState();
                this.chunkNo++;
                await actualSend(iRequest, this.common, this.patterns, state);
                this.updateProgress();
                setTimeout(iRecursive.bind(this), iRequest.every());
            }
            setTimeout(iRecursive.bind(this), iRequest.every());
        }
    }

    getState() {
        return {
            chunkNo: this.chunkNo,
            currentIndex: this.payloader.index,
            _finalIndex: () => this.payloader.index, // Will be computed later
            fnRev: this.filename.split('').reverse().join(''), // TODO: opsec
        };
    }

    finished() {
        return this.payloader.finished() || !this.running;
    }

    updateProgress() {
        self.onprogress(this.chunkNo, this.payloader.index, this.payloader.payload.length, this.startTime);
    }

    async loop() {
        // TODO: save and restore progress from local storage
        this.startTime = Date.now();
        this.running = true;
        let stageIndex = 0;
        while (!this.finished()) {
            const stage = this.cycle[stageIndex];
            console.log(`stage #${stageIndex+1}/${this.cycle.length}, chunk #${this.chunkNo}`);
            
            await stage.sendMany(this);
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

const elStatus = document.getElementById('status');
const elTask = document.getElementById('task');

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

function onprogress(chunkNo, index, length, startTime) {
    const elapsedTime = Date.now() - startTime;
    const eta = new Date(startTime + elapsedTime / (index / length));
    // const etaRelative = elapsedTime / (index / (length - index));
    elStatus.textContent = (index === length ?
      'Done!' :
      `${Math.floor(100*index/length)}% ` +
      `[${Math.floor(index/1024)} / ${Math.floor(length/1024)}KiB] ` +
      `[${chunkNo+1} requests] ` +
      `[eta: ${eta.toTimeString()}, ${formatRelativeTime(eta)}]`
    );
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
    
    const buffer = new Uint8Array(await file.arrayBuffer());
    console.log(`loaded ${buffer.length} bytes`)

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

    const sha1 = await computeHash('SHA-1', buffer);
    const sha256 = await computeHash('SHA-256', buffer);
    document.getElementById('task').textContent = `Uploading ${file.name}:`;
    if (!window.crypto.subtle) {
        document.getElementById('sha1').textContent = `(http connection, unable to compute hash with subtlecrypto)`;
    } else {
        document.getElementById('sha1').textContent = `sha1: ${sha1}`;
        document.getElementById('sha256').textContent = `sha256: ${sha256}`;
    }

    const reqr = new Requester({ payloader, generator, patterns, intermittent, cycle, common, filename });
    window.activeRequester = reqr;
    reqr.onprogress = onprogress;
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

