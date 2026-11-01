// kullanma be bra
import fs from 'fs';
import tls from 'tls';
import crypto from 'crypto';
import http2 from 'http2';

const TOKEN = "";
const GUILD = '1560758190742962267';
const TLS_REQ = 11;
const H2_REQ = 11;
const MIN_BOOST = 14;
let mfaToken = fs.readFileSync('./mfa.txt', 'utf8').trim();

const guildsCache = {};

function buildHttpRequest(code) {
    const body = JSON.stringify({ code });
    let req = `PATCH /api/v9/guilds/${GUILD}/vanity-url HTTP/1.1\r\nHost: canary.discord.com\r\nAuthorization: ${TOKEN}\r\n`;
    if (mfaToken) req += `x-discord-mfa-authorization: ${mfaToken}\r\n`;
    req += `Content-Type: application/json\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/132.0.0.0 Safari/537.36\r\nX-Super-Properties: eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEzMi4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTMyIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzQ1Njc4fQ==\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: keep-alive\r\n\r\n` + body;
    return Buffer.from(req);
}

function createSocket() {
    const s = tls.connect({ host: 'canary.discord.com', port: 443, rejectUnauthorized: false });
    s.setNoDelay(true);
    s.on('data', (d) => {
        const body = d.toString().split('\r\n\r\n')[1];
        if (body) console.log(body.trim());
    });
    s.on('error', () => { });
    s.on('close', () => { pool[pool.indexOf(s)] = createSocket(); });
    return s;
}

const pool = Array.from({ length: TLS_REQ }, createSocket);

const createH2Session = (i) => {
    const session = http2.connect('https://canary.discord.com:443', {
        maxVersion: 'TLSv1.3',
        minVersion: 'TLSv1.3', ciphers: 'TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384',
        ecdhCurve: 'X25519', ALPNProtocols: ['h2'], rejectUnauthorized: false,
        highWaterMark: 32 * 1024, peerMaxConcurrentStreams: 1000,
        paddingStrategy: http2.constants.PADDING_STRATEGY_NONE,
        maxConcurrentStreams: 200, enablePush: false, initialWindowSize: 4 * 1024 * 1024,
        maxFrameSize: 4 * 1024 * 1024, headerTableSize: 16384, maxHeaderListSize: 32768
    });
    session.ref();
    session.once('connect', () => {
        console.log(`[HTTP2] Session ${i} connected`);
        try {
            const req = session.request({
                ':method': 'GET',
                ':path': '/api/v9/gateway',
                ':scheme': 'https',
                ':authority': 'canary.discord.com',
            });
            req.on('error', () => {});
            req.end();
        } catch (e) {}
    });
    session.on('error', (err) => { console.error(`[HTTP2] Session ${i} error:`, err.message); setTimeout(() => { h2Conns[i] = createH2Session(i); }, 100); });
    session.on('close', () => { console.warn(`[HTTP2] Session ${i} closed`); setTimeout(() => { h2Conns[i] = createH2Session(i); }, 100); });
    return session;
};

const h2Conns = Array.from({ length: H2_REQ }, (_, i) => createH2Session(i));

const B_GUILD_UPDATE = Buffer.from('GUILD_UPDATE');
const B_VANITY_NULL = Buffer.from('"vanity_url_code":null');
const B_D_PREFIX = Buffer.from('"d":');
const B_ID_PREFIX = Buffer.from('"id":"');
const B_OP10 = Buffer.from('"op":10');
const B_READY = Buffer.from('READY');
const B_QUOTE = Buffer.from('"');
const B_SUBS_PREFIX = Buffer.from('"premium_subscription_count":');

function encodeFrame(data) {
    const payload = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const len = payload.length;
    const mask = crypto.randomBytes(4);
    let hdrLen = len < 126 ? 2 : len < 65536 ? 4 : 10;
    const frame = Buffer.allocUnsafe(hdrLen + 4 + len);
    frame[0] = 0x81;
    if (len < 126) { frame[1] = 0x80 | len; }
    else if (len < 65536) { frame[1] = 0x80 | 126; frame.writeUInt16BE(len, 2); }
    else { frame[1] = 0x80 | 127; frame.writeBigUInt64BE(BigInt(len), 2); }
    mask.copy(frame, hdrLen);
    for (let i = 0; i < len; i++) frame[hdrLen + 4 + i] = payload[i] ^ mask[i & 3];
    return frame;
}

function processFrames(state) {
    while (state.buf.length >= 2) {
        let len = state.buf[1] & 0x7F, off = 2;
        if (len === 126) { if (state.buf.length < 4) break; len = state.buf.readUInt16BE(2); off = 4; }
        else if (len === 127) { if (state.buf.length < 10) break; len = Number(state.buf.readBigUInt64BE(2)); off = 10; }
        if (state.buf.length < off + len) break;
        const op = state.buf[0] & 0x0F;
        if (op === 0x1 || op === 0x0) onMessage(state.buf.slice(off, off + len));
        state.buf = state.buf.slice(off + len);
    }
}

let wsSocket = null;

function wsSend(data) {
    if (wsSocket && !wsSocket.destroyed) wsSocket.write(encodeFrame(data));
}

function extractSubs(data) {
    const idx = data.indexOf(B_SUBS_PREFIX);
    if (idx === -1) return null;
    const start = idx + B_SUBS_PREFIX.length;
    let end = start;
    while (end < data.length && data[end] >= 0x30 && data[end] <= 0x39) end++;
    if (end === start) return null;
    return parseInt(data.slice(start, end).toString(), 10);
}

function extractGuildId(data) {
    const dIdx = data.indexOf(B_D_PREFIX);
    const idIdx = data.indexOf(B_ID_PREFIX, dIdx);
    if (idIdx === -1) return null;
    const s = idIdx + B_ID_PREFIX.length;
    const e = data.indexOf(B_QUOTE, s);
    if (e === -1) return null;
    return data.slice(s, e).toString();
}

function fire(code) {
    const buffer = buildHttpRequest(code);
    for (let i = 0; i < TLS_REQ; i++) pool[i].write(buffer);

    const bodyy = JSON.stringify({ code });
    const len = Buffer.byteLength(bodyy).toString();
    for (let i = h2Conns.length - 1; i >= 0; i--) {
        try {
            if (!h2Conns[i] || h2Conns[i].destroyed) continue;
            const req = h2Conns[i].request({
                ':method': 'PATCH',
                ':path': `/api/v9/guilds/${GUILD}/vanity-url`,
                ':authority': 'canary.discord.com',
                'authorization': TOKEN,
                'content-type': 'application/json',
                'accept-encoding': 'identity',
                'content-length': len,
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'x-super-properties': 'eyJicm93c2VyIjoiRmlyZWZveCIsImJyb3dzZXJfdXNlcl9hZ2VudCI6IkZpcmVmb3hfQ29tbWl0dGVkIn0=',
                'x-discord-mfa-authorization': mfaToken,
            });
            let resp = '';
            req.on('data', chunk => { resp += chunk.toString('latin1'); });
            req.on('end', () => { if (resp.includes('code')) console.log(`h2[${i}]:`, resp); });
            req.on('error', () => {});
            req.end(bodyy);
        } catch (e) {}
    }
}

function onMessage(data) {
    if (data.indexOf(B_GUILD_UPDATE) !== -1) {
        const guildId = extractGuildId(data);
        if (!guildId) return;

        const subs = extractSubs(data);
        if (subs !== null && guildsCache[guildId]) {
            guildsCache[guildId].subs = subs;
            const color = subs < MIN_BOOST ? '\x1b[31m' : '\x1b[32m';
            console.log(`${color}[SUBS]\x1b[0m guild ${guildId} → ${subs} boost`);
            if (subs < MIN_BOOST) {
                console.log(`\x1b[31m\x1b[1m GODLY\x1b[0m guild ${guildId} boost ${subs} < ${MIN_BOOST}`);
                fire(guildsCache[guildId].code);
                return;
            }
        }

        if (data.indexOf(B_VANITY_NULL) !== -1) {
            const cache = guildsCache[guildId];
            if (cache) {
                console.log(`\x1b[32m[CAPTURE]\x1b[0m Guild ${guildId} vanity boşaldı (subs: ${cache.subs})`);
                fire(cache.code);
            }
        }
        return;
    }

    if (data.indexOf(B_OP10) !== -1) {
        setInterval(() => wsSend(JSON.stringify({ op: 1, d: null })), JSON.parse(data).d.heartbeat_interval);
        return;
    }

    if (data.indexOf(B_READY) !== -1) {
        const msg = JSON.parse(data);
        if (msg.d?.guilds) msg.d.guilds.forEach(g => {
            const subs = g.premium_subscription_count ?? 0;
            if (g.vanity_url_code) {
                guildsCache[g.id] = { code: g.vanity_url_code, subs };
                console.log(`{ server: \x1b[32m'${g.id}'\x1b[0m, vanity: \x1b[32m'${g.vanity_url_code}'\x1b[0m, subs: \x1b[33m${subs}\x1b[0m },`);
            }
        });
    }
}

function connectGateway() {
    const state = { buf: Buffer.alloc(0), upgraded: false };
    wsSocket = tls.connect({ host: 'gateway.discord.gg', port: 443, rejectUnauthorized: false }, () => {
        wsSocket.setNoDelay(true);
        wsSocket.write(Buffer.from(
            `GET /?v=10&encoding=json HTTP/1.1\r\nHost: gateway.discord.gg\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}\r\nSec-WebSocket-Version: 13\r\n\r\n`
        ));
    });
    wsSocket.on('data', (chunk) => {
        if (!state.upgraded) {
            if (!chunk.includes('101')) return;
            state.upgraded = true;
            wsSend(JSON.stringify({ op: 2, d: { token: TOKEN, intents: 1, properties: { os: 'Windows', browser: 'Chrome', device: 'PC' } } }));
            const hEnd = chunk.indexOf('\r\n\r\n');
            if (hEnd !== -1 && hEnd + 4 < chunk.length) { state.buf = chunk.slice(hEnd + 4); processFrames(state); }
            return;
        }
        state.buf = Buffer.concat([state.buf, chunk]);
        processFrames(state);
    });
    wsSocket.on('close', () => setTimeout(connectGateway, 1000));
    wsSocket.on('error', () => { });
}

connectGateway();

process.on('uncaughtException', (e) => console.error(e.message));
