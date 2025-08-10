from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
from pathlib import Path

class AESHandler(BaseHTTPRequestHandler):
    def _set_headers(self, content_type='text/html'):
        self.send_response(200)
        self.send_header('Content-type', content_type)
        self.end_headers()

    def do_GET(self):
        if self.path == '/styles.css':
            self._serve_static_file('styles.css', 'text/css')
        else:
            self._serve_homepage()

    def _serve_static_file(self, filename, content_type):
        try:
            static_path = Path(__file__).parent / 'static' / filename
            with open(static_path, 'rb') as file:
                self._set_headers(content_type)
                self.wfile.write(file.read())
        except FileNotFoundError:
            self.send_error(404, "File not found")

    def _serve_homepage(self):
        try:
            template_path = Path(__file__).parent.parent / 'templates' / 'index.html'
            with open(template_path, 'rb') as file:
                self._set_headers()
                self.wfile.write(file.read())
        except FileNotFoundError:
            self.send_error(404, "Page not found")

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = urllib.parse.parse_qs(self.rfile.read(content_length).decode('utf-8')
        
        action = post_data.get('action', [''])[0]
        response = {}
        
        try:
            if action == 'encrypt':
                plaintext = post_data['plaintext'][0]
                key = post_data['key'][0].encode('utf-8')
                
                if len(key) not in [16, 24, 32]:
                    raise ValueError("Key must be 16, 24, or 32 bytes long")
                
                iv = get_random_bytes(16)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
                ciphertext = cipher.encrypt(padded_data)
                encrypted_data = iv + ciphertext
                
                response['status'] = 'success'
                response['ciphertext'] = base64.b64encode(encrypted_data).decode('utf-8')
                response['iv'] = base64.b64encode(iv).decode('utf-8')
                
            elif action == 'decrypt':
                ciphertext = base64.b64decode(post_data['ciphertext'][0])
                key = post_data['key'][0].encode('utf-8')
                iv = ciphertext[:16]
                actual_ciphertext = ciphertext[16:]
                
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted_padded = cipher.decrypt(actual_ciphertext)
                plaintext = unpad(decrypted_padded, AES.block_size).decode('utf-8')
                
                response['status'] = 'success'
                response['plaintext'] = plaintext
                
            else:
                response['status'] = 'error'
                response['message'] = 'Invalid action'
                
        except Exception as e:
            response['status'] = 'error'
            response['message'] = str(e)
        
        self._set_headers('application/json')
        self.wfile.write(json.dumps(response).encode('utf-8'))

def run(server_class=HTTPServer, handler_class=AESHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting AES encryption server on port {port}...')
    httpd.serve_forever()

if __name__ == '__main__':
    run()