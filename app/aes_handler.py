from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
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

    def _process_key(self, key_str):
        """Convert any length key string to valid AES key (16, 24, or 32 bytes)"""
        key_hash = SHA256.new(key_str.encode('utf-8')).digest()
        return {
            'aes_128': key_hash[:16],
            'aes_192': key_hash[:24],
            'aes_256': key_hash[:32]
        }

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
        post_data = urllib.parse.parse_qs(self.rfile.read(content_length).decode('utf-8'))
        
        action = post_data.get('action', [''])[0]
        response = {}
        
        try:
            if action == 'encrypt':
                plaintext = post_data['plaintext'][0]
                key_str = post_data['key'][0]
                
                key_variants = self._process_key(key_str)
                key = key_variants['aes_256']  # Use strongest by default
                
                iv = get_random_bytes(16)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
                ciphertext = cipher.encrypt(padded_data)
                encrypted_data = iv + ciphertext
                
                response['status'] = 'success'
                response['ciphertext'] = base64.b64encode(encrypted_data).decode('utf-8')
                response['key_info'] = {
                    'aes_128': base64.b64encode(key_variants['aes_128']).decode('utf-8'),
                    'aes_192': base64.b64encode(key_variants['aes_192']).decode('utf-8'),
                    'aes_256': base64.b64encode(key_variants['aes_256']).decode('utf-8')
                }
                
            elif action == 'decrypt':
                ciphertext = base64.b64decode(post_data['ciphertext'][0])
                key_str = post_data['key'][0]
                
                key_variants = self._process_key(key_str)
                decrypted = None
                
                # Try all key sizes
                for key_size, key in key_variants.items():
                    try:
                        iv = ciphertext[:16]
                        actual_ciphertext = ciphertext[16:]
                        cipher = AES.new(key, AES.MODE_CBC, iv)
                        decrypted_padded = cipher.decrypt(actual_ciphertext)
                        decrypted = unpad(decrypted_padded, AES.block_size).decode('utf-8')
                        response['used_key_size'] = key_size
                        break
                    except (ValueError, KeyError):
                        continue
                
                if decrypted is None:
                    raise ValueError("Decryption failed with all key sizes")
                
                response['status'] = 'success'
                response['plaintext'] = decrypted
                
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
