from app import create_app
from app.aes_handler import AESHandler
from http.server import HTTPServer
import os

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    server_address = ('', port)
    httpd = HTTPServer(server_address, AESHandler)
    print(f"Starting server on port {port}")
    httpd.serve_forever()