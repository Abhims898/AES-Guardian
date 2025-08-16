AES Encryption Web Application

A secure web-based implementation of the Advanced Encryption Standard (AES) with an intuitive interface for real-time encryption and decryption operations.


Key Features

🔒 AES-256-CBC Encryption: Industry-standard symmetric encryption

🔑 Flexible Key Handling: Accepts keys of any length (auto-converted via SHA-256)

📋 Clipboard Integration: One-click copy for encrypted/decrypted results

⚙️ Adaptive Key Sizing: Supports 128/192/256-bit keys with automatic negotiation

📱 Responsive Design: Mobile-friendly interface



Technology Stack

Backend: Python (PyCryptodome)

Frontend: HTML5, CSS3, JavaScript

Server: Python HTTP.server

Security: AES-CBC with PKCS#7 padding and random IV generation



Installation

bash
# Clone repository
git clone https://github.com/Abhims898/AES-Guardian

# Install dependencies
pip install pycryptodome

# Run application
python wsgi.py
Access the application at: http://localhost:8000


Usage

Encryption Tab:

Enter plaintext in the input field

Provide any secret key

Click "Encrypt" to generate Base64-encoded ciphertext

Decryption Tab:

Paste Base64 ciphertext

Enter the original secret key

Click "Decrypt" to recover the original message


Security Features

SHA-256 key derivation from any input

Random 16-byte IV for each encryption

PKCS#7 padding validation

Secure CBC mode implementation

Server-side key zeroization after processing


Contributing

Contributions are welcome! Please submit pull requests for:

Implementation of additional AES modes (GCM, CTR)

Enhanced key management features

Improved UI/UX components

Security audit recommendations

GitHub Repository Link: https://github.com/Abhims898/AES-Guardian

Render Cloud Link for demo: https://aes-guardian.onrender.com

