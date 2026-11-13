# ChaCha20 Encryption & Decryption Simulator

Web-based educational tool (Python + Flask + HTML/CSS/JavaScript) that demonstrates the
ChaCha20 stream cipher (RFC 8439).

## Features
- Random 256-bit key and 96-bit nonce generation
- Encrypt text to hexadecimal ciphertext, decrypt it back
- Copy and download the result
- Step-by-step view: initial state, all 20 rounds (slider), keystream, XOR table
- "Verify with library" button compares our own implementation with Python `cryptography`
- Unit tests using the official RFC 8439 test vectors

## Requirements
- Python 3.9 or newer
- Packages: Flask, cryptography (listed in requirements.txt)

## Setup and run
    python -m venv venv
    venv\Scripts\activate          (Windows)      source venv/bin/activate   (Linux/macOS)
    pip install -r requirements.txt
    python app.py
Open http://127.0.0.1:5000 in your browser.

## Run the tests
    python -m unittest discover tests -v

## Project structure
    app.py              Flask server and API routes
    chacha20.py         ChaCha20 algorithm (quarter round, block function, encrypt/decrypt)
    templates/index.html  Web page
    static/style.css      Styling
    static/script.js      Front-end logic and visualisation
    tests/test_chacha20.py  Unit tests

## Security note
Educational project only. Never reuse a nonce with the same key. Real applications should use
ChaCha20-Poly1305 (authenticated encryption) from a vetted library.

## Deployment (Render.com, free tier)
1. Push this folder to a GitHub repository.
2. On render.com create a new "Web Service" and connect the repository.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Deploy and open the public URL.
