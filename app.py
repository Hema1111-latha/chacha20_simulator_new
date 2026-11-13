"""
app.py - Flask web server for the ChaCha20 Encryption/Decryption Simulator.
Run with:  python app.py   then open http://127.0.0.1:5000
"""
import base64
import binascii
import os

from flask import Flask, jsonify, render_template, request

from chacha20 import chacha20_block, chacha20_crypt

app = Flask(__name__)


# ---------- helpers ----------
def parse_hex(value: str, expected_len: int, label: str) -> bytes:
    value = (value or "").strip().replace(" ", "")
    if len(value) != expected_len * 2:
        raise ValueError(f"{label} must be {expected_len * 2} hex characters "
                         f"({expected_len} bytes). You entered {len(value)}.")
    try:
        return bytes.fromhex(value)
    except ValueError:
        raise ValueError(f"{label} contains non-hexadecimal characters.")


def parse_counter(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError("Counter must be a whole number.")


def words_hex(words):
    return [f"{w:08x}" for w in words]


def build_steps(key, nonce, counter, plaintext: bytes):
    """Collect data for the 'how it works' panel (first block + XOR table)."""
    keystream, info = chacha20_block(key, nonce, counter, trace=True)
    ciphertext = bytes(p ^ k for p, k in zip(plaintext[:16], keystream))
    xor_rows = [
        {
            "char": chr(p) if 32 <= p < 127 else ".",
            "plain": f"{p:02x}",
            "plain_bin": f"{p:08b}",
            "key": f"{k:02x}",
            "key_bin": f"{k:08b}",
            "cipher": f"{c:02x}",
            "cipher_bin": f"{c:08b}",
        }
        for p, k, c in zip(plaintext[:16], keystream, ciphertext)
    ]
    return {
        "initial": words_hex(info["initial"]),
        "rounds": [words_hex(r) for r in info["rounds"]],
        "final": words_hex(info["final"]),
        "keystream_hex": keystream.hex(),
        "xor_rows": xor_rows,
    }


# ---------- routes ----------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/generate", methods=["POST"])
def generate():
    """Generate a random 256-bit key and a random 96-bit nonce."""
    return jsonify(key=os.urandom(32).hex(), nonce=os.urandom(12).hex())


@app.route("/api/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json(force=True, silent=True) or {}
    try:
        key = parse_hex(data.get("key"), 32, "Key")
        nonce = parse_hex(data.get("nonce"), 12, "Nonce")
        counter = parse_counter(data.get("counter", 1))
        text = data.get("plaintext", "")
        if not text:
            raise ValueError("Please enter a message to encrypt.")
        plaintext = text.encode("utf-8")
        ciphertext = chacha20_crypt(key, nonce, plaintext, counter)
        return jsonify(
            ciphertext_hex=ciphertext.hex(),
            ciphertext_b64=base64.b64encode(ciphertext).decode(),
            length=len(ciphertext),
            blocks=(len(plaintext) + 63) // 64,
            steps=build_steps(key, nonce, counter, plaintext),
        )
    except ValueError as e:
        return jsonify(error=str(e)), 400


@app.route("/api/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json(force=True, silent=True) or {}
    try:
        key = parse_hex(data.get("key"), 32, "Key")
        nonce = parse_hex(data.get("nonce"), 12, "Nonce")
        counter = parse_counter(data.get("counter", 1))
        raw = (data.get("ciphertext") or "").strip().replace(" ", "")
        if not raw:
            raise ValueError("Please enter the ciphertext (hex) to decrypt.")
        try:
            ciphertext = bytes.fromhex(raw)
        except ValueError:
            raise ValueError("Ciphertext must be valid hexadecimal.")
        plaintext = chacha20_crypt(key, nonce, ciphertext, counter)
        # A wrong key/nonce gives random bytes, which usually is not valid UTF-8
        text = plaintext.decode("utf-8", errors="replace")
        valid = True
        try:
            plaintext.decode("utf-8")
        except UnicodeDecodeError:
            valid = False
        return jsonify(plaintext=text, valid_utf8=valid)
    except ValueError as e:
        return jsonify(error=str(e)), 400


@app.route("/api/verify", methods=["POST"])
def verify():
    """Compare our implementation with the trusted 'cryptography' library."""
    data = request.get_json(force=True, silent=True) or {}
    try:
        key = parse_hex(data.get("key"), 32, "Key")
        nonce = parse_hex(data.get("nonce"), 12, "Nonce")
        counter = parse_counter(data.get("counter", 1))
        text = data.get("plaintext", "")
        if not text:
            raise ValueError("Enter a message first, then click Verify.")
        plaintext = text.encode("utf-8")
        ours = chacha20_crypt(key, nonce, plaintext, counter)

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        # The library expects a 16-byte nonce = 4-byte little-endian counter + 12-byte nonce
        lib_nonce = counter.to_bytes(4, "little") + nonce
        enc = Cipher(algorithms.ChaCha20(key, lib_nonce), mode=None).encryptor()
        theirs = enc.update(plaintext)
        return jsonify(match=(ours == theirs),
                       ours=ours.hex(), library=theirs.hex())
    except ImportError:
        return jsonify(error="The 'cryptography' package is not installed."), 500
    except ValueError as e:
        return jsonify(error=str(e)), 400


if __name__ == "__main__":
    # Local use only. In production the app is served by gunicorn (see Procfile).
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=port)
