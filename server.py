import base64
import json
from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import unpad

app = Flask(__name__)

print("Server: Generating RSA Keys... please wait.")
server_key_pair = RSA.generate(2048)
server_private_key = server_key_pair
server_public_key = server_key_pair.publickey()
print("Server: Ready on port 5000.")

@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    """Sends the RSA Public Key to the client."""
    return jsonify({
        "public_key": server_public_key.export_key().decode('utf-8')
    })

@app.route('/receive_message', methods=['POST'])
def receive_message():
    """Receives, validates, and decrypts the message."""
    try:
        data = request.json
        
        # Decode Base64
        encrypted_aes_key = base64.b64decode(data['encrypted_key'])
        encrypted_payload = base64.b64decode(data['payload'])
        received_hmac = data['hmac']
        iv = base64.b64decode(data['iv'])

        # Decrypt AES Key using RSA
        rsa_cipher = PKCS1_OAEP.new(server_private_key)
        session_key = rsa_cipher.decrypt(encrypted_aes_key)

        # Verify HMAC
        h = HMAC.new(session_key, encrypted_payload, digestmod=SHA256)
        try:
            h.hexverify(received_hmac)
        except ValueError:
            return jsonify({"status": "Error", "message": "Tampering detected!"}), 400

        # Decrypt Message using AES
        aes_cipher = AES.new(session_key, AES.MODE_CBC, iv)
        decrypted_raw = aes_cipher.decrypt(encrypted_payload)
        decrypted_json_str = unpad(decrypted_raw, AES.block_size).decode('utf-8')

        # Save to file
        with open("received_student.json", "w", encoding="utf-8") as f:
            f.write(decrypted_json_str)

        print(f"Server: Decrypted message from {json.loads(decrypted_json_str)['name']}")

        return jsonify({
            "status": "Success", 
            "message": "Message decrypted and verified successfully."
        })

    except Exception as e:
        return jsonify({"status": "Error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)