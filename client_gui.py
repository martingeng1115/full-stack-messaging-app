import customtkinter as ctk
import json
import requests
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# Appearance Settings
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("dark-blue")

class MessagingApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure Full-Stack Messenger")
        self.geometry("600x750") 

        self.scroll_frame = ctk.CTkScrollableFrame(self, width=580, height=730)
        self.scroll_frame.pack(pady=10, padx=10, fill="both", expand=True)

        # Title
        self.label = ctk.CTkLabel(self.scroll_frame, text="Secure Student Entry", font=("Arial", 24, "bold"))
        self.label.pack(pady=10)

    
        self.name_entry = ctk.CTkEntry(self.scroll_frame, placeholder_text="Student Name", width=400)
        self.name_entry.pack(pady=5)

        self.id_entry = ctk.CTkEntry(self.scroll_frame, placeholder_text="Student ID", width=400)
        self.id_entry.pack(pady=5)

        self.major_entry = ctk.CTkEntry(self.scroll_frame, placeholder_text="Major", width=400)
        self.major_entry.pack(pady=5)

        # Button
        self.send_btn = ctk.CTkButton(self.scroll_frame, text="Encrypt & Send", command=self.send_secure_message, width=400, fg_color="green")
        self.send_btn.pack(pady=15)

        # VISUALIZATION
        
        #Public Key Display
        self.lbl_key = ctk.CTkLabel(self.scroll_frame, text="Step 1: Received RSA Public Key", font=("Arial", 14, "bold"))
        self.lbl_key.pack(pady=(10, 0), anchor="w", padx=20)
        
        self.pub_key_box = ctk.CTkTextbox(self.scroll_frame, height=100, width=500)
        self.pub_key_box.pack(pady=5)

        # Ciphertext Display
        self.lbl_cipher = ctk.CTkLabel(self.scroll_frame, text="Step 2: AES Encrypted Ciphertext (Base64)", font=("Arial", 14, "bold"))
        self.lbl_cipher.pack(pady=(10, 0), anchor="w", padx=20)

        self.cipher_box = ctk.CTkTextbox(self.scroll_frame, height=80, width=500, text_color="yellow")
        self.cipher_box.pack(pady=5)

        #Logs
        self.lbl_log = ctk.CTkLabel(self.scroll_frame, text="App Status / Logs", font=("Arial", 14, "bold"))
        self.lbl_log.pack(pady=(10, 0), anchor="w", padx=20)

        self.status_box = ctk.CTkTextbox(self.scroll_frame, height=100, width=500)
        self.status_box.pack(pady=5)

    def log(self, text):
        self.status_box.insert("end", f">> {text}\n")
        self.status_box.see("end")

    def send_secure_message(self):
        try:
            self.status_box.delete("0.0", "end") 
            self.log("Starting process...")

            #Serialization
            student_data = {
                "name": self.name_entry.get(),
                "id": self.id_entry.get(),
                "major": self.major_entry.get()
            }
            json_payload = json.dumps(student_data, indent=4)
            with open("sent_student.json", "w", encoding="utf-8") as f:
                f.write(json_payload)

            # Public Key
            self.log("Fetching RSA Public Key from Server...")
            response = requests.get('http://127.0.0.1:5000/get_public_key')
            server_pub_key_str = response.json()['public_key']
    
            self.pub_key_box.delete("0.0", "end")
            self.pub_key_box.insert("0.0", server_pub_key_str)
            self.log("Public Key received and displayed.")

            server_pub_key = RSA.import_key(server_pub_key_str)


            session_key = get_random_bytes(16)
            iv = get_random_bytes(16)


            rsa_cipher = PKCS1_OAEP.new(server_pub_key)
            encrypted_key = rsa_cipher.encrypt(session_key)

    
            aes_cipher = AES.new(session_key, AES.MODE_CBC, iv)
            encrypted_payload_bytes = aes_cipher.encrypt(pad(json_payload.encode('utf-8'), AES.block_size))
            
            encrypted_payload_b64 = base64.b64encode(encrypted_payload_bytes).decode('utf-8')
            self.cipher_box.delete("0.0", "end")
            self.cipher_box.insert("0.0", encrypted_payload_b64)
            self.log("Message encrypted and displayed.")

            # HMAC 
            h = HMAC.new(session_key, encrypted_payload_bytes, digestmod=SHA256)
            hmac_sig = h.hexdigest()

        
            final_payload = {
                "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8'),
                "payload": encrypted_payload_b64,
                "iv": base64.b64encode(iv).decode('utf-8'),
                "hmac": hmac_sig
            }

            self.log("Sending payload to server...")
            res = requests.post('http://127.0.0.1:5000/receive_message', json=final_payload)
            
            if res.status_code == 200:
                self.log("SUCCESS: Server verified and decrypted the message.")
            else:
                self.log(f"FAILURE: {res.text}")

        except Exception as e:
            self.log(f"Error: {str(e)}")

if __name__ == "__main__":
    app = MessagingApp()
    app.mainloop()