from Crypto.Cipher import ChaCha20
import hashlib

class CHACHA:
    
    def __init__(self, key):
        self.key = hashlib.sha256(str(key).encode()).digest()
        
    def encrypt(self, input_data):
        cipher = ChaCha20.new(key=self.key)
        nonce = cipher.nonce
        ciphertext = cipher.encrypt(input_data)
        return nonce + ciphertext

    def decrypt(self, ciphertext):
        # Ekstrak nonce (12 byte pertama) dan ciphertext (sisanya)
        nonce = ciphertext[:12]
        ciphertext = ciphertext[12:]
        
        # Buat cipher ChaCha20 dengan key dan nonce
        cipher = ChaCha20.new(key=self.key, nonce=nonce)
        
        # Dekripsi ciphertext
        plaintext = cipher.decrypt(ciphertext)
        
        return plaintext
        

# Contoh penggunaan
# key = "mysecretpassword" # Kunci ChaCha20 harus sepanjang 32 byte
# cha = CHACHA(key)
# # Enkripsi
# # cha.encrypt_file('input.pdf', 'encrypted.pdf')

# # # Dekripsi
# cha.decrypt_file('input.pdf', 'decrypted.pdf')

# Inisialisasi
# cha = CHACHA("kunci_rahasia")

# # Enkripsi
# plaintext = b"Ini adalah pesan rahasia"
# encrypted_data = cha.encrypt(plaintext)
# print(f"Data terenkripsi: {encrypted_data}")

# # Dekripsi
# decrypted_data = cha.decrypt(encrypted_data)
# print(f"Data terdekripsi: {decrypted_data.decode()}")