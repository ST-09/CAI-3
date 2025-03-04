from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def generate_key():
    """Genera una clave AES-256 segura."""
    return os.urandom(32)

def encrypt_dicom(input_file, output_file, key):
    """Cifra un archivo DICOM con AES-256 CBC."""
    iv = os.urandom(16)  # Vector de inicialización
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    
    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)

def decrypt_dicom(input_file, output_file, key):
    """Descifra un archivo DICOM cifrado con AES-256 CBC."""
    with open(input_file, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    with open(output_file, 'wb') as f:
        f.write(plaintext)

# Ejemplo de uso
def main():
    key = generate_key()
    input_file = 'image-000002.dcm'
    encrypted_file = 'imagen_encrypted.dcm'
    decrypted_file = 'imagen_decrypted.dcm'
    
    print("Cifrando archivo...")
    encrypt_dicom(input_file, encrypted_file, key)
    print("Archivo cifrado guardado en:", encrypted_file)
    
    print("Descifrando archivo...")
    decrypt_dicom(encrypted_file, decrypted_file, key)
    print("Archivo descifrado guardado en:", decrypted_file)

if __name__ == "__main__":
    main()