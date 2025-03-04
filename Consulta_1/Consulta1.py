from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import hashlib

def generate_key():
    """Genera una clave AES-256 segura."""
    return os.urandom(32)

def save_key(key, filename="aes_key.bin"):
    """Guarda la clave en un archivo seguro."""
    with open(filename, "wb") as f:
        f.write(key)

def load_key(filename="aes_key.bin"):
    """Carga la clave desde un archivo seguro."""
    with open(filename, "rb") as f:
        return f.read()

def calculate_sha256(filename):
    """Calcula el hash SHA-256 de un archivo."""
    sha256 = hashlib.sha256()
    try:
        with open(filename, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        print(f"Error: El archivo {filename} no existe.")
        return None

def encrypt_dicom(input_file, output_file, key):
    """Cifra un archivo DICOM con AES-256 CBC."""
    try:
        if not os.path.exists(input_file) or os.stat(input_file).st_size == 0:
            print("Error: El archivo de entrada no existe o está vacío.")
            return

        iv = os.urandom(16)  # Vector de inicialización
        cipher = AES.new(key, AES.MODE_CBC, iv)

        with open(input_file, 'rb') as f:
            plaintext = f.read()

        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        with open(output_file, 'wb') as f:
            f.write(iv + ciphertext)

        print(f"Archivo cifrado con éxito: {output_file}")
    except Exception as e:
        print(f"Error en el cifrado: {e}")

def decrypt_dicom(input_file, output_file, key):
    """Descifra un archivo DICOM cifrado con AES-256 CBC."""
    try:
        if not os.path.exists(input_file) or os.stat(input_file).st_size == 0:
            print("Error: El archivo de entrada no existe o está vacío.")
            return

        with open(input_file, 'rb') as f:
            iv = f.read(16)
            ciphertext = f.read()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        with open(output_file, 'wb') as f:
            f.write(plaintext)

        print(f"Archivo descifrado con éxito: {output_file}")
    except Exception as e:
        print(f"Error en el descifrado: {e}")

# Ejemplo de uso
def main():
    key = generate_key()
    save_key(key)  # Guardar la clave para futuras ejecuciones

    input_file = 'image-000002.dcm'
    encrypted_file = 'imagen_encrypted.dcm'
    decrypted_file = 'imagen_decrypted.dcm'

    print("\nCifrando archivo...")
    encrypt_dicom(input_file, encrypted_file, key)

    # Verificación de integridad antes de descifrar
    original_hash = calculate_sha256(input_file)
    encrypted_hash = calculate_sha256(encrypted_file)

    if original_hash and encrypted_hash:
        print(f"Hash original: {original_hash}")
        print(f"Hash cifrado: {encrypted_hash}")

    print("\nDescifrando archivo...")
    decrypt_dicom(encrypted_file, decrypted_file, key)

    # Verificación de integridad después de descifrar
    decrypted_hash = calculate_sha256(decrypted_file)

    if original_hash and decrypted_hash:
        print(f"Hash descifrado: {decrypted_hash}")

        if original_hash == decrypted_hash:
            print("✅ Verificación exitosa: El archivo descifrado es idéntico al original.")
        else:
            print("⚠️ Advertencia: El archivo descifrado NO coincide con el original.")

if __name__ == "__main__":
    main()
