from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import psutil
import time

# Función de cifrado
def encrypt_dicom(input_file, output_file, key):
    """Cifra un archivo DICOM con AES-256 CBC."""
    iv = get_random_bytes(16)  # Vector de inicialización (16 bytes)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)  # Guardamos el IV junto con el ciphertext

# Función de descifrado
def decrypt_dicom(input_file, output_file, key):
    """Descifra un archivo DICOM cifrado con AES-256 CBC."""
    with open(input_file, 'rb') as f:
        iv = f.read(16)  # Leemos el IV
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    with open(output_file, 'wb') as f:
        f.write(plaintext)

# Función de medición de rendimiento (CPU, memoria y tiempo)
def measure_performance(encrypt_func, decrypt_func, key, algo_name):
    input_file = 'image-000002.dcm'
    encrypted_file = f"{algo_name}_encrypted.dcm"
    
    cpu_before = psutil.cpu_percent()
    mem_before = psutil.virtual_memory().used

    start_time = time.time()
    encrypt_func(input_file, encrypted_file, key)
    end_time = time.time()

    cpu_after = psutil.cpu_percent()
    mem_after = psutil.virtual_memory().used

    print(f"🔄 {algo_name} - Cifrado:")
    print(f"⏳ Tiempo: {end_time - start_time:.4f} seg")
    print(f"📊 CPU: {cpu_before}% → {cpu_after}%")
    print(f"💾 Memoria: {mem_before / 1e6:.2f} MB → {mem_after / 1e6:.2f} MB")

# Función de medición de velocidad (tiempos de cifrado y descifrado)
def measure_speed(encrypt_func, decrypt_func, key, algo_name):
    input_file = 'image-000002.dcm'
    encrypted_file = f"{algo_name}_encrypted.dcm"
    decrypted_file = f"{algo_name}_decrypted.dcm"

    start_encrypt = time.time()
    encrypt_func(input_file, encrypted_file, key)
    end_encrypt = time.time()

    start_decrypt = time.time()
    decrypt_func(encrypted_file, decrypted_file, key)
    end_decrypt = time.time()

    print(f"⚡ {algo_name} - Cifrado: {end_encrypt - start_encrypt:.4f} seg")
    print(f"⚡ {algo_name} - Descifrado: {end_decrypt - start_decrypt:.4f} seg")

# Main: Ejecutar cifrado/descifrado con AES-256 y medición de desempeño
if __name__ == "__main__":
    key_aes = get_random_bytes(32)  # Generar clave AES-256
    key_wrong = get_random_bytes(32)  # Clave incorrecta para probar

    input_file = 'image-000002.dcm'
    encrypted_file = 'imagen_encrypted.dcm'
    decrypted_file = 'imagen_decrypted.dcm'

    try:
        # Cifrar con AES-256
        print("🔒 Cifrando con AES-256...")
        encrypt_dicom(input_file, encrypted_file, key_aes)
        print(f"Archivo cifrado con éxito: {encrypted_file}")

        # Intentar descifrar con la clave incorrecta
        print("❌ Intentando descifrar con clave incorrecta...")
        decrypt_dicom(encrypted_file, decrypted_file, key_wrong)
        print("❌ ERROR AES: El descifrado funcionó con clave incorrecta.")
    except ValueError:
        print("✅ AES-256: Descifrado fallido con clave incorrecta.")

    # Medición de rendimiento y velocidad para AES-256
    measure_performance(encrypt_dicom, decrypt_dicom, key_aes, "AES-256")
    measure_speed(encrypt_dicom, decrypt_dicom, key_aes, "AES-256")
