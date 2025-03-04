from twofish import Twofish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import psutil
import time

def generate_key_twofish():
    """Genera una clave para Twofish (256 bits)."""
    return get_random_bytes(32)  # Twofish usa una clave de 256 bits

def encrypt_twofish(input_file, output_file, key):
    """Cifra un archivo DICOM con Twofish."""
    cipher = Twofish(key)

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Asegúrate de que el texto tiene un tamaño múltiplo de 16 bytes (el tamaño del bloque)
    plaintext = pad(plaintext, 16)

    ciphertext = b""
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        ciphertext += cipher.encrypt(block)

    with open(output_file, 'wb') as f:
        f.write(ciphertext)

def decrypt_twofish(input_file, output_file, key):
    """Descifra un archivo DICOM cifrado con Twofish."""
    cipher = Twofish(key)

    with open(input_file, 'rb') as f:
        ciphertext = f.read()

    plaintext = b""
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        plaintext += cipher.decrypt(block)

    # Eliminar el padding después de descifrar
    plaintext = unpad(plaintext, 16)

    with open(output_file, 'wb') as f:
        f.write(plaintext)

# Medición de rendimiento para Twofish
def measure_performance_twofish(encrypt_func, decrypt_func, key, algo_name):
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

# Medición de velocidad para Twofish
def measure_speed_twofish(encrypt_func, decrypt_func, key, algo_name):
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

# Ejemplo de ejecución
key_twofish = generate_key_twofish()
measure_performance_twofish(encrypt_twofish, decrypt_twofish, key_twofish, "Twofish")
measure_speed_twofish(encrypt_twofish, decrypt_twofish, key_twofish, "Twofish")
