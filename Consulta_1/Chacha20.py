from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import psutil
import time

def generate_key_chacha20():
    """Genera una clave para ChaCha20."""
    return get_random_bytes(32)  # ChaCha20 usa una clave de 256 bits

def encrypt_chacha20(input_file, output_file, key):
    """Cifra un archivo DICOM con ChaCha20."""
    cipher = ChaCha20.new(key=key, nonce=get_random_bytes(8))

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(plaintext)

    with open(output_file, 'wb') as f:
        f.write(cipher.nonce + ciphertext)  # Guardar nonce y texto cifrado

def decrypt_chacha20(input_file, output_file, key):
    """Descifra un archivo DICOM cifrado con ChaCha20."""
    with open(input_file, 'rb') as f:
        nonce = f.read(8)  # Leer nonce
        ciphertext = f.read()

    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)

    with open(output_file, 'wb') as f:
        f.write(plaintext)

# Medición de rendimiento para ChaCha20
def measure_performance_chacha20(encrypt_func, decrypt_func, key, algo_name):
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

# Medición de velocidad para ChaCha20
def measure_speed_chacha20(encrypt_func, decrypt_func, key, algo_name):
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
key_chacha20 = generate_key_chacha20()
measure_performance_chacha20(encrypt_chacha20, decrypt_chacha20, key_chacha20, "ChaCha20")
measure_speed_chacha20(encrypt_chacha20, decrypt_chacha20, key_chacha20, "ChaCha20")
