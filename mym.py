import sys
import ecdsa
import hashlib
import base58
import codecs
from cryptography.fernet import Fernet
import multiprocessing


def wif_to_hex(wif):
    decoded_wif = base58.b58decode(wif)
    hex_key = decoded_wif[1:-5].hex()
    return hex_key


def private_to_public(private_key):
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    public_key = verifying_key.to_string('compressed').hex()
    return public_key


def private_key_brute(private_key_hex, target_public_key, process_num):
    while True:
        private_key = bytes.fromhex(private_key_hex)
        public_key = private_to_public(private_key)
        private_key_int = int(private_key_hex, 16)
        private_key_int += 1
        private_key_hex = hex(private_key_int)[2:]

        if public_key == target_public_key:
            print(f'Process {process_num}: Private key found: {private_key_hex}\nPublic key: {public_key}')
            return private_key_hex


def to_basee58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    address_int = int(address_hex, 16)
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string


def create_bitcoin(mode=None):
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    public_key = private_key.get_verifying_key().to_string().hex()
    public_key_bytess = bytes.fromhex("02" if int(public_key[0], 16) % 2 == 0 else "03") + bytes.fromhex(public_key)
    print("public key:", public_key_bytess.hex()[:66])
    sha256_hash = hashlib.sha256(bytes.fromhex(public_key)).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    versioned_hash = b"\x00" + ripemd160_hash
    sha256_hash2 = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()
    address_bytes = versioned_hash + sha256_hash2[:4]
    address = base58.b58encode(address_bytes).decode()
    print("Private Key:", private_key.to_string().hex())
    print("Address:", address)
    # Uncompressed
    PK0 = private_key.to_string().hex()
    PK1 = '80' + PK0
    PK2 = hashlib.sha256(codecs.decode(PK1, 'hex')).digest()
    PK3 = hashlib.sha256(PK2).digest()
    checksum = PK3[:4]
    PK4 = PK1 + codecs.encode(checksum, 'hex').decode()
    WIF = to_basee58(PK4)
    # Compressed WIF
    PK5 = PK0 + '01'
    PK6 = '80' + PK5
    PK7 = hashlib.sha256(codecs.decode(PK6, 'hex')).digest()
    PK8 = hashlib.sha256(PK7).digest()
    checksum_comp = PK8[:4]
    PK9 = PK6 + codecs.encode(checksum_comp, 'hex').decode()
    WIF_comp = to_basee58(PK9)
    print("Compressed WIF: ", WIF_comp)
    print("Regular WIF: ", WIF)
    print()
    print("Please keep your private key safe!")
    print(
        "The key is automatically saved locally as '.txt', but it's advised to encrypt it with a password for security.")
    prompt = input("To encrypt the .txt file with a password, press 'Y' to continue.\n"
                   "To ignore and save the private key without encryption, press 'N': ")
    if prompt.lower() == 'y':
        password = input("Enter password: ")
        encrypted_private_key = encrypt_private_key(private_key.to_string().hex(), password)
        with open('private_key.txt', 'w') as f:
            f.write(f'private_key: {encrypted_private_key}\n')
    else:
        with open('private_key.txt', 'w') as f:
            f.write(f'private_key: {PK0}\n')
            f.write(f'address: {address}')
        print('Save securely offline!')


def decrypt_user_private_key():
    encrypted_private_key = input("Insert encrypted message here: ")
    password = input("Insert encryption password here: ")
    decrypted_private_key = decrypt_private_key(encrypted_private_key, password)
    with open('private_key.txt', 'w') as f:
        f.write(f'private_key: {decrypted_private_key}\n')


def encrypt_private_key(private_key, password):
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    encrypted_private_key = cipher_suite.encrypt(private_key.encode())
    return encrypted_private_key.decode()


def decrypt_private_key(encrypted_private_key, password):
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    decrypted_private_key = cipher_suite.decrypt(encrypted_private_key.encode())
    return decrypted_private_key.decode()


def public_key_hash_address(public_key):
    public_key_bytes = bytes.fromhex(public_key)
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    print("SHA256_hash:", sha256_hash.hex())
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    print("ripemd160:", ripemd160_hash.hex())
    versioned_hash = b"\x00" + ripemd160_hash
    sha256_hash2 = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()
    address_bytes = versioned_hash + sha256_hash2[:4]
    address = base58.b58encode(address_bytes).decode()
    return address


def next_public_key_division(public_key, scalar_value):
    public_key_bytes = bytes.fromhex(public_key)
    vk = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)
    point = vk.pubkey.point
    scalar_value_inv = pow(scalar_value, -1, ecdsa.SECP256k1.order)
    new_point = scalar_value_inv * point
    new_vk = ecdsa.VerifyingKey.from_public_point(new_point, curve=ecdsa.SECP256k1)
    new_public_key = new_vk.to_string().hex()
    return new_public_key


def next_public_key_addition(public_key, scalar_value):
    public_key_bytes = bytes.fromhex(public_key)
    vk = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)
    point = vk.pubkey.point
    new_point = point + scalar_value * ecdsa.SECP256k1.generator
    new_vk = ecdsa.VerifyingKey.from_public_point(new_point, curve=ecdsa.SECP256k1)
    new_public_key = new_vk.to_string().hex()
    return new_public_key


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python mym.py generate")
        sys.exit(1)
    command = sys.argv[1]
    if command == "brute":
        target_public_key = input('Enter target public key here: ')
        wif_input = input("Enter WIF private key: ")
        num_processes = multiprocessing.cpu_count()

        hex_output = wif_to_hex(wif_input)
        private_key_hex = hex_output

        processes = []
        for i in range(num_processes):
            process = multiprocessing.Process(
                target=private_key_brute,
                args=(private_key_hex, target_public_key, i + 1)
            )
            processes.append(process)
            process.start()

        for process in processes:
            process.join()

        print('Finished searching.')

    elif command == "generate":
        create_bitcoin()
    elif command == "decrypt":
        decrypt_user_private_key()
    elif command == "-m":
        if len(sys.argv) < 4:
            print("Usage: python mym.py -m <mode> <public_key> [scalar_number]")
            sys.exit(1)
        mode = sys.argv[2]
        if mode != "OP" and mode != "PA":
            print("Invalid mode. Supported modes: OP, PA")
            sys.exit(1)
        public_key = sys.argv[3]
        if mode == "OP":
            if len(sys.argv) != 5:
                print("Usage: python mym.py -m OP <public_key> <scalar_number>")
                sys.exit(1)
            try:
                scalar_value = int(sys.argv[4])
            except ValueError:
                print("Invalid scalar value. Please provide a valid integer.")
                sys.exit(1)
            operation = input("Choose the operation:\n1. Addition\n2. Division\n")
            if operation == "1":
                result = next_public_key_addition(public_key, scalar_value)
            elif operation == "2":
                result = next_public_key_division(public_key, scalar_value)
            else:
                print("Invalid operation choice.")
                sys.exit(1)
            pub = "04" + result
            compress_pub = pub[2:]
            public_key_bytes = bytes.fromhex("02" if int(compress_pub[0], 16) % 2 == 0 else "03") + bytes.fromhex(compress_pub)
            print("New Public Key:", public_key_bytes.hex()[:66])
        elif mode == "PA":
            result = public_key_hash_address(public_key)
            print("Bitcoin Address:", result)
        else:
            print("Invalid command. Use 'generate' to create a Bitcoin address.")
            sys.exit(1)
