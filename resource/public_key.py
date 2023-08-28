import sys
import ecdsa
import hashlib
import base58
import codecs
from cypt import encrypt_private_key


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
