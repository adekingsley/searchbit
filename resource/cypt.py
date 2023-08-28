from cryptography.fernet import Fernet


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
