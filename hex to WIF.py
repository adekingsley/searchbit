import codecs
import hashlib


def base58(address_hex):
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


PK = input("Enter private key: ")
PK0 = PK
PK1 = '80' + PK0
PK2 = hashlib.sha256(codecs.decode(PK1, 'hex')).digest()
PK3 = hashlib.sha256(PK2).digest()
checksum = PK3[:4]
PK4 = PK1 + codecs.encode(checksum, 'hex').decode()
WIF = base58(PK4)
print("Regular WIF: ", WIF)
# Compressed WIF
PK5 = PK0 + '01'  # Append '01' for compressed format
PK6 = '80' + PK5
PK7 = hashlib.sha256(codecs.decode(PK6, 'hex')).digest()
PK8 = hashlib.sha256(PK7).digest()
checksum_comp = PK8[:4]
PK9 = PK6 + codecs.encode(checksum_comp, 'hex').decode()
WIF_comp = base58(PK9)
print("Compressed WIF: ", WIF_comp)
