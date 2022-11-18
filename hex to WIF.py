dec = int(input("Enter a decimal number: "))
A = (hex(dec))
# From private key(hex) to Wallet Import Format(WIF)
import codecs  #If not installed: "pip3 install codecs"
import hashlib
# PK0 is a demo private key.
PK = input("Enter private key: ")
PK0 = PK
#PK0 = "841846de7afbe32ee7ded837872c6e0825db095275b8afed0000000000000000"
PK1 = '80'+ PK0
PK2 = hashlib.sha256(codecs.decode(PK1, 'hex'))
PK3 = hashlib.sha256(PK2.digest())
checksum = codecs.encode(PK3.digest(), 'hex')[0:8]
PK4 = PK1 + str(checksum)[2:10]  #I know it looks wierd

# Define base58
def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add ‘1’ for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string

WIF = base58(PK4)
print(WIF)