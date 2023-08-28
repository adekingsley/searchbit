from resource.cypt import encrypt_private_key, decrypt_user_private_key
import multiprocessing
from resource.public_key import *


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
