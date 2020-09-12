from Crypto.Cipher import AES
from hashlib import sha256
from struct import pack
import math


class AES_CBC_ESSIV:
    def __init__(self, key):
        self.key = key
        self.salt = sha256(self.key).digest()
        self.essiv_cipher = AES.new(self.salt, AES.MODE_ECB)

    def decrypt(self, data, file_output=b'', block_size=512):
        decrypted_data = b''
        number_of_blocks = int(math.ceil(float(len(data)) / block_size))

        for block_number in range(0, number_of_blocks):
            long_block_number = pack("<I", block_number) + b"\x00" * 12
            essiv = self.essiv_cipher.encrypt(long_block_number)

            cipher = AES.new(self.key, AES.MODE_CBC, essiv)
            if file_output != b'':
                file_output.write(cipher.decrypt(data[block_number * block_size: (block_number + 1) * block_size]))
            else:
                decrypted_data += cipher.decrypt(data[block_number * block_size: (block_number + 1) * block_size])
        return decrypted_data

    def encrypt(self, data, file_output=b'', block_size=512):
        encrypted_data = b''
        number_of_blocks = int(math.ceil(float(len(data)) / block_size))

        for block_number in range(0, number_of_blocks):
            long_block_number = pack("<I", block_number) + b"\x00" * 12
            essiv = self.essiv_cipher.encrypt(long_block_number)

            cipher = AES.new(self.key, AES.MODE_CBC, essiv)
            if file_output != b'':
                file_output.write(cipher.encrypt(data[block_number * block_size: (block_number + 1) * block_size]))
            else:
                encrypted_data += cipher.encrypt(data[block_number * block_size: (block_number + 1) * block_size])
        return encrypted_data
