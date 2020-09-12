from android_aes import AES_CBC_ESSIV
from hashlib import sha256
from os import urandom
from binascii import hexlify

random_data = urandom(0x10000)

key = urandom(0x10)
print(hexlify(key))

cipher = AES_CBC_ESSIV(key)
output = open('ENCRYPTED_DATA', 'wb')
cipher.encrypt(random_data, file_output=output)
output.close()

encrypted_data = open('ENCRYPTED_DATA', 'rb').read()
output2 = open('DECRYPTED_DATA', 'wb')
cipher.decrypt(encrypted_data, file_output=output2)
output2.close()

decrypted_data = open('DECRYPTED_DATA', 'rb').read()

print('RANDOM DATA    : ', sha256(random_data).hexdigest())
print('ENCRYPTED DATA : ', sha256(encrypted_data).hexdigest())
print('DECRYPTED DATA : ', sha256(decrypted_data).hexdigest())
