from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Cipher import PKCS1_OAEP
import random

random.seed(42)
aes_key = get_random_bytes(32)

with open("sender_public.pem", "rb") as f:
    sender_public_key_data = f.read()
public_key_s = RSA.import_key(sender_public_key_data)

# Read receiver's private key (for decrypting AES key)
with open("receiver_private.pem", "rb") as f:
    receiver_private_key_data = f.read()
private_key_r = RSA.import_key(receiver_private_key_data)

file = open("send.bin","rb")
file.seek(0, 2)
file_size = file.tell()
file.seek(0)  

message_size = file_size - (528)

enc_aes_key = file.read(256)
vec = file.read(16)
cipher_text = file.read(max(0,message_size))
signature = file.read(256)
file.close()

#signature fail for demo purposes
sig_change = bytearray(signature)
sig_change[0] = 0x01
bad_signature = bytes(sig_change)
signature = bad_signature

cipher_rsa = PKCS1_OAEP.new(private_key_r)
aes_key = cipher_rsa.decrypt(enc_aes_key)

cipher_aes = AES.new(aes_key,AES.MODE_CBC,vec)
plaintext = unpad(cipher_aes.decrypt(cipher_text),AES.block_size)

rec_hash = SHA256.new(plaintext)

try:
    pkcs1_15.new(public_key_s).verify(rec_hash, signature)
    print("Signature Verified")
    print(plaintext)
except (ValueError, TypeError):
    print("Signature Verification Failed")


