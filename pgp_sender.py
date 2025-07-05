from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Cipher import PKCS1_OAEP
import random

aes_key = get_random_bytes(32)

key_pair_s = RSA.generate(2048,)
private_key_s = key_pair_s.export_key()
public_key_s = key_pair_s.public_key().export_key()

key_pair_r = RSA.generate(2048,)
private_key_r = key_pair_r.export_key()
public_key_r = key_pair_r.public_key().export_key()

with open("sender_private.pem", "wb") as f:
    f.write(private_key_s)
with open("sender_public.pem", "wb") as f:
    f.write(public_key_s)
with open("receiver_private.pem", "wb") as f:
    f.write(private_key_r)
with open("receiver_public.pem", "wb") as f:
    f.write(public_key_r)
    

file = open("mail.txt","rb")
text = file.read()
file.close()

hash = SHA256.new(text)

sender_pv_key = RSA.import_key(private_key_s)
signature = pkcs1_15.new(sender_pv_key).sign(hash)

vec = get_random_bytes(16)

cipher_aes = AES.new(aes_key,AES.MODE_CBC,vec)
cipher_text = cipher_aes.encrypt(pad(text,AES.block_size))

receiver_pub_key = RSA.import_key(public_key_r)
cipher_rsa = PKCS1_OAEP.new(receiver_pub_key)
enc_aes_key = cipher_rsa.encrypt(aes_key)

file = open("send.bin","wb")
wri = enc_aes_key+vec+cipher_text+signature
print(wri)
file.write(wri)
file.close()