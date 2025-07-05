from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Cipher import PKCS1_OAEP
import socket
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


if __name__ == "__main__":
    host = "127.0.0.1"
    port = 4455

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    print(f"Connected to TCP server at {host}:{port}")


print("from file or input?[f/i]")
choice = input()

if choice == "f":

    file = open("mail.txt","rb")
    text = file.read()
    file.close()
elif choice == "i":
    text = input("Enter Message to send:").encode

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

client.sendall(wri)
data = client.recv(1024)
if not data:
    print("Server disconnected.")
else:
    data = data.decode("utf-8")
    print(f"Server: {data}")


input("Press Enter to Close")