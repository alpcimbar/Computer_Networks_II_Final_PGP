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

file = open("mail.txt","rb")
text = file.read()
file.close()

            
with open("receiver_public.pem", "rb") as f:
    receiver_public_key_data = f.read()
public_key_r = RSA.import_key(receiver_public_key_data)

with open("sender_private.pem", "rb") as f:
    sender_private_key_data = f.read()
private_key_s = RSA.import_key(sender_private_key_data)


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
    text = input("Enter Message to send:").encode()

hash = SHA256.new(text)

signature = pkcs1_15.new(private_key_s).sign(hash)

vec = get_random_bytes(16)

cipher_aes = AES.new(aes_key,AES.MODE_CBC,vec)
cipher_text = cipher_aes.encrypt(pad(text,AES.block_size))

cipher_rsa = PKCS1_OAEP.new(public_key_r)
enc_aes_key = cipher_rsa.encrypt(aes_key)

file = open("send.bin","wb")
wri = enc_aes_key+vec+cipher_text+signature
print(wri)
file.write(wri)
file.close()
print("test")
client.sendall(wri)
data = client.recv(1024)
if not data:
    print("Server disconnected.")
else:
    data = data.decode("utf-8")
    print(f"Server: {data}")


input("Press Enter to Close")