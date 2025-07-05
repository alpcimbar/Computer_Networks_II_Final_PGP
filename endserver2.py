from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Cipher import PKCS1_OAEP
import random
import socket

random.seed(42)
aes_key = get_random_bytes(32)

if __name__ == "__main__":
    host = "127.0.0.2"
    port = 4455

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)

    print(f"TCP server started at {host}:{port}")
    conn, addr = server.accept()
    print(f"Client connected from {addr}")

    data = conn.recv(1024)
    if not data:
            print("Client disconnected.")

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


data = data.decode()
print(f"Client: {data}")

#file = open("send.bin","rb")
#file.seek(0, 2)
#file_size = file.tell()
#file.seek(0)  

#message_size = file_size - (528)

#enc_aes_key = file.read(256)
#vec = file.read(16)
#cipher_text = file.read(max(0,message_size))
#signature = file.read(256)
#file.close()

enc_aes_key = conn.recv(256)
#enc_aes_key = recv_all(conn, 256)

vec = conn.recv(16)
#vec = recv_all(conn, 16)

rest = b""
while True:
    chunk = conn.recv(4096)
    if not chunk:
        break
    rest += chunk
signature = rest[-256:]
cipher_text = rest[:-256]

#signature fail for demo purposes
#sig_change = bytearray(signature)
#sig_change[0] = 0x01
#bad_signature = bytes(sig_change)
#signature = bad_signature

cipher_rsa = PKCS1_OAEP.new(private_key_r)
aes_key = cipher_rsa.decrypt(enc_aes_key)

cipher_aes = AES.new(aes_key,AES.MODE_CBC,vec)
plaintext = unpad(cipher_aes.decrypt(cipher_text),AES.block_size)

rec_hash = SHA256.new(plaintext)

success_flag = 0
try:
    pkcs1_15.new(public_key_s).verify(rec_hash, signature)
    print("Signature Verified")
    print(plaintext)
    success_flag = 1
except (ValueError, TypeError):
    print("Signature Verification Failed")
    success_flag = 0


if success_flag:
    response = "ACK"
else:
    response ="NACK"

conn.sendall(response.encode("utf-8"))
print(response)

input("Press Enter to Close")