import socket

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 4455

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    print(f"Connected to TCP server at {host}:{port}")

    while True:
        msg = input("Enter mail message to send: ")
        
        client.sendall(msg.encode("utf-8"))

        data = client.recv(1024)
        if not data:
            print("Server disconnected.")
            break

        data = data.decode("utf-8")
        print(f"Server: {data}")
