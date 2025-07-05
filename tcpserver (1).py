import socket

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 4455

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)

    print(f"TCP server started at {host}:{port}")
    conn, addr = server.accept()
    print(f"Client connected from {addr}")

    while True:
        data = conn.recv(1024)
        if not data:
            print("Client disconnected.")
            break

        data = data.decode("utf-8")
        print(f"Client: {data}")

        response = input("Enter response to client: ")
        conn.sendall(response.encode("utf-8"))
