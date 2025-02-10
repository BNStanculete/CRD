from socket import socket, AF_INET, SOCK_STREAM
import ssl

true_positives = 0
true_negatives = 0


with socket(AF_INET, SOCK_STREAM) as server_socket:
    server_socket.bind(("0.0.0.0", 443))
    server_socket.listen(1)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="../.ssh/cert.crt", keyfile="../.ssh/cert.key")
    secure_socket = context.wrap_socket(server_socket, server_side=True)

    while True:
        try:
            client_socket, addr = secure_socket.accept()

            # Prepare a simple HTTPS response
            http_response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=UTF-8\r\n"
                "Content-Length: 13\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Hello, HTTPS!"
            )

            # Send the response to the client
            client_socket.sendall(http_response.encode('utf-8'))
            print("Response sent, closing connection.")

            print(addr)
            client_socket.close()
        except Exception as e:
            print(f"ERROR: {e}")
