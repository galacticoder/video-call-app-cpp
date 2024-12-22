#include <iostream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/dtls1.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>

#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"

// Error handling function
// void handle_error(const char *msg)
// {
// 	perror(msg);
// 	exit(1);
// }

// // Initialize OpenSSL
// void init_openssl()
// {
// 	OpenSSL_add_all_algorithms();
// 	SSL_load_error_strings();
// 	SSL_library_init();
// }

int main()
{
	// Initialize OpenSSL
	init_openssl();

	// Create socket
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		handle_error("Failed to create socket");
	}

	// Set up server address
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(SERVER_PORT);
	if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0)
	{
		handle_error("Invalid server IP address");
	}

	// Create DTLS context
	const SSL_METHOD *method = DTLS_client_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx)
	{
		handle_error("Failed to create SSL context");
	}

	// Create a new SSL object
	SSL *ssl = SSL_new(ctx);
	if (!ssl)
	{
		handle_error("Failed to create SSL object");
	}

	// Set the socket file descriptor for the SSL object
	if (SSL_set_fd(ssl, sock) != 1)
	{
		handle_error("Failed to associate socket with SSL object");
	}

	// Connect the socket to the server address
	if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		handle_error("Failed to connect to server");
	}

	// Set up the SSL handshake
	if (SSL_connect(ssl) != 1)
	{
		handle_error("Failed to establish SSL connection");
	}

	std::cout << "Connected to server with cipher: " << SSL_get_cipher(ssl) << std::endl;

	// Send a message to the server
	std::string msg = "Hello, DTLS server!";
	if (SSL_write(ssl, msg.c_str(), msg.length()) <= 0)
	{
		handle_error("Failed to send message");
	}

	// Receive a response from the server
	char buffer[1024];
	int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
	if (bytes_received <= 0)
	{
		handle_error("Failed to receive message");
	}

	buffer[bytes_received] = '\0';
	std::cout << "Received message: " << buffer << std::endl;

	// Clean up
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sock);
	SSL_CTX_free(ctx);

	return 0;
}
