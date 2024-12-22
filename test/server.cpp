#include <iostream>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

void handleErrors(const char *msg)
{
	perror(msg);
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
}

int main()
{
	SSL_library_init();
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	const SSL_METHOD *method = DTLS_server_method(); // DTLS server method
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx)
	{
		handleErrors("Unable to create SSL context");
	}

	// Load certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
		SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
	{
		handleErrors("Failed to load certificate or private key");
	}

	int sockfd;
	struct sockaddr_in serverAddr, clientAddr;
	socklen_t addrLen = sizeof(clientAddr);

	// Create UDP socket
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		handleErrors("Socket creation failed");
	}

	// Configure server address
	memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = INADDR_ANY;
	serverAddr.sin_port = htons(PORT);

	// Bind socket
	if (bind(sockfd, (const struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
	{
		handleErrors("Bind failed");
	}

	std::cout << "DTLS server listening on port " << PORT << "\n";

	// Set up BIO for the socket
	BIO *bio = BIO_new_dgram(sockfd, BIO_NOCLOSE);
	SSL *ssl = SSL_new(ctx);
	SSL_set_bio(ssl, bio, bio);

	// Accept the incoming connection using DTLS
	if (SSL_accept(ssl) <= 0)
	{
		handleErrors("SSL handshake failed");
	}

	char buffer[BUFFER_SIZE];
	while (true)
	{
		memset(buffer, 0, BUFFER_SIZE);
		int n = SSL_read(ssl, buffer, BUFFER_SIZE); // Read message from client
		if (n <= 0)
		{
			handleErrors("SSL_read failed");
		}

		std::cout << "Client: " << buffer << "\n";

		// Respond to the client
		const char *response = "Message received securely!";
		if (SSL_write(ssl, response, strlen(response)) <= 0)
		{
			handleErrors("SSL_write failed");
		}
	}

	// Clean up SSL and socket
	SSL_free(ssl);
	close(sockfd);
	SSL_CTX_free(ctx);
	EVP_cleanup();
	return 0;
}
