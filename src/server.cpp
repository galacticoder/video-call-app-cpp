#include <iostream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/dtls1.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "../include/dtls1.h"
#include "../include/openssl.hpp"
#include "../include/networking.hpp"
#include "../include/keys.hpp"

int main()
{
	OpenSSL::initOpenssl();
	GenerateKeys::generateCertificate(serverKeyFile, serverCertFile);

	SSL_CTX *ctx = OpenSSL::createContext();
	OpenSSL::configureContext(ctx, serverKeyFile, serverCertFile);

	const int port = Networking::findAvailablePort();
	int sockfd = Networking::startServerSocket(port);
	std::cout << "Server listening on port " << port << std::endl;

	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);

	BIO *bio = BIO_new_dgram(sockfd, BIO_NOCLOSE);
	SSL *ssl = SSL_new(ctx);
	SSL_set_bio(ssl, bio, bio);

	if (SSL_accept(ssl) <= 0)
	{
		std::cout << "SSL handshake failed" << std::endl;
	}

	char buffer[BUFFERSIZE];
	while (true)
	{
		memset(buffer, 0, BUFFERSIZE);
		int n = SSL_read(ssl, buffer, BUFFERSIZE);
		if (n <= 0)
		{
			std::cout << "Client has exited." << std::endl;
			break;
		}

		std::cout << "Client: " << buffer << "\n";

		const char *response = "Message received securely!";
		if (SSL_write(ssl, response, strlen(response)) <= 0)
		{
			std::cout << "Client has exited." << std::endl;
			break;
		}
	}

	SSL_free(ssl);
	close(sockfd);
	SSL_CTX_free(ctx);
	EVP_cleanup();

	return 0;
}
