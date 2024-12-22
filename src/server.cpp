#include <iostream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "../include/dtls1.h"
#include "../include/openssl.hpp"
#include "../include/networking.hpp"
#include "../include/keys.hpp"

int main()
{
	std::cout << "test" << std::endl;
	OpenSSL::initOpenssl();
	GenerateKeys::generateCertificate(serverKeyFile, serverCertFile);

	SSL_CTX *ctx = OpenSSL::createContext();
	OpenSSL::configureContext(ctx, serverKeyFile, serverCertFile);

	const int port = Networking::findAvailablePort();
	int sockfd = Networking::startServerSocket(port);
	std::cout << "Server listening on port " << port << std::endl;

	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);

	char buffer[BUFFERSIZE];

	while (true)
	{
		int len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &client_len);
		if (len < 0)
		{
			perror("Error receiving data");
			continue;
		}

		SSL *ssl = SSL_new(ctx);
		SSL_set_fd(ssl, sockfd);

		if (SSL_accept(ssl) <= 0)
		{
			ERR_print_errors_fp(stderr);
		}
		else
		{
			std::cout << "Received secured data: " << buffer << std::endl;
		}

		SSL_free(ssl);
	}

	close(sockfd);
	SSL_CTX_free(ctx);
	OpenSSL::cleanupOpenssl();
	return 0;
}
