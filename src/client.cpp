#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/dtls1.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include "../include/openssl.hpp"
#include "../include/networking.hpp"
#include "../include/keys.hpp"

#define BUFFER_SIZE 4096

void communicateWithServer(SSL *ssl)
{
	char buffer[BUFFER_SIZE];
	std::string message = "Hello from DTLS client!";
	if (SSL_write(ssl, message.c_str(), message.size()) <= 0)
	{
		throw std::runtime_error("Failed to send message to server");
	}

	int bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1);
	if (bytesRead > 0)
	{
		buffer[bytesRead] = '\0';
		std::cout << "Received from server: " << buffer << std::endl;
	}
	else
	{
		throw std::runtime_error("Failed to read response from server");
	}
}

int main()
{
	const std::string serverAddress = "127.0.0.1";
	const int serverPort = 8080;

	OpenSSL::initOpenssl();

	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(serverPort);

	if (inet_pton(AF_INET, serverAddress.c_str(), &serverAddr.sin_addr) <= 0)
	{
		std::cout << "Invalid server IP address" << std::endl;
	}

	SSL_CTX *ctx = ClientOpenSSL::createSSLContext(clientCertFile, clientKeyFile);
	int sockfd = ClientNetworking::createUDPSocket(serverAddress, serverPort, serverAddr);
	SSL *ssl = ClientNetworking::createObjectSSL(sockfd, ctx);
	ClientNetworking::connectToServer(sockfd, serverAddr, ssl);

	std::cout << "Connected to server with cipher: " << SSL_get_cipher(ssl) << std::endl;

	std::string msg = "Hello, DTLS server!";
	if (SSL_write(ssl, msg.c_str(), msg.length()) <= 0)
	{
		std::cout << "Failed to send message" << std::endl;
	}

	char buffer[1024];
	int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
	if (bytes_received <= 0)
	{
		std::cout << "Failed to receive message" << std::endl;
	}

	buffer[bytes_received] = '\0';
	std::cout << "Received message: " << buffer << std::endl;

	// Clean up
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sockfd);
	SSL_CTX_free(ctx);
	EVP_cleanup();

	return 0;
}
