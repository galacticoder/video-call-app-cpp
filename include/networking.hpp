#pragma once

#include <iostream>
#include <sys/socket.h>
#include <boost/asio.hpp>
#include <fmt/core.h>
#include <netinet/in.h>
#include <unistd.h>

#define BUFFERSIZE 4096

class Networking
{
private:
	static bool isPortAvailable(int &port)
	{
		int pavtempsock;
		struct sockaddr_in addr;
		bool available = false;

		pavtempsock = socket(AF_INET, SOCK_STREAM, 0);

		if (pavtempsock < 0)
		{
			std::cerr << "Cannot create socket to test port availability" << std::endl;
			return false;
		}

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(port);

		bind(pavtempsock, (struct sockaddr *)&addr, sizeof(addr)) < 0 ? available = false : available = true;

		close(pavtempsock);
		return available;
	}

public:
	static int findAvailablePort()
	{
		int defaultPort = 8080;

		if (isPortAvailable(defaultPort))
			return defaultPort;

		for (int i = 49152; i <= 65535; i++)
		{
			if (isPortAvailable(i))
				return i;
		}

		std::cout << "No available ports have been found." << std::endl;
		return 0;
	}

	static int startServerSocket(const int &port)
	{
		struct sockaddr_in server_addr;

		int sockfd;
		if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		{
			std::cerr << "Socket creation failed" << std::endl;
			return -1;
		}

		std::memset(&server_addr, 0, sizeof(server_addr));

		// Configure server address
		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = INADDR_ANY;
		server_addr.sin_port = htons(port);

		// Bind the socket to the address
		if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
		{
			std::cerr << "Bind failed!" << std::endl;
			close(sockfd);
			return -1;
		}

		return sockfd;
	}
};

class ClientNetworking
{
public:
	static int createUDPSocket(const std::string &serverAddress, int port, sockaddr_in &serverAddr)
	{
		struct sockaddr_in server_addr;
		int sockfd;

		if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		{
			std::cerr << "Socket creation failed!" << std::endl;
			return -1;
		}

		return sockfd;
	}

	static SSL *createObjectSSL(int &sockfd, SSL_CTX *&ctx)
	{
		SSL *ssl = SSL_new(ctx);
		if (!ssl)
		{
			std::cerr << "Unable to create SSL object!" << std::endl;
			exit(EXIT_FAILURE);
		}

		if (SSL_set_fd(ssl, sockfd) != 1)
		{
			std::cerr << "Unable to associate socket with SSL!" << std::endl;
			SSL_free(ssl);
			exit(EXIT_FAILURE);
		}

		return ssl;
	}

	static void connectToServer(int &sockfd, sockaddr_in &serverAddr, SSL *ssl)
	{
		if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
		{
			std::cout << "Failed to connect to server" << std::endl;
			exit(EXIT_FAILURE);
		}

		if (SSL_connect(ssl) != 1)
		{
			std::cout << "Failed to establish SSL connection" << std::endl;
			exit(EXIT_FAILURE);
		}
	}
};