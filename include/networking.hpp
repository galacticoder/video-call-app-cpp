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

		int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
		if (sockfd < 0)
		{
			perror("Cannot create socket");
			exit(EXIT_FAILURE);
		}

		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = INADDR_ANY;
		server_addr.sin_port = htons(port);

		if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
		{
			perror("Bind failed");
			close(sockfd);
			exit(EXIT_FAILURE);
		}

		return sockfd;
	}
};