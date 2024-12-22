#pragma once

#include <iostream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>

class OpenSSL
{
public:
	static void initOpenssl()
	{
		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();
		SSL_library_init();
	}

	static void cleanupOpenssl()
	{
		EVP_cleanup();
		ERR_free_strings();
	}

	static SSL_CTX *createContext()
	{
		const SSL_METHOD *method = DTLS_server_method();

		SSL_CTX *ctx = SSL_CTX_new(method);
		if (!ctx)
		{
			perror("Unable to create SSL context");
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}
		return ctx;
	}

	static void configureContext(SSL_CTX *ctx, const std::string &keyFile, const std::string &certFile)
	{
		if (SSL_CTX_use_certificate_file(ctx, certFile.c_str(), SSL_FILETYPE_PEM) <= 0)
		{
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}
		if (SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0)
		{
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}
		if (!SSL_CTX_check_private_key(ctx))
		{
			std::cerr << "Private key does not match the certificate public key" << std::endl;
			exit(EXIT_FAILURE);
		}
	}
};