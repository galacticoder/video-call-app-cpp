#pragma once

#include <iostream>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <stdexcept>
#include <string>
#include <memory>
#include <csignal>
#include <fmt/core.h>

#define KEYSIZE 4096

#define serverCertFile "server-keys/server.crt"
#define serverKeyFile "server-keys/server.key"

#define clientCertFile "client-keys/client.crt"
#define clientKeyFile "client-keys/client.key"

class GenerateKeys
{
public:
	static void generateRSAKeys(const std::string &privateKeyFile, const std::string &publicKeyFile, int bits = KEYSIZE)
	{
		std::cout << "Generating keys.." << std::endl;
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
		if (!ctx)
		{
			ERR_print_errors_fp(stderr);
			raise(SIGINT);
		}

		if (EVP_PKEY_keygen_init(ctx) <= 0)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_CTX_free(ctx);
			raise(SIGINT);
		}

		if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_CTX_free(ctx);
			raise(SIGINT);
		}

		EVP_PKEY *pkey = NULL;
		if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
		{
			ERR_print_errors_fp(stderr);
			EVP_PKEY_CTX_free(ctx);
			raise(SIGINT);
		}

		EVP_PKEY_CTX_free(ctx);

		BIO *privateKeyBio = BIO_new_file(privateKeyFile.c_str(), "w+");
		PEM_write_bio_PrivateKey(privateKeyBio, pkey, NULL, NULL, 0, NULL, NULL);
		BIO_free_all(privateKeyBio);

		BIO *publicKeyBio = BIO_new_file(publicKeyFile.c_str(), "w+");
		PEM_write_bio_PUBKEY(publicKeyBio, pkey);
		BIO_free_all(publicKeyBio);

		EVP_PKEY_free(pkey);
	}

	static void generateCertificate(const std::string &keyFile, const std::string &certFile)
	{
		EVP_PKEY_CTX *pkeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
		if (!pkeyCtx)
		{
			throw std::runtime_error("Failed to create key context");
		}

		if (EVP_PKEY_keygen_init(pkeyCtx) <= 0)
		{
			EVP_PKEY_CTX_free(pkeyCtx);
			throw std::runtime_error("Failed to initialize key generation");
		}

		if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkeyCtx, 2048) <= 0)
		{
			EVP_PKEY_CTX_free(pkeyCtx);
			throw std::runtime_error("Failed to set RSA key size");
		}

		EVP_PKEY *pkey = nullptr;
		if (EVP_PKEY_keygen(pkeyCtx, &pkey) <= 0)
		{
			EVP_PKEY_CTX_free(pkeyCtx);
			throw std::runtime_error("Failed to generate RSA key pair");
		}

		EVP_PKEY_CTX_free(pkeyCtx);

		FILE *keyFilePtr = fopen(keyFile.c_str(), "w");
		if (!keyFilePtr)
		{
			EVP_PKEY_free(pkey);
			throw std::runtime_error("Failed to open key file for writing");
		}

		if (!PEM_write_PrivateKey(keyFilePtr, pkey, nullptr, nullptr, 0, nullptr, nullptr))
		{
			fclose(keyFilePtr);
			EVP_PKEY_free(pkey);
			throw std::runtime_error("Failed to write private key to file");
		}

		fclose(keyFilePtr);

		X509 *cert = X509_new();
		if (!cert)
		{
			EVP_PKEY_free(pkey);
			throw std::runtime_error("Failed to create X509 certificate");
		}

		ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
		X509_gmtime_adj(X509_get_notBefore(cert), 0);
		X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 60 * 60);

		X509_set_pubkey(cert, pkey);

		X509_NAME *name = X509_get_subject_name(cert);
		X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"localhost", -1, -1, 0);
		X509_set_issuer_name(cert, name);

		if (!X509_sign(cert, pkey, EVP_sha256()))
		{
			X509_free(cert);
			EVP_PKEY_free(pkey);
			throw std::runtime_error("Failed to sign certificate");
		}

		FILE *certFilePtr = fopen(certFile.c_str(), "w");
		if (!certFilePtr)
		{
			X509_free(cert);
			EVP_PKEY_free(pkey);
			throw std::runtime_error("Failed to open certificate file for writing");
		}

		if (!PEM_write_X509(certFilePtr, cert))
		{
			fclose(certFilePtr);
			X509_free(cert);
			EVP_PKEY_free(pkey);
			throw std::runtime_error("Failed to write certificate to file");
		}

		fclose(certFilePtr);
		X509_free(cert);
		EVP_PKEY_free(pkey);
	}
};

class LoadKey
{
public:
	static EVP_PKEY *LoadPrivateKey(const std::string &privateKeyFile)
	{
		BIO *bio = BIO_new_file(privateKeyFile.c_str(), "r");
		if (!bio)
		{
			std::cerr << "Error loading private rsa key: ";
			ERR_print_errors_fp(stderr);
			return nullptr;
		}

		EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
		BIO_free(bio);

		if (!pkey)
		{
			std::cerr << "Error loading private rsa key: ";
			ERR_print_errors_fp(stderr);
			return nullptr;
		}

		std::cout << "Loaded RSA Private key file (" << privateKeyFile << ") successfully" << std::endl;

		return pkey;
	}

	static EVP_PKEY *LoadPublicKey(const std::string &publicKeyFile)
	{
		BIO *bio = BIO_new_file(publicKeyFile.c_str(), "r");
		if (!bio)
		{
			ERR_print_errors_fp(stderr);
			std::cerr << fmt::format("Error loading public rsa key from path {}", publicKeyFile) << std::endl;
			return nullptr;
		}

		EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
		BIO_free(bio);

		if (!pkey)
		{
			std::cerr << fmt::format("Error loading public rsa key from path {}", publicKeyFile) << std::endl;
			return nullptr;
		}

		std::cout << "Loaded RSA Public key file (" << publicKeyFile << ") successfully" << std::endl;

		return pkey;
	}
};
