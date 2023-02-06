#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#define INPUT_FILE     "input.txt"
#define ENCRYPTED_FILE "ciphertext.img"
#define DECRYPTED_FILE "decrypted_plaintext.txt"

#define CERTIFICATE_FILE "cert.pem"
#define PRIVATE_KEY_FILE "key.pem"


/**
 * Save datum to a file.
 */
static void save_to_file(const char *filename, gnutls_datum_t *data) {
	FILE *fp = fopen(filename, "wb");
	if (fp == NULL) {
		fprintf(stderr, "Error opening file for writing\n");
		return;
	}
	size_t written = fwrite(data->data, 1, data->size, fp);
	if (written != data->size) {
		fprintf(stderr, "Error writing data to file\n");
	}
	fclose(fp);
}


static void print_crt(gnutls_x509_crt_t crt)
{
	gnutls_datum_t tmp;
	gnutls_x509_crt_print(crt, GNUTLS_CRT_PRINT_COMPACT, &tmp);
	printf("\nCertificate: %.*s\n", tmp.size, tmp.data);
	gnutls_free(tmp.data);
}


int main(void)
{
	gnutls_pubkey_t pubkey;
	gnutls_privkey_t privkey;
	gnutls_x509_privkey_t key;
	gnutls_x509_crt_t crt;
	gnutls_datum_t plaintext;
	gnutls_datum_t ciphertext, decrypted_plaintext;
	gnutls_datum_t cert_data, key_data;
	int ret;

	ret = gnutls_load_file(CERTIFICATE_FILE, &cert_data);
	if (ret < 0)
	{
		fprintf(stderr, "Failed to load certificate data: %s\n", gnutls_strerror(ret));
		return 1;
	}

	ret = gnutls_load_file(PRIVATE_KEY_FILE, &key_data);
	if (ret < 0)
	{
		fprintf(stderr, "Failed to load private key data: %s\n", gnutls_strerror(ret));
		return 1;
	}

	ret = gnutls_x509_privkey_init(&key);
	if (ret < 0) {
		fprintf(stderr, "Error initializing x509 private key: %s\n", gnutls_strerror(ret));
		return 1;
	}

	ret = gnutls_x509_privkey_import(key, &key_data, GNUTLS_X509_FMT_PEM);
	if (ret < 0)
	{
		fprintf(stderr, "Error loading x509 private key: %s\n", gnutls_strerror(ret));
		return 1;
	}

	ret = gnutls_privkey_init(&privkey);
	if (ret < 0) {
		fprintf(stderr, "Error initializing private key: %s\n", gnutls_strerror(ret));
		return 1;
	}

	ret = gnutls_privkey_import_x509(privkey, key, 0);
	if (ret < 0) {
		fprintf(stderr, "Error importing private key: %s\n", gnutls_strerror(ret));
		return 1;
	}

	ret = gnutls_pubkey_init(&pubkey);
	if (ret < 0)
	{
		fprintf(stderr, "Error initializing public key: %s\n", gnutls_strerror(ret));
		return 1;
	}

	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0) {
		fprintf(stderr, "Error gnutls_x509_crt_init: %s\n", gnutls_strerror(ret));
		return 1;
	}

	ret = gnutls_x509_crt_import(crt, &cert_data, GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		fprintf(stderr, "Error gnutls_x509_crt_import: %s\n", gnutls_strerror(ret));
		return 1;
	}

	print_crt(crt);

	ret = gnutls_pubkey_import_x509(pubkey, crt, 0);
	if (ret < 0) {
		fprintf(stderr, "Error loading public key: %s\n", gnutls_strerror(ret));
		return 1;
	}

	ret = gnutls_load_file(INPUT_FILE, &plaintext);
	if (ret < 0) {
		fprintf(stderr, "Failed to load input data: %s\n", gnutls_strerror(ret));
		return 1;
	}

	ret = gnutls_pubkey_encrypt_data(pubkey, 0, &plaintext, &ciphertext);
	if (ret < 0) {
		fprintf(stderr, "Failed to encrypt data: %s\n", gnutls_strerror(ret));
		return 1;
	}

	save_to_file(ENCRYPTED_FILE, &ciphertext);

	ret = gnutls_privkey_decrypt_data(privkey, 0, &ciphertext, &decrypted_plaintext);
	if (ret < 0) {
		fprintf(stderr, "Failed to decrypt data: %s\n", gnutls_strerror(ret));
		return 1;
	}

	save_to_file(DECRYPTED_FILE, &decrypted_plaintext);

	gnutls_free(ciphertext.data);
	gnutls_free(decrypted_plaintext.data);
	gnutls_free(plaintext.data);

	gnutls_x509_crt_deinit(crt);
	gnutls_x509_privkey_deinit(key);
	gnutls_privkey_deinit(privkey);
	gnutls_pubkey_deinit(pubkey);
	gnutls_global_deinit();

	return 0;
}
