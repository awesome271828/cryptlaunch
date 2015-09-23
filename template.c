#include <stdio.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/evp.h>

#ifndef ITERATIONS
#define ITERATIONS 10000
#endif

typedef unsigned char byte;

extern char _binary_salt_start;

extern char _binary_iv_start;

extern char _binary_tag_start;

extern char _binary_program_start;
extern char _binary_program_end;

static int derive_key(
		const char *password,
		byte *salt,
		int saltlen,
		int iterations,
		byte *out)
{
	return PKCS5_PBKDF2_HMAC(
			password,
			strlen(password),
			salt,
			saltlen,
			iterations,
			EVP_sha512(),
			32,
			out
			);
}

static int decrypt(
		byte *ciphertext,
		int ciphertext_len,
		byte *tag,
		byte *key,
		byte *iv,
		byte *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;
	int plainlen;

	if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) return -1;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) return -1;

	if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return -1;

	int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	EVP_CIPHER_CTX_free(ctx);

	return ret;
}

int main(int argc, char **argv, char **envp)
{
	byte key[32];

	byte *program = &_binary_program_start;

	int program_len = &_binary_program_end - (char *)program;

	char *password = getpass("Password: ");

	if (!password) return 1;

	// Derive key from password with PBKDF2
	if (derive_key(password, &_binary_salt_start, 32, ITERATIONS, key) != 1) return 1;

	int shm_fd = shm_open("/program", O_RDWR | O_CREAT, 0700);

	if (shm_fd == -1) return 1;

	// Resize file to program size
	if (ftruncate(shm_fd, program_len) == -1) return 1;

	// Obtain pointer to memory
	byte *image = mmap(NULL, program_len, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

	if (image == MAP_FAILED) return 1;

	// Decrypt linked program and write to memory
	if (decrypt(
				program,
				program_len,
				&_binary_tag_start,
				key,
				&_binary_iv_start,
				image
			   ) <= 0)
	{
		fputs("Decryption failed!\n", stderr);
		return 1;
	}

	munmap(image, program_len);
	close(shm_fd);

	// Obtain read-only fd of memory
	shm_fd = shm_open("/program", O_RDONLY, 0);

	// Delete file on fd closure (fd was opened with FD_CLOEXEC)
	shm_unlink("/program");

	fputs("Executing ELF image...\n", stderr);

	// Execute program
	fexecve(shm_fd, argv, envp);

	fputs("Something went wrong!\n", stderr);

	return 1;
}
