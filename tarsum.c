#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>

#include <archive.h>
#include <archive_entry.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#if !HAVE_EVP_MD_CTX_NEW
#define EVP_MD_CTX_new(md) EVP_MD_CTX_create()
#endif

#if !HAVE_EVP_MD_CTX_FREE
#define EVP_MD_CTX_free(md) EVP_MD_CTX_destroy((md))
#endif

static const char *
openssl_error_string(void)
{
	return "OpenSSL error";
}

static long
optunsigned(const char *opt, int *error)
{
	char *end;
	unsigned long lu;

	errno = 0;
	lu = strtoul(opt, &end, 0);
	if (lu == ULONG_MAX && errno != 0)
		return (*error = errno), -1;
	if (*opt == '\0' || *end != '\0')
		return (*error = EILSEQ), -1;
	if (lu > LONG_MAX)
		return (*error = ERANGE), -1;

	return lu;
}

int
main(int argc, char **argv)
{
	const EVP_MD *algo = EVP_sha256();
	const char *path = NULL;
	struct archive *a;
	struct archive_entry *entry;
	int optc, r, error;

	setlocale(LC_ALL, "");
	ERR_load_crypto_strings();
	OpenSSL_add_all_digests();

	while (-1 != (optc = getopt(argc, argv, "a:"))) {
		switch (optc) {
		case 'a':
			switch (optunsigned(optarg, &error)) {
			default:
				errx(1, "%s: unknown algorithm", optarg);
			}
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		errx(1, "no tar file specified");

	path = (argc > 0)? *argv : "/dev/stdin";

	a = archive_read_new();
	archive_read_support_filter_all(a);
	archive_read_support_format_all(a);
	r = archive_read_open_filename(a, path, 10240); // Note 1
	if (r != ARCHIVE_OK)
		exit(1);
	while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
		const char *path = archive_entry_pathname(entry);
		unsigned char md[EVP_MAX_MD_SIZE];
		char mdx[(2 * sizeof md) + 1];
		unsigned mdlen;
		EVP_MD_CTX *ctx;
		const void *buf;
		size_t buflen, i;

		if (!(ctx = EVP_MD_CTX_new()) || !EVP_DigestInit_ex(ctx, algo, NULL))
			errx(1, "%s", openssl_error_string());

		while (ARCHIVE_OK == (r = archive_read_data_block(a, &buf, &buflen, &(off_t){ 0 }))) {
			if (!EVP_DigestUpdate(ctx, buf, buflen))
				errx(1, "%s", openssl_error_string());
		}
		switch (r) {
		case ARCHIVE_EOF:
			break;
		case ARCHIVE_WARN:
			warnx("%s: %s", path, archive_error_string(a));
			break;
		default:
			errx(1, "%s: %s", path, archive_error_string(a));
		}

		if (!EVP_DigestFinal_ex(ctx, md, &mdlen))
			errx(1, "%s", openssl_error_string());
		EVP_MD_CTX_free(ctx);
		for (i = 0; i < mdlen; i++) {
			mdx[(2 * i) + 0] = "0123456789abcdef"[0x0f & (md[i] >> 4)];
			mdx[(2 * i) + 1] = "0123456789abcdef"[0x0f & (md[i] >> 0)];
		}
		mdx[mdlen * 2] = '\0';

		printf("%s  %s\n", mdx, archive_entry_pathname(entry));
	}
	if (archive_errno(a) != ARCHIVE_OK)
		err(1, "%s", archive_error_string(a));
	r = archive_read_free(a);  // Note 3
	if (r != ARCHIVE_OK)
		exit(1);

	return 0;
}
