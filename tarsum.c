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

#include "llrb.h"

#undef MIN
#define MIN(a, b) (((a) < (b))? (a) : (b))

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

static void
SHA256(void *dst, size_t lim, const void *src, size_t len)
{
	static EVP_MD_CTX *ctx;
	unsigned char md[32];
	unsigned mdlen;
	if (!ctx && !(ctx = EVP_MD_CTX_new()))
		errx(1, "%s", openssl_error_string());
	if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
		errx(1, "%s", openssl_error_string());
	if (!EVP_DigestUpdate(ctx, src, len))
		errx(1, "%s", openssl_error_string());
	if (!EVP_DigestFinal_ex(ctx, md, &mdlen))
		errx(1, "%s", openssl_error_string());
	memcpy(dst, md, MIN(mdlen, lim));
}

static char *
md2hex(const void *_src, size_t len)
{
	static unsigned char md[(2 * EVP_MAX_MD_SIZE) + 1];
	struct { unsigned char *p, *pe; } src, dst;

	src.p = (void *)_src;
	src.pe = src.p + MIN(((sizeof md - 1) / 2), len);
	dst.p = md;

	for (; src.p < src.pe; src.p++) {
		*dst.p++ = "0123456789abcdef"[0x0f & (*src.p >> 4)];
		*dst.p++ = "0123456789abcdef"[0x0f & (*src.p >> 0)];
	}
	*dst.p = '\0';

	return (char *)md;
}

struct entry {
	unsigned char name[32]; /* SHA256 digest length */
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned mdlen;
	char path[256];
	LLRB_ENTRY(entry) rbe;
};

static LLRB_HEAD(entries, entry) entries;

static int
entrycmp(const struct entry *a, const struct entry *b)
{
	return memcmp(a->name, b->name, sizeof a->name);
}

LLRB_GENERATE_STATIC(entries, entry, rbe, entrycmp);

static void
entryadd(const char *path, const void *md, size_t mdlen)
{
	struct entry *ent, *oent;
	if (!(ent = malloc(sizeof *ent)))
		err(1, "malloc");
	memset(ent, 0, sizeof *ent);
	SHA256(ent->name, sizeof ent->name, path, strlen(path));
	memcpy(ent->md, md, MIN(mdlen, sizeof ent->md));
	ent->mdlen = mdlen;
	strlcpy(ent->path, path, sizeof ent->path);
	if ((oent = LLRB_INSERT(entries, &entries, ent))) {
		warnx("duplicate (%s) (%s)", path, ent->path);
		warnx("  %s", md2hex(ent->name, sizeof ent->name));
		warnx("  %s", md2hex(oent->name, sizeof oent->name));
		free(ent);
	}
}

static const struct entry *
entryget(const char *path)
{
	struct entry key;
	SHA256(key.name, sizeof key.name, path, strlen(path));
	return LLRB_FIND(entries, &entries, &key);
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
		unsigned mdlen;
		EVP_MD_CTX *ctx;
		const void *buf;
		size_t buflen, i;

		if (archive_entry_hardlink(entry)) {
			const struct entry *ent = entryget(archive_entry_hardlink(entry));
			if (ent) {
				printf("%s  %s\n", md2hex(ent->md, ent->mdlen), path);
			}
			continue;
		}

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

		printf("%s  %s\n", md2hex(md, mdlen), path);
		entryadd(path, md, mdlen);
	}
	if (archive_errno(a) != ARCHIVE_OK)
		err(1, "%s", archive_error_string(a));
	r = archive_read_free(a);  // Note 3
	if (r != ARCHIVE_OK)
		exit(1);

	return 0;
}
