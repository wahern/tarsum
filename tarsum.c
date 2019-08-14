#include <ctype.h> /* isdigit(3) */
#include <errno.h> /* EILSEQ errno */
#include <limits.h> /* LINE_MAX ULONG_MAX */
#include <locale.h> /* LC_ALL setlocale(3) */
#include <langinfo.h> /* D_T_FMT nl_langinfo(3) */
#include <stdarg.h> /* va_list va_start va_end */
#include <stdint.h> /* intmax_t */
#include <stdio.h> /* _IOFBF BUFSIZ fflush(3) fpurge(3) fputc(3) fputs(3) setvbuf(3) */
#include <stdlib.h> /* exit(3) free(3) malloc(3) strtoul(3) */
#include <string.h> /* memcpy(3) strerror(3) */
#include <time.h> /* localtime(3) strftime(3) */

#include <err.h> /* vwarnx(3) */

#include <archive.h>
#include <archive_entry.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "llrb.h"

#ifndef HAVE___FPURGE
#define HAVE___FPURGE (__linux || __sun)
#endif

#ifndef HAVE_FPURGE
#define HAVE_FPURGE 1
#endif

#ifndef HAVE_STDIO_EXT_H
#define HAVE_STDIO_EXT_H HAVE___FPURGE
#endif

#undef MIN
#define MIN(a, b) (((a) < (b))? (a) : (b))
#undef MAX
#define MAX(a, b) (((a) > (b))? (a) : (b))

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

__attribute__((noreturn))
static void
panic(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vwarnx(fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

#if HAVE_STDIO_EXT_H
#include <stdio_ext.h>
#endif

static void
purge(FILE *fp)
{
#if HAVE___FPURGE
	__fpurge(fp);
#elif HAVE_FPURGE
	fpurge(fp);
#else
	(void)0;
#endif
}

static int
parseulong(unsigned long *_lu, const char *opt)
{
	char *end;
	unsigned long lu;

	errno = 0;
	lu = strtoul(opt, &end, 0);
	if (lu == ULONG_MAX && errno != 0)
		return errno;
	if (*opt == '\0' || *end != '\0')
		return EILSEQ;

	*_lu = lu;
	return 0;
}

static int
fromxdigit(unsigned char ch, int def)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	/* XXX: A-F and a-f aren't guaranteed contiguous */
	if (ch >= 'a' && ch <= 'f')
		return 10 + (ch - 'a');
	if (ch >= 'A' && ch <= 'F')
		return 10 + (ch - 'A');
	return def;
}

struct fieldspec {
	int fmt;
	int sub;
};

static void
printifield(const struct fieldspec *fs, intmax_t v, FILE *fp)
{
	switch (fs->fmt) {
	case 'O':
		fprintf(fp, "%jo", v);
		break;
	case 'U':
		fprintf(fp, "%ju", (uintmax_t)v);
		break;
	case 'X':
		fprintf(fp, "%jx", v);
		break;
	default:
		fprintf(fp, "%jd", v);
		break;
	}
}

static void
printsfield(const char *fmt, const struct fieldspec *fs, int field, const char *s, FILE *fp)
{
	if (fs->fmt && fs->fmt != 'S')
		panic("%s: unsupported format sequence (%c format not supported for %%%c field)", fmt, fs->fmt, field);
	fputs(s, fp);
}

static void
printtfield(const char *timefmt, const struct fieldspec *fs, time_t v, FILE *fp)
{
	if (fs->fmt == 'S') {
		static char buf[MAX(BUFSIZ, LINE_MAX)];
		size_t n = strftime(buf, sizeof buf, timefmt, localtime(&v));
		if (n > 0 && n < sizeof buf) {
			fputs(buf, fp);
		} else {
			panic("%s: unable to format timestamp (%jd)", timefmt, (intmax_t)v);
		}
	} else {
		printifield(fs, v, fp);
	}
}

#define TOKEN(a, b) (((unsigned char)(a) << 8) | ((unsigned char)(b) << 0))
#define isescaped(t) (0xff & ((t) >> 8))

/* printentry
 *
 * NOTE: escape sequences mirror POSIX shell printf(1), format sequences
 * patterned after BSD stat(1).
 */
static void
printentry(const EVP_MD *algo, const char *timefmt, const char *_fmt, const char *path, const void *md, size_t mdlen, struct archive_entry *ent, FILE *fp)
{
	const unsigned char *fmt = (const unsigned char *)_fmt;
	unsigned char escaped = 0;
	struct fieldspec fs = { 0 };

	while (*fmt) {
		int tok = TOKEN(escaped, *fmt++);

		switch (tok) {
		case '\\':
			escaped = '\\';
			continue;
		case '%':
			escaped = '%';
			fs = (struct fieldspec){ 0 };
			continue;
		}

		switch (tok) {
		case TOKEN('\\', '0'): /* FALL THROUGH */
		case TOKEN('\\', '1'): /* FALL THROUGH */
		case TOKEN('\\', '2'): /* FALL THROUGH */
		case TOKEN('\\', '3'): /* FALL THROUGH */
		case TOKEN('\\', '4'): /* FALL THROUGH */
		case TOKEN('\\', '5'): /* FALL THROUGH */
		case TOKEN('\\', '6'): /* FALL THROUGH */
		case TOKEN('\\', '7'):
			tok = (tok & 0xff) - '0';
			for (int n = 1; n < 3 && *fmt >= '0' && *fmt <= '7'; n++) {
				tok <<= 3;
				tok |= *fmt++ - '0';
			}
			fputc(tok, fp);
			break;
		case TOKEN('\\', 'x'):
			if (EOF != (tok = fromxdigit(*fmt, EOF))) {
				if (EOF != fromxdigit(*++fmt, EOF)) {
					tok <<= 4;
					tok |= fromxdigit(*fmt++, 0);
				}
				fputc(tok, fp);
			} else {
				purge(fp);
				panic("%s: empty escape sequence", _fmt);
			}
			break;
		case TOKEN('\\', '\\'):
			fputc('\\', fp);
			break;
		case TOKEN('\\', 'a'):
			fputc('\a', fp);
			break;
		case TOKEN('\\', 'b'):
			fputc('\b', fp);
			break;
		case TOKEN('\\', 'f'):
			fputc('\f', fp);
			break;
		case TOKEN('\\', 'n'):
			fputc('\n', fp);
			break;
		case TOKEN('\\', 'r'):
			fputc('\r', fp);
			break;
		case TOKEN('\\', 't'):
			fputc('\t', fp);
			break;
		case TOKEN('\\', 'v'):
			fputc('\v', fp);
			break;
		case TOKEN('%', '%'):
			fputc('%', fp);
			break;
		case TOKEN('%', 'A'):
			printsfield(_fmt, &fs, 'A', EVP_MD_name(algo), fp);
			break;
		case TOKEN('%', 'C'):
			printsfield(_fmt, &fs, 'C', md2hex(md, mdlen), fp);
			break;
		case TOKEN('%', 'D'):
			fs.fmt = 'D';
			continue;
		case TOKEN('%', 'H'):
			fs.sub = 'H';
			continue;
		case TOKEN('%', 'L'):
			fs.sub = 'L';
			continue;
		case TOKEN('%', 'M'):
			fs.sub = 'M';
			continue;
		case TOKEN('%', 'N'):
			printsfield(_fmt, &fs, 'N', path, fp);
			break;
		case TOKEN('%', 'S'):
			fs.fmt = 'S';
			continue;
		case TOKEN('%', 'O'):
			fs.fmt = 'O';
			continue;
		case TOKEN('%', 'U'):
			fs.fmt = 'U';
			continue;
		case TOKEN('%', 'X'):
			fs.fmt = 'X';
			continue;
		case TOKEN('%', 'a'):
			printtfield(timefmt, &fs, archive_entry_atime(ent), fp);
			break;
		case TOKEN('%', 'c'):
			printtfield(timefmt, &fs, archive_entry_ctime(ent), fp);
			break;
		case TOKEN('%', 'g'):
			if (fs.fmt == 'S') {
				const char *grp = archive_entry_gname(ent);
				if (grp) {
					fputs(grp, fp);
					break;
				}
				/* FALL THROUGH */
			}
			printifield(&fs, archive_entry_gid(ent), fp);
			break;
		case TOKEN('%', 'm'):
			printtfield(timefmt, &fs, archive_entry_mtime(ent), fp);
			break;
		case TOKEN('%', 'u'):
			if (fs.fmt == 'S') {
				const char *usr = archive_entry_uname(ent);
				if (usr) {
					fputs(usr, fp);
					break;
				}
				/* FALL THROUGH */
			}
			printifield(&fs, archive_entry_uid(ent), fp);
			break;
		case TOKEN('%', 'z'):
			printifield(&fs, archive_entry_size(ent), fp);
			break;
		default:
			if (isescaped(tok)) {
				purge(fp);
				panic("%s: unknown %s sequence (%c%c)", _fmt, (isescaped(tok) == '\\')? "escape" : "format", (unsigned char)(tok >> 8), (unsigned char)tok);
			}
			fputc(tok, fp);
			break;
		}

		escaped = 0;
	}

	if (escaped) {
		purge(fp);
		panic("%s: empty %s sequence", _fmt, (escaped == '\\')? "escape" : "format");
	}

	fflush(fp);
}

static const EVP_MD *
optdigest(const char *opt)
{
	const EVP_MD *md = NULL;

	if (isdigit((unsigned char)*opt)) {
		unsigned long bits;
		int error;

		if ((error = parseulong(&bits, opt)))
			panic("%s: %s", opt, strerror(error));

		switch (bits) {
		case 256:
			md = EVP_sha256();
			break;
		case 384:
			md = EVP_sha384();
			break;
		case 512:
			md = EVP_sha512();
			break;
		}
	} else {
		md = EVP_get_digestbyname(opt);
	}

	if (md == NULL)
		panic("%s: unknown digest algorithn", opt);

	return md;
}

#define SHORTOPTS "a:f:t:h"
#define F_DEFAULT "%C  %N\\n"
static void
usage(const char *arg0, FILE *fp)
{
	const char *progname = strrchr(arg0, '/')? strrchr(arg0, '/') + 1 : arg0;

	fprintf(fp,
		"Usage: %s [-" SHORTOPTS "] [PATH]\n" \
		"  -a DIGEST   digest algorithm (default: \"sha256\")\n" \
		"  -f FORMAT   format specification (default: \"%s\")\n" \
		"  -t TIMEFMT  strftime format specification\n" \
		"  -h          print this usage message\n" \
		"\n" \
		"FORMAT (see printf(1) and BSD stat(1))\n" \
		"  \\NNN  octal escape sequence\n" \
		"  \\xNN  hexadecimal escape sequence\n" \
		"  \\n    LF/NL\n" \
		"  %%A    digest name\n" \
		"  %%C    file digest\n" \
		"  %%N    file name (full path)\n" \
		"  %%g    GID or group name\n" \
		"  %%m    last modification time\n" \
		"  %%u    UID or user name\n" \
		"  %%z    file size\n" \
		"\n" \
		"Report bugs to <william@25thandClement.com>\n",
	progname, F_DEFAULT);
}

int
main(int argc, char **argv)
{
	const EVP_MD *algo = EVP_sha256();
	const char *fmt = F_DEFAULT;
	const char *timefmt = "";
	const char *path = NULL;
	struct archive *a;
	struct archive_entry *entry;
	int optc, r;

	setlocale(LC_ALL, "");
	timefmt = nl_langinfo(D_T_FMT);
	setvbuf(stdout, NULL, _IOFBF, MAX(BUFSIZ, LINE_MAX));
	ERR_load_crypto_strings();
	OpenSSL_add_all_digests();

	while (-1 != (optc = getopt(argc, argv, SHORTOPTS))) {
		switch (optc) {
		case 'a':
			algo = optdigest(optarg);
			break;
		case 'f':
			fmt = optarg;
			break;
		case 't':
			timefmt = optarg;
			break;
		case 'h':
			usage(*argv, stdout);
			return 0;
		default:
			usage(*argv, stderr);
			return EXIT_FAILURE;
		}
	}

	argc -= optind;
	argv += optind;

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
		size_t buflen;

		if (archive_entry_hardlink(entry)) {
			const struct entry *ent = entryget(archive_entry_hardlink(entry));
			if (ent) {
				/* XXX: will entry have the fields or should we pass ent? */
				printentry(algo, timefmt, fmt, path, ent->md, ent->mdlen, entry, stdout);
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

		printentry(algo, timefmt, fmt, path, md, mdlen, entry, stdout);
		entryadd(path, md, mdlen);
	}
	if (archive_errno(a) != ARCHIVE_OK)
		err(1, "%s", archive_error_string(a));
	r = archive_read_free(a);  // Note 3
	if (r != ARCHIVE_OK)
		exit(1);

	return 0;
}
