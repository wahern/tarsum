/* ==========================================================================
 * tarsum.c - checksum utility for tar files
 * --------------------------------------------------------------------------
 * Copyright (c) 2019  William Ahern
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ==========================================================================
 */
#include <ctype.h> /* isdigit(3) */
#include <errno.h> /* EILSEQ ENOBUFS ENOMEM ERANGE errno */
#include <limits.h> /* LINE_MAX ULONG_MAX */
#include <locale.h> /* LC_ALL setlocale(3) */
#include <langinfo.h> /* D_T_FMT nl_langinfo(3) */
#include <regex.h> /* regex_t regcomp(3) regerror(3) regexec(3) regfree(3) */
#include <stdarg.h> /* va_list va_start va_end */
#include <stdint.h> /* intmax_t */
#include <stdio.h> /* _IOFBF BUFSIZ fflush(3) fpurge(3) fputc(3) fputs(3) setvbuf(3) */
#include <stdlib.h> /* exit(3) free(3) malloc(3) strtoul(3) */
#include <string.h> /* memcpy(3) memset(3) strdup(3) strerror(3) strlen(3) */
#include <time.h> /* localtime(3) strftime(3) */

#include <err.h> /* vwarnx(3) */
#include <sys/queue.h> /* TAILQ_* */

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

#ifndef HAVE_REALLOCARRAY
#ifdef __GLIBC_PREREQ
#define HAVE_REALLOCARRAY (__GLIBC_PREREQ(2, 26) && _GNU_SOURCE)
#else
#define HAVE_REALLOCARRAY (!__linux && !__APPLE__)
#endif
#endif

#ifndef HAVE_STDIO_EXT_H
#define HAVE_STDIO_EXT_H HAVE___FPURGE
#endif

#ifndef HAVE_STRLCPY
#define HAVE_STRLCPY (!__GLIBC__)
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

static int
addsize_overflow(size_t *r, size_t a, size_t b)
{
	if (~a < b)
		return ERANGE;
	*r = a + b;
	return 0;
}

#define SBUF_INTO(_base, _size) { \
	.base = (unsigned char *)(_base), \
	.size = (_size), \
}

struct sbuf {
	unsigned char *base;
	size_t size, p;
};

static struct sbuf *
sbuf_init(struct sbuf *sbuf, void *base, size_t size)
{
	sbuf->base = base;
	sbuf->size = size;
	sbuf->p = 0;
	return sbuf;
}

static size_t
sbuf_clamp(struct sbuf *sbuf, size_t n)
{
	return (sbuf->p < sbuf->size)? MIN(n, sbuf->size - sbuf->p) : 0;
}

static int
sbuf_error(struct sbuf *sbuf)
{
	return (sbuf->p <= sbuf->size)? 0 : ENOBUFS;
}

static void *
sbuf_getptr(struct sbuf *sbuf)
{
	return &sbuf->base[MIN(sbuf->p, sbuf->size)];
}

static int
sbuf_ffwd(struct sbuf *sbuf, size_t n)
{
	sbuf->p = (~sbuf->p < n)? SIZE_MAX : sbuf->p + n;
	return sbuf_error(sbuf);
}

static int
sbuf_putc(struct sbuf *sbuf, unsigned char ch)
{
	if (sbuf->p < sbuf->size) {
		sbuf->base[sbuf->p++] = ch;
		return 0;
	} else if (sbuf->p < SIZE_MAX) {
		sbuf->p++;
		return ENOBUFS;
	} else {
		return ENOBUFS;
	}
}

static int
sbuf_put(struct sbuf *sbuf, const void *src, size_t len)
{
	size_t n = sbuf_clamp(sbuf, len);
	if (n) {
		memcpy(&sbuf->base[sbuf->p], src, n);
		sbuf->p += n;
		len -= n;
	}

	return sbuf_ffwd(sbuf, len);
}

static int
sbuf_puts(struct sbuf *sbuf, const void *src)
{
	return sbuf_put(sbuf, src, strlen(src));
}

static int
sbuf_puts0(struct sbuf *sbuf, const void *src)
{
	sbuf_puts(sbuf, src);
	return sbuf_putc(sbuf, '\0');
}

static void *
tarsum_reallocarray(void *arr, size_t nmemb, size_t size)
{
#if HAVE_REALLOCARRAY
	return reallocarray(arr, nmemb, size);
#else
	if (nmemb > 0 && SIZE_MAX / nmemb < size) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(arr, nmemb * size);
#endif
}

static size_t
tarsum_strlcpy(char *dst, const char *src, size_t lim)
{
#if HAVE_STRLCPY
	return strlcpy(dst, src, lim);
#else
	size_t len = strlen(src);
	if (lim) {
		size_t n = MIN(lim - 1, len);
		memcpy(dst, src, n);
		dst[n] = '\0';
	}
	return len;
#endif
}

#define TARSUM_EBASE -(('T' << 24) | ('A' << 16) | ('R' << 8) | 'S')

enum tarsum_errors {
	TARSUM_EREGCOMP = TARSUM_EBASE,
	TARSUM_EREGEXEC,
	TARSUM_EBADNSUB,
	TARSUM_EBADFLAG,
	TARSUM_ELAST,
};

#define TARSUM_F_DEFAULT "%C  %N\\n"
/*
 * glibc 2.27:  %a %b %e %H:%M:%S %Y
 * macOS 10.14: %a %b %e %X %Y
 * musl 1.1.22: %a %b %e %T %Y
 * OpenBSD 6.5: %a %b %e %H:%M:%S %Y
 *
 * NOTE: %T is equivalent to %H:%M:%S. %X is the national representation of
 * the time.
 */
#define TARSUM_T_DEFAULT "%a %b %e %H:%M:%S %Y"

#define TARSUMOPTS_INIT(opts) *tarsumopts_staticinit((opts))

struct tarsumopts {
	const EVP_MD *mdtype; /* -a option flag */
	const char *format;   /* -f option flag */
	const char *timefmt;  /* -t option flag */
};

struct tarsum_subexpr {
	char *patexpr, *replexpr, *flags;
	regex_t regex;
	TAILQ_ENTRY(tarsum_subexpr) tqe;
	struct { char *base; size_t size; } replbuf;
	size_t nmatch;
	regmatch_t match[];
};

struct tarsum {
	const EVP_MD *mdtype;
	char *format;
	char *timefmt;
	TAILQ_HEAD(, tarsum_subexpr) subexprs;
	struct archive *archive;

	struct {
		int64_t soh; /* start of heading */
		int64_t stx; /* start of text */
		int64_t etx; /* end of text */
	} cursor;

	struct regerror {
		char descr[256];
		int error;
	} regerr;
};

static struct tarsumopts *
tarsumopts_staticinit(struct tarsumopts *opts)
{
	*opts = (struct tarsumopts){
		.mdtype = EVP_sha256(),
		.format = TARSUM_F_DEFAULT,
		.timefmt = TARSUM_T_DEFAULT,
	};
	return opts;
}

static void subexpr_free(struct tarsum_subexpr *);

static int
tarsum_destroy(struct tarsum *ts)
{
	int error = 0, status;

	free(ts->format);
	free(ts->timefmt);

	if (ARCHIVE_OK != (status = archive_read_free(ts->archive)))
		error = status; /* XXX: translate? */

	while (!TAILQ_EMPTY(&ts->subexprs)) {
		struct tarsum_subexpr *subexpr = TAILQ_FIRST(&ts->subexprs);
		TAILQ_REMOVE(&ts->subexprs, subexpr, tqe);
		subexpr_free(subexpr);
	}

	memset(ts, 0, sizeof *ts);

	return error;
}

static int
tarsum_init(struct tarsum *ts, const struct tarsumopts *tsopts)
{
	int error;

	*ts = (struct tarsum){ 0 };
	TAILQ_INIT(&ts->subexprs);

	ts->mdtype = tsopts->mdtype;
	if (!(ts->format = strdup(tsopts->format)))
		goto syerr;
	if (!(ts->timefmt = strdup(tsopts->timefmt)))
		goto syerr;
	if (!(ts->archive = archive_read_new()))
		goto syerr;
	archive_read_support_filter_all(ts->archive);
	archive_read_support_format_all(ts->archive);

	return 0;
syerr:
	error = errno;
	tarsum_destroy(ts);
	return error;
}

/*
 * NOTE: substring match counter from my Lua Unix (lunix) regcomp code
 */
#define NSUB_ESCAPE 0x100
#define NSUB_BRACKET 0x200
#define NSUB_ESCAPED(ch) ((ch) | NSUB_ESCAPE)
#define NSUB_BRACKETED(ch) ((ch) | NSUB_BRACKET)

static size_t
regcomp_nsub(const char *cp, const int cflags)
{
	const char *obp = NULL;
	int state = 0, ch;
	size_t n = 0;

	for (; (ch = (*cp)? (state | *cp) : 0); cp++) {
		state &= ~NSUB_ESCAPE;

		switch (ch) {
		case '\\':
			state |= NSUB_ESCAPE;
			break;
		case '[':
			obp = cp;
			state |= NSUB_BRACKET;
			break;
		case NSUB_BRACKETED(']'):
			if (cp == &obp[1])
				break;
			if (cp == &obp[2] && obp[1] == '^')
				break;
			obp = NULL;
			state &= ~NSUB_BRACKET;
			break;
		case '(':
			n += !!(cflags & REG_EXTENDED);
			break;
		case NSUB_ESCAPED('('):
			n += !(cflags & REG_EXTENDED);
			break;
		default:
			break;
		}
	}

	return n;
}

static void
regerror_fill(struct regerror *regerr, int error, const regex_t *regex, const char *what)
{
	regerr->error = error;
	if (what) {
		struct sbuf buf = SBUF_INTO(regerr->descr, sizeof regerr->descr);
		sbuf_puts(&buf, what);
		sbuf_puts(&buf, ": ");
		size_t n = regerror(error, regex, sbuf_getptr(&buf), sbuf_clamp(&buf, SIZE_MAX));
		if (0 == sbuf_ffwd(&buf, n + 1))
			return;
	}
	regerror(error, regex, regerr->descr, sizeof regerr->descr);
}

static int
subexpr_exec(struct tarsum_subexpr *subexpr, char **dst, const char *src, struct regerror *regerr)
{
	struct sbuf buf;
	int error;

	if ((error = regexec(&subexpr->regex, src, subexpr->nmatch, subexpr->match, 0))) {
		if (error == REG_NOMATCH) {
			*dst = (char *)src;
			return 0;
		} else {
			regerror_fill(regerr, error, &subexpr->regex, src);
			return error;
		}
	}
again:
	sbuf_init(&buf, subexpr->replbuf.base, subexpr->replbuf.size);
	sbuf_put(&buf, src, subexpr->match[0].rm_so);

	int escaped = 0;
	for (const char *replexpr = subexpr->replexpr; *replexpr; replexpr++) {
		if (escaped) {
			if (!(*replexpr >= '0' && *replexpr <= '9')) {
				sbuf_putc(&buf, *replexpr);
			} else if ((size_t)(*replexpr - '0') < subexpr->nmatch) {
				regmatch_t *rm = &subexpr->match[*replexpr - '0'];
				sbuf_put(&buf, &src[rm->rm_so], rm->rm_eo - rm->rm_so);
			}
		} else if (*replexpr == '\\') {
			escaped = 1;
		} else if (*replexpr == '&') {
			regmatch_t *rm = &subexpr->match[0];
			sbuf_put(&buf, &src[rm->rm_so], rm->rm_eo - rm->rm_so);
		} else {
			sbuf_putc(&buf, *replexpr);
		}
	}

	sbuf_put(&buf, &src[subexpr->match[0].rm_eo], strlen(src) - subexpr->match[0].rm_eo);
	sbuf_putc(&buf, '\0');

	if (buf.p <= buf.size) {
		*dst = subexpr->replbuf.base;
		if (strchr(subexpr->flags, 'p')) {
			warnx("%s >> %s", src, (**dst == '\0')? "<empty string>" : *dst);
		}
		return 0;
	}

	char *tmpbuf = realloc(subexpr->replbuf.base, buf.p);
	if (!tmpbuf)
		return errno;
	subexpr->replbuf.base = tmpbuf;
	subexpr->replbuf.size = buf.p;
	goto again;
}

static void
subexpr_free(struct tarsum_subexpr *subexpr)
{
	regfree(&subexpr->regex);
	free(subexpr->replbuf.base);
	free(subexpr);
}

static int
subexpr_init(struct tarsum_subexpr **_subexpr, const char *patexpr, const char *replexpr, const char *flags, struct regerror *regerr)
{
	struct tarsum_subexpr *subexpr = NULL;
	int cflags = 0;
	size_t nmatch, size;
	int error;

	for (const char *flag = flags; *flag; flag++) {
		switch (*flag) {
		case 'e':
			cflags |= REG_EXTENDED;
			break;
		case 'i':
			cflags |= REG_ICASE;
			break;
		case 'm':
			cflags |= REG_NEWLINE;
			break;
		case 'p':
			break;
		default:
			/* FIXME: need to communicate flag character to caller */
			warnx("%c: unsupported pattern flag", *flag);
			return TARSUM_EBADFLAG;
		}
	}

	size = offsetof(struct tarsum_subexpr, match);
	size += strlen(patexpr) + 1;
		size += strlen(replexpr) + 1;
	size += strlen(flags) + 1;

	/* +1 for 0th match */
	nmatch = 1 + regcomp_nsub(patexpr, cflags);
	if (SIZE_MAX / sizeof subexpr->match[0] < nmatch)
		return ENOMEM;
	if (addsize_overflow(&size, size, sizeof subexpr->match[0] * nmatch))
		return ENOMEM;

	if (!(subexpr = calloc(1, size)))
		return errno;

	struct sbuf sbuf = { .base = (void *)subexpr, .size = size, };
	sbuf_ffwd(&sbuf, offsetof(struct tarsum_subexpr, match));
	sbuf_ffwd(&sbuf, sizeof subexpr->match[0] * nmatch);
	subexpr->patexpr = sbuf_getptr(&sbuf); sbuf_puts0(&sbuf, patexpr);
	subexpr->replexpr = sbuf_getptr(&sbuf); sbuf_puts0(&sbuf, replexpr);
	subexpr->flags = sbuf_getptr(&sbuf); sbuf_puts0(&sbuf, flags);
	if ((error = sbuf_error(&sbuf))) {
		free(subexpr);
		return error;
	}

	subexpr->nmatch = nmatch;

	if ((error = regcomp(&subexpr->regex, subexpr->patexpr, cflags))) {
		regerror_fill(regerr, error, &subexpr->regex, patexpr);
		free(subexpr);
		return TARSUM_EREGCOMP;
	}

	/* shouldn't happen */
	if (subexpr->regex.re_nsub >= subexpr->nmatch) {
		regfree(&subexpr->regex);
		free(subexpr);
		return TARSUM_EBADNSUB;
	}

	*_subexpr = subexpr;

	return 0;
}

static int
subexpr_split(char **patexpr, char **replexpr, char **flags, char *cp)
{
	int delim, escaped;

	delim = *cp++;
	if (!delim || delim == '\\')
		return EINVAL;

	*patexpr = cp;
	escaped = 0;
	for (; *cp; cp++) {
		if (escaped) {
			escaped = 0;
		} else if (*cp == '\\') {
			escaped = 1;
		} else if (*cp == delim) {
			*cp++ = '\0';
			break;
		}
	}

	*replexpr = cp;
	escaped = 0;
	for (; *cp; cp++) {
		if (escaped) {
			escaped = 0;
		} else if (*cp == '\\') {
			escaped = 1;
		} else if (*cp == delim) {
			*cp++ = '\0';
			break;
		}
	}

	*flags = cp;

	return 0;
}

static int
tarsum_addsubexpr(struct tarsum *ts, const char *_subexpr)
{
	char *subexpr = NULL, *patexpr, *replexpr, *flags;
	int error;

	if (!_subexpr)
		return EINVAL;
	if (!(subexpr = strdup(_subexpr)))
		return errno;
	if (!(error = subexpr_split(&patexpr, &replexpr, &flags, subexpr))) {
		struct tarsum_subexpr *subexpr;
		if (!(error = subexpr_init(&subexpr, patexpr, replexpr, flags, &ts->regerr))) {
			TAILQ_INSERT_TAIL(&ts->subexprs, subexpr, tqe);
		}
	}
	free(subexpr);
	return error;
}

/*
 * NOTE: as of libarchive 3.4.0 the status return codes are all negative
 * except for ARCHIVE_EOF
 */
static const char *
tarsum_strerror(int error)
{
	switch (error) {
	case TARSUM_EREGCOMP:
		return "regcomp failure";
	case TARSUM_EREGEXEC:
		return "regexec failure";
	case TARSUM_EBADNSUB:
		return "miscalculated number of substring matches";
	case TARSUM_EBADFLAG:
		return "unsupported pattern flag";
	default:
		/* FIXME: figure out better way stringify libarchive error codes */
		return strerror(error);
	}
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
	tarsum_strlcpy(ent->path, path, sizeof ent->path);
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
printifield(const struct tarsum *ts, const struct fieldspec *fs, intmax_t v, FILE *fp)
{
	(void)ts;
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
printsfield(const struct tarsum *ts, const struct fieldspec *fs, int field, const char *s, FILE *fp)
{
	if (fs->fmt && fs->fmt != 'S')
		panic("%s: unsupported format sequence (%c format not supported for %%%c field)", ts->format, fs->fmt, field);
	fputs(s, fp);
}

static void
printtfield(const struct tarsum *ts, const struct fieldspec *fs, time_t v, FILE *fp)
{
	if (fs->fmt == 'S') {
		static char buf[MAX(BUFSIZ, LINE_MAX)];
		size_t n = strftime(buf, sizeof buf, ts->timefmt, localtime(&v));
		if (n > 0 && n < sizeof buf) {
			fputs(buf, fp);
		} else {
			panic("%s: unable to format timestamp (%jd)", ts->timefmt, (intmax_t)v);
		}
	} else {
		printifield(ts, fs, v, fp);
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
printentry(struct tarsum *ts, const char *path, const void *md, size_t mdlen, struct archive_entry *ent, FILE *fp)
{
	const unsigned char *fmt = (const unsigned char *)ts->format;
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
				panic("%s: empty escape sequence", ts->format);
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
			printsfield(ts, &fs, 'A', EVP_MD_name(ts->mdtype), fp);
			break;
		case TOKEN('%', 'C'):
			printsfield(ts, &fs, 'C', md2hex(md, mdlen), fp);
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
			printsfield(ts, &fs, 'N', path, fp);
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
			printtfield(ts, &fs, archive_entry_atime(ent), fp);
			break;
		case TOKEN('%', 'c'):
			printtfield(ts, &fs, archive_entry_ctime(ent), fp);
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
			printifield(ts, &fs, archive_entry_gid(ent), fp);
			break;
		case TOKEN('%', 'm'):
			printtfield(ts, &fs, archive_entry_mtime(ent), fp);
			break;
		case TOKEN('%', 'o'):
			switch (fs.sub) {
			case '\0':
				printifield(ts, &fs, ts->cursor.stx, fp);
				break;
			case 'H':
				printifield(ts, &fs, ts->cursor.soh, fp);
				break;
			case 'L':
				printifield(ts, &fs, ts->cursor.etx, fp);
				break;
			default:
				purge(fp);
				panic("%s: unsupported format sequence (%%%co)", ts->format, fs.sub);
			}
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
			printifield(ts, &fs, archive_entry_uid(ent), fp);
			break;
		case TOKEN('%', 'z'):
			switch (fs.sub) {
			case '\0':
				printifield(ts, &fs, archive_entry_size(ent), fp);
				break;
			case 'H':
				printifield(ts, &fs, ts->cursor.stx - ts->cursor.soh, fp);
				break;
			case 'L':
				printifield(ts, &fs, ts->cursor.etx - ts->cursor.soh, fp);
				break;
			default:
				purge(fp);
				panic("%s: unsupported format sequence (%%%co)", ts->format, fs.sub);
			}
			break;
			break;
		default:
			if (isescaped(tok)) {
				purge(fp);
				panic("%s: unknown %s sequence (%c%c)", ts->format, (isescaped(tok) == '\\')? "escape" : "format", (unsigned char)(tok >> 8), (unsigned char)tok);
			}
			fputc(tok, fp);
			break;
		}

		escaped = 0;
	}

	if (escaped) {
		purge(fp);
		panic("%s: empty %s sequence", ts->format, (escaped == '\\')? "escape" : "format");
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

static void
optsfree(const char ***opts, size_t *optc)
{
	free(*opts);
	*opts = NULL;
	*optc = 0;
}

static const char **
optspush(const char ***opts, size_t *optc, const char *opt)
{
	const char **p = tarsum_reallocarray(*opts, *optc + 2, sizeof *p);
	if (!p)
		panic("%s", strerror(errno));
	p[(*optc)++] = opt;
	p[*optc] = NULL;
	return *opts = p;
}

#define SHORTOPTS "a:f:s:t:h"
static void
usage(const char *arg0, const struct tarsumopts *opts, FILE *fp)
{
	const char *progname = strrchr(arg0, '/')? strrchr(arg0, '/') + 1 : arg0;

	fprintf(fp,
		"Usage: %s [-" SHORTOPTS "] [PATH]\n" \
		"  -a DIGEST   digest algorithm (default: \"%s\")\n" \
		"  -f FORMAT   format specification (default: \"%s\")\n" \
		"  -s SUBEXPR  path substitution expression\n" \
		"  -t TIMEFMT  strftime format specification\n" \
		"  -h          print this usage message\n" \
		"\n" \
		"FORMAT (see printf(1) and BSD stat(1))\n" \
		"  \\NNN  octal escape sequence\n" \
		"  \\xNN  hexadecimal escape sequence\n" \
		"  \\L    C escape sequence (\\\\, \\a, \\b, \\f, \\n, \\r, \\t, \\v)\n" \
		"  %%%%    percent literal\n" \
		"  %%A    digest name\n" \
		"  %%C    file digest\n" \
		"  %%N    file name (full path)\n" \
		"  %%g    GID or group name (%%Sg)\n" \
		"  %%m    last modification time (%%Sm: strftime formatting)\n" \
		"  %%o    file offset (%%Ho: header record, %%Lo: end of last file record)\n" \
		"  %%u    UID or user name (%%Su)\n" \
		"  %%z    file size (%%Hz: header record(s), %%Lz: header and file records)\n" \
		"\n" \
		"Report bugs to <william@25thandClement.com>\n",
	progname, EVP_MD_name(opts->mdtype), opts->timefmt);
}

int
main(int argc, char **argv)
{
	struct tarsumopts opts = TARSUMOPTS_INIT(&opts);
	const char **subexprs = NULL;
	size_t nsubexpr = 0;
	const char *path = NULL;
	struct archive_entry *entry;
	struct tarsum ts = { 0 };
	int optc, status, error;

	setlocale(LC_ALL, "");
	opts.timefmt = nl_langinfo(D_T_FMT);
	setvbuf(stdout, NULL, _IOFBF, MAX(BUFSIZ, LINE_MAX));
	ERR_load_crypto_strings();
	OpenSSL_add_all_digests();

	while (-1 != (optc = getopt(argc, argv, SHORTOPTS))) {
		switch (optc) {
		case 'a':
			opts.mdtype = optdigest(optarg);
			break;
		case 'f':
			opts.format = optarg;
			break;
		case 's':
			optspush(&subexprs, &nsubexpr, optarg);
			break;
		case 't':
			opts.timefmt = optarg;
			break;
		case 'h':
			usage(*argv, &opts, stdout);
			return 0;
		default:
			usage(*argv, &opts, stderr);
			return EXIT_FAILURE;
		}
	}

	argc -= optind;
	argv += optind;

	path = (argc > 0)? *argv : "/dev/stdin";

	error = tarsum_init(&ts, &opts);
	for (const char **subexpr = subexprs; !error && subexpr && *subexpr; subexpr++) {
		error = tarsum_addsubexpr(&ts, *subexpr);
		if (error == TARSUM_EREGCOMP) {
			warnx("%s", ts.regerr.descr);
			warnx("%s: bad substitution expression", *subexpr);
		}
	}
	optsfree(&subexprs, &nsubexpr);
	if (error)
		panic("unable to initialize context: %s", tarsum_strerror(error));

	if (ARCHIVE_OK != (status = archive_read_open_filename(ts.archive, path, 10240)))
		panic("%s: %s", path, archive_error_string(ts.archive));
	while (archive_read_next_header(ts.archive, &entry) == ARCHIVE_OK) {
		const char *path = archive_entry_pathname(entry);
		unsigned char md[EVP_MAX_MD_SIZE];
		unsigned mdlen;
		EVP_MD_CTX *ctx;
		const void *buf;
		size_t buflen;

		struct tarsum_subexpr *subexpr;
		TAILQ_FOREACH(subexpr, &ts.subexprs, tqe) {
			char *_path = NULL;
			if ((error = subexpr_exec(subexpr, &_path, path, &ts.regerr))) {
				if (error == TARSUM_EREGEXEC) {
					warnx("%s", ts.regerr.descr);
				}
				panic("unable to apply substitution expression: %s", tarsum_strerror(error));
			}
			path = _path;
		}

		ts.cursor.soh = archive_read_header_position(ts.archive);
		ts.cursor.stx = archive_filter_bytes(ts.archive, 0);
		ts.cursor.etx = ts.cursor.stx;

		if (archive_entry_hardlink(entry)) {
			/* XXX: should we do archive_read_data_skip? */

			const struct entry *ent = entryget(archive_entry_hardlink(entry));
			if (ent) {
				/* XXX: will entry have the fields or should we pass ent? */
				printentry(&ts, path, ent->md, ent->mdlen, entry, stdout);
			}
			continue;
		}

		if (!(ctx = EVP_MD_CTX_new()) || !EVP_DigestInit_ex(ctx, ts.mdtype, NULL))
			errx(1, "%s", openssl_error_string());

		while (ARCHIVE_OK == (status = archive_read_data_block(ts.archive, &buf, &buflen, &(off_t){ 0 }))) {
			if (!EVP_DigestUpdate(ctx, buf, buflen))
				errx(1, "%s", openssl_error_string());
		}
		switch (status) {
		case ARCHIVE_EOF:
			break;
		case ARCHIVE_WARN:
			warnx("%s: %s", path, archive_error_string(ts.archive));
			break;
		default:
			errx(1, "%s: %s", path, archive_error_string(ts.archive));
		}

		if (!EVP_DigestFinal_ex(ctx, md, &mdlen))
			errx(1, "%s", openssl_error_string());
		EVP_MD_CTX_free(ctx);

		ts.cursor.etx = archive_filter_bytes(ts.archive, 0);

		printentry(&ts, path, md, mdlen, entry, stdout);
		entryadd(path, md, mdlen);
	}
	if (archive_errno(ts.archive) != ARCHIVE_OK)
		panic("%s: %s", path, archive_error_string(ts.archive));
	if ((error = tarsum_destroy(&ts)))
		panic("%s: %s", path, tarsum_strerror(error));

	return 0;
}
