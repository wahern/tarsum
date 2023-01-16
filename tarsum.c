/* ==========================================================================
 * tarsum.c - checksum utility for tar files
 * --------------------------------------------------------------------------
 * Copyright (c) 2017, 2019, 2022  William Ahern
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
#include <assert.h> /* assert(3) */
#include <ctype.h> /* isdigit(3) */
#include <errno.h> /* EILSEQ ENOBUFS ENOMEM ERANGE errno */
#include <limits.h> /* LINE_MAX ULONG_MAX */
#include <locale.h> /* LC_ALL setlocale(3) */
#include <langinfo.h> /* D_T_FMT nl_langinfo(3) */
#include <regex.h> /* regex_t regcomp(3) regerror(3) regexec(3) regfree(3) */
#include <stdarg.h> /* va_list va_start va_end */
#include <stdint.h> /* intmax_t */
#include <stdio.h> /* _IOFBF BUFSIZ fflush(3) fopen(3) fpurge(3) fputc(3) fputs(3) getdelim(3) setvbuf(3) vsnprintf(3) */
#include <stdlib.h> /* abort(3) exit(3) free(3) malloc(3) strtoul(3) */
#include <string.h> /* memcpy(3) memset(3) strdup(3) strerror(3) strlen(3) */
#include <time.h> /* localtime(3) strftime(3) time(3) */

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

#define countof(a) (sizeof (a) / sizeof *(a))

#if WITH_DEBUG
#define DEBUG(...) warnx(__VA_ARGS__)
#define DEBUG_DO(...) __VA_ARGS__
#else
#define DEBUG(...) (void)0
#define DEBUG_DO(...) (void)0
#endif

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

static int
errno_assert(int error)
{
	if (error)
		return error;
#if __GNUC__
	__builtin_trap();
	__builtin_unreachable();
#else
	abort();
	return EFAULT;
#endif
}

/*
 * FIXME: Our simple sbuf structure is being used in ways never intended,
 * leading to confusing inconsistencies. Should import our fifo.h library.
 */
#define SBUF_INTO(_base, _size) { \
	.base = (unsigned char *)(_base), \
	.size = (_size), \
}

struct sbuf {
	unsigned char *base;
	size_t size, p;
	int error;
};

static struct sbuf *
sbuf_init(struct sbuf *sbuf, void *base, size_t size)
{
	sbuf->base = base;
	sbuf->size = size;
	sbuf->p = 0;
	sbuf->error = 0;
	return sbuf;
}

static struct sbuf *
sbuf_reset(struct sbuf *sbuf)
{
	sbuf->p = 0;
	sbuf->error = 0;
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
	if (sbuf->error) {
		return sbuf->error;
	} else if (sbuf->p > sbuf->size) {
		return (sbuf->error = ENOBUFS);
	} else {
		return 0;
	}
}

static int
sbuf_seterror(struct sbuf *sbuf, int error)
{
	if (!sbuf->error) {
		sbuf->error = error;
	}
	return sbuf->error;
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
	} else if (sbuf->p < SIZE_MAX) {
		sbuf->p++;
	}
	return sbuf_error(sbuf);
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

static int
sbuf_putxc(struct sbuf *sbuf, unsigned char ch)
{
	sbuf_putc(sbuf, "0123456789abcdef"[0x0f & (ch >> 4)]);
	return sbuf_putc(sbuf, "0123456789abcdef"[0x0f & (ch >> 0)]);
}

static int
sbuf_putx(struct sbuf *sbuf, void *_src, size_t len)
{
	const unsigned char *src = _src;

	for (size_t p = 0; p < len; p++) {
		sbuf_putxc(sbuf, src[p]);
	}

	return sbuf_error(sbuf);
}

static int
sbuf_putf(struct sbuf *sbuf, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(sbuf_getptr(sbuf), sbuf_clamp(sbuf, SIZE_MAX), fmt, ap);
	if (n >= 0) {
		sbuf_ffwd(sbuf, n);
	} else {
		sbuf_seterror(sbuf, errno_assert(errno));
	}
	va_end(ap);

	return sbuf_error(sbuf);
}

static int
sbuf_putvc(struct sbuf *sbuf, unsigned char ch, int nextc, const char *special)
{
	switch (ch) {
	case '\0':
		sbuf_putc(sbuf, '\\');
		sbuf_putc(sbuf, '0');
		if (nextc == -1 || (nextc >= '0' && nextc <= '7')) {
			sbuf_putc(sbuf, '0');
			sbuf_putc(sbuf, '0');
		}
		break;
	case '\a':
		sbuf_putc(sbuf, '\\');
		sbuf_putc(sbuf, 'a');
		break;
	case '\b':
		sbuf_putc(sbuf, '\\');
		sbuf_putc(sbuf, 'b');
		break;
	case '\f':
		sbuf_putc(sbuf, '\\');
		sbuf_putc(sbuf, 'f');
		break;
	case '\n':
		sbuf_putc(sbuf, '\\');
		sbuf_putc(sbuf, 'n');
		break;
	case '\r':
		sbuf_putc(sbuf, '\\');
		sbuf_putc(sbuf, 'r');
		break;
	case '\t':
		sbuf_putc(sbuf, '\\');
		sbuf_putc(sbuf, 't');
		break;
	case '\v':
		sbuf_putc(sbuf, '\\');
		sbuf_putc(sbuf, 'v');
		break;
	case '\\':
		sbuf_putc(sbuf, '\\');
		sbuf_putc(sbuf, '\\');
		break;
	default:
		if (ch >= 0x20 && ch <= 0x7e) {
			if (special && strchr(special, ch))
				sbuf_putc(sbuf, ch);
			sbuf_putc(sbuf, ch);
		} else {
			sbuf_putc(sbuf, '\\');
			sbuf_putc(sbuf, "01234567"[0x7 & (ch >> 5)]);
			sbuf_putc(sbuf, "01234567"[0x7 & (ch >> 3)]);
			sbuf_putc(sbuf, "01234567"[0x7 & (ch >> 0)]);
		}
		break;
	}

	return sbuf_error(sbuf);
}

static int
sbuf_putv(struct sbuf *sbuf, const void *_src, size_t len, int nextc, const char *special)
{
	const unsigned char *src = _src;
	size_t p = 0;

	if (len > 0) {
		if (len > 1) {
			for (size_t pe = len - 1; p < pe; p++)
				sbuf_putvc(sbuf, src[p], src[p + 1], special);
		}

		sbuf_putvc(sbuf, src[p], nextc, special);
	}

	return sbuf_error(sbuf);
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
	TARSUM_EBADSUBI,
	TARSUM_EBADLINE,
	TARSUM_ENOMATCH,
	TARSUM_ENULLCAP,
	TARSUM_EDUPCSUM,
	TARSUM_ELAST,
};

#define TARSUM_F_DEFAULT "%C  %N%$"
#define TARSUM_R_DEFAULT "%N: %R%$"
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
	const EVP_MD *mdtype;  /* -a option flag */
	const char *checklist; /* -C option flag */
	const char *format;    /* -f option flag */
	const char *report;    /* -R option flag */
	const char *timefmt;   /* -t option flag */
	int rs;                /* -0 option flag */
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
	int rs;
	char *timefmt;
	TAILQ_HEAD(, tarsum_subexpr) subexprs;
	struct archive *archive;

	struct tarsum_cursor {
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
		.report = TARSUM_R_DEFAULT,
		.timefmt = TARSUM_T_DEFAULT,
		.rs = -1,
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

	*ts = (struct tarsum){ .rs = tsopts->rs, };
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

static void
regerror_clear(struct regerror *regerr)
{
	regerr->error = 0;
	regerr->descr[0] = '\0';
}

static int
subexpr_setbuf(struct tarsum_subexpr *subexpr, size_t size)
{
	char *buf = realloc(subexpr->replbuf.base, size);
	if (!buf)
		return errno_assert(errno);
	subexpr->replbuf.base = buf;
	subexpr->replbuf.size = size;
	return 0;
}

static int
subexpr_exec(struct tarsum_subexpr *subexpr, char **dst, const char *_src, struct regerror *regerr)
{
	const regmatch_t *const rm = subexpr->match;
	const char *src;
	struct sbuf buf;
	size_t reps;
	int eflags, error;

	DEBUG_DO(subexpr_setbuf(subexpr, 1000));
restart:
	src = _src;
	sbuf_init(&buf, subexpr->replbuf.base, subexpr->replbuf.size);
	reps = 0;
	eflags = 0;
again:
	DEBUG("REGEX -> %s", src);
	if ((error = regexec(&subexpr->regex, src, subexpr->nmatch, subexpr->match, eflags))) {
		DEBUG("NO MATCH");
		if (error != REG_NOMATCH) {
			regerror_fill(regerr, error, &subexpr->regex, src);
			return TARSUM_EREGEXEC;
		} else if (reps > 0) {
			goto suffix;
		} else {
			return 0;
		}
	}
	DEBUG("MATCH -> %.*s(%.*s)%.*s", (int)rm[0].rm_so, src, (int)(rm[0].rm_eo - rm[0].rm_so), &src[rm[0].rm_so], (int)(strlen(src) - rm[0].rm_eo), &src[rm[0].rm_eo]);

	/* copy unmatched prefix */
	sbuf_put(&buf, src, rm[0].rm_so);

	int escaped = 0, rc;
	for (const char *replexpr = subexpr->replexpr; (rc = *replexpr); replexpr++) {
		if (escaped) {
			if (!(rc >= '0' && rc <= '9')) {
				sbuf_putc(&buf, rc);
			} else if ((size_t)(rc - '0') < subexpr->nmatch) {
				size_t i = rc - '0';
				if (rm[i].rm_so >= 0)
					sbuf_put(&buf, &src[rm[i].rm_so], rm[i].rm_eo - rm[i].rm_so);
			}
			escaped = 0;
		} else if (rc == '\\') {
			escaped = 1;
		} else if (rc == '&') {
			sbuf_put(&buf, &src[rm[0].rm_so], rm[0].rm_eo - rm[0].rm_so);
		} else {
			sbuf_putc(&buf, rc);
		}
	}

	/* retire prefix and match */
	src += rm[0].rm_eo;

	/*
	 * try again if g flag specified, but short-circuit on zero-width
	 * matches
	 *
	 * NOTE: Zero-width matches (e.g. [[:<:]] and [[:>:]], but also ^
	 * and $ in some circumstances) could cause us to loop infinitely.
	 * Examples:
	 *
	 *   /[[:<:]]/x/g
	 *   /$/x/g
	 *   /^.|$/x/ge
	 *
	 * We can't properly support them without using REG_STARTEND. Even
	 * if we bumped src on zero-width matches, the matching semantics
	 * can't work without REG_STARTEND providing lookbehind capability.
	 *
	 * Some ERE constructs also don't seem to work correctly without
	 * REG_STARTEND, such as /^|$/x/ge, which [on macOS, at least] only
	 * matches once even without our zero-width match short-circuit.
	 * Perhaps the implementation itself has a loop mitigation hack that
	 * disables $ matches on REG_NOTBOL?
	 *
	 * For these reasons we don't bother using a smarter test that could
	 * permit some EREs currently aborted prematurely.
	 *
	 * TODO: Use REG_STARTEND where available.
	 */
	if (strchr(subexpr->flags, 'g') && (rm[0].rm_eo - rm[0].rm_so) > 0) {
		reps++;
		eflags |= REG_NOTBOL;
		goto again;
	}
suffix:
	/* copy unmatched suffix */
	sbuf_puts0(&buf, src);

	if (!(buf.p <= buf.size)) {
		if ((error = subexpr_setbuf(subexpr, buf.p)))
			return error;
		goto restart;
	}

	*dst = subexpr->replbuf.base;
	if (strchr(subexpr->flags, 'p')) {
		warnx("%s >> %s", _src, (**dst == '\0')? "<empty string>" : *dst);
	}

	return 0;
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
		case '|': /* chain subexprs */
			break;
		case 'e':
			cflags |= REG_EXTENDED;
			break;
		case 'g': /* global replacement */
			break;
		case 'i':
			cflags |= REG_ICASE;
			break;
		case 'm':
			cflags |= REG_NEWLINE;
			break;
		case 'p': /* print diagnostic on replacement */
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
		return errno_assert(errno);

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
		return errno_assert(errno);
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
		return "miscalculated number of subexpression matches";
	case TARSUM_EBADFLAG:
		return "unsupported pattern flag";
	case TARSUM_EBADSUBI:
		return "specified subexpression index is zero or greater than number of subexpression matches";
	case TARSUM_EBADLINE:
		return "empty, truncated, or malformed checksum line";
	case TARSUM_ENOMATCH:
		return "checksum regular expression did not match record";
	case TARSUM_ENULLCAP:
		return "empty subexpression capture for file name or digest";
	case TARSUM_EDUPCSUM:
		return "duplicate checksum with conflicting digest";
	default:
		/* FIXME: figure out better way stringify libarchive error codes */
		return strerror(error);
	}
}

struct fileid {
	unsigned char md[32]; /* SHA256 digest length */
};

struct checksum {
	LLRB_ENTRY(checksum) rbe;
	TAILQ_ENTRY(checksum) tqe;
	unsigned found;
	struct fileid id;
	unsigned char md[EVP_MAX_MD_SIZE];
	char path[];
};

struct checklist {
	regex_t regex;
	size_t mdlen;
	char *formatre; /* regular expression matching format specifier */
	size_t nmatch;
	regmatch_t *match;
	regmatch_t *Nsub, *Csub;
	LLRB_HEAD(checksums, checksum) checksums;
	TAILQ_HEAD(, checksum) loaded;

	struct {
		char *line;
		size_t linelen;
		struct regerror regerr;
	} loaderr;

	struct {
		size_t nerrors; /* # of loading errors */
		size_t nloaded; /* # of checksums loaded */
		size_t nfiles;  /* # of files in archive */

		size_t nok;     /* # of matching checksums */
		size_t nfailed; /* # of checksum failures */
		size_t nmissed; /* # of checksums in checklist not in archive */
	} report;
};

static int
csumcmp(const struct checksum *a, const struct checksum *b)
{
	return memcmp(a->id.md, b->id.md, sizeof a->id.md);
}

LLRB_GENERATE_STATIC(checksums, checksum, rbe, csumcmp)

static void
checklist_clearerr(struct checklist *C)
{
	free(C->loaderr.line);
	C->loaderr.linelen = 0;
	regerror_clear(&C->loaderr.regerr);
}

static void
checklist_destroy(struct checklist **_C)
{
	struct checklist *C = *_C;
	struct checksum *cs;

	if (C == NULL)
		return;
	*_C = NULL;

	checklist_clearerr(C);

	while ((cs = TAILQ_FIRST(&C->loaded))) {
		TAILQ_REMOVE(&C->loaded, cs, tqe);
		free(cs);
	}

	free(C->formatre);
	free(C->match);
	regfree(&C->regex);
	free(C);
}

static int
checklist_init(struct checklist **_C, const EVP_MD *mdtype, const char *formatre, int cflags, size_t Nsub, size_t Csub, struct regerror *regerr)
{
	struct checklist *C = NULL;
	int error;

	*_C = NULL;

	/*
	 * NB: Error block at bottom of function uses checklist_destroy,
	 * which assumes C->regex initialized, so return early
	 * initialization errors directly. C object becomes consistent only
	 * after we compile C->regex, a consequence of POSIX seemingly
	 * refraining from guaranteeing that regex_t can be copied by value.
	 */
	if (!(C = calloc(1, sizeof *C))) {
		return errno_assert(errno);
	} else if ((error = regcomp(&C->regex, formatre, cflags))) {
		regerror_fill(regerr, error, &C->regex, NULL);
		free(C);
		return TARSUM_EREGCOMP;
	}
	/* all other members are safe 0-initialized except .loaded TAILQ */
	TAILQ_INIT(&C->loaded);

	C->mdlen = EVP_MD_size(mdtype);

	if (!(C->formatre = strdup(formatre)))
		goto syerr;

	C->nmatch = 1 + C->regex.re_nsub; /* +1 for 0th match */
	if (!(C->match = calloc(C->nmatch, sizeof *C->match)))
		goto syerr;

	if (Nsub == 0 || Nsub >= C->nmatch
	||  Csub == 0 || Csub >= C->nmatch
	||  Nsub == Csub) {
		error = TARSUM_EBADSUBI;
		goto error;
	}
	C->Nsub = &C->match[Nsub];
	C->Csub = &C->match[Csub];

	*_C = C;

	return 0;
syerr:
	error = errno_assert(errno);
error:
	checklist_destroy(&C);

	return error;
}

static struct checksum *
checklist_findid(struct checklist *C, struct fileid *id)
{
	struct checksum key = { .id = *id };
	return LLRB_FIND(checksums, &C->checksums, &key);
}

static struct checksum *
checklist_findpath(struct checklist *C, const char *path)
{
	struct fileid id;
	SHA256(id.md, sizeof id.md, path, strlen(path));
	return checklist_findid(C, &id);
}

static int fromxdigit(unsigned char, int);

static _Bool
hex2bin(struct sbuf *dst, const char *src, size_t len)
{
	size_t p = 0;

	while (len - p >= 2) {
		int hi = fromxdigit(src[p++], -1);
		int lo = fromxdigit(src[p++], -1);
		if (lo == -1 || hi == -1)
			return 0;
		sbuf_putc(dst, ((hi << 4) | (lo << 0)));
	}
	return p == len;
}

static int
checklist_addcsum(struct checklist *C, const char *path, size_t pathlen, const char *hex, size_t hexlen)
{
	struct checksum *cs = NULL;
	int error;

	size_t size = offsetof(struct checksum, path);
	if ((error = addsize_overflow(&size, size, pathlen + 1)))
		goto error;
	if (!(cs = calloc(1, size)))
		goto syerr;

	SHA256(cs->id.md, sizeof cs->id.md, path, pathlen);

	struct sbuf md = SBUF_INTO(cs->md, sizeof cs->md);
	if (!hex2bin(&md, hex, hexlen) || sbuf_error(&md) || md.p != C->mdlen) {
		error = TARSUM_EBADLINE;
		goto error;
	}

	memcpy(cs->path, path, pathlen);

	struct checksum *cs0;
	if ((cs0 = LLRB_INSERT(checksums, &C->checksums, cs))) {
		if (0 == memcmp(cs0->md, cs->md, C->mdlen)) {
			DEBUG("duplicate checksum record for %s", cs->path);
			free(cs);
		} else {
			char hex0[(2 * EVP_MAX_MD_SIZE) + 1] = "";
			struct sbuf buf = SBUF_INTO(hex0, sizeof hex0 - 1);
			sbuf_putx(&buf, cs0->md, C->mdlen);

			DEBUG("conflicting checksum records for %s (expected %s, got %.*s)", cs->path, hex0, (int)hexlen, hex);
			error = TARSUM_EDUPCSUM;
			goto error;
		}
	} else {
		TAILQ_INSERT_TAIL(&C->loaded, cs, tqe);
		C->report.nloaded++;
	}

	return 0;
syerr:
	error = errno_assert(errno);
error:
	free(cs);
	return error;
}

static int
checklist_loadline(struct checklist *C, const char *line)
{
	const char *path, *md;
	size_t pathlen, mdlen;
	regoff_t n;
	int error;

	if ((error = regexec(&C->regex, line, C->nmatch, C->match, 0))) {
		if (error == REG_NOMATCH) {
			return TARSUM_ENOMATCH;
		} else {
			regerror_fill(&C->loaderr.regerr, error, &C->regex, NULL);
			return TARSUM_EREGEXEC;
		}
	}

	/*
	 * FIXME: 0th match should have matched entire line, beginning to
	 * end, otherwise we may be silently discarding input
	 */

	n = C->Nsub->rm_eo - C->Nsub->rm_so;
	if (n <= 0)
		return TARSUM_ENULLCAP;
	path = &line[C->Nsub->rm_so];
	pathlen = n;

	n = C->Csub->rm_eo - C->Csub->rm_so;
	if (n <= 0)
		return TARSUM_ENULLCAP;
	md = &line[C->Csub->rm_so];
	mdlen = n;

	return checklist_addcsum(C, path, pathlen, md, mdlen);
}

static int
checklist_loadfile(struct checklist *C, FILE *fp, int rs)
{
	char *line = NULL;
	size_t linesiz = 0;
	ssize_t linelen;
	int error;

	while ((linelen = getdelim(&line, &linesiz, rs, fp)) > 0) {
		if (line[linelen - 1] != rs) {
			error = TARSUM_EBADLINE;
			goto error;
		}

		/* FIXME: deal with empty lines */

		if ((error = checklist_loadline(C, line)))
			goto error;
	}

	if (!feof(fp))
		goto syerr;

	free(line);

	return 0;
syerr:
	error = errno_assert(errno);
error:
	if (linelen > 0) {
		free(C->loaderr.line);
		C->loaderr.line = line;
		C->loaderr.linelen = linelen;
	} else {
		free(C->loaderr.line);
		C->loaderr.line = NULL;
		C->loaderr.linelen = 0;
		free(line);
	}

	return error;
}

struct entry {
	struct fileid id;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned mdlen;
	char path[256];
	LLRB_ENTRY(entry) rbe;
};

static LLRB_HEAD(entries, entry) entries;

static int
entrycmp(const struct entry *a, const struct entry *b)
{
	return memcmp(a->id.md, b->id.md, sizeof a->id.md);
}

LLRB_GENERATE_STATIC(entries, entry, rbe, entrycmp)

static struct entry *
entryadd(const char *path, const void *md, size_t mdlen)
{
	struct entry *ent, *oent;
	if (!(ent = malloc(sizeof *ent)))
		err(1, "malloc");
	memset(ent, 0, sizeof *ent);
	SHA256(ent->id.md, sizeof ent->id.md, path, strlen(path));
	memcpy(ent->md, md, MIN(mdlen, sizeof ent->md));
	ent->mdlen = mdlen;
	tarsum_strlcpy(ent->path, path, sizeof ent->path);
	if ((oent = LLRB_INSERT(entries, &entries, ent))) {
		warnx("duplicate (%s) (%s)", path, ent->path);
		warnx("  %s", md2hex(ent->id.md, sizeof ent->id.md));
		warnx("  %s", md2hex(oent->id.md, sizeof oent->id.md));
		free(ent);
		return oent;
	}
	return ent;
}

static const struct entry *
entryget(const char *path)
{
	struct entry key;
	SHA256(key.id.md, sizeof key.id.md, path, strlen(path));
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

#define purge_and_panic(fp, ...) do { \
	purge((fp)); \
	panic(__VA_ARGS__); \
} while (0)

static int
parseulong(unsigned long *_lu, const char *opt)
{
	char *end;
	unsigned long lu;

	errno = 0;
	lu = strtoul(opt, &end, 0);
	if (lu == ULONG_MAX && errno != 0)
		return errno_assert(errno);
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

struct fields {
	int rs;
	const EVP_MD *A;
	struct {
		const void *md;
		size_t mdlen;
	} C;
	const char *N;
	const char *R;
	mode_t T;
	time_t a;
	time_t c;
	struct {
		const char *name;
		la_int64_t gid;
	} g;
	time_t m;
	struct tarsum_cursor o;
	struct {
		const char *name;
		la_int64_t uid;
	} u;
	int64_t z;
};

struct fieldspec {
	int fmt;
	int sub;
};

static void
printifield(const char *format, const struct fieldspec *fs, int field, intmax_t v, FILE *fp)
{
	(void)format;
	(void)field;

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
printsfield(const char *format, const struct fieldspec *fs, int field, const char *s, FILE *fp)
{
	if (s == NULL)
		purge_and_panic(fp, "%s: unsupported format sequence (%%%c field undefined in this context)", format, field);
	if (fs->fmt && fs->fmt != 'S')
		purge_and_panic(fp, "%s: unsupported format sequence (%c format not supported for %%%c field)", format, fs->fmt, field);
	fputs(s, fp);
}

static void
printtfield(const char *format, const char *timefmt, const struct fieldspec *fs, int field, time_t v, FILE *fp)
{
	if (v == -1)
		purge_and_panic(fp, "%s: unsupported format sequence (%%%c field undefined in this context)", format, field);

	if (fs->fmt == 'S') {
		static char buf[MAX(BUFSIZ, LINE_MAX)];
		size_t n = strftime(buf, sizeof buf, timefmt, localtime(&v));
		if (n > 0 && n < sizeof buf) {
			fputs(buf, fp);
		} else {
			purge_and_panic(fp, "%s: unable to format timestamp (%jd)", timefmt, (intmax_t)v);
		}
	} else {
		printifield(format, fs, field, v, fp);
	}
}

static void
printTfield(const char *format, const struct fieldspec *fs, mode_t mode, FILE *fp)
{
	if (fs->fmt && fs->fmt != 'S')
		purge_and_panic(fp, "%s: unsupported format sequence (%c format not supported for %%%c field)", format, fs->fmt, 'T');

	switch (fs->sub) {
	case 'H':
		switch (S_IFMT & mode) {
		case S_IFIFO:
			fputs("Fifo File", fp);
			break;
		case S_IFCHR:
			fputs("Character Device", fp);
			break;
		case S_IFDIR:
			fputs("Directory", fp);
			break;
		case S_IFBLK:
			fputs("Block Device", fp);
			break;
		case S_IFREG:
			fputs("Regular File", fp);
			break;
		case S_IFLNK:
			fputs("Symbolic Link", fp);
			break;
		case S_IFSOCK:
			fputs("Socket", fp);
			break;
		default:
			fputs("Unknown", fp);
			break;
		}
		break;
	case '\0':
		/* FALL THROUGH */
	case 'L':
		switch (S_IFMT & mode) {
		case S_IFIFO:
			fputc('|', fp);
			break;
		case S_IFCHR:
			break;
		case S_IFDIR:
			fputc('/', fp);
			break;
		case S_IFBLK:
			break;
		case S_IFREG:
			if (mode & (S_IXUSR|S_IXGRP|S_IXOTH)) {
				fputc('*', fp);
			}
			break;
		case S_IFLNK:
			fputc('@', fp);
			break;
		case S_IFSOCK:
			fputc('=', fp);
			break;
		default:
			/* just ignore */
			break;
		}
		break;
	case 'M':
		/*
		 * print characters used for find(1) -type (M subfield
		 * specifier for T specifier unused by BSD stat(1))
		 */
		switch (S_IFMT & mode) {
		case S_IFIFO:
			fputc('p', fp);
			break;
		case S_IFCHR:
			fputc('c', fp);
			break;
		case S_IFDIR:
			fputc('d', fp);
			break;
		case S_IFBLK:
			fputc('b', fp);
			break;
		case S_IFREG:
			fputc('f', fp);
			break;
		case S_IFLNK:
			fputc('l', fp);
			break;
		case S_IFSOCK:
			fputc('s', fp);
			break;
		default:
			/* just ignore */
			break;
		}
		break;
	default:
		purge_and_panic(fp, "%s: unsupported format sequence (%%%co)", format, fs->sub);
	}
}

static void
printugfield(const char *format, const struct fieldspec *_fs, int field, const char *name, la_int64_t id, FILE *fp)
{
	struct fieldspec fs = *_fs;

	if (fs.fmt == 'S') {
		if (name) {
			printsfield(format, &fs, field, name, fp);
			return;
		}
		fs.fmt = 'D';
	}

	if (id == -1)
		purge_and_panic(fp, "%s: unsupported format sequence (%%%c field undefined in this context)", format, field);

	printifield(format, &fs, field, id, fp);
}

#define TOKEN(a, b) (((unsigned char)(a) << 8) | ((unsigned char)(b) << 0))
#define isescaped(t) (0xff & ((t) >> 8))

/* print
 *
 * NOTE: escape sequences mirror POSIX shell printf(1), format sequences
 * patterned after BSD stat(1).
 */
static void
print(const char *format, const char *timefmt, const struct fields *fields, FILE *fp)
{
	const unsigned char *fmt = (const unsigned char *)format;
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
				purge_and_panic(fp, "%s: empty escape sequence", format);
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
		case TOKEN('%', '$'):
			fputc((fields->rs >= 0)? fields->rs : '\n', fp);
			break;
		case TOKEN('%', 'A'):
			printsfield(format, &fs, 'A', EVP_MD_name(fields->A), fp);
			break;
		case TOKEN('%', 'C'):
			printsfield(format, &fs, 'C', (fields->C.md)? md2hex(fields->C.md, fields->C.mdlen) : NULL, fp);
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
			printsfield(format, &fs, 'N', fields->N, fp);
			break;
		case TOKEN('%', 'S'):
			fs.fmt = 'S';
			continue;
		case TOKEN('%', 'O'):
			fs.fmt = 'O';
			continue;
		case TOKEN('%', 'R'):
			printsfield(format, &fs, 'R', fields->R, fp);
			break;
		case TOKEN('%', 'T'):
			printTfield(format, &fs, fields->T, fp);
			break;
		case TOKEN('%', 'U'):
			fs.fmt = 'U';
			continue;
		case TOKEN('%', 'X'):
			fs.fmt = 'X';
			continue;
		case TOKEN('%', 'a'):
			printtfield(format, timefmt, &fs, 'a', fields->a, fp);
			break;
		case TOKEN('%', 'c'):
			printtfield(format, timefmt, &fs, 'c', fields->c, fp);
			break;
		case TOKEN('%', 'g'):
			printugfield(format, &fs, 'g', fields->g.name, fields->g.gid, fp);
			break;
		case TOKEN('%', 'm'):
			printtfield(format, timefmt, &fs, 'm', fields->m, fp);
			break;
		case TOKEN('%', 'o'):
			switch (fs.sub) {
			case '\0':
				printifield(format, &fs, 'o', fields->o.stx, fp);
				break;
			case 'H':
				printifield(format, &fs, 'o', fields->o.soh, fp);
				break;
			case 'L':
				printifield(format, &fs, 'o', fields->o.etx, fp);
				break;
			default:
				purge_and_panic(fp, "%s: unsupported format sequence (%%%co)", format, fs.sub);
			}
			break;
		case TOKEN('%', 'u'):
			printugfield(format, &fs, 'u', fields->u.name, fields->u.uid, fp);
			break;
		case TOKEN('%', 'z'):
			switch (fs.sub) {
			case '\0':
				printifield(format, &fs, 'z', fields->z, fp);
				break;
			case 'H':
				printifield(format, &fs, 'z', fields->o.stx - fields->o.soh, fp);
				break;
			case 'L':
				printifield(format, &fs, 'z', fields->o.etx - fields->o.soh, fp);
				break;
			default:
				purge_and_panic(fp, "%s: unsupported format sequence (%%%co)", format, fs.sub);
			}
			break;
		default:
			if (isescaped(tok)) {
				purge_and_panic(fp, "%s: unknown %s sequence (%c%c)", format, (isescaped(tok) == '\\')? "escape" : "format", (unsigned char)(tok >> 8), (unsigned char)tok);
			}
			fputc(tok, fp);
			break;
		}

		escaped = 0;
	}

	if (escaped) {
		purge_and_panic(fp, "%s: empty %s sequence", format, (escaped == '\\')? "escape" : "format");
	}

	fflush(fp);
}

static void
printentry(struct tarsum *ts, const char *path, const void *md, size_t mdlen, struct archive_entry *ent, FILE *fp)
{
	const struct fields fields = {
		.rs = ts->rs,
		.A = ts->mdtype,
		.C = { md, mdlen },
		.N = path,
		.R = NULL,
		.T = archive_entry_mode(ent),
		.a = archive_entry_atime(ent),
		.c = archive_entry_ctime(ent),
		.g = { archive_entry_gname(ent), archive_entry_gid(ent) },
		.m = archive_entry_mtime(ent),
		.o = ts->cursor,
		.u = { archive_entry_uname(ent), archive_entry_uid(ent) },
		.z = archive_entry_size(ent),
	};
	print(ts->format, ts->timefmt, &fields, fp);
}

static void
char2re(struct tarsum *ts, struct sbuf *buf, unsigned char ch)
{
	(void)ts;

	/* 9.4.3 ERE Special Characters (https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap09.html#tag_09_04_03) */
	switch (ch) {
	case '.':
	case '[':
	case '\\':
	case '(':
	case ')':
	case '*':
	case '+':
	case '?':
	case '{':
	case '|':
	case '^':
	case '$':
		sbuf_putc(buf, '\\');
		/* FALL THROUGH */
	default:
		sbuf_putc(buf, ch);
		break;
	}
}

static void
term2re(struct tarsum *ts, struct sbuf *buf, unsigned char ch, int *lc)
{
	char2re(ts, buf, ch);
	*lc = ch;
}

static void
literal2re(struct tarsum *ts, struct sbuf *buf, const char *s)
{
	while (*s) {
		char2re(ts, buf, *s++);
	}
}

/* 9.3.5 RE Bracket Expression (https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap09.html#tag_09_03_05) */
static void
charset2re(struct tarsum *ts, struct sbuf *buf, const char *charset, _Bool invert)
{
	int ch;
	(void)ts;

	sbuf_putc(buf, '[');

	if (invert)
		sbuf_putc(buf, '^');

	if (strchr(charset, ']'))
		sbuf_putc(buf, ']');
	if (strchr(charset, '-'))
		sbuf_putc(buf, '-');

	while ((ch = *charset++)) {
		switch (ch) {
		case '[': /* avoid "[:", "[=", or "[:" sequences (see below) */
		case ']': /* always goes first (see above) */
		case '-': /* always goes first (see above) */
			break;
		case '\\':
			/* FALL THROUGH */
		case '^':
			sbuf_putc(buf, '\\');
			/* FALL THROUGH */
		default:
			sbuf_putc(buf, ch);
			break;
		}
	}

	if (strchr(charset, '['))
		sbuf_putc(buf, '[');

	sbuf_putc(buf, ']');
}

static void
mode2re(struct tarsum *ts, struct sbuf *buf, const struct fieldspec *fs, size_t *ncap)
{
	static const char *const names[] = {
		"Fifo File",
		"Character Device",
		"Directory",
		"Block Device",
		"Regular File",
		"Symbolic Link",
		"Socket",
		"Unknown",
	};

	switch (fs->sub) {
	case 'H':
		sbuf_putc(buf, '(');
		for (unsigned i = 0; i < countof(names); i++) {
			if (i > 0)
				sbuf_putc(buf, '|');
			literal2re(ts, buf, names[i]);
		}
		sbuf_putc(buf, ')');
		++*ncap;
		break;
	case '\0':
		/* FALL THROUGH */
	case 'L':
		charset2re(ts, buf, "|/*@=", 0);
		break;
	case 'M':
		charset2re(ts, buf, "pcdbfls", 0);
		break;
	default:
		panic("%s: unsupported format sequence (%%%co)", ts->format, fs->sub);
	}
}

static void
time2re(struct tarsum *ts, struct sbuf *buf, const struct fieldspec *fs)
{
	if (fs->fmt == 'S') {
		size_t min = 0, max = 0;
		char viz[256];
		struct tm tm;
		time_t t = 1577836800; /* 2020-01-01 00:00:00 */
		size_t n = strftime(viz, sizeof viz, ts->timefmt, localtime_r(&t, &tm));
		if (n == 0)
			goto nobufs;

		min = n;
		max = n;
		for (unsigned i = 1; i <= 86400; i++) {
			t++;
			n = strftime(viz, sizeof viz, ts->timefmt, localtime_r(&t, &tm));
			if (n == 0)
				goto nobufs;
			if (n < min)
				min = n;
			if (n > max)
				max = n;
		}

		for (unsigned i = 1; i <= 31; i++) {
			t += (i * 86400);
			n = strftime(viz, sizeof viz, ts->timefmt, localtime_r(&t, &tm));
			if (n == 0)
				goto nobufs;
			if (n < min)
				min = n;
			if (n > max)
				max = n;
		}

		for (unsigned i = 1; i <= 14; i++) {
			t += (i * (86400 * 28));
			n = strftime(viz, sizeof viz, ts->timefmt, localtime_r(&t, &tm));
			if (n == 0)
				goto nobufs;
			if (n < min)
				min = n;
			if (n > max)
				max = n;
		}

		if (min != max)
			warnx("%s: time format not fixed size (%zu to %zu bytes)", ts->timefmt, min, max);

		sbuf_putf(buf, ".{%zu,%zu}", min, max);
	} else {
		sbuf_puts(buf, "[0-9]+");
	}

	return;
nobufs:
	panic("%s: unable to translate time format to regular expression (result too large)", ts->timefmt);
}

static void
user2re(struct tarsum *ts, struct sbuf *buf, const struct fieldspec *fs)
{
	(void)ts;

	if (fs->fmt == 'S') {
		sbuf_puts(buf, "[._[:alnum:]][-._[:alnum:]]*");
	} else {
		sbuf_puts(buf, "[0-9]+");
	}
}

static void
integer2re(const struct tarsum *ts, struct sbuf *buf, const struct fieldspec *fs)
{
	(void)ts;

	switch (fs->fmt) {
	case 'O':
		sbuf_puts(buf, "-?[0-7]+");
		break;
	case 'U':
		sbuf_puts(buf, "[0-9]+");
		break;
	case 'X':
		sbuf_puts(buf, "[0-9A-Fa-f]+");
		break;
	default:
		sbuf_puts(buf, "-?[0-9]+");
		break;
	}
}

static void
format2re(struct tarsum *ts, struct sbuf *buf, size_t *_Nsub, size_t *_Csub, int *rs)
{
	const unsigned char *fmt = (const unsigned char *)ts->format;
	unsigned char escaped = 0;
	struct fieldspec fs = { 0 };
	size_t ncap = 0, Nsub = 0, Csub = 0;
	int lc = -1; /* last literal character */

	sbuf_putc(buf, '^');

	while (*fmt) {
		lc = -1;

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
			term2re(ts, buf, tok, &lc);
			break;
		case TOKEN('\\', 'x'):
			if (EOF != (tok = fromxdigit(*fmt, EOF))) {
				if (EOF != fromxdigit(*++fmt, EOF)) {
					tok <<= 4;
					tok |= fromxdigit(*fmt++, 0);
				}
				term2re(ts, buf, tok, &lc);
			} else {
				panic("%s: empty escape sequence", ts->format);
			}
			break;
		case TOKEN('\\', '\\'):
			term2re(ts, buf, '\\', &lc);
			break;
		case TOKEN('\\', 'a'):
			term2re(ts, buf, '\a', &lc);
			break;
		case TOKEN('\\', 'b'):
			term2re(ts, buf, '\b', &lc);
			break;
		case TOKEN('\\', 'f'):
			term2re(ts, buf, '\f', &lc);
			break;
		case TOKEN('\\', 'n'):
			term2re(ts, buf, '\n', &lc);
			break;
		case TOKEN('\\', 'r'):
			term2re(ts, buf, '\r', &lc);
			break;
		case TOKEN('\\', 't'):
			term2re(ts, buf, '\t', &lc);
			break;
		case TOKEN('\\', 'v'):
			term2re(ts, buf, '\v', &lc);
			break;
		case TOKEN('%', '%'):
			term2re(ts, buf, '%', &lc);
			break;
		case TOKEN('%', '$'):
			term2re(ts, buf, (ts->rs >= 0)? ts->rs : '\n', &lc);
			break;
		case TOKEN('%', 'A'):
			literal2re(ts, buf, EVP_MD_name(ts->mdtype));
			break;
		case TOKEN('%', 'C'):
			sbuf_putf(buf, "([0-9A-Fa-f]{%d})", 2 * EVP_MD_size(ts->mdtype));
			Csub = ++ncap; /* matches are 1-indexed */
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
			sbuf_puts(buf, "(..*)"); /* capture file names greedily */
			Nsub = ++ncap; /* matches are 1-indexed */
			break;
		case TOKEN('%', 'S'):
			fs.fmt = 'S';
			continue;
		case TOKEN('%', 'O'):
			fs.fmt = 'O';
			continue;
		case TOKEN('%', 'R'):
			sbuf_puts(buf, "(OK|FAILED|MISSING)");
			++ncap;
			break;
		case TOKEN('%', 'T'):
			mode2re(ts, buf, &fs, &ncap);
			break;
		case TOKEN('%', 'U'):
			fs.fmt = 'U';
			continue;
		case TOKEN('%', 'X'):
			fs.fmt = 'X';
			continue;
		case TOKEN('%', 'a'):
			time2re(ts, buf, &fs);
			break;
		case TOKEN('%', 'c'):
			time2re(ts, buf, &fs);
			break;
		case TOKEN('%', 'g'):
			user2re(ts, buf, &fs);
			break;
		case TOKEN('%', 'm'):
			time2re(ts, buf, &fs);
			break;
		case TOKEN('%', 'o'):
			integer2re(ts, buf, &fs);
			break;
		case TOKEN('%', 'u'):
			user2re(ts, buf, &fs);
			break;
		case TOKEN('%', 'z'):
			integer2re(ts, buf, &fs);
			break;
		default:
			if (isescaped(tok)) {
				panic("%s: unknown %s sequence (%c%c)", ts->format, (isescaped(tok) == '\\')? "escape" : "format", (unsigned char)(tok >> 8), (unsigned char)tok);
			}
			term2re(ts, buf, tok, &lc);
			break;
		}

		escaped = 0;
	}

	if (escaped) {
		panic("%s: empty %s sequence", ts->format, (escaped == '\\')? "escape" : "format");
	}

	*_Nsub = Nsub;
	*_Csub = Csub;

	if (lc == -1)
		term2re(ts, buf, '\n', &lc);

	*rs = lc;

	/*
	 * NB: regexec operates on NUL-terminated strings, so even though we
	 * detect and accept '\0' as a record separator, we have to treat it
	 * slightly differently
	 */
	if (lc == '\0')
		buf->p--;
	for (size_t p = 0, pe = MIN(buf->p, buf->size); p < pe; p++) {
		if (buf->base[p] == '\0')
			panic("%s: embedded \\0 not allowed within records", ts->format);
	}

	sbuf_putc(buf, '$');
}

static void
printreport(struct tarsumopts *opts, const char *path, const char *status, FILE *fp)
{
	const struct fields fields = {
		.rs = opts->rs,
		.A = opts->mdtype,
		.C = { NULL, 0 },
		.N = path,
		.R = status,
		.T = 0,
		.a = -1,
		.c = -1,
		.g = { NULL, -1 },
		.m = -1,
		.o = { -1, -1, -1 },
		.u = { NULL, -1 },
		.z = -1,
	};
	print(opts->report, opts->timefmt, &fields, fp);
}

static void
checkentry(struct tarsumopts *opts, struct checklist *checklist, const char *path, const void *md, size_t mdlen, struct fileid *id, FILE *fp)
{
	struct checksum *cs = (id)? checklist_findid(checklist, id) : checklist_findpath(checklist, path);

	checklist->report.nfiles++;

	if (cs) {
		cs->found++;

		assert(checklist->mdlen == mdlen);
		if (0 == memcmp(cs->md, md, mdlen)) {
			checklist->report.nok++;
			printreport(opts, path, "OK", fp);
		} else {
			checklist->report.nfailed++;
			printreport(opts, path, "FAILED", fp);
		}
	} else {
		warnx("%s: checksum not found in checklist", path);
	}
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

#define SHORTOPTS "0a:C:f:R:s:t:h"
static void
usage(const char *arg0, const struct tarsumopts *opts, FILE *fp)
{
	const char *progname = strrchr(arg0, '/')? strrchr(arg0, '/') + 1 : arg0;

	fprintf(fp,
		"Usage: %s [-" SHORTOPTS "] [TARFILE-PATH]\n" \
		"  -0          use NUL (\\0) as default record separator\n" \
		"  -a DIGEST   digest algorithm (default: \"%s\")\n" \
		"  -C PATH     checklist for verification of archive contents\n" \
		"  -f FORMAT   format specification (default: \"%s\")\n" \
		"  -R FORMAT   verification report format (default: \"%s\" )\n" \
		"  -s SUBEXPR  path substitution expression (see BSD tar(1) -s)\n" \
		"  -t TIMEFMT  strftime format specification (default: \"%s\")\n" \
		"  -h          print this usage message\n" \
		"\n" \
		"FORMAT (see printf(1) and BSD stat(1))\n" \
		"  \\NNN  octal escape sequence\n" \
		"  \\xNN  hexadecimal escape sequence\n" \
		"  \\L    C escape sequence (\\\\, \\a, \\b, \\f, \\n, \\r, \\t, \\v)\n" \
		"  %%%%    percent literal\n" \
		"  %%$    record separator (e.g. \\n or \\0)\n" \
		"  %%A    digest name\n" \
		"  %%C    file digest\n" \
		"  %%N    file name (full path)\n" \
		"  %%R    verification status (OK, FAILED, MISSING)\n" \
		"  %%T    file type (ls -L suffix character; use %%HT for long name, %%MT for single letter)\n" \
		"  %%g    GID or group name (%%Sg)\n" \
		"  %%m    last modification time (%%Sm: strftime formatting)\n" \
		"  %%o    file offset (%%Ho: header record, %%Lo: end of last file record)\n" \
		"  %%u    UID or user name (%%Su)\n" \
		"  %%z    file size (%%Hz: header record(s), %%Lz: header and file records)\n" \
		"\n" \
		"Report bugs to <william@25thandClement.com>\n",
	progname, EVP_MD_name(opts->mdtype), opts->format, opts->report, opts->timefmt);
}

int
main(int argc, char **argv)
{
	struct tarsumopts opts = TARSUMOPTS_INIT(&opts);
	const char **subexprs = NULL;
	size_t nsubexpr = 0;
	struct checklist *checklist = NULL;
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
		case '0':
			opts.rs = '\0';
			break;
		case 'a':
			opts.mdtype = optdigest(optarg);
			break;
		case 'C':
			opts.checklist = optarg;
			break;
		case 'f':
			opts.format = optarg;
			break;
		case 'R':
			opts.report = optarg;
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

	if ((error = tarsum_init(&ts, &opts)))
		panic("unable to initialize context: %s", tarsum_strerror(error));

	unsigned nerrs = 0;
	for (const char **subexpr = subexprs; subexpr && *subexpr; subexpr++) {
		if ((error = tarsum_addsubexpr(&ts, *subexpr))) {
			if (error == TARSUM_EREGCOMP) {
				warnx("%s", ts.regerr.descr);
				warnx("%s: bad substitution expression", *subexpr);
			} else {
				warnx("%s: %s", *subexpr, tarsum_strerror(error));
			}
			nerrs++;
		}
	}
	optsfree(&subexprs, &nsubexpr);
	if (nerrs) {
		tarsum_destroy(&ts);
		panic("encountered %u errors loading substitution expressions", nerrs);
	}

	if (opts.checklist) {
		static char _sbuf[1024], _formatreviz[1024];
		struct sbuf sbuf = SBUF_INTO(_sbuf, sizeof _sbuf - 1);
		struct sbuf formatreviz = SBUF_INTO(_formatreviz, sizeof _formatreviz - 1);
		size_t Nsub = 0, Csub = 0;
		int rs = -1;

		/*
		 * translate checksum output format specifier into a
		 * regular expression
		 */
		format2re(&ts, &sbuf, &Nsub, &Csub, &rs);
		if ((error = sbuf_error(&sbuf)))
			panic("format2re: %s", tarsum_strerror(error));
		sbuf_putv(&formatreviz, sbuf.base, MIN(sbuf.p, sbuf.size), '\n', "\"");
		DEBUG("translated %s to %s", ts.format, formatreviz.base);

		if ((error = checklist_init(&checklist, ts.mdtype, (char *)sbuf.base, REG_EXTENDED, Nsub, Csub, &ts.regerr))) {
			warnx("using checksum regular expression \"%s\"", formatreviz.base);
			if (error == TARSUM_EREGCOMP) {
				warnx("%s", ts.regerr.descr);
			}
			panic("unable to initialize checklist: %s", tarsum_strerror(error));
		}

		FILE *fp = fopen(opts.checklist, "rte");
		if (!fp)
			panic("%s: %s", opts.checklist, tarsum_strerror(errno));
		while ((error = checklist_loadfile(checklist, fp, rs))) {
			if (checklist->report.nerrors++ == 0) {
				warnx("using checksum regular expression \"%s\"", formatreviz.base);
				warnx("loading checklist from %s", opts.checklist);
			}
			if (error == TARSUM_EREGEXEC) {
				warnx("%s", checklist->loaderr.regerr.descr);
			}
			if (checklist->loaderr.line) {
				sbuf_putv(sbuf_reset(&sbuf), checklist->loaderr.line, checklist->loaderr.linelen, '\n', "\"");
				sbuf_putc(&sbuf, '\0');
				warnx("error loading checksum \"%s\": %s", sbuf.base, tarsum_strerror(error));
			} else {
				warnx("error loading checksum: %s", tarsum_strerror(error));
			}
		}
		fclose(fp);
	}

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
			char *repl = NULL;
			if ((error = subexpr_exec(subexpr, &repl, path, &ts.regerr))) {
				if (error == TARSUM_EREGEXEC) {
					warnx("%s", ts.regerr.descr);
				}
				panic("unable to apply substitution expression: %s", tarsum_strerror(error));
			} else if (repl) {
				path = repl;
				if (!strchr(subexpr->flags, '|'))
					break;
			}
		}

		if (!*path)
			continue;

		ts.cursor.soh = archive_read_header_position(ts.archive);
		ts.cursor.stx = archive_filter_bytes(ts.archive, 0);
		ts.cursor.etx = ts.cursor.stx;

		if (archive_entry_hardlink(entry)) {
			/* XXX: should we do archive_read_data_skip? */

			const struct entry *ent = entryget(archive_entry_hardlink(entry));
			if (ent) {
				if (checklist) {
					/* NB: deliberately passing NULL fileid */
					checkentry(&opts, checklist, path, ent->md, ent->mdlen, NULL, stdout);
				} else {
					/* XXX: will entry have the fields or should we pass ent? */
					printentry(&ts, path, ent->md, ent->mdlen, entry, stdout);
				}
			}
			continue;
		}

		if(archive_entry_filetype(entry) != AE_IFREG)
		{
			/* Only process regular files. */
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

		struct entry *ent = entryadd(path, md, mdlen);
		if (checklist) {
			checkentry(&opts, checklist, path, md, mdlen, &ent->id, stdout);
		} else {
			printentry(&ts, path, md, mdlen, entry, stdout);
		}
	}

	int exitcode = 0;

	if (checklist) {
		struct checksum *cs;
		TAILQ_FOREACH(cs, &checklist->loaded, tqe) {
			if (!cs->found) {
				checklist->report.nmissed++;
				printreport(&opts, cs->path, "MISSING", stdout);
			}
		}
		fflush(stdout);

		if (checklist->report.nerrors) {
			warnx("%zu errors loading checklist", checklist->report.nerrors);
			exitcode = EXIT_FAILURE;
		}
		if (checklist->report.nloaded == 0) {
			warnx("empty checklist");
			exitcode = EXIT_FAILURE;
		}
		if (checklist->report.nfailed || checklist->report.nmissed) {
			if (checklist->report.nfailed)
				warnx("%zu checksum failures", checklist->report.nfailed);
			if (checklist->report.nmissed)
				warnx("%zu files missing from archive", checklist->report.nmissed);
			exitcode = EXIT_FAILURE;
		}

		assert(exitcode != 0 || checklist->report.nloaded == checklist->report.nok);
		checklist_destroy(&checklist);
	}

	if (archive_errno(ts.archive) != ARCHIVE_OK) {
		warnx("%s: %s", path, archive_error_string(ts.archive));
		exitcode = EXIT_FAILURE;
	}
	if ((error = tarsum_destroy(&ts))) {
		warnx("%s: %s", path, tarsum_strerror(error));
		exitcode = EXIT_FAILURE;
	}

	return exitcode;
}
