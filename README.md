# tarsum

## DESCRIPTION

`tarsum` generates and validates checksums for files encapsulated within
common archive file formats. It supports a format specification grammar
based on the [BSD stat(1)](https://man.openbsd.org/stat.1) utility for
specifying the checklist and reporting formats. This makes it easy to
interoperate with different checksum utilities (e.g. [GNU coreutils md5sum](https://www.gnu.org/software/coreutils/manual/html_node/md5sum-invocation.html)
or [OpenBSD sha256](https://man.openbsd.org/sha256.1)), which utilize
different line formats. This also effectively provides a way to
programmatically query file metadata from a shell without expanding the
archive.

## DEPENDENCIES

- [libarchive](https://www.libarchive.org/) (-larchive) for handling archives formats.
- [OpenSSL](https://www.openssl.org/) (-lcrypto) for digest algorithms.
- Modern POSIX'ish platform.

## BUILDING

See the included [Makefile](Makefile), which should work out-of-the-box
on most systems:

```
$ make
```

On systems like macOS without libarchive or OpenSSL in the native
distribution or SDK, you need to specify the location of those libraries.
For example, in an environment where libarchive is manually installed under
/usr/local/libarchive, and OpenSSL managed by MacPorts:

```
$ make LIBARCHIVE_PREFIX=/usr/local/libarchive OPENSSL_PREFIX=/opt/local
```

The Makefile macros are broken out in such a way that it should never be
necessary to directly edit it, unless it's simply easier to edit once than
to override on every invocation.

## USAGE

```
Usage: tarsum [-0a:C:f:R:s:t:h] [TARFILE-PATH]
  -0          use NUL (\0) as default record separator
  -a DIGEST   digest algorithm (default: "SHA256")
  -C PATH     checklist for verification of archive contents
  -f FORMAT   format specification (default: "%C  %N%$")
  -R FORMAT   verification report format (default: "%N: %R%$" )
  -s SUBEXPR  path substitution expression (see BSD tar(1) -s)
  -t TIMEFMT  strftime format specification (default: "%a %b %e %X %Y")
  -h          print this usage message

FORMAT (see printf(1) and BSD stat(1))
  \NNN  octal escape sequence
  \xNN  hexadecimal escape sequence
  \L    C escape sequence (\\, \a, \b, \f, \n, \r, \t, \v)
  %%    percent literal
  %$    record separator (e.g. \n or \0)
  %A    digest name
  %C    file digest
  %N    file name (full path)
  %R    verification status (OK, FAILED, MISSING)
  %T    file type (ls -L suffix character; use %HT for long name, %MT for single letter)
  %g    GID or group name (%Sg)
  %m    last modification time (%Sm: strftime formatting)
  %o    file offset (%Ho: header record, %Lo: end of last file record)
  %u    UID or user name (%Su)
  %z    file size (%Hz: header record(s), %Lz: header and file records)

Report bugs to <william@25thandClement.com>
```

## HACKING

I originally threw together tarsum.c in a few hours. Some parts are
organized as-if they were to be built as a shared library, others assume a
simple binary.

The format specification grammar should be straightforward (tastes
notwithstanding) for someone with experience hacking on common Unix
software providing similar facilties (e.g. libc). Most of that logic is kept
encapsulated in the `print` routine. What's somewhat unique is that for
parsing checklists the format specification is translated into a regular
expression, a task performed by the `format2re` routine.

## BOOKMARKS

* https://dev.gentoo.org/~mgorny/articles/portability-of-tar-features.html

## LICENSE

Copyright (c) 2017, 2019, 2022  William Ahern

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
