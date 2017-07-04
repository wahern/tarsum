all: tarsum

CPPFLAGS = -I/usr/local/libarchive/include -I/usr/local/openssl/include
LDFLAGS = -L/usr/local/libarchive/lib -L/usr/local/openssl/lib
LDLIBS = -larchive -lcrypto


