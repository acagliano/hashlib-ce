//--------------------------------------
// Program Name: VAPOR
// Author: Anthony Cagliano
// License:
// Description:
//--------------------------------------

/* Keep these headers */

#include <stdint.h>
#include <tice.h>


/* Standard headers - it's recommended to leave them included */

/* Other available headers */
#include "add64.h"

// stdarg.h, setjmp.h, assert.h, ctype.h, float.h, iso646.h, limits.h, errno.h, debug.h
#define	SHA1_BLOCK_LENGTH		64
#define	SHA1_DIGEST_LENGTH		20
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest
typedef uint8_t BYTE;             // 8-bit byte
typedef uint32_t WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	WORD datalen;
	uint8_t bitlen[8];
	WORD state[5];
	WORD k[4];
} SHA1_CTX;


typedef struct {
	BYTE data[64];
	WORD datalen;
	uint8_t bitlen[8];
	WORD state[8];
} SHA256_CTX;

typedef struct {
    uint32_t privkey[2];
    uint32_t pubkey;
} keypairs_t;

typedef struct {
    keypairs_t send;
    uint32_t recv_key;
} RSA_CTX;

typedef union
{
    uint8_t c[64];
    uint32_t l[16];
} CHAR64LONG16;

// MAIN FUNCTIONS
//uint24_t hashlib_ChecksumU24(const uint8_t *buf, size_t len);
//uint32_t hashlib_ChecksumU32(const uint8_t *buf, size_t len);
//uint32_t hashlib_CRC32(const uint8_t *buf, size_t len);
//void hashlib_SHA1(const uint8_t *buf, uint32_t len, uint8_t *digest);
//void hashlib_SHA256(const uint8_t *buf, uint32_t len, uint8_t *digest);


// SUPPORTING FUNCTIONS
void sha1_init(SHA1_CTX *ctx);
void sha1_transform(SHA1_CTX *ctx, const BYTE data[]);
void sha1_update(SHA1_CTX *ctx, const BYTE data[], uint32_t len);
void sha1_final(SHA1_CTX *ctx, BYTE hash[]);

void sha256_init(SHA256_CTX *ctx);
void sha256_transform(SHA256_CTX *ctx, const BYTE data[]);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], uint32_t len);
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);

int main(void){
    
}


uint24_t hashlib_ChecksumU24(const uint8_t *buf, size_t len){
    size_t i;
    uint24_t checksum=0;
    for(i=0; i<len; i++) checksum+=buf[i];
    return checksum;
}

uint32_t hashlib_ChecksumU32(const uint8_t *buf, size_t len){
    size_t i;
    uint32_t checksum=0;
    for(i=0; i<len; i++) checksum+=buf[i];
    return checksum;
}

uint32_t hashlib_CRC32(const uint8_t *buf, size_t len){
    static uint32_t table[256];
    uint32_t crc=0;
    static int have_table = 0;
    uint32_t rem;
    uint8_t octet;
    uint24_t i, j;
    const uint8_t *p, *q;

/* This check is not thread safe; there is no mutex. */
    if (have_table == 0) {
/* Calculate CRC table. */
        for (i = 0; i < 256; i++) {
            rem = i;  /* remainder from polynomial division */
            for (j = 0; j < 8; j++) {
                if (rem & 1) {
                    rem >>= 1;
                    rem ^= 0xedb88320;
                } else
                    rem >>= 1;
            }
            table[i] = rem;
        }
        have_table = 1;
    }

    crc = ~crc;
    q = buf + len;
    for (p = buf; p < q; p++) {
        octet = *p;  /* Cast to unsigned octet. */
        crc = (crc >> 8) ^ table[(crc & 0xff) ^ octet];
    }
    return ~crc;
}

void hashlib_SHA1(const uint8_t *buf, uint32_t len, uint8_t *digest){
    SHA1_CTX ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, buf, len);
    sha1_final(&ctx, digest);
}

void hashlib_SHA256(const uint8_t *buf, uint32_t len, uint8_t *digest){
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, buf, len);
    sha256_final(&ctx, digest);
}



/* Hash a single 512-bit block. This is the core of the algorithm. */
#define ROTLEFT_SHA1(a, b) ((a << b) | (a >> (32 - b)))

/*********************** FUNCTION DEFINITIONS ***********************/
void sha1_transform(SHA1_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, i, j, t, m[80];

	for (i = 0, j = 0; i < 16; ++i, j += 4){
        WORD d1 = data[j];
        WORD d2 = data[j + 1];
        WORD d3 = data[j + 2];
        WORD d4 = data[j + 3];
        m[i] = (d1 << 24) + (d2 << 16) + (d3 << 8) + d4;
    }
	for ( ; i < 80; ++i) {
		m[i] = (m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]);
		m[i] = (m[i] << 1) | (m[i] >> 31);
	}

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];

	for (i = 0; i < 20; ++i) {
		t = ROTLEFT_SHA1(a, 5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i];
		e = d;
		d = c;
		c = ROTLEFT_SHA1(b, 30);
		b = a;
		a = t;
	}
	for ( ; i < 40; ++i) {
		t = ROTLEFT_SHA1(a, 5) + (b ^ c ^ d) + e + ctx->k[1] + m[i];
		e = d;
		d = c;
		c = ROTLEFT_SHA1(b, 30);
		b = a;
		a = t;
	}
	for ( ; i < 60; ++i) {
		t = ROTLEFT_SHA1(a, 5) + ((b & c) ^ (b & d) ^ (c & d))  + e + ctx->k[2] + m[i];
		e = d;
		d = c;
		c = ROTLEFT_SHA1(b, 30);
		b = a;
		a = t;
	}
	for ( ; i < 80; ++i) {
		t = ROTLEFT_SHA1(a, 5) + (b ^ c ^ d) + e + ctx->k[3] + m[i];
		e = d;
		d = c;
		c = ROTLEFT_SHA1(b, 30);
		b = a;
		a = t;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
}

void sha1_init(SHA1_CTX *ctx)
{
	ctx->datalen = 0;
	zero64(&ctx->bitlen);
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xc3d2e1f0;
	ctx->k[0] = 0x5a827999;
	ctx->k[1] = 0x6ed9eba1;
	ctx->k[2] = 0x8f1bbcdc;
	ctx->k[3] = 0xca62c1d6;
}

void sha1_update(SHA1_CTX *ctx, const BYTE data[], uint32_t len)
{
	size_t i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha1_transform(ctx, ctx->data);
			add64lu(&ctx->bitlen, 512);
			ctx->datalen = 0;
		}
	}
}

void sha1_final(SHA1_CTX *ctx, BYTE hash[])
{
	WORD i;
    int x;
	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha1_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	add64lu(&ctx->bitlen,ctx->datalen * 8);
	for (x=0;x<8;x++){ //put this in a loop for efficiency
		ctx->data[63-x] = ctx->bitlen[x];
	}
	sha1_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and MD uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
	}
}

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
static const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DEFINITIONS ***********************/
void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, f, g, h, i, j, tmp1, tmp2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4){
		WORD d1 = data[j];
        WORD d2 = data[j + 1];
        WORD d3 = data[j + 2];
        WORD d4 = data[j + 3];
        m[i] = (d1 << 24) + (d2 << 16) + (d3 << 8) + d4;
    }
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		tmp1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		tmp2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + tmp1;
		d = c;
		c = b;
		b = a;
		a = tmp1 + tmp2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	zero64(ctx->bitlen);
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const BYTE data[], uint32_t len)
{
	WORD i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			add64lu(&ctx->bitlen, 512);
			ctx->datalen = 0;
		}
	}
}

void sha256_final(SHA256_CTX *ctx, BYTE hash[])
{
	WORD i;
    int x;
	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	add64lu(&ctx->bitlen,ctx->datalen * 8);
	for (x=0;x<8;x++){ //put this in a loop for efficiency
		ctx->data[63-x] = ctx->bitlen[x];
	}
	sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}
