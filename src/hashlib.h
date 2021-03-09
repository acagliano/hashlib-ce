#ifndef HASHLIB_H
#define HASHLIB_H

#include <stdint.h>

// INCLUDE FILE FOR HASHLIB

// ############################################
// Context Definitions for SHA-* Computations
// ############################################

typedef struct _sha1_ctx {
	uint8_t data[64];
	uint32_t datalen;
	uint8_t bitlen[8];
	uint32_t state[5];
	uint32_t k[4];
} sha1_ctx;

typedef struct _sha256_ctx {
	uint8_t data[64];
	uint32_t datalen;
	uint8_t bitlen[8];
	uint32_t state[8];
} sha256_ctx;

#define SHA1_DIGEST_LEN     20
#define SHA256_DIGEST_LEN   32

// #################################
// Context Definitions for RSA-256
// #################################

typedef struct _rsa_pubkey {
  uint8_t key[32];	// using a 256-bit key. It's not a full security impl., but hell... this is a calculator.
} rsa_pubkey_t;		// this algorithm is more for teaching myself and proof of concept..

typedef struct _rsa_privkey { 
  uint8_t key[32];
} rsa_privkey_t;

typedef struct _rsa_ctx {
  rsa_privkey_t privkey;   // client encrypts outgoing traffic with this
  rsa_pubkey_t pubkey;    // client decrypts incoming traffic with this (server should generate and send)
} rsa_ctx;

// ## @BECK = you can use the pubkey field here when *initializing* the public-key context for the remote host.
// However, once we handshake with the remote host, the remote public key overwrites this
// Since iirc, once we send it out, we don't need it again

// ##############################
// ####### LESSER HASHES ########
// ##############################

// Standard Checksum 24-Bit
//
// # Inputs #
//  buf = pointer to data to hash
//  len = size of region to hash
// # Outputs #
//  an unsigned 24-bit integer

uint24_t hashlib_ChecksumU24(const uint8_t *buf, size_t len);

// Standard Checksum 32-Bit
//
// # Inputs #
//  buf = pointer to data to hash
//  len = size of region to hash
// # Outputs #
//  an unsigned 32-bit integer

uint32_t hashlib_ChecksumU32(const uint8_t *buf, size_t len);

// CRC-32 Cyclic Redundancy Check
//
// # Inputs #
//  buf = pointer to data to hash
//  len = size of region to hash
// # Outputs #
//  an unsigned 32-bit integer

uint32_t hashlib_CRC32(const uint8_t *buf, size_t len);


// ##########################
// ###### SHA1 HASHING ######
// ##########################
//
// There are two ways to use the SHA-1 hashing algorithms, and what method you choose depends
// on what your use case is. 
//
// hashlib_sha1init()	\
// hashlib_sha1update()	|	Multi-Pass Hashing
// hashlib_sha1final()	/
//
// In the above method, you call hashlib_sha1init on a pre-declared sha1_ctx structure to set the defaults.
// If you do not call hashlib_sha1init, your hash will be incorrect.
// You can then call hashlib_sha1update whenever you have a new block of data to hash.
// You can then call hashlib_sha1final when you are done and want to render your hash.
//
// hashlib_SHA1()	|	Single-Pass Hashing
//
// The above method is an optional static function wrapper that you can call if you are sure that the entire
// block of data you need to hash is available to you and in one place, such as an appvar or program or other
// variable. In this case, you do not need to initialize or declare your sha1 context; it is all handled in the wrapper.

// Init Context for SHA1
//
// # Inputs #
//  ctx = pointer to an SHA1_CTX
//  Any call to the other two SHA1 functions must start with this
//  or your SHA will be invalid

void hashlib_sha1init(sha1_ctx *ctx);

// Update Context for SHA1
//
// # Inputs #
//  ctx = pointer to an SHA1_CTX
//  buf = ptr to a block of data to hash
//  len = size of the block of data to hash
//  MUST CALL HASHLIB_SHA1INIT first!!!!

void hashlib_sha1update(sha1_ctx *ctx, const uint8_t* buf, uint32_t len);

// Finalize Context and Render Digest for SHA1
//
// # Inputs #
//  ctx = pointer to an SHA1_CTX
//  digest = pointer to buffer to write digest

void hashlib_sha1final(sha1_ctx *ctx, uint8_t* digest);

// One-Shot SHA-1 Computation
//
// # Inputs #
//  buf = pointer to data to hash
//  len = length of data to hash
//  digest = pointer to buffer to write digest

static void hashlib_SHA1(uint8_t* buf, size_t len, uint8_t* digest) {
	sha1_ctx ctx;
	hashlib_sha1init(&ctx);
	hashlib_sha1update(&ctx, buf, len);
	hashlib_sha1final(&ctx, digest);
}

// ############################
// ###### SHA256 HASHING ######
// ############################

// Init Context for SHA256
//
// # Inputs #
//  ctx = pointer to an SHA256_CTX
//  Any call to the other two SHA256 functions must start with this
//  or your SHA will be invalid

void hashlib_sha256init(sha256_ctx *ctx);

// Update Context for SHA256
//
// # Inputs #
//  ctx = pointer to an SHA256_CTX
//  buf = ptr to a block of data to hash
//  len = size of the block of data to hash
//  MUST CALL HASHLIB_SHA256INIT first!!!!

void hashlib_sha256update(sha256_ctx *ctx, const uint8_t* buf, uint32_t len);

// Finalize Context and Render Digest for SHA256
//
// # Inputs #
//  ctx = pointer to an SHA256_CTX
//  digest = pointer to buffer to write digest

void hashlib_sha256final(sha256_ctx *ctx, uint8_t* digest);

// One-Shot SHA-256 Computation
//
// # Inputs #
//  ctx = pointer to an SHA256_CTX
//  buf = pointer to data to hash
//  len = length of data to hash
//  digest = pointer to buffer to write digest

static void hashlib_SHA256(uint8_t* buf, size_t len, uint8_t* digest) {
	sha256_ctx ctx;
	hashlib_sha256init(&ctx);
	hashlib_sha256update(&ctx, buf, len);
	hashlib_sha256final(&ctx, digest);
}

// ######################
// ###### RSA-256  ######
// ######################
//
//	RSA-256, which I will dub "TI-RSA" is a lightweight implementation of RSA
//	for the TI-84+ CE. It uses a 256-bit pair of keys to conduct asymmetric
//	encrypted data transfers between a TI-84+ CE client and some remote host.
//
//	NOTE: 256-bit keys are NOT cryptographically secure for practical applications
//	RSA standard requires at least 1024-bits. Nonetheless this is here as 
//	proof-of-concept and a learning exercise for me (and beck, as I provided him
//	the algorithm, and a C implementation and he's doing the ASM for it.)
//	DO NOT SEND SENSITIVE DATA WITH THIS PROTOCOL
//	better yet, don't send sensitive data with a calculator
//

// Init Context for RSA-256
//
// # Inputs #
//  ctx = pointer to an RSA_CTX
//  Any call to the other RSA functions must start with this
//  or you will get unintended results

// void hashlib_RSAInit(rsa_ctx* ctx);

// Sets the public key generated by the remote host to be used for decryption
//
// # Inputs #
//  ctx = Pointer to an RSA Context initialized by calling hashlib_RSAInit()
//  key = Pointer to a 256-bit public key, usually sent by a remote host

// void hashlib_RSASetRemoteKey(rsa_ctx* ctx, uint8_t* key);

// Encrypt a Block of Data Using an RSA Context
// 
// # Inputs #
// ctx = Pointer to an RSA Context initialized by calling hashlib_RSAInit()
// buf = A pointer to a buffer to encrypt
// len = The length of the data to encrypt
// ? out_buf ? = A pointer to a buffer to hold the cipher (if not doing in-place encryption)

// void hashlib_RSAEncrypt(rsa_ctx* ctx, uint8_t* buf, size_t len, [uint8_t* out_buf]);

// Decrypt a Block of Data Using an RSA Context
// 
// # Inputs #
// ctx = An RSA Context initialized by first calling hashlib_RSAInit()
// buf = A pointer to a buffer to decrypt
// len = The length of the data to decrypt
// ? out_buf ? = A pointer to a buffer to hold the decrypted data (if not doing in-place decryption)

// void hashlib_RSADecrypt(rsa_ctx* ctx, uint8_t* buf, size_t len, [uint8_t* out_buf]);

// ## @BECK if you are going to do data transformation in-place, remove out_buf from the prototypes and documentation ##

#endif
