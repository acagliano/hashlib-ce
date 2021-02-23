#ifndef HASHLIB_H
#define HASHLIB_H

#include <stdint.h>

// INCLUDE FILE FOR HASHLIB

#define SHA1_DIGEST_LEN     20
#define SHA256_DIGEST_LEN   32

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

// SHA-1 Hash
//
// # Inputs #
//  buf = pointer to data to hash
//  len = size of region to hash
//  digest = pointer to location to write hash to (20-bytes)

void hashlib_SHA1(const uint8_t *buf, uint32_t len, uint8_t *digest);

// SHA-256 Hash
//
// # Inputs #
//  buf = pointer to data to hash
//  len = size of region to hash
//  digest = pointer to location to write hash to (32 bytes)

void hashlib_SHA256(const uint8_t *buf, uint32_t len, uint8_t *digest);


#endif
