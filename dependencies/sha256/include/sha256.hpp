/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <cstdint>
#include <stddef.h>
#include <string>
#include <array>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest
#define SHA256_STR_LENGTH (SHA256_BLOCK_SIZE * 2 + 1)

/**************************** DATA TYPES ****************************/
typedef std::array<std::uint8_t, SHA256_BLOCK_SIZE> sha256_digest_t;

typedef struct {
	std::uint8_t data[64];
	std::uint32_t datalen;
	unsigned long long bitlen;
	std::uint32_t state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const std::uint8_t data[], size_t len);
void sha256_final(SHA256_CTX *ctx, sha256_digest_t &hash);
bool sha256_file(const std::string& filename, sha256_digest_t &hash);
bool hash_to_string(const sha256_digest_t &hash, char *str, std::size_t len);
bool string_to_hash(const char *str, sha256_digest_t &hash);

#endif   // SHA256_H
