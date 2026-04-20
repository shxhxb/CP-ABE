#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

/*
 * 杂凑：SHA-256；带标签哈希入 Zr / G1 / GT；对称封装 AES-256-CBC + PKCS#7 式 padding。
 */
#include <stddef.h>
#include <stdint.h>
#include <pbc/pbc.h>

void hash256(const void *data, size_t len, uint8_t out32[32]);

void hash_to_zr(pairing_t pairing, element_t out_zr, const char *label, const void *data, size_t len);

void hash_to_gt(pairing_t pairing, element_t out_gt, const char *label, const void *data, size_t len);

void hash_to_g1(pairing_t pairing, element_t out_g1, const char *label, const void *data, size_t len);

int sym_encrypt_aes256_cbc(const uint8_t key[32], const uint8_t *pt, size_t pt_len,
                           uint8_t **ct_out, size_t *ct_len_out);

int sym_decrypt_aes256_cbc(const uint8_t key[32], const uint8_t *ct, size_t ct_len,
                           uint8_t **pt_out, size_t *pt_len_out);

#endif
