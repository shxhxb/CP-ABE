/* 供 abe_core：SHA-256、标签哈希进 Zr/G1/GT、AES-256-CBC；对应论文中 H、对称封装实例 */
#include "crypto_utils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

void hash256(const void *data, size_t len, uint8_t out32[32]) {
  SHA256((const unsigned char *)data, len, out32);
}

void hash_to_zr(pairing_t pairing, element_t out_zr, const char *label, const void *data, size_t len) {
  uint8_t buf[32];
  size_t lablen = label ? strlen(label) : 0;
  size_t tot = lablen + len;
  uint8_t *tmp = (uint8_t *)malloc(tot);
  if (label && lablen) memcpy(tmp, label, lablen);
  if (len) memcpy(tmp + lablen, data, len);
  hash256(tmp, tot, buf);
  free(tmp);
  element_t h;
  element_init_Zr(h, pairing);
  element_from_hash(h, buf, 32);
  element_set(out_zr, h);
  element_clear(h);
}

void hash_to_gt(pairing_t pairing, element_t out_gt, const char *label, const void *data, size_t len) {
  uint8_t buf[32];
  size_t lablen = label ? strlen(label) : 0;
  size_t tot = lablen + len;
  uint8_t *tmp = (uint8_t *)malloc(tot);
  if (label && lablen) memcpy(tmp, label, lablen);
  if (len) memcpy(tmp + lablen, data, len);
  hash256(tmp, tot, buf);
  element_t h;
  element_init_GT(h, pairing);
  element_from_hash(h, buf, 32);
  element_set(out_gt, h);
  element_clear(h);
}

void hash_to_g1(pairing_t pairing, element_t out_g1, const char *label, const void *data, size_t len) {
  uint8_t buf[32];
  size_t lablen = label ? strlen(label) : 0;
  size_t tot = lablen + len;
  uint8_t *tmp = (uint8_t *)malloc(tot);
  if (label && lablen) memcpy(tmp, label, lablen);
  if (len) memcpy(tmp + lablen, data, len);
  hash256(tmp, tot, buf);
  element_t h;
  element_init_G1(h, pairing);
  element_from_hash(h, buf, 32);
  element_set(out_g1, h);
  element_clear(h);
}

int sym_encrypt_aes256_cbc(const uint8_t key[32], const uint8_t *pt, size_t pt_len,
                             uint8_t **ct_out, size_t *ct_len_out) {
  if (!ct_out || !ct_len_out) return -1;
  size_t blk = (pt_len + 16) / 16 * 16;
  uint8_t iv[16];
  if (RAND_bytes(iv, 16) != 1) return -2;
  uint8_t *buf = (uint8_t *)malloc(16 + blk);
  if (!buf) return -3;
  memcpy(buf, iv, 16);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    free(buf);
    return -4;
  }
  int len = 0, tot = 16;
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    free(buf);
    return -5;
  }
  if (EVP_EncryptUpdate(ctx, buf + 16, &len, pt, (int)pt_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    free(buf);
    return -6;
  }
  tot += len;
  if (EVP_EncryptFinal_ex(ctx, buf + tot, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    free(buf);
    return -7;
  }
  tot += len;
  EVP_CIPHER_CTX_free(ctx);
  *ct_out = buf;
  *ct_len_out = (size_t)tot;
  return 0;
}

int sym_decrypt_aes256_cbc(const uint8_t key[32], const uint8_t *ct, size_t ct_len,
                           uint8_t **pt_out, size_t *pt_len_out) {
  if (ct_len < 16 || !pt_out || !pt_len_out) return -1;
  const uint8_t *iv = ct;
  const uint8_t *data = ct + 16;
  size_t dlen = ct_len - 16;
  uint8_t *buf = (uint8_t *)malloc(dlen + 32);
  if (!buf) return -2;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    free(buf);
    return -3;
  }
  int len = 0, tot = 0;
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    free(buf);
    return -4;
  }
  if (EVP_DecryptUpdate(ctx, buf, &len, data, (int)dlen) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    free(buf);
    return -5;
  }
  tot += len;
  if (EVP_DecryptFinal_ex(ctx, buf + tot, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    free(buf);
    return -6;
  }
  tot += len;
  EVP_CIPHER_CTX_free(ctx);
  *pt_out = buf;
  *pt_len_out = (size_t)tot;
  return 0;
}
