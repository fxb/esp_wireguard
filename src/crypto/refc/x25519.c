#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <psa/crypto.h>

#include "../../crypto.h"

// Cache imported PSA keys across calls: the device static key is reused for
// the lifetime of the device and each handshake ephemeral key performs
// multiple scalar multiplications, so importing and destroying a key per
// call wastes time on the handshake hot path. Two slots cover both keys.
// No locking: all WireGuard crypto runs in the lwIP tcpip thread.
#define X25519_KEY_CACHE_SLOTS (2)

struct x25519_cache_slot {
  bool valid;
  uint32_t last_used;
  unsigned char n[32];
  psa_key_id_t key_id;
};

static struct x25519_cache_slot cache[X25519_KEY_CACHE_SLOTS];
static uint32_t cache_use_counter = 0;

static int cache_get_key(const unsigned char *n, psa_key_id_t *key_id) {
  struct x25519_cache_slot *slot;
  int i;

  for (i = 0; i < X25519_KEY_CACHE_SLOTS; i++) {
    slot = &cache[i];
    if (slot->valid && crypto_equal(slot->n, n, 32)) {
      slot->last_used = ++cache_use_counter;
      *key_id = slot->key_id;
      return 0;
    }
  }

  // Miss: reuse the least recently used slot (invalid slots have
  // last_used == 0 and are picked first).
  slot = &cache[0];
  for (i = 1; i < X25519_KEY_CACHE_SLOTS; i++) {
    if (cache[i].last_used < slot->last_used) {
      slot = &cache[i];
    }
  }
  if (slot->valid) {
    psa_destroy_key(slot->key_id);
    crypto_zero(slot->n, 32);
    slot->valid = false;
  }

  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
  psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
  psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
  psa_set_key_bits(&attributes, 255);

  psa_status_t status = psa_import_key(&attributes, n, 32, &slot->key_id);
  if (status != PSA_SUCCESS) {
    return -1;
  }

  memcpy(slot->n, n, 32);
  slot->valid = true;
  slot->last_used = ++cache_use_counter;
  *key_id = slot->key_id;
  return 0;
}

int crypto_scalarmult_curve25519(
    unsigned char *q,
    const unsigned char *n,
    const unsigned char *p) {
  psa_key_id_t key_id;

  if (cache_get_key(n, &key_id) != 0) {
    return -1;
  }

  size_t output_length = 0;
  psa_status_t status = psa_raw_key_agreement(PSA_ALG_ECDH, key_id, p, 32, q, 32, &output_length);

  return (status == PSA_SUCCESS) ? 0 : -1;
}
