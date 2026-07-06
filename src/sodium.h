#pragma once

#include <string.h>
#include <psa/crypto.h>

static inline int crypto_scalarmult_curve25519(
    unsigned char *q,
    const unsigned char *n,
    const unsigned char *p) {
  psa_status_t status;
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_key_id_t key_id = 0;

  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
  psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
  psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
  psa_set_key_bits(&attributes, 255);

  status = psa_import_key(&attributes, n, 32, &key_id);
  if (status != PSA_SUCCESS) {
    return -1;
  }

  size_t output_length = 0;
  status = psa_raw_key_agreement(PSA_ALG_ECDH, key_id, p, 32, q, 32, &output_length);

  psa_destroy_key(key_id);

  return (status == PSA_SUCCESS) ? 0 : -1;
}
