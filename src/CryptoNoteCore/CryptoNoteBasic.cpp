// Copyright (c) 2018, Logicoin

#include "CryptoNoteBasic.h"
#include "crypto/crypto.h"

namespace CryptoNote {

KeyPair generateKeyPair() {
  KeyPair k;
  Crypto::generate_keys(k.publicKey, k.secretKey);
  return k;
}

}
