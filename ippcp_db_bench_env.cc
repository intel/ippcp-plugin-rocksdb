//  Copyright (c) 2021-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#include <rocksdb/utilities/object_registry.h>

#include "ippcp_provider.h"

namespace ROCKSDB_NAMESPACE {

#ifndef ROCKSDB_LITE

extern "C" FactoryFunc<Env> ippcp_db_bench_env;

// Registers a sample ippcp encrypted environment that can be used in db_bench
// by passing --env_uri=ippcp_db_bench_env parameter.

FactoryFunc<Env> ippcp_db_bench_env = ObjectLibrary::Default()->AddFactory<Env>(
    "ippcp_db_bench_env",
    [](const std::string& /* uri */, std::unique_ptr<Env>* f,
       std::string* /* errmsg */) {
      auto provider =
          std::shared_ptr<EncryptionProvider>(IppcpProvider::CreateProvider());
      provider->AddCipher("", "a6d2ae2816157e2b3c4fcf098815f7xb", 32, false);
      *f = std::unique_ptr<Env>(NewEncryptedEnv(Env::Default(), provider));
      return f->get();
    });

#endif  // ROCKSDB_LITE

}  // namespace ROCKSDB_NAMESPACE
