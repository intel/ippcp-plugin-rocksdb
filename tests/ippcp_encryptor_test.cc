//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  Copyright (c) 2020 Intel Corporation
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#include <rocksdb/db.h>
#include <rocksdb/env_encryption.h>
#include <rocksdb/options.h>
#include <rocksdb/slice.h>
#include <rocksdb/utilities/options_util.h>
#include <rocksdb/utilities/object_registry.h>

#include <cmath>
#include <iostream>
#include <string>
#include <tuple>

#include "../ippcp_provider.h"
#include <gtest/gtest.h>

namespace ROCKSDB_NAMESPACE
{

  TEST(IppcpBasicTests, LoadIppcpProvider)
  {
    std::string IPPCP = IppcpProvider::kName();
    std::shared_ptr<EncryptionProvider> provider;
    Status s = EncryptionProvider::CreateFromString(ConfigOptions(), IPPCP, &provider);
    ASSERT_TRUE(s.ok());
    ASSERT_NE(provider, nullptr);
    ASSERT_EQ(provider->Name(), IPPCP);
    std::string cipher_key;
    cipher_key.assign("a6d2ae2816157e2b3c4fcf098815f7x1");
    s = provider->AddCipher("", cipher_key.c_str(), cipher_key.length(), false);
    ASSERT_TRUE(s.ok()) << s.ToString();
    ;
  }

  TEST(IppcpBasicTests, TestAddKeys)
  {
    std::string IPPCP = IppcpProvider::kName();
    std::shared_ptr<EncryptionProvider> provider;
    Status s = EncryptionProvider::CreateFromString(ConfigOptions(), IPPCP, &provider);
    ASSERT_TRUE(s.ok()) << s.ToString();
    ;
    ASSERT_NE(provider, nullptr);
    std::string cipher_key;
    cipher_key.assign("a6d2ae2816157e2b3c4fcf098815f7x2");
    s = provider->AddCipher("", cipher_key.c_str(), cipher_key.length(), false);
    ASSERT_TRUE(s.ok()) << s.ToString();

    provider.reset();
    s = EncryptionProvider::CreateFromString(ConfigOptions(), IPPCP, &provider);
    ASSERT_TRUE(s.ok()) << s.ToString();
    ;
    ASSERT_NE(provider, nullptr);
    cipher_key.assign("a6d2ae2816157e2beeeeeeee");
    s = provider->AddCipher("", cipher_key.c_str(), cipher_key.length(), false);
    ASSERT_TRUE(s.ok()) << s.ToString();

    provider.reset();
    cipher_key.assign("a6d2ae2816157e21");
    s = EncryptionProvider::CreateFromString(ConfigOptions(), IPPCP, &provider);
    ASSERT_TRUE(s.ok()) << s.ToString();
    ASSERT_NE(provider, nullptr);
    s = provider->AddCipher("", cipher_key.c_str(), cipher_key.length(), false);
    ASSERT_TRUE(s.ok()) << s.ToString();
  }

  TEST(IppcpBasicTests, TestIncorrectKeyLength)
  {
    std::string IPPCP = IppcpProvider::kName();
    std::shared_ptr<EncryptionProvider> provider;
    Status s = EncryptionProvider::CreateFromString(ConfigOptions(), IPPCP, &provider);
    ASSERT_TRUE(s.ok());
    ASSERT_NE(provider, nullptr);
    std::string cipher_key;

    // empty encryption key
    cipher_key.assign("");
    s = provider->AddCipher("", cipher_key.c_str(), cipher_key.length(), false);
    ASSERT_TRUE(s.IsInvalidArgument()) << s.ToString();

    // incoorect encryption key length
    cipher_key.assign("a6d2ae2");
    s = provider->AddCipher("", cipher_key.c_str(), cipher_key.length(), false);
    ASSERT_TRUE(s.IsInvalidArgument()) << s.ToString();
  }

  TEST(IppcpBasicTests, TestAddingMultipleKeys)
  {
    std::string IPPCP = IppcpProvider::kName();
    std::shared_ptr<EncryptionProvider> provider;
    Status s = EncryptionProvider::CreateFromString(ConfigOptions(), IPPCP, &provider);
    ASSERT_TRUE(s.ok());
    ASSERT_NE(provider, nullptr);
    std::string cipher_key;
    // correct encryption key
    cipher_key.assign("a6d2ae2816157e21");
    s = provider->AddCipher("", cipher_key.c_str(), cipher_key.length(), false);
    ASSERT_TRUE(s.ok()) << s.ToString();

    // adding multiple cipher/encryption keys not allowed
    cipher_key.assign("a6d2ae281wwwwddd22222213");
    s = provider->AddCipher("", cipher_key.c_str(), cipher_key.length(), false);
    ASSERT_TRUE(s.IsInvalidArgument()) << s.ToString();
  }

  TEST(IppcpEncryptionTests, CounterBlkTests)
  {
    std::string IPPCP = IppcpProvider::kName();
    std::shared_ptr<EncryptionProvider> provider;
    // creating ipp provider and setting cipher key
    Status s = EncryptionProvider::CreateFromString(ConfigOptions(), IPPCP, &provider);
    ASSERT_TRUE(s.ok());
    ASSERT_NE(provider, nullptr);
    std::string cipher_key;
    cipher_key.assign("a6d2ae2816157e2b3c4fcf098815f7x2");
    s = provider->AddCipher("", cipher_key.c_str(), cipher_key.length(), false);
    ASSERT_TRUE(s.ok()) << s.ToString();
    // initilizing prefix which sets the 128 initVector data memmber
    // the first 8 bytes will be used for counter
    size_t prefixLen = 16; // minimum size of prefix is 16(blockSize)
    uint8_t ctr[] = {0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    Slice prefix((char *)ctr, prefixLen);

    std::unique_ptr<BlockAccessCipherStream> stream;
    const EnvOptions options;
    // creating cipher stream object to perform encryption and decryption
    s = provider->CreateCipherStream("", options, prefix, &stream);
    ASSERT_TRUE(s.ok()) << s.ToString();

    std::string input1, input2, input3, plainTxt;
    uint64_t offset = 0; // offset where from we need to perform encryption/decryption
    plainTxt = "";
    input1.assign("1 input for CounterBlk hellooo0 ");
    input2.assign("2 input for CounterBlk hellooo0 ");
    input3.assign("3 input for CounterBlk  helloo0 ");
    // concatenate the strings and encrypt them
    plainTxt = input1 + input2 + input3;
    s = stream->Encrypt(offset, (char *)plainTxt.c_str(), plainTxt.length()); // does in place encryption so plainTxt will be encrypted now
    s = stream->Decrypt(offset, (char *)plainTxt.c_str(), plainTxt.length()); // in .place decryption
    ASSERT_EQ(input1 + input2 + input3, plainTxt) << " both are strings are same after decryption!!";
  }

  /*
  This test checks wraparound condition for counter.The plugin code uses 64 bit intrinsic _mm_add_epi64 for addition as index is 64bits.
  plugin counter for all ff -> (ff ff ff ff ff ff ff ff 0 0 0 0 0 0 0 0) and (ff ff ff ff ff ff ff ff 0 0 0 0 0 0 0 1) so on
  if the kCounterLen passed to ipp lib is 128 then it use all 128 bits for addition which means counter created
  by plugin and ipp code will differ as it will rollover to all 0.
  if all FF counter is passed to ipp then new counter created ->() 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 ),( 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 2) etc

  To fix this issue the counter addition bit length needs to be same in both plugin and ipp lib code
  so kCounterLen needs to be 64 bits.

  This test will fail if kCounterLen is 128
  */
  TEST(IppcpEncryptionTests, CounterBlkOverFlowTests)
  {
    std::string IPPCP = IppcpProvider::kName();
    std::shared_ptr<EncryptionProvider> provider;
    // creating ipp provider and setting cipher key
    Status s = EncryptionProvider::CreateFromString(ConfigOptions(), IPPCP, &provider);
    ASSERT_TRUE(s.ok());
    ASSERT_NE(provider, nullptr);
    std::string cipher_key;
    cipher_key.assign("a6d2ae2816157e2b3c4fcf098815f7x2");
    s = provider->AddCipher("", cipher_key.c_str(), cipher_key.length(), false);
    ASSERT_TRUE(s.ok()) << s.ToString();

    // creating prefix which sets the 128 initVector data memmber
    size_t prefixLen = 16; // minimum size of prefix is 16
    // setting prefix/counter to all ff's to check the overflow
    uint8_t ctr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    Slice prefix((char *)ctr, prefixLen);
    // creating cipher stream object to perform encryption and decryption
    std::unique_ptr<BlockAccessCipherStream> stream;
    const EnvOptions options;
    s = provider->CreateCipherStream("", options, prefix, &stream);
    ASSERT_TRUE(s.ok()) << s.ToString();

    // creating string each of 16 byte(blocksize) for encryption
    std::string str1, str2, str3;
    str1.assign("1111111111111111");
    str2.assign("2222222222222222");
    str3.assign("3333333333333333");

    std::string encryptedString = "";
    encryptedString += str1;
    encryptedString += str2;
    encryptedString += str3;
    // encrypted all the strings in one go.Here ipp lib will create counter block for 2nd and 3rd string block
    s = stream->Encrypt(0, (char *)encryptedString.c_str(), encryptedString.length());
    std::string cipherTxt = encryptedString.substr(str1.length());
    // decrypt the encrypted string from str2 onwards i.e from block 2 onwards
    s = stream->Decrypt(str1.length(), (char *)cipherTxt.c_str(), cipherTxt.length());
    // the decrypted string should match the str2 + str3
    ASSERT_EQ((str2 + str3), cipherTxt) << " both are strings are same after decryption!!";
    ASSERT_TRUE(s.ok()) << s.ToString();
  }

  /*
  This test encrypts the input data and then decrypts it. Decrypted data should match the input for success.
  This Matches RocksDB Encryption API flow.
  */
  TEST(IppcpEncryptionTests, EncryptDecryptTest)
  {
    std::string IPPCP = IppcpProvider::kName();
    std::shared_ptr<EncryptionProvider> provider;
    Status s = EncryptionProvider::CreateFromString(ConfigOptions(), IPPCP, &provider);
    ASSERT_TRUE(s.ok());
    ASSERT_NE(provider, nullptr);

    std::string cipher_key;
    cipher_key.assign("a6d2ae2816157e2b3c4fcf098815f7x2");
    s = provider->AddCipher("", cipher_key.c_str(), cipher_key.length(), false);
    ASSERT_TRUE(s.ok()) << s.ToString();

    size_t prefixLen = provider->GetPrefixLength();
    ASSERT_GT(prefixLen, 0);
    char *buf = (char *)malloc(prefixLen);
    ASSERT_NE(buf, nullptr);
    std::unique_ptr<BlockAccessCipherStream> stream;
    const EnvOptions options;
    s = provider->CreateNewPrefix("", buf, prefixLen);
    ASSERT_TRUE(s.ok()) << s.ToString();
    Slice prefix(buf, prefixLen);

    s = provider->CreateCipherStream("", options, prefix, &stream);
    ASSERT_TRUE(s.ok()) << s.ToString();

    std::string input, plainTxt;
    uint64_t offset = prefixLen;
    input.assign("test ippcp crypto");
    plainTxt = input;                                                   //  input becomes cipher txt in below API.
    s = stream->Encrypt(offset, (char *)input.c_str(), input.length()); // does in place encryption
    ASSERT_TRUE(s.ok()) << s.ToString();
    s = stream->Decrypt(offset, (char *)input.c_str(), input.length());
    ASSERT_EQ(plainTxt, input) << " both are strings are same after decryption!!";
    free(buf);
  }

  /*
  This test encrypts the multple input data and then decrypts it in one go.
  Decrypted data should match the combined input for success.
  This is to test the random decryption functionality.
  */

  TEST(IppcpEncryptionTests, RandomDecryptionTests)
  {
    std::string IPPCP = IppcpProvider::kName();
    std::shared_ptr<EncryptionProvider> provider;
    Status s = EncryptionProvider::CreateFromString(ConfigOptions(), IPPCP, &provider);
    ASSERT_TRUE(s.ok());
    ASSERT_NE(provider, nullptr);

    std::string cipher_key;
    cipher_key.assign("a6d2ae2816157e2b3c4fcf098815f7x2");
    s = provider->AddCipher("", cipher_key.c_str(), cipher_key.length(), false);
    ASSERT_TRUE(s.ok()) << s.ToString();

    size_t prefixLen = provider->GetPrefixLength();
    ASSERT_GT(prefixLen, 0);
    char *buf = (char *)malloc(prefixLen);
    ASSERT_NE(buf, nullptr);
    s = provider->CreateNewPrefix("", buf, prefixLen);
    ASSERT_TRUE(s.ok()) << s.ToString();
    Slice prefix(buf, prefixLen);

    std::unique_ptr<BlockAccessCipherStream> stream;
    const EnvOptions options;
    s = provider->CreateCipherStream("", options, prefix, &stream);
    ASSERT_TRUE(s.ok()) << s.ToString();

    std::string input1, plainTxt, cipherTxt;
    uint64_t offset = prefixLen;

    input1.assign("1 input for encryption hellooo0 ");
    plainTxt = input1;
    s = stream->Encrypt(offset, (char *)input1.c_str(), input1.length()); // does in place encryption
    ASSERT_TRUE(s.ok()) << s.ToString();
    cipherTxt = input1;
    offset += input1.length();

    std::string input2;
    input2.assign("2 input for encryption hellooo0 ");
    plainTxt += input2;
    s = stream->Encrypt(offset, (char *)input2.c_str(), input2.length()); // does in place encryption
    ASSERT_TRUE(s.ok()) << s.ToString();
    cipherTxt += input2;
    offset += input2.length();

    std::string input3;
    input3.assign("3 input for encryption  helloo0 ");
    plainTxt += input3;
    s = stream->Encrypt(offset, (char *)input3.c_str(), input3.length()); // does in place encryption
    ASSERT_TRUE(s.ok()) << s.ToString();
    cipherTxt += input3;
    // decrypt the all the input string in one go.
    s = stream->Decrypt(prefixLen, (char *)cipherTxt.c_str(), cipherTxt.length());

    ASSERT_EQ(plainTxt, cipherTxt) << " both are strings are same after decryption!!";
    free(buf);
  }

  TEST(IppcpEncryptionTests, EncryptDecryptWithDifferentKeys)
  {
    std::string IPPCP = IppcpProvider::kName();
    std::shared_ptr<EncryptionProvider> provider;
    Status s = EncryptionProvider::CreateFromString(ConfigOptions(), IPPCP, &provider);
    ASSERT_TRUE(s.ok());
    ASSERT_NE(provider, nullptr);

    std::string cipher_key;
    cipher_key.assign("a6d2ae2816157e2b3c4fcf098815f7x2");
    s = provider->AddCipher("", cipher_key.c_str(), cipher_key.length(), false);
    ASSERT_TRUE(s.ok()) << s.ToString();

    size_t prefixLen = provider->GetPrefixLength();
    ASSERT_GT(prefixLen, 0);
    char *buf = (char *)malloc(prefixLen);
    ASSERT_NE(buf, nullptr);
    std::unique_ptr<BlockAccessCipherStream> stream;
    const EnvOptions options;
    s = provider->CreateNewPrefix("", buf, prefixLen);
    ASSERT_TRUE(s.ok()) << s.ToString();
    Slice prefix(buf, prefixLen);
    s = provider->CreateCipherStream("", options, prefix, &stream);
    ASSERT_TRUE(s.ok()) << s.ToString();

    std::string input, plainTxt, cipherTxt;
    uint64_t offset = prefixLen;

    input.assign("test ippcp crypto");
    plainTxt = input;

    s = stream->Encrypt(offset, (char *)input.c_str(), input.length()); // does in place encryption
    ASSERT_TRUE(s.ok()) << s.ToString();
    cipherTxt = input; // encrypted txt

    provider.reset();
    s = EncryptionProvider::CreateFromString(ConfigOptions(), IPPCP, &provider);
    ASSERT_TRUE(s.ok()) << s.ToString();
    ;
    ASSERT_NE(provider, nullptr);

    // change the key
    cipher_key.assign("a6d2ae2816157e2b");
    s = provider->AddCipher("", cipher_key.c_str(), cipher_key.length(), false);
    ASSERT_TRUE(s.ok()) << s.ToString();
    s = stream->Decrypt(offset, (char *)cipherTxt.c_str(), input.length());
    ASSERT_TRUE(s.ok()) << s.ToString();
    ASSERT_NE(plainTxt, cipherTxt) << " both are strings are same after decryption!!";
    free(buf);
  }

  struct TestParam
  {
    TestParam(std::string _cipher_desc, std::string _cipher_key, std::string _plainTxt = "") : cipher_desc(_cipher_desc), cipher_key(_cipher_key), plainTxt(_plainTxt) {}

    std::string cipher_desc;
    std::string cipher_key;
    std::string plainTxt;
    std::string GetOpts()
    {
      return "cipher_desc = " + cipher_desc + ";  cipher_key = " + cipher_key + ";  cipher_size = " + std::to_string(cipher_key.length()) + ";  plaintxt = " + plainTxt;
    }
  };

  class IppcpProviderTest : public testing::TestWithParam<std::tuple<std::string, std::string, std::string>>
  {
  public:
    static void SetUpTestSuite()
    {
      ObjectLibrary::Default()->AddFactory<EncryptionProvider>(
          IppcpProvider::kName(),
          [](const std::string & /* uri */, std::unique_ptr<EncryptionProvider> *f,
             std::string * /* errmsg */)
          {
            *f = IppcpProvider::CreateProvider();
            return f->get();
          });
    }
    void SetUp() override
    {
      TestParam test_param(std::get<0>(GetParam()), std::get<1>(GetParam()), std::get<2>(GetParam()));
      ConfigOptions config_options;
      Status s = EncryptionProvider::CreateFromString(config_options, IppcpProvider::kName(), &provider);
    }
    std::shared_ptr<EncryptionProvider> provider;
    const EnvOptions soptions_;
  };

  TEST_P(IppcpProviderTest, EncryptDecrypt)
  {
    TestParam test_param(std::get<0>(GetParam()), std::get<1>(GetParam()), std::get<2>(GetParam()));
    Status s = provider->AddCipher(test_param.cipher_desc, (char *)test_param.cipher_key.c_str(), test_param.cipher_key.length(), false);
    ASSERT_TRUE(s.ok()) << s.ToString();

    size_t prefixLen = 16; // minimum size of prefix is 16(blockSize)
    uint8_t ctr[] = {0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    Slice prefix((char *)ctr, prefixLen);

    std::unique_ptr<BlockAccessCipherStream> stream;
    s = provider->CreateCipherStream("", soptions_, prefix, &stream);
    ASSERT_TRUE(s.ok()) << s.ToString();

    std::string input = test_param.plainTxt;
    s = stream->Encrypt(0, (char *)input.c_str(), input.length());
    ASSERT_TRUE(s.ok()) << s.ToString();
    s = stream->Decrypt(0, (char *)input.c_str(), input.length());
    ASSERT_TRUE(s.ok()) << s.ToString();
    ASSERT_TRUE(test_param.plainTxt == input) << " both are strings are same after decryption!!";
  }

  // working but uses cartesian product
  INSTANTIATE_TEST_SUITE_P(IppcpProviderTestInstance,
                           IppcpProviderTest,
                           testing::Combine(testing::Values("ippcp_test_aes"),                                                                                                                                                                                            // key description
                                            testing::Values("a6d2ae2816157e2b3c4fcf098815f7xb", "a6d2ae2816157e2334512345", "a6d2ae2816157e23"),                                                                                                                          // encryption key                                                                                                                                                                                                     // offset for encryption and decryption
                                            testing::Values("Hello world", "Helloooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo        worldddddddddddddddddddddddddddddddd 111111111111111111111111111111111111111111111111111111111111111"))); // plain text to encrypt

} // end of namespace

int main(int argc, char *argv[])
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
