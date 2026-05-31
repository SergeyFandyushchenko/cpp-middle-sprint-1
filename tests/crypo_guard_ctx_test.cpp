#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>

#include <sstream>
#include <string>

using namespace CryptoGuard;

class CryptoGuardCtxTest : public ::testing::Test {
protected:
    void SetUp() override { ctx_ = std::make_unique<CryptoGuardCtx>(); }

    void TearDown() override { ctx_.reset(); }

    std::unique_ptr<CryptoGuardCtx> ctx_;
};

TEST_F(CryptoGuardCtxTest, EncryptDecryptSimpleString) {
    std::string originalData = "Hello, World! This is a test message for encryption.";
    std::string password = "test_password_123";

    std::stringstream inputStream(originalData);
    std::stringstream encryptedStream;
    std::stringstream decryptedStream;

    ASSERT_NO_THROW(ctx_->EncryptFile(inputStream, encryptedStream, password));
    ASSERT_NE(encryptedStream.str(), originalData);

    encryptedStream.clear();
    encryptedStream.seekg(0, std::ios::beg);

    ASSERT_NO_THROW(ctx_->DecryptFile(encryptedStream, decryptedStream, password));

    ASSERT_EQ(decryptedStream.str(), originalData);
}

TEST_F(CryptoGuardCtxTest, EncryptDecryptEmptyData) {
    std::string originalData;
    std::string password = "test_password";

    std::stringstream inputStream(originalData);
    std::stringstream encryptedStream;
    std::stringstream decryptedStream;

    ASSERT_NO_THROW(ctx_->EncryptFile(inputStream, encryptedStream, password));

    encryptedStream.clear();
    encryptedStream.seekg(0, std::ios::beg);

    ASSERT_NO_THROW(ctx_->DecryptFile(encryptedStream, decryptedStream, password));

    ASSERT_EQ(decryptedStream.str(), originalData);
}

TEST_F(CryptoGuardCtxTest, EncryptWithWrongPasswordThrows) {
    std::string originalData = "Sensitive data";
    std::string password1 = "correct_password";
    std::string password2 = "wrong_password";

    std::stringstream inputStream(originalData);
    std::stringstream encryptedStream;
    std::stringstream decryptedStream;

    ASSERT_NO_THROW(ctx_->EncryptFile(inputStream, encryptedStream, password1));

    encryptedStream.clear();
    encryptedStream.seekg(0, std::ios::beg);

    ASSERT_THROW(ctx_->DecryptFile(encryptedStream, decryptedStream, password2), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, EncryptLargeData) {
    std::string originalData(10000, 'A');
    for (size_t i = 0; i < originalData.size(); ++i) {
        originalData[i] = static_cast<char>(i % 256);
    }
    std::string password = "strong_password";

    std::stringstream inputStream(originalData);
    std::stringstream encryptedStream;
    std::stringstream decryptedStream;

    ASSERT_NO_THROW(ctx_->EncryptFile(inputStream, encryptedStream, password));

    encryptedStream.clear();
    encryptedStream.seekg(0, std::ios::beg);

    ASSERT_NO_THROW(ctx_->DecryptFile(encryptedStream, decryptedStream, password));

    ASSERT_EQ(decryptedStream.str(), originalData);
}

TEST_F(CryptoGuardCtxTest, DecryptWithEmptyPasswordThrows) {
    std::stringstream emptyStream;
    std::stringstream outputStream;

    ASSERT_THROW(ctx_->DecryptFile(emptyStream, outputStream, ""), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, EncryptWithEmptyPasswordThrows) {
    std::stringstream inputStream("data");
    std::stringstream outputStream;

    ASSERT_THROW(ctx_->EncryptFile(inputStream, outputStream, ""), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, ChecksumCalculation) {
    std::string testData = "Hello, World!";
    std::stringstream inputStream(testData);

    std::string checksum = ctx_->CalculateChecksum(inputStream);

    ASSERT_FALSE(checksum.empty());
    ASSERT_EQ(checksum.length(), 64);  // SHA-256 produces 64 hex characters
}

TEST_F(CryptoGuardCtxTest, ChecksumEmptyData) {
    std::stringstream inputStream("");

    std::string checksum = ctx_->CalculateChecksum(inputStream);

    ASSERT_FALSE(checksum.empty());
    ASSERT_EQ(checksum.length(), 64);

    std::string expectedEmptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    ASSERT_EQ(checksum, expectedEmptyHash);
}

TEST_F(CryptoGuardCtxTest, ChecksumConsistency) {
    std::string testData = "Consistent data for testing";
    std::stringstream inputStream1(testData);
    std::stringstream inputStream2(testData);

    std::string checksum1 = ctx_->CalculateChecksum(inputStream1);
    std::string checksum2 = ctx_->CalculateChecksum(inputStream2);

    ASSERT_EQ(checksum1, checksum2);
}

TEST_F(CryptoGuardCtxTest, ChecksumAfterEncryptDecrypt) {
    std::string originalData = "Data for checksum verification";
    std::string password = "checksum_test_password";

    std::stringstream originalStream(originalData);
    std::stringstream encryptedStream;
    std::stringstream decryptedStream;

    std::string originalChecksum = ctx_->CalculateChecksum(originalStream);

    originalStream.clear();
    originalStream.seekg(0, std::ios::beg);

    ctx_->EncryptFile(originalStream, encryptedStream, password);

    encryptedStream.clear();
    encryptedStream.seekg(0, std::ios::beg);

    ctx_->DecryptFile(encryptedStream, decryptedStream, password);

    std::string decryptedChecksum = ctx_->CalculateChecksum(decryptedStream);

    ASSERT_EQ(originalChecksum, decryptedChecksum);
}

TEST_F(CryptoGuardCtxTest, ChecksumBadStreamThrows) {
    std::stringstream badStream;
    badStream.setstate(std::ios::badbit);

    ASSERT_THROW(ctx_->CalculateChecksum(badStream), std::runtime_error);
}