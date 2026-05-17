#include <crypto_guard_ctx.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <array>
#include <iomanip>
#include <iostream>
#include <vector>

namespace CryptoGuard {

namespace {

constexpr size_t KEY_SIZE = 32;  // AES-256 key size
constexpr size_t IV_SIZE = 16;   // AES block size (IV length)
constexpr size_t BUFFER_SIZE = 4096;
constexpr std::array<unsigned char, 8> SALT = {'1', '2', '3', '4', '5', '6', '7', '8'};

struct AesCipherParams {
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX *ctx) const {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
};

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX *ctx) const {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    }
};

using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

std::string GetOpenSSLError() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

void ThrowOpenSSLError(const std::string &context) { throw std::runtime_error(context + ": " + GetOpenSSLError()); }

struct Action {
    enum class Mode { ENCRYPT, DECRYPT };
    Mode mode_;
    int GetParam() const { return mode_ == Mode::DECRYPT ? 0 : 1; }
    std::string_view ModeName() const { return mode_ == Mode::DECRYPT ? "decrypt" : "encrypt"; }
};

}  // namespace

class CryptoGuardCtx::Impl {
public:
    Impl() { OpenSSL_add_all_algorithms(); }
    ~Impl() { EVP_cleanup(); }

    void ProcessStream(std::iostream &inStream, std::iostream &outStream, std::string_view password,
                       Action action) const;
    std::string CalculateChecksum(std::iostream &inStream) const;
    AesCipherParams CreateCipherParamsFromPassword(std::string_view password) const;
};

void CryptoGuardCtx::Impl::ProcessStream(std::iostream &inStream, std::iostream &outStream, std::string_view password,
                                         Action action) const {
    if (!inStream.good()) {
        throw std::runtime_error("Input stream is not in a good state");
    }
    if (!outStream.good()) {
        throw std::runtime_error("Output stream is not in a good state");
    }
    if (password.empty()) {
        throw std::runtime_error("Password cannot be empty");
    }

    auto params = CreateCipherParamsFromPassword(password);

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        ThrowOpenSSLError("Failed to create cipher context");
    }

    if (EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), action.GetParam()) !=
        1) {
        ThrowOpenSSLError("EVP_CipherInit_ex failed");
    }

    std::vector<unsigned char> inBuffer(BUFFER_SIZE);
    std::vector<unsigned char> outBuffer(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;

    inStream.seekg(0, std::ios::beg);

    while (inStream.good() && !inStream.eof()) {
        inStream.read(reinterpret_cast<char *>(inBuffer.data()), BUFFER_SIZE);
        std::streamsize bytesRead = inStream.gcount();
        if (bytesRead > 0) {
            if (EVP_CipherUpdate(ctx.get(), outBuffer.data(), &outLen, inBuffer.data(), static_cast<int>(bytesRead)) !=
                1) {
                ThrowOpenSSLError("EVP_CipherUpdate failed");
            }

            if (outLen > 0) {
                outStream.write(reinterpret_cast<char *>(outBuffer.data()), outLen);
                if (!outStream.good()) {
                    throw std::runtime_error("Failed to write to output stream");
                }
            }
        }
    }

    if (EVP_CipherFinal_ex(ctx.get(), outBuffer.data(), &outLen) != 1) {
        ThrowOpenSSLError("EVP_CipherFinal_ex failed");
    }

    if (outLen > 0) {
        outStream.write(reinterpret_cast<char *>(outBuffer.data()), outLen);
        if (!outStream.good()) {
            throw std::runtime_error("Failed to write final block to output stream");
        }
    }

    outStream.flush();
}

AesCipherParams CryptoGuardCtx::Impl::CreateCipherParamsFromPassword(std::string_view password) const {
    AesCipherParams params;
    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), SALT.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());
    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream) const {
    if (!inStream.good()) {
        throw std::runtime_error("Input stream is not in a good state for checksum calculation");
    }

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) {
        ThrowOpenSSLError("Failed to create MD context");
    }

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        ThrowOpenSSLError("EVP_DigestInit_ex failed");
    }

    std::vector<unsigned char> buffer(BUFFER_SIZE);
    inStream.seekg(0, std::ios::beg);

    while (inStream.good() && !inStream.eof()) {
        inStream.read(reinterpret_cast<char *>(buffer.data()), BUFFER_SIZE);
        std::streamsize bytesRead = inStream.gcount();
        if (bytesRead > 0) {
            if (EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<size_t>(bytesRead)) != 1) {
                ThrowOpenSSLError("EVP_DigestUpdate failed");
            }
        }
    }

    std::array<unsigned char, SHA256_DIGEST_LENGTH> hash{};
    unsigned int hashLen = 0;

    if (EVP_DigestFinal_ex(ctx.get(), hash.data(), &hashLen) != 1) {
        ThrowOpenSSLError("EVP_DigestFinal_ex failed");
    }

    std::stringstream result;
    result << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hashLen; ++i) {
        result << std::setw(2) << static_cast<int>(hash[i]);
    }

    return result.str();
}

CryptoGuardCtx::CryptoGuardCtx() : pImpl{std::make_unique<Impl>()} {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl->ProcessStream(inStream, outStream, password, Action{Action::Mode::ENCRYPT});
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl->ProcessStream(inStream, outStream, password, Action{Action::Mode::DECRYPT});
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
