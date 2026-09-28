#include "crypto_guard_ctx.h"

#include <openssl/evp.h>

#include <array>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>

namespace CryptoGuard {

namespace {

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX *ctx) const noexcept { EVP_CIPHER_CTX_free(ctx); }
};

using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

}  // namespace

class CryptoGuardCtx::PImpl {
public:
    PImpl();
    ~PImpl();

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);

private:
    AesCipherParams CreateChiperParamsFromPassword(std::string_view password);
};

CryptoGuardCtx::PImpl::PImpl() { OpenSSL_add_all_algorithms(); }

CryptoGuardCtx::PImpl::~PImpl() { EVP_cleanup(); }

void CryptoGuardCtx::PImpl::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    if (!inStream) {
        throw std::runtime_error{"Input stream is in a bad state"};
    }
    if (!outStream) {
        throw std::runtime_error{"Output stream is in a bad state"};
    }

    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = 1;

    EvpCipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
    if (!ctx) {
        throw std::runtime_error{"Failed to create cipher context"};
    }

    if (EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt) !=
        1) {
        throw std::runtime_error{"Failed to initialize cipher"};
    }

    constexpr std::size_t kBufferSize = 1024;
    std::vector<unsigned char> inBuf(kBufferSize);
    std::vector<unsigned char> outBuf(kBufferSize + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;

    for (;;) {
        inStream.read(reinterpret_cast<char *>(inBuf.data()), static_cast<std::streamsize>(inBuf.size()));
        if (inStream.bad()) {
            throw std::runtime_error{"Failed to read input stream"};
        }

        const auto inLen = static_cast<int>(inStream.gcount());
        if (inLen <= 0) {
            break;
        }

        if (EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inLen) != 1) {
            throw std::runtime_error{"Failed to encrypt data"};
        }

        outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
        if (!outStream) {
            throw std::runtime_error{"Failed to write output stream"};
        }
    }

    if (EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen) != 1) {
        throw std::runtime_error{"Failed to finalize encryption"};
    }

    outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
    if (!outStream) {
        throw std::runtime_error{"Failed to write output stream"};
    }
}

void CryptoGuardCtx::PImpl::DecryptFile(std::iostream &, std::iostream &, std::string_view) {}

std::string CryptoGuardCtx::PImpl::CalculateChecksum(std::iostream &) { return {}; }

AesCipherParams CryptoGuardCtx::PImpl::CreateChiperParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
}

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<PImpl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;

CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
