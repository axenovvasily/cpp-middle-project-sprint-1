#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>

#include <sstream>
#include <stdexcept>
#include <string>

TEST(CryptoGuardCtx, EncryptProducesCiphertext) {
    CryptoGuard::CryptoGuardCtx ctx;
    const std::string plain = "Hello OpenSSL crypto world!";
    std::stringstream in(plain);
    std::stringstream out;

    ctx.EncryptFile(in, out, "1234");

    const auto cipher = out.str();
    EXPECT_FALSE(cipher.empty());
    EXPECT_NE(cipher, plain);
    EXPECT_EQ(cipher.size() % 16, 0);
}

TEST(CryptoGuardCtx, EncryptIsDeterministicForSamePassword) {
    CryptoGuard::CryptoGuardCtx ctx;
    constexpr std::string_view password = "secret";
    const std::string plain = "The same message";

    std::stringstream in1(plain);
    std::stringstream out1;
    ctx.EncryptFile(in1, out1, password);

    std::stringstream in2(plain);
    std::stringstream out2;
    ctx.EncryptFile(in2, out2, password);

    EXPECT_EQ(out1.str(), out2.str());
}

TEST(CryptoGuardCtx, EncryptThrowsOnBadInputStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in("data");
    in.setstate(std::ios::badbit);
    std::stringstream out;

    ASSERT_THROW(ctx.EncryptFile(in, out, "secret"), std::runtime_error);
}

TEST(CryptoGuardCtx, EncryptThrowsOnBadOutputStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in("data");
    std::stringstream out;
    out.setstate(std::ios::badbit);

    ASSERT_THROW(ctx.EncryptFile(in, out, "secret"), std::runtime_error);
}
