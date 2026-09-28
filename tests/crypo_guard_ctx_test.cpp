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

TEST(CryptoGuardCtx, DecryptRestoresPlaintext) {
    CryptoGuard::CryptoGuardCtx ctx;
    constexpr std::string_view password = "1234";
    const std::string plain(1500, 'A');

    std::stringstream in(plain);
    std::stringstream encrypted;
    ctx.EncryptFile(in, encrypted, password);

    std::stringstream cipherIn(encrypted.str());
    std::stringstream out;
    ctx.DecryptFile(cipherIn, out, password);

    EXPECT_EQ(out.str(), plain);
}

TEST(CryptoGuardCtx, DecryptThrowsOnWrongPassword) {
    CryptoGuard::CryptoGuardCtx ctx;
    const std::string plain = "secret message";

    std::stringstream in(plain);
    std::stringstream encrypted;
    ctx.EncryptFile(in, encrypted, "right-password");

    std::stringstream cipherIn(encrypted.str());
    std::stringstream out;
    ASSERT_THROW(ctx.DecryptFile(cipherIn, out, "wrong-password"), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptThrowsOnBadInputStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in("data");
    in.setstate(std::ios::badbit);
    std::stringstream out;

    ASSERT_THROW(ctx.DecryptFile(in, out, "secret"), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptThrowsOnBadOutputStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in("data");
    std::stringstream out;
    out.setstate(std::ios::badbit);

    ASSERT_THROW(ctx.DecryptFile(in, out, "secret"), std::runtime_error);
}

TEST(CryptoGuardCtx, ChecksumMatchesSha256) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in("abc");

    EXPECT_EQ(ctx.CalculateChecksum(in), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(CryptoGuardCtx, ChecksumDiffersForDifferentInput) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream first("alpha");
    std::stringstream second("beta");

    EXPECT_NE(ctx.CalculateChecksum(first), ctx.CalculateChecksum(second));
}

TEST(CryptoGuardCtx, ChecksumThrowsOnBadInputStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream in("data");
    in.setstate(std::ios::badbit);

    ASSERT_THROW(ctx.CalculateChecksum(in), std::runtime_error);
}
