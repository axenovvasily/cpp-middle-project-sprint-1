#include "crypto_guard_ctx.h"

#include <memory>

namespace CryptoGuard {

class CryptoGuardCtx::PImpl {};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<PImpl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;

CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::iostream &, std::iostream &, std::string_view) {}

void CryptoGuardCtx::DecryptFile(std::iostream &, std::iostream &, std::string_view) {}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &) { return {}; }

}  // namespace CryptoGuard
