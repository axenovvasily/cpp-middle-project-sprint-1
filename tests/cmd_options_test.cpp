#include "cmd_options.h"

#include <gtest/gtest.h>

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void ParseInto(CryptoGuard::ProgramOptions &options, std::vector<std::string> args) {
    args.insert(args.begin(), "CryptoGuard");
    std::vector<char *> argv;
    argv.reserve(args.size());
    for (auto &arg : args) {
        argv.push_back(arg.data());
    }
    options.Parse(static_cast<int>(argv.size()), argv.data());
}

class CoutCapture {
public:
    CoutCapture() : previous_(std::cout.rdbuf(buffer_.rdbuf())) {}
    ~CoutCapture() { std::cout.rdbuf(previous_); }

    std::string Str() const { return buffer_.str(); }

private:
    std::ostringstream buffer_;
    std::streambuf *previous_;
};

using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

}  // namespace

TEST(ProgramOptions, ParsesEncryptWithShortOptions) {
    CryptoGuard::ProgramOptions options;
    ParseInto(options, {"--command", "encrypt", "-i", "plain.txt", "-o", "cipher.txt", "-p", "secret"});

    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "plain.txt");
    EXPECT_EQ(options.GetOutputFile(), "cipher.txt");
    EXPECT_EQ(options.GetPassword(), "secret");
    EXPECT_FALSE(options.IsHelpRequested());
}

TEST(ProgramOptions, ParsesDecryptWithLongOptions) {
    CryptoGuard::ProgramOptions options;
    ParseInto(options,
              {"--command", "decrypt", "--input", "cipher.txt", "--output", "plain.txt", "--password", "secret"});

    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), "cipher.txt");
    EXPECT_EQ(options.GetOutputFile(), "plain.txt");
    EXPECT_EQ(options.GetPassword(), "secret");
}

TEST(ProgramOptions, ParsesChecksumWithoutOutputAndPassword) {
    CryptoGuard::ProgramOptions options;
    ParseInto(options, {"--command", "checksum", "--input", "plain.txt"});

    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "plain.txt");
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptions, HelpPrintsAvailableOptions) {
    CoutCapture capture;
    CryptoGuard::ProgramOptions options;
    ParseInto(options, {"--help"});

    EXPECT_TRUE(options.IsHelpRequested());
    EXPECT_NE(capture.Str().find("Allowed options"), std::string::npos);
    EXPECT_NE(capture.Str().find("encrypt"), std::string::npos);
}

TEST(ProgramOptions, ShortHelpSetsHelpRequested) {
    CoutCapture capture;
    CryptoGuard::ProgramOptions options;
    ParseInto(options, {"-h"});

    EXPECT_TRUE(options.IsHelpRequested());
    EXPECT_FALSE(capture.Str().empty());
}

TEST(ProgramOptions, RejectsUnsupportedCommand) {
    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(ParseInto(options, {"--command", "compress", "-i", "plain.txt"}), std::runtime_error);
}

TEST(ProgramOptions, EncryptRequiresOutputFile) {
    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(ParseInto(options, {"--command", "encrypt", "-i", "plain.txt", "-p", "secret"}), std::runtime_error);
}

TEST(ProgramOptions, DecryptRequiresPassword) {
    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(ParseInto(options, {"--command", "decrypt", "-i", "cipher.txt", "-o", "plain.txt"}),
                 std::runtime_error);
}

TEST(ProgramOptions, RejectsMissingInput) {
    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(ParseInto(options, {"--command", "checksum"}), boost::program_options::required_option);
}

TEST(ProgramOptions, RejectsUnknownOption) {
    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(ParseInto(options, {"--command", "checksum", "-i", "plain.txt", "--extra"}),
                 boost::program_options::unknown_option);
}
