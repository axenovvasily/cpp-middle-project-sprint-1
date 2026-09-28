#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);
        if (options.IsHelpRequested()) {
            return 0;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::fstream input(options.GetInputFile(), std::ios::in | std::ios::binary);
            if (!input) {
                throw std::runtime_error{"Failed to open input file"};
            }

            std::fstream output(options.GetOutputFile(), std::ios::out | std::ios::binary | std::ios::trunc);
            if (!output) {
                throw std::runtime_error{"Failed to open output file"};
            }

            cryptoCtx.EncryptFile(input, output, options.GetPassword());

            output.clear();
            output.close();
            if (!output) {
                throw std::runtime_error{"Failed to close output file"};
            }
            input.clear();
            input.close();
            if (!input) {
                throw std::runtime_error{"Failed to close input file"};
            }

            std::print("File encoded successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT:
            std::print("File decoded successfully\n");
            break;

        case COMMAND_TYPE::CHECKSUM:
            std::print("Checksum: {}\n", "CHECKSUM_NOT_IMPLEMENTED");
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}
