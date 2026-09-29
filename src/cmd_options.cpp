#include "cmd_options.h"

#include <iostream>
#include <stdexcept>
#include <string_view>

namespace CryptoGuard {

namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help,h", "list of available options")("command", po::value<std::string>()->required(),
                                                               "command: encrypt, decrypt or checksum")(
        "input,i", po::value<std::string>(&inputFile_)->required(), "path to the input file")(
        "output,o", po::value<std::string>(&outputFile_), "path to the file where the result will be saved")(
        "password,p", po::value<std::string>(&password_), "password for encryption and decryption");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);

    if (vm.contains("help")) {
        std::cout << desc_ << '\n';
        helpRequested_ = true;
        return;
    }

    po::notify(vm);

    const auto command = vm["command"].as<std::string>();
    const auto it = commandMapping_.find(std::string_view{command});
    if (it == commandMapping_.end()) {
        throw std::runtime_error{"Unsupported command"};
    }
    command_ = it->second;

    if (command_ == COMMAND_TYPE::CHECKSUM) {
        return;
    }

    if (outputFile_.empty()) {
        throw std::runtime_error{"Output file is required for encrypt and decrypt"};
    }
    if (password_.empty()) {
        throw std::runtime_error{"Password is required for encrypt and decrypt"};
    }
}

}  // namespace CryptoGuard
