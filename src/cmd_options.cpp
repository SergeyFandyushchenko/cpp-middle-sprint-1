#include "cmd_options.h"

#include <boost/program_options/parsers.hpp>

#include <cstdlib>
#include <iostream>

namespace po = boost::program_options;

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    // clang-format off
    desc_.add_options()
        ("help,h", "Show list of available options")
        ("command,c", po::value<std::string>(), "Command: encrypt, decrypt or checksum")
        ("input,i", po::value<std::string>(), "Path to input file")
        ("output,o", po::value<std::string>(), "Path to output file for saving result")
        ("password,p", po::value<std::string>(), "Password for encryption/decryption");
    // clang-format on
}

ProgramOptions::STATUS_PARSE ProgramOptions::Parse(int argc, char *argv[]) {
    try {
        po::variables_map vm;

        po::store(po::parse_command_line(argc, argv, desc_), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc_ << std::endl;
            return STATUS_PARSE::SUCCESS_EXIT;
        }

        if (!vm.count("command")) {
            throw std::runtime_error("Error: command not specified. Use --help for help.");
        }

        // Map string command to enum
        std::string commandStr = vm["command"].as<std::string>();
        auto it = commandMapping_.find(commandStr);
        if (it == commandMapping_.end()) {
            throw std::runtime_error("Error: unknown command '" + commandStr +
                                     "'. Available commands: encrypt, decrypt, checksum");
        }

        command_ = it->second;

        // Check required options depending on command
        if (!vm.count("input")) {
            throw std::runtime_error("Error: input file not specified (--input)");
        }
        inputFile_ = vm["input"].as<std::string>();

        // For encrypt and decrypt, output and password are required
        if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
            if (!vm.count("output")) {
                throw std::runtime_error(
                    "Error: for encrypt/decrypt commands, output file must be specified (--output)");
            }
            outputFile_ = vm["output"].as<std::string>();

            if (!vm.count("password")) {
                throw std::runtime_error(
                    "Error: for encrypt/decrypt commands, password must be specified (--password)");
            }
            password_ = vm["password"].as<std::string>();

            // Additional check: input and output files must not be the same
            if (inputFile_ == outputFile_) {
                throw std::runtime_error("Error: input and output files cannot be the same");
            }
        }

        // For checksum, only input is required
        if (command_ == COMMAND_TYPE::CHECKSUM) {
            // output and password are optional for checksum
            if (vm.count("output")) {
                outputFile_ = vm["output"].as<std::string>();
            }
            if (vm.count("password")) {
                // Warning, but not an error
                std::cout << "Warning: --password option is ignored for checksum command" << std::endl;
            }
        }

    } catch (const po::error &e) {
        std::cerr << "Command line parsing error: " << e.what() << std::endl;
        std::cerr << "Use --help for help" << std::endl;
        return STATUS_PARSE::FAILURE_EXIT;
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::cerr << "Use --help for help" << std::endl;
        return STATUS_PARSE::FAILURE_EXIT;
    }

    return STATUS_PARSE::SUCCESS;
}

}  // namespace CryptoGuard