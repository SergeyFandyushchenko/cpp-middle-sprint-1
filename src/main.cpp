#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <openssl/evp.h>

#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>

#include <filesystem>

int main(int argc, char *argv[]) {
    {
        // Debug: print current working directory
        std::cout << "Current working directory: " << std::filesystem::current_path() << std::endl;

        // Debug: check if file exists
        std::string inputFile = "input.txt";  // or whatever path
        if (std::filesystem::exists(inputFile)) {
            std::cout << "File exists: " << inputFile << std::endl;
        } else {
            std::cout << "File does NOT exist: " << inputFile << std::endl;
        }
    }

    try {
        CryptoGuard::ProgramOptions options;
        if (auto status = options.Parse(argc, argv);
            status == CryptoGuard::ProgramOptions::STATUS_PARSE::SUCCESS_EXIT) {
            exit(EXIT_SUCCESS);
        } else if (status == CryptoGuard::ProgramOptions::STATUS_PARSE::FAILURE_EXIT) {
            exit(EXIT_FAILURE);
        }

        auto command = options.GetCommand();
        auto inputFile = options.GetInputFile();
        auto outputFile = options.GetOutputFile();
        auto password = options.GetPassword();

        std::print("Command: {}\n", command == CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT   ? "encrypt"
                                    : command == CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT ? "decrypt"
                                                                                                    : "checksum");
        std::print("Input file: {}\n", inputFile);

        if (!outputFile.empty()) {
            std::print("Output file: {}\n", outputFile);
        }

        if (!password.empty()) {
            std::print("Password: {} (length: {})\n", std::string(password.size(), '*'), password.size());
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

        switch (command) {
        case COMMAND_TYPE::ENCRYPT: {
            std::print("\nStarting encryption process...\n");

            std::fstream inFile(inputFile, std::ios::in | std::ios::binary);
            if (!inFile.is_open()) {
                throw std::runtime_error("Cannot open input file: " + inputFile);
            }

            std::fstream outFile(outputFile, std::ios::out | std::ios::binary);
            if (!outFile.is_open()) {
                throw std::runtime_error("Cannot create output file: " + outputFile);
            }

            cryptoCtx.EncryptFile(inFile, outFile, password);

            std::print("File '{}' encrypted successfully to '{}'\n", inputFile, outputFile);
            break;
        }

        case COMMAND_TYPE::DECRYPT: {
            std::print("\nStarting decryption process...\n");

            std::fstream inFile(inputFile, std::ios::in | std::ios::binary);
            if (!inFile.is_open()) {
                throw std::runtime_error("Cannot open input file: " + inputFile);
            }

            std::fstream outFile(outputFile, std::ios::out | std::ios::binary);
            if (!outFile.is_open()) {
                throw std::runtime_error("Cannot create output file: " + outputFile);
            }

            cryptoCtx.DecryptFile(inFile, outFile, password);

            std::print("File '{}' decrypted successfully to '{}'\n", inputFile, outputFile);
            break;
        }

        case COMMAND_TYPE::CHECKSUM: {
            std::print("\nCalculating checksum...\n");

            std::fstream inFile(inputFile, std::ios::in | std::ios::binary);
            if (!inFile.is_open()) {
                throw std::runtime_error("Cannot open input file: " + inputFile);
            }

            std::string checksum = cryptoCtx.CalculateChecksum(inFile);
            std::print("Checksum (SHA-256): {}\n", checksum);
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }
    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}
