#include "cmd_options.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace CryptoGuard;

// To test successful scenarios
ProgramOptions ExpectParseSuccess(const char *argv[], size_t argc) {
    ProgramOptions options;
    auto status = options.Parse(static_cast<int>(argc), const_cast<char **>(argv));
    EXPECT_EQ(status, ProgramOptions::STATUS_PARSE::SUCCESS);
    return options;
}

template <size_t N>
ProgramOptions ExpectParseSuccess(const char *(&argv)[N]) {
    return ExpectParseSuccess(argv, N);
}

// For testing erroneous scenarios
void ExpectParseFailure(const char *argv[], size_t argc, const std::string &expectedErrorSubstring) {
    ProgramOptions options;
    testing::internal::CaptureStderr();
    auto status = options.Parse(static_cast<int>(argc), const_cast<char **>(argv));
    std::string stderr_output = testing::internal::GetCapturedStderr();

    EXPECT_EQ(status, ProgramOptions::STATUS_PARSE::FAILURE_EXIT);
    EXPECT_THAT(stderr_output, ::testing::HasSubstr(expectedErrorSubstring));
}

template <size_t N>
void ExpectParseFailure(const char *(&argv)[N], const std::string &expectedErrorSubstring) {
    ExpectParseFailure(argv, N, expectedErrorSubstring);
}

// Test 1: Verify correct parsing of encrypt command with all parameters
TEST(ProgramOptions, ValidEncryptCommand) {
    const char *argv[] = {"program",  "--command",     "encrypt",    "--input",  "test.txt",
                          "--output", "encrypted.bin", "--password", "secret123"};
    auto options = ExpectParseSuccess(argv);
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "test.txt");
    EXPECT_EQ(options.GetOutputFile(), "encrypted.bin");
    EXPECT_EQ(options.GetPassword(), "secret123");
}

// Test 2: Verify correct parsing of decrypt command
TEST(ProgramOptions, ValidDecryptCommand) {
    const char *argv[] = {"program",  "--command",     "decrypt",    "--input",  "encrypted.bin",
                          "--output", "decrypted.txt", "--password", "secret123"};
    auto options = ExpectParseSuccess(argv);
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), "encrypted.bin");
    EXPECT_EQ(options.GetOutputFile(), "decrypted.txt");
    EXPECT_EQ(options.GetPassword(), "secret123");
}

// Test 3: Verify checksum command (does not require output and password)
TEST(ProgramOptions, ValidChecksumCommand) {
    const char *argv[] = {"program", "--command", "checksum", "--input", "file.txt"};
    auto options = ExpectParseSuccess(argv);
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "file.txt");
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

// Test 4: Verify handling of unknown command
TEST(ProgramOptions, UnknownCommand) {
    const char *argv[] = {"program", "--command", "unknown", "--input", "test.txt"};
    ExpectParseFailure(argv, "unknown command");
}

// Test 5: Verify missing required command
TEST(ProgramOptions, MissingCommand) {
    const char *argv[] = {"program", "--input", "test.txt", "--output", "out.bin"};
    ExpectParseFailure(argv, "command not specified");
}

// Test 6: Verify missing input file
TEST(ProgramOptions, MissingInputFile) {
    const char *argv[] = {"program", "--command", "encrypt", "--output", "out.bin", "--password", "pass"};
    ExpectParseFailure(argv, "input file not specified");
}

// Test 7: Verify handling of short options
TEST(ProgramOptions, ShortOptions) {
    const char *argv[] = {"program", "-c", "encrypt", "-i", "input.txt", "-o", "output.bin", "-p", "mypass"};
    auto options = ExpectParseSuccess(argv);
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.bin");
    EXPECT_EQ(options.GetPassword(), "mypass");
}

// Test 8: Verify missing password for encrypt
TEST(ProgramOptions, MissingPasswordForEncrypt) {
    const char *argv[] = {"program", "--command", "encrypt", "--input", "test.txt", "--output", "out.bin"};
    ExpectParseFailure(argv, "password must be specified");
}

// Test 9: Verify missing output for encrypt
TEST(ProgramOptions, MissingOutputForEncrypt) {
    const char *argv[] = {"program", "--command", "encrypt", "--input", "test.txt", "--password", "pass"};
    ExpectParseFailure(argv, "output file must be specified");
}

// Test 10: Verify input and output files are the same
TEST(ProgramOptions, SameInputAndOutputFiles) {
    const char *argv[] = {"program",  "--command", "encrypt",    "--input", "same.txt",
                          "--output", "same.txt",  "--password", "pass"};
    ExpectParseFailure(argv, "cannot be the same");
}

// Test 11: Verify help command
TEST(ProgramOptions, HelpCommand) {
    ProgramOptions options;
    const char *argv[] = {"program", "--help"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    testing::internal::CaptureStdout();
    auto status = options.Parse(argc, const_cast<char **>(argv));
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_EQ(status, ProgramOptions::STATUS_PARSE::SUCCESS_EXIT);
    EXPECT_THAT(output, ::testing::HasSubstr("Allowed options"));
    EXPECT_THAT(output, ::testing::HasSubstr("--help"));
    EXPECT_THAT(output, ::testing::HasSubstr("--command"));
    EXPECT_THAT(output, ::testing::HasSubstr("--input"));
    EXPECT_THAT(output, ::testing::HasSubstr("--output"));
    EXPECT_THAT(output, ::testing::HasSubstr("--password"));
}

// Test 12: Verify case sensitivity of commands
TEST(ProgramOptions, CaseSensitiveCommands) {
    const char *argv[] = {"program", "--command", "ENCRYPT", "--input", "test.txt"};
    ExpectParseFailure(argv, "unknown command");
}