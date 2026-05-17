#include "cmd_options.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace CryptoGuard;

// Test 1: Verify correct parsing of encrypt command with all parameters
TEST(ProgramOptions, ValidEncryptCommand) {
    ProgramOptions options;
    const char *argv[] = {"program",  "--command",     "encrypt",    "--input",  "test.txt",
                          "--output", "encrypted.bin", "--password", "secret123"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    EXPECT_NO_THROW(options.Parse(argc, const_cast<char **>(argv)));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "test.txt");
    EXPECT_EQ(options.GetOutputFile(), "encrypted.bin");
    EXPECT_EQ(options.GetPassword(), "secret123");
}

// Test 2: Verify correct parsing of decrypt command
TEST(ProgramOptions, ValidDecryptCommand) {
    ProgramOptions options;
    const char *argv[] = {"program",  "--command",     "decrypt",    "--input",  "encrypted.bin",
                          "--output", "decrypted.txt", "--password", "secret123"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    EXPECT_NO_THROW(options.Parse(argc, const_cast<char **>(argv)));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), "encrypted.bin");
    EXPECT_EQ(options.GetOutputFile(), "decrypted.txt");
    EXPECT_EQ(options.GetPassword(), "secret123");
}

// Test 3: Verify checksum command (does not require output and password)
TEST(ProgramOptions, ValidChecksumCommand) {
    ProgramOptions options;
    const char *argv[] = {"program", "--command", "checksum", "--input", "file.txt"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    EXPECT_NO_THROW(options.Parse(argc, const_cast<char **>(argv)));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "file.txt");
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

// Test 4: Verify handling of unknown command
TEST(ProgramOptions, UnknownCommand) {
    ProgramOptions options;
    const char *argv[] = {"program", "--command", "unknown", "--input", "test.txt"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    EXPECT_EXIT(options.Parse(argc, const_cast<char **>(argv)), ::testing::ExitedWithCode(EXIT_FAILURE),
                ".*unknown command.*");
}

// Test 5: Verify missing required command
TEST(ProgramOptions, MissingCommand) {
    ProgramOptions options;
    const char *argv[] = {"program", "--input", "test.txt", "--output", "out.bin"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    EXPECT_EXIT(options.Parse(argc, const_cast<char **>(argv)), ::testing::ExitedWithCode(EXIT_FAILURE),
                ".*command not specified.*");
}

// Test 6: Verify missing input file
TEST(ProgramOptions, MissingInputFile) {
    ProgramOptions options;
    const char *argv[] = {"program", "--command", "encrypt", "--output", "out.bin", "--password", "pass"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    EXPECT_EXIT(options.Parse(argc, const_cast<char **>(argv)), ::testing::ExitedWithCode(EXIT_FAILURE),
                ".*input file not specified.*");
}

// Test 7: Verify handling of short options
TEST(ProgramOptions, ShortOptions) {
    ProgramOptions options;
    const char *argv[] = {"program", "-c", "encrypt", "-i", "input.txt", "-o", "output.bin", "-p", "mypass"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    EXPECT_NO_THROW(options.Parse(argc, const_cast<char **>(argv)));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.bin");
    EXPECT_EQ(options.GetPassword(), "mypass");
}

// Test 8: Verify missing password for encrypt
TEST(ProgramOptions, MissingPasswordForEncrypt) {
    ProgramOptions options;
    const char *argv[] = {"program", "--command", "encrypt", "--input", "test.txt", "--output", "out.bin"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    EXPECT_EXIT(options.Parse(argc, const_cast<char **>(argv)), ::testing::ExitedWithCode(EXIT_FAILURE),
                ".*password must be specified.*");
}

// Test 9: Verify missing output for encrypt
TEST(ProgramOptions, MissingOutputForEncrypt) {
    ProgramOptions options;
    const char *argv[] = {"program", "--command", "encrypt", "--input", "test.txt", "--password", "pass"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    EXPECT_EXIT(options.Parse(argc, const_cast<char **>(argv)), ::testing::ExitedWithCode(EXIT_FAILURE),
                ".*output file must be specified.*");
}

// Test 10: Verify input and output files are the same
TEST(ProgramOptions, SameInputAndOutputFiles) {
    ProgramOptions options;
    const char *argv[] = {"program",  "--command", "encrypt",    "--input", "same.txt",
                          "--output", "same.txt",  "--password", "pass"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    EXPECT_EXIT(options.Parse(argc, const_cast<char **>(argv)), ::testing::ExitedWithCode(EXIT_FAILURE),
                ".*cannot be the same.*");
}

// Test 11: Verify help command
TEST(ProgramOptions, HelpCommand) {
    ProgramOptions options;
    const char *argv[] = {"program", "--help"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    // Redirect stdout to check help output
    testing::internal::CaptureStdout();
    EXPECT_EXIT(options.Parse(argc, const_cast<char **>(argv)), ::testing::ExitedWithCode(EXIT_SUCCESS), ".*");
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_THAT(output, ::testing::HasSubstr("Allowed options"));
    EXPECT_THAT(output, ::testing::HasSubstr("--help"));
    EXPECT_THAT(output, ::testing::HasSubstr("--command"));
    EXPECT_THAT(output, ::testing::HasSubstr("--input"));
    EXPECT_THAT(output, ::testing::HasSubstr("--output"));
    EXPECT_THAT(output, ::testing::HasSubstr("--password"));
}

// Test 12: Verify case sensitivity of commands
TEST(ProgramOptions, CaseSensitiveCommands) {
    ProgramOptions options;
    const char *argv[] = {"program", "--command", "ENCRYPT", "--input", "test.txt"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    EXPECT_EXIT(options.Parse(argc, const_cast<char **>(argv)), ::testing::ExitedWithCode(EXIT_FAILURE),
                ".*unknown command.*");
}