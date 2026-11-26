#include "pwgen.h"
#include "totp.h"
#include "vault.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>

namespace {
    void require(bool condition, const char* message) {
        if (!condition) {
            throw std::runtime_error(message);
        }
    }

    void testGenerator() {
        const std::array<std::string_view, 4> alphabets{
            "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789", "!@#$%&"
        };
        Secret password;
        for (unsigned mask = 1; mask <= pwgen::all; ++mask) {
            for (std::size_t length : {8, 24, 128}) {
                for (int sample = 0; sample < 12; ++sample) {
                    pwgen::generate(length, mask, password);
                    require(password.view().size() == length, "Generated password length");
                    for (std::size_t i = 0; i < alphabets.size(); ++i) {
                        const bool present = password.view().find_first_of(alphabets[i]) != std::string_view::npos;
                        require(present == ((mask & (1u << i)) != 0), "Generated password character sets");
                    }
                }
            }
        }
        for (const auto length : {7u, 129u}) {
            try {
                pwgen::generate(length, pwgen::all, password);
                throw std::runtime_error("Generator accepted an invalid length.");
            } catch (const std::invalid_argument&) {
            }
        }
    }

    void testTotp() {
        Secret key;
        Secret code;
        require(totp::decodeBase32("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", key), "Base32 normalization");
        require(key.view() == "12345678901234567890", "Base32 decoded bytes");

        // RFC 6238 Appendix B SHA-1 vectors reduced to six digits.
        struct Vector { std::uint64_t seconds; std::string_view code; };
        constexpr Vector vectors[] = {
            {59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"},
            {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}
        };
        for (const auto& vector : vectors) {
            totp::code(key, vector.seconds, code);
            require(code.view() == vector.code, "RFC 6238 SHA-1 vector");
        }
        totp::code(key, 58, code);
        require(code.view() == "287082", "TOTP stable inside the window");
        totp::code(key, 60, code);
        require(code.view() == "359152", "TOTP rotates at the window boundary");

        require(totp::decodeBase32("AAAAAAAAAAAAAAAAAAAAAAAAAA======", key) && key.size == 16, "Valid padded Base32");
        require(totp::decodeBase32("AAAAAAAAAAAAAAAAAAAAAAAAAA", key) && key.size == 16, "Valid unpadded Base32");
        for (const auto invalid : {"", "MZXW6===", "GEZDGNBVGY3TQOJQ!GEZDGNBVGY3TQOJQ",
            "AAAAAAAAAAAAAAAAAAAAAAAAAB======", "AAAAAAAAAAAAAAAAAAAAAAAAAA==",
            "AAAAAAAAAAAAAAAAAAAAAAAAAA=AAA", "AAAAAAAAAAAAAAAAAAAAAAAAA"}) {
            require(!totp::decodeBase32(invalid, key) && key.size == 0, "Rejected invalid setup key");
        }
        require(!totp::decodeBase32(std::string(104, 'A'), key), "Oversized setup key");
    }

    void testVault() {
        using vault::Kind;
        const auto label = "test-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64());
        const auto cleanup = [&] {
            vault::remove(Kind::password, label);
            vault::remove(Kind::authenticator, label);
        };
        try {
            Secret password;
            pwgen::generate(24, pwgen::all, password);
            Secret seed;
            require(totp::decodeBase32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", seed), "Test seed decoding");
            Secret loaded;
            require(!vault::read(Kind::password, label, loaded), "Missing credential");
            vault::save(Kind::password, label, password);
            require(!vault::read(Kind::authenticator, label, loaded), "Password and authenticator namespaces");
            vault::save(Kind::authenticator, label, seed);
            require(vault::read(Kind::password, label, loaded) && loaded.view() == password.view(), "Password round trip");
            require(vault::read(Kind::authenticator, label, loaded) && loaded.view() == seed.view(), "Binary seed round trip");
            const auto labels = vault::list(Kind::password);
            require(std::find(labels.begin(), labels.end(), label) != labels.end(), "Credential listing");
            password.data.fill('x');
            password.size = password.data.size();
            vault::save(Kind::password, label, password);
            require(vault::read(Kind::password, label, loaded) && loaded.view() == password.view(), "Credential replacement at size limit");
            require(vault::remove(Kind::password, label), "Credential deletion");
            require(!vault::read(Kind::password, label, loaded), "Deleted credential missing");
            require(vault::read(Kind::authenticator, label, loaded), "Deletion restricted to one namespace");
        } catch (...) {
            cleanup();
            throw;
        }
        cleanup();
    }
}

int main(int argc, char**) {
    try {
        if (argc > 1) {
            testVault();
        } else {
            testGenerator();
            testTotp();
            require(vault::validLabel("example.com / user@example.com"), "Valid account label");
            for (const auto invalid : {"", " leading", "trailing ", "line\nbreak", "escape\x1b"}) {
                require(!vault::validLabel(invalid), "Rejected unsafe account label");
            }
            require(!vault::validLabel(std::string(121, 'a')), "Rejected oversized account label");
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
