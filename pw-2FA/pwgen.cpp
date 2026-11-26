#include "pwgen.h"
#include "console.h"
#include <bcrypt.h>
#include <charconv>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace {
    constexpr std::array<std::string_view, 4> alphabets{
        "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789", "!@#$%&"
    };
    constexpr std::size_t minLength = 8;
    constexpr std::size_t maxLength = 128;

    class RandomBytes {
        SensitiveBuffer<unsigned char, 64> bytes;
        std::size_t next = bytes.data.size();

    public:
        std::size_t choose(std::size_t bound) {
            const auto limit = 256 - (256 % bound);
            while (true) {
                if (next == bytes.data.size()) {
                    if (BCryptGenRandom(nullptr, bytes.data.data(), static_cast<ULONG>(bytes.data.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
                        throw std::runtime_error("Windows could not generate secure random bytes.");
                    }
                    next = 0;
                }
                const auto byte = bytes.data[next++];
                if (byte < limit) {
                    return byte % bound;
                }
            }
        }
    };
}

void pwgen::generate(std::size_t length, unsigned classes, Secret& password) {
    if (length < minLength || length > maxLength || classes == 0 || (classes & ~all) != 0) {
        throw std::invalid_argument("Invalid password length or character sets.");
    }

    std::string alphabet;
    std::array<unsigned, 256> classFor{};
    for (std::size_t i = 0; i < alphabets.size(); ++i) {
        const unsigned category = 1u << i;
        if ((classes & category) != 0) {
            alphabet += alphabets[i];
            for (const unsigned char character : alphabets[i]) {
                classFor[character] = category;
            }
        }
    }

    // Sample uniformly from passwords that contain every selected character class.
    RandomBytes random;
    unsigned included;
    do {
        included = 0;
        for (std::size_t i = 0; i < length; ++i) {
            const auto character = alphabet[random.choose(alphabet.size())];
            password.data[i] = character;
            included |= classFor[static_cast<unsigned char>(character)];
        }
    } while (included != classes);
    password.size = length;
}

bool pwgen::prompt(Secret& password) {
    std::string input;
    unsigned classes = 0;
    while (console::line("Character sets (LC UC NUM SYM, Enter for all, 0 to cancel): ", input)) {
        if (input == "0") {
            return false;
        }
        if (input.empty()) {
            classes = all;
            break;
        }
        std::istringstream tokens(input);
        for (std::string token; tokens >> token;) {
            if (token == "LC" || token == "lc") classes |= lowercase;
            else if (token == "UC" || token == "uc") classes |= uppercase;
            else if (token == "NUM" || token == "num") classes |= digits;
            else if (token == "SYM" || token == "sym") classes |= symbols;
            else if (token == "AL" || token == "al") classes |= all;
            else {
                classes = 0;
                break;
            }
        }
        if (classes != 0) {
            break;
        }
        std::cout << "Invalid character sets.\n";
    }
    if (classes == 0) {
        return false;
    }

    while (console::line("Length (8-128, Enter for 24, 0 to cancel): ", input)) {
        if (input == "0") {
            return false;
        }
        std::size_t length = 24;
        if (!input.empty()) {
            const auto end = input.data() + input.size();
            const auto parsed = std::from_chars(input.data(), end, length);
            if (parsed.ec != std::errc{} || parsed.ptr != end || length < minLength || length > maxLength) {
                std::cout << "Enter a whole number from 8 to 128.\n";
                continue;
            }
        }
        generate(length, classes, password);
        return true;
    }
    return false;
}

void pwgen::getNewPassword() {
    if (!console::interactive()) {
        throw std::runtime_error("Password generation requires an interactive Windows console.");
    }
    Secret password;
    if (prompt(password)) {
        console::reveal(password);
    }
}
