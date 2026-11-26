#include "totp.h"
#include <bcrypt.h>
#include <stdexcept>

bool totp::decodeBase32(std::string_view input, Secret& key) {
    constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    constexpr std::array<int, 8> requiredPadding{0, -1, 6, -1, 4, 3, -1, 1};
    unsigned accumulator = 0;
    unsigned bits = 0;
    std::size_t symbols = 0;
    std::size_t padding = 0;
    std::size_t bytes = 0;
    key.size = 0;

    for (char character : input) {
        if (character == ' ') {
            continue;
        }
        if (character == '=') {
            ++padding;
            if (padding > 6) {
                return false;
            }
            continue;
        }
        if (character >= 'a' && character <= 'z') {
            character = static_cast<char>(character - 'a' + 'A');
        }
        const auto digit = alphabet.find(character);
        if (digit == alphabet.npos || padding != 0) {
            return false;
        }
        ++symbols;
        accumulator = (accumulator << 5) | static_cast<unsigned>(digit);
        bits += 5;
        if (bits >= 8) {
            if (bytes == 64) {
                return false;
            }
            bits -= 8;
            key.data[bytes++] = static_cast<char>(accumulator >> bits);
            accumulator &= (1u << bits) - 1;
        }
    }

    const int expected = requiredPadding[symbols % 8];
    if (bytes < 16 || accumulator != 0 || expected < 0 ||
        (padding != 0 && padding != static_cast<std::size_t>(expected))) {
        return false;
    }
    key.size = bytes;
    return true;
}

void totp::code(const Secret& key, std::uint64_t unixSeconds, Secret& output) {
    if (key.size < 16 || key.size > 64) {
        throw std::invalid_argument("Invalid TOTP setup key length.");
    }

    std::array<UCHAR, 8> message{};
    auto counter = unixSeconds / period;
    for (auto it = message.rbegin(); it != message.rend(); ++it) {
        *it = static_cast<UCHAR>(counter & 0xff);
        counter >>= 8;
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA1_ALGORITHM, nullptr,
        BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0) {
        throw std::runtime_error("Windows could not open the TOTP HMAC provider.");
    }
    SensitiveBuffer<UCHAR, 20> digest;
    // CNG declares mutable pointers for these read-only hash inputs.
    const auto* bytes = reinterpret_cast<const UCHAR*>(key.data.data());
    const auto status = BCryptHash(algorithm, const_cast<PUCHAR>(bytes), static_cast<ULONG>(key.size),
        message.data(), static_cast<ULONG>(message.size()), digest.data.data(), static_cast<ULONG>(digest.data.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) {
        throw std::runtime_error("Windows could not generate the TOTP code.");
    }

    const auto offset = digest.data.back() & 0x0Fu;
    std::uint32_t number = digest.data[offset] & 0x7Fu;
    for (unsigned i = 1; i < 4; ++i) {
        number = (number << 8) | digest.data[offset + i];
    }
    output.size = 6;
    for (std::size_t i = output.size; i > 0; --i) {
        output.data[i - 1] = static_cast<char>('0' + (number % 10));
        number /= 10;
    }
}
