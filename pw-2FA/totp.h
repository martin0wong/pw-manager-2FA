#pragma once

#include "secret.h"
#include <cstdint>

namespace totp {
    inline constexpr std::uint64_t period = 30;
    bool decodeBase32(std::string_view input, Secret& key);
    void code(const Secret& key, std::uint64_t unixSeconds, Secret& output);
}
