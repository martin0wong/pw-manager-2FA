#pragma once

#include "secret.h"

namespace pwgen {
    inline constexpr unsigned lowercase = 1;
    inline constexpr unsigned uppercase = 2;
    inline constexpr unsigned digits = 4;
    inline constexpr unsigned symbols = 8;
    inline constexpr unsigned all = lowercase | uppercase | digits | symbols;

    void generate(std::size_t length, unsigned classes, Secret& password);
    bool prompt(Secret& password);
    void getNewPassword();
}
