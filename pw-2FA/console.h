#pragma once

#include "secret.h"
#include <string>

namespace console {
    bool interactive();
    bool line(const char* prompt, std::string& value);
    bool secret(const char* prompt, Secret& value);
    void reveal(const Secret& value);
}
