#pragma once

#include "secret.h"
#include <string>
#include <vector>

namespace vault {
    enum class Kind { password, authenticator };

    bool validLabel(std::string_view label);
    void save(Kind kind, std::string_view label, const Secret& value);
    bool read(Kind kind, std::string_view label, Secret& value);
    std::vector<std::string> list(Kind kind);
    bool remove(Kind kind, std::string_view label);
}
