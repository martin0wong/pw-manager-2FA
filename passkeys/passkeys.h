#pragma once

#include <windows.h>
#include <array>
#include <string>
#include <string_view>
#include <vector>

namespace passkeys {
    inline constexpr CLSID providerId{0xf3522273, 0xe805, 0x407b, {0x95, 0xad, 0x89, 0x46, 0x4a, 0x98, 0x4c, 0x34}};
    inline constexpr std::array<BYTE, 16> aaguid{0x18, 0xb3, 0xc2, 0xae, 0xf9, 0x94, 0x45, 0x0c,
        0xb5, 0xcb, 0x4c, 0xe2, 0x6e, 0xb3, 0xf2, 0xc5};

    using Bytes = std::vector<BYTE>;
    using Id = std::array<BYTE, 32>;
    struct Entry {
        Id id{};
        std::string rp;
        Bytes userId;
        std::wstring user;
    };

    void check(HRESULT status);
    Id sha256(const BYTE* data, DWORD size);
    Id randomId();
    std::wstring hex(const Id& id);
    bool validRp(std::string_view rp);
    std::wstring wide(std::string_view value);
    Bytes makeKey(const Entry& entry);
    void save(const Entry& entry);
    void erase(const Id& id);
    std::vector<Entry> entries();
    Bytes sign(const Id& id, const Id& hash);
    Bytes authenticatorData(std::string_view rp, bool attested);
    Bytes authenticatorInfo();
}
