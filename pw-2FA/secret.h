#pragma once

#include <windows.h>
#include <array>
#include <string_view>

template<typename Character, std::size_t Capacity>
struct SensitiveBuffer {
    std::array<Character, Capacity> data{};

    SensitiveBuffer() = default;
    SensitiveBuffer(const SensitiveBuffer&) = delete;
    SensitiveBuffer& operator=(const SensitiveBuffer&) = delete;
    ~SensitiveBuffer() { SecureZeroMemory(data.data(), sizeof(data)); }
};

struct Secret : SensitiveBuffer<char, 512> {
    std::size_t size = 0;

    std::string_view view() const { return {data.data(), size}; }
};
