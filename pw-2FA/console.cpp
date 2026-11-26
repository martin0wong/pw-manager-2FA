#include "console.h"
#include <iostream>
#include <stdexcept>

namespace {
    bool isConsole(DWORD stream) {
        DWORD mode = 0;
        return GetConsoleMode(GetStdHandle(stream), &mode) != 0;
    }

    bool isControl(wchar_t character) {
        return character < 32 || (character >= 127 && character <= 159);
    }
}

bool console::interactive() {
    return isConsole(STD_INPUT_HANDLE) && isConsole(STD_OUTPUT_HANDLE);
}

bool console::line(const char* prompt, std::string& value) {
    std::cout << prompt << std::flush;
    return static_cast<bool>(std::getline(std::cin, value));
}

bool console::secret(const char* prompt, Secret& value) {
    if (!interactive()) {
        throw std::runtime_error("Secret entry requires an interactive Windows console.");
    }

    std::cout << prompt << std::flush;
    SensitiveBuffer<wchar_t, 512> input;
    SensitiveBuffer<INPUT_RECORD, 1> event;
    std::size_t length = 0;
    bool overflow = false;
    while (true) {
        DWORD count = 0;
        if (!ReadConsoleInputW(GetStdHandle(STD_INPUT_HANDLE), event.data.data(), 1, &count) || count != 1) {
            throw std::runtime_error("Could not read console input.");
        }
        const auto& record = event.data.front();
        const auto& key = record.Event.KeyEvent;
        if (record.EventType != KEY_EVENT || !key.bKeyDown) {
            continue;
        }

        const auto character = key.uChar.UnicodeChar;
        if (character == L'\r' || character == L'\n' || character == L'\x1b') {
            std::cout << '\n';
            if (character == L'\x1b') {
                return false;
            }
            break;
        }
        for (WORD i = 0; i < key.wRepeatCount && !overflow; ++i) {
            if (character == L'\b' && length > 0) {
                if (input.data[--length] >= 0xDC00 && input.data[length] <= 0xDFFF && length > 0 &&
                    input.data[length - 1] >= 0xD800 && input.data[length - 1] <= 0xDBFF) {
                    input.data[length--] = 0;
                }
                input.data[length] = 0;
            } else if (!isControl(character)) {
                overflow = length == input.data.size();
                if (!overflow) {
                    input.data[length++] = character;
                }
            }
        }
    }

    if (length == 0) {
        return false;
    }
    const int bytes = overflow ? 0 : WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        input.data.data(), static_cast<int>(length), value.data.data(),
        static_cast<int>(value.data.size()), nullptr, nullptr);
    if (bytes == 0) {
        throw std::runtime_error("Secret must be valid Unicode and at most 512 UTF-8 bytes.");
    }
    value.size = static_cast<std::size_t>(bytes);
    return true;
}

void console::reveal(const Secret& value) {
    if (!interactive()) {
        throw std::runtime_error("Displaying a secret requires an interactive Windows console.");
    }
    SensitiveBuffer<wchar_t, 514> output;
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data.data(),
        static_cast<int>(value.size), output.data.data(), static_cast<int>(output.data.size() - 2));
    if (length <= 0) {
        throw std::runtime_error("The stored password is invalid.");
    }
    for (int i = 0; i < length; ++i) {
        if (isControl(output.data[i])) {
            throw std::runtime_error("The stored password contains unsupported control characters.");
        }
    }
    output.data[length] = L'\r';
    output.data[length + 1] = L'\n';
    std::cout << std::flush;
    DWORD written = 0;
    const auto characters = static_cast<DWORD>(length + 2);
    if (!WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), output.data.data(), characters, &written, nullptr)
        || written != characters) {
        throw std::runtime_error("Could not display the secret.");
    }
}
