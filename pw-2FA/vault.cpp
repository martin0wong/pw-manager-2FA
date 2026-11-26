#include "vault.h"
#include <wincred.h>
#include <algorithm>
#include <cstring>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <system_error>

namespace {
    std::wstring prefix(vault::Kind kind) {
        return kind == vault::Kind::password ? L"pw-2FA:v1:password:" : L"pw-2FA:v1:totp:";
    }

    std::wstring target(vault::Kind kind, std::string_view label) {
        if (!vault::validLabel(label)) {
            throw std::invalid_argument("Invalid credential label.");
        }
        return prefix(kind) + std::wstring(label.begin(), label.end());
    }

    [[noreturn]] void storageError(const char* action, DWORD error) {
        throw std::system_error(static_cast<int>(error), std::system_category(), action);
    }

    void wipe(CREDENTIALW* credential) {
        if (credential->CredentialBlob != nullptr) {
            SecureZeroMemory(credential->CredentialBlob, credential->CredentialBlobSize);
        }
    }
}

bool vault::validLabel(std::string_view label) {
    return !label.empty() && label.size() <= 120 && label.front() != ' ' && label.back() != ' ' &&
        std::all_of(label.begin(), label.end(), [](char c) { return c >= ' ' && c <= '~'; });
}

void vault::save(Kind kind, std::string_view label, const Secret& value) {
    if (value.size == 0 || value.size > value.data.size()) {
        throw std::invalid_argument("Invalid credential size.");
    }
    auto name = target(kind, label);
    CREDENTIALW credential{};
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = name.data();
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    credential.CredentialBlobSize = static_cast<DWORD>(value.size);
    credential.CredentialBlob = reinterpret_cast<BYTE*>(const_cast<char*>(value.data.data()));
    if (!CredWriteW(&credential, 0)) {
        storageError("Could not save the credential", GetLastError());
    }
}

bool vault::read(Kind kind, std::string_view label, Secret& value) {
    const auto name = target(kind, label);
    CREDENTIALW* credential = nullptr;
    if (!CredReadW(name.c_str(), CRED_TYPE_GENERIC, 0, &credential)) {
        const auto error = GetLastError();
        if (error == ERROR_NOT_FOUND) {
            return false;
        }
        storageError("Could not read the credential", error);
    }

    const auto dispose = [](CREDENTIALW* record) {
        wipe(record);
        CredFree(record);
    };
    const std::unique_ptr<CREDENTIALW, decltype(dispose)> record(credential, dispose);
    if (record->CredentialBlobSize == 0 || record->CredentialBlobSize > value.data.size() ||
        record->CredentialBlob == nullptr) {
        throw std::runtime_error("The stored credential has an invalid size.");
    }
    std::memcpy(value.data.data(), record->CredentialBlob, record->CredentialBlobSize);
    value.size = record->CredentialBlobSize;
    return true;
}

std::vector<std::string> vault::list(Kind kind) {
    const auto base = prefix(kind);
    const auto filter = base + L'*';
    DWORD count = 0;
    CREDENTIALW** credentials = nullptr;
    if (!CredEnumerateW(filter.c_str(), 0, &count, &credentials)) {
        const auto error = GetLastError();
        if (error == ERROR_NOT_FOUND) {
            return {};
        }
        storageError("Could not list credentials", error);
    }
    const std::unique_ptr<CREDENTIALW*, decltype(&CredFree)> records(credentials, CredFree);
    for (DWORD i = 0; i < count; ++i) {
        wipe(credentials[i]);
    }

    std::vector<std::string> labels;
    for (DWORD i = 0; i < count; ++i) {
        const auto& record = *credentials[i];
        if (record.Type != CRED_TYPE_GENERIC) {
            continue;
        }
        const std::wstring_view name(record.TargetName);
        if (name.size() <= base.size()) {
            continue;
        }
        const auto label = name.substr(base.size());
        if (std::all_of(label.begin(), label.end(), [](wchar_t c) { return c >= L' ' && c <= L'~'; })) {
            std::string readable;
            readable.reserve(label.size());
            std::transform(label.begin(), label.end(), std::back_inserter(readable),
                [](wchar_t c) { return static_cast<char>(c); });
            if (validLabel(readable)) {
                labels.push_back(readable);
            }
        }
    }
    std::sort(labels.begin(), labels.end());
    return labels;
}

bool vault::remove(Kind kind, std::string_view label) {
    const auto name = target(kind, label);
    if (!CredDeleteW(name.c_str(), CRED_TYPE_GENERIC, 0)) {
        const auto error = GetLastError();
        if (error == ERROR_NOT_FOUND) {
            return false;
        }
        storageError("Could not delete the credential", error);
    }
    return true;
}
