#include "passkeys.h"
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincred.h>
#include <algorithm>
#include <cstring>
#include <iterator>
#include <memory>

namespace {
    using namespace passkeys;
    constexpr std::wstring_view prefix = L"pw-2FA:passkey:v1:";

    struct Handle {
        NCRYPT_HANDLE value = 0;
        Handle() = default;
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
        ~Handle() { if (value) NCryptFreeObject(value); }
    };

    void provider(Handle& handle) {
        check(NCryptOpenStorageProvider(&handle.value, MS_KEY_STORAGE_PROVIDER, 0));
    }

    std::wstring name(const Id& id) {
        return std::wstring(prefix) + hex(id);
    }

    void cng(NTSTATUS status) {
        if (status < 0) check(HRESULT_FROM_NT(status));
    }

    bool decodeId(std::wstring_view value, Id& id) {
        if (value.size() != prefix.size() + 2 * id.size() || value.substr(0, prefix.size()) != prefix) return false;
        value.remove_prefix(prefix.size());
        constexpr std::wstring_view digits = L"0123456789abcdef";
        for (size_t i = 0; i < id.size(); ++i) {
            const auto hi = digits.find(value[2 * i]);
            const auto lo = digits.find(value[2 * i + 1]);
            if (hi == digits.npos || lo == digits.npos) return false;
            id[i] = static_cast<BYTE>(16 * hi + lo);
        }
        return true;
    }

    Bytes derInteger(const BYTE* part) {
        const BYTE* end = part + 32;
        while (part < end - 1 && *part == 0) ++part;
        const bool leadingZero = (*part & 0x80) != 0;
        Bytes result{2, static_cast<BYTE>(end - part + leadingZero)};
        if (leadingZero) result.push_back(0);
        result.insert(result.end(), part, end);
        return result;
    }
}

void passkeys::check(HRESULT status) {
    if (FAILED(status)) throw status;
}

passkeys::Id passkeys::sha256(const BYTE* data, DWORD size) {
    Id digest{};
    cng(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, const_cast<BYTE*>(data), size,
        digest.data(), static_cast<ULONG>(digest.size())));
    return digest;
}

passkeys::Id passkeys::randomId() {
    Id id{};
    cng(BCryptGenRandom(nullptr, id.data(), static_cast<ULONG>(id.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    return id;
}

std::wstring passkeys::hex(const Id& id) {
    constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring encoded;
    for (BYTE byte : id) {
        encoded += digits[byte >> 4];
        encoded += digits[byte & 15];
    }
    return encoded;
}

bool passkeys::validRp(std::string_view rp) {
    return !rp.empty() && rp.size() <= 253 && std::all_of(rp.begin(), rp.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
    });
}

std::wstring passkeys::wide(std::string_view value) {
    if (value.empty()) return {};
    const auto size = static_cast<int>(value.size());
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), size, nullptr, 0);
    if (!count) check(E_INVALIDARG);
    std::wstring result(static_cast<size_t>(count), L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), size, result.data(), count)) {
        check(E_INVALIDARG);
    }
    return result;
}

passkeys::Bytes passkeys::makeKey(const Entry& entry) {
    Handle storage;
    provider(storage);
    Handle key;
    check(NCryptCreatePersistedKey(storage.value, &key.value, NCRYPT_ECDSA_P256_ALGORITHM,
        name(entry.id).c_str(), 0, 0));
    try {
        DWORD signing = NCRYPT_ALLOW_SIGNING_FLAG;
        check(NCryptSetProperty(key.value, NCRYPT_KEY_USAGE_PROPERTY, reinterpret_cast<BYTE*>(&signing),
            sizeof(signing), NCRYPT_PERSIST_FLAG));
        DWORD exportPolicy = 0;
        check(NCryptSetProperty(key.value, NCRYPT_EXPORT_POLICY_PROPERTY,
            reinterpret_cast<BYTE*>(&exportPolicy), sizeof(exportPolicy), NCRYPT_PERSIST_FLAG));
        check(NCryptFinalizeKey(key.value, 0));
        std::array<BYTE, sizeof(BCRYPT_ECCKEY_BLOB) + 64> blob{};
        DWORD size = 0;
        check(NCryptExportKey(key.value, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr,
            blob.data(), static_cast<DWORD>(blob.size()), &size, 0));
        if (size != blob.size()) check(E_UNEXPECTED);
        // COSE EC2 key, ES256, P-256, X and Y coordinates.
        Bytes cose{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20};
        const auto x = blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB);
        cose.insert(cose.end(), x, x + 32);
        cose.insert(cose.end(), {0x22, 0x58, 0x20});
        cose.insert(cose.end(), x + 32, blob.end());
        return cose;
    } catch (...) {
        if (NCryptDeleteKey(key.value, 0) == ERROR_SUCCESS) key.value = 0;
        throw;
    }
}

void passkeys::save(const Entry& entry) {
    if (!validRp(entry.rp) || entry.userId.empty() || entry.userId.size() > 64 ||
        entry.user.empty() || entry.user.size() > 128) check(E_INVALIDARG);
    // The record stores only public metadata. The signing key stays in CNG.
    Bytes blob{static_cast<BYTE>(entry.rp.size())};
    blob.insert(blob.end(), entry.rp.begin(), entry.rp.end());
    blob.insert(blob.end(), entry.userId.begin(), entry.userId.end());
    auto target = name(entry.id);
    CREDENTIALW record{};
    record.Type = CRED_TYPE_GENERIC;
    record.TargetName = target.data();
    record.UserName = const_cast<wchar_t*>(entry.user.c_str());
    record.Persist = CRED_PERSIST_LOCAL_MACHINE;
    record.CredentialBlobSize = static_cast<DWORD>(blob.size());
    record.CredentialBlob = blob.data();
    if (!CredWriteW(&record, 0)) check(HRESULT_FROM_WIN32(GetLastError()));
}

std::vector<passkeys::Entry> passkeys::entries() {
    const auto filter = std::wstring(prefix) + L'*';
    CREDENTIALW** records = nullptr;
    DWORD count = 0;
    if (!CredEnumerateW(filter.c_str(), 0, &count, &records)) {
        const auto error = GetLastError();
        if (error == ERROR_NOT_FOUND) return {};
        check(HRESULT_FROM_WIN32(error));
    }
    const std::unique_ptr<CREDENTIALW*, decltype(&CredFree)> cleanup(records, CredFree);
    std::vector<Entry> results;
    for (DWORD i = 0; i < count; ++i) {
        const auto& record = *records[i];
        Entry entry;
        const auto* data = record.CredentialBlob;
        const auto size = record.CredentialBlobSize;
        if (record.Type != CRED_TYPE_GENERIC || !record.UserName || !data || size < 3 ||
            !decodeId(record.TargetName, entry.id)) continue;
        const DWORD rpLength = data[0];
        if (rpLength >= size - 1 || size - 1 - rpLength > 64) continue;
        entry.rp.assign(reinterpret_cast<const char*>(data + 1), rpLength);
        if (!validRp(entry.rp)) continue;
        entry.userId.assign(data + 1 + rpLength, data + size);
        entry.user = record.UserName;
        if (!entry.user.empty() && entry.user.size() <= 128) results.push_back(std::move(entry));
    }
    return results;
}

void passkeys::erase(const Id& id) {
    Handle storage;
    provider(storage);
    Handle key;
    const auto target = name(id);
    const auto opened = NCryptOpenKey(storage.value, &key.value, target.c_str(), 0, NCRYPT_SILENT_FLAG);
    if (opened != NTE_BAD_KEYSET && opened != NTE_NOT_FOUND) {
        check(opened);
        check(NCryptDeleteKey(key.value, 0));
        key.value = 0;
    }
    if (!CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0)) {
        const auto error = GetLastError();
        if (error != ERROR_NOT_FOUND) check(HRESULT_FROM_WIN32(error));
    }
}

passkeys::Bytes passkeys::sign(const Id& id, const Id& hash) {
    Handle storage;
    provider(storage);
    Handle key;
    check(NCryptOpenKey(storage.value, &key.value, name(id).c_str(), 0, NCRYPT_SILENT_FLAG));
    std::array<BYTE, 64> raw{};
    DWORD size = 0;
    check(NCryptSignHash(key.value, nullptr, const_cast<BYTE*>(hash.data()), static_cast<DWORD>(hash.size()),
        raw.data(), static_cast<DWORD>(raw.size()), &size, NCRYPT_SILENT_FLAG));
    if (size != raw.size()) check(E_UNEXPECTED);
    auto r = derInteger(raw.data());
    auto s = derInteger(raw.data() + 32);
    Bytes result{0x30, static_cast<BYTE>(r.size() + s.size())};
    result.insert(result.end(), r.begin(), r.end());
    result.insert(result.end(), s.begin(), s.end());
    return result;
}

passkeys::Bytes passkeys::authenticatorData(std::string_view rp, bool attested) {
    const auto digest = sha256(reinterpret_cast<const BYTE*>(rp.data()), static_cast<DWORD>(rp.size()));
    Bytes data(digest.begin(), digest.end());
    // UP + UV, plus AT on registration. A zero signature counter is supported by WebAuthn.
    data.insert(data.end(), {static_cast<BYTE>(attested ? 0x45 : 0x05), 0, 0, 0, 0});
    return data;
}

passkeys::Bytes passkeys::authenticatorInfo() {
    // CTAP getInfo map: FIDO 2.0, AAGUID, discoverable credentials, presence and verification,
    // internal transport, and one supported public-key algorithm (ES256).
    Bytes info{0xa5, 0x01, 0x81, 0x68, 'F','I','D','O','_','2','_','0', 0x03, 0x50};
    info.insert(info.end(), aaguid.begin(), aaguid.end());
    info.insert(info.end(), {0x04, 0xa3, 0x62, 'r','k', 0xf5, 0x62, 'u','p', 0xf5,
        0x62, 'u','v', 0xf5, 0x09, 0x81, 0x68, 'i','n','t','e','r','n','a','l',
        0x0a, 0x81, 0xa2, 0x63, 'a','l','g', 0x26, 0x64, 't','y','p','e',
        0x6a, 'p','u','b','l','i','c','-','k','e','y'});
    return info;
}
