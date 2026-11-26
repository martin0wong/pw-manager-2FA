#include "protocol.h"
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <algorithm>
#include <iostream>
#include <memory>
#include <stdexcept>

namespace {
    using namespace passkeys;

    void require(bool passed, const char* message) {
        if (!passed) throw std::runtime_error(message);
    }

    void validateSignature(const Bytes& cose, const Id& digest, const Bytes& signature) {
        require(cose.size() == 77, "P-256 COSE key length");
        // Decode WebAuthn's DER signature into the fixed-width integers CNG expects.
        CERT_ECC_SIGNATURE* parts = nullptr;
        DWORD size = 0;
        require(CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ECC_SIGNATURE, signature.data(),
            static_cast<DWORD>(signature.size()), CRYPT_DECODE_ALLOC_FLAG, nullptr, &parts, &size) != 0,
            "Decode DER signature with Windows");
        const std::unique_ptr<CERT_ECC_SIGNATURE, decltype(&LocalFree)> release(parts, LocalFree);
        std::array<BYTE, 64> raw{};
        for (const auto* part : {&parts->r, &parts->s}) {
            require(part->cbData <= 32, "P-256 integer width");
            const int offset = part == &parts->r ? 0 : 32;
            std::reverse_copy(part->pbData, part->pbData + part->cbData, raw.begin() + offset + 32 - part->cbData);
        }

        BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDSA_PUBLIC_P256_MAGIC, 32};
        const auto* headerBytes = reinterpret_cast<const BYTE*>(&header);
        Bytes key(headerBytes, headerBytes + sizeof(header));
        key.insert(key.end(), cose.begin() + 10, cose.begin() + 42);
        key.insert(key.end(), cose.begin() + 45, cose.end());
        BCRYPT_KEY_HANDLE publicKey = nullptr;
        require(BCryptImportKeyPair(BCRYPT_ECDSA_P256_ALG_HANDLE, nullptr, BCRYPT_ECCPUBLIC_BLOB, &publicKey,
            key.data(), static_cast<ULONG>(key.size()), 0) == 0, "Import generated public key");
        const auto result = BCryptVerifySignature(publicKey, nullptr, const_cast<BYTE*>(digest.data()),
            static_cast<ULONG>(digest.size()), raw.data(), static_cast<ULONG>(raw.size()), 0);
        auto changedHash = digest;
        changedHash[0] ^= 1;
        const auto changed = BCryptVerifySignature(publicKey, nullptr, changedHash.data(),
            static_cast<ULONG>(changedHash.size()), raw.data(), static_cast<ULONG>(raw.size()), 0);
        BCryptDestroyKey(publicKey);
        require(result == 0 && changed < 0, "Signature valid only for the original challenge");
    }

    void validateExportPolicy(const Id& id) {
        NCRYPT_PROV_HANDLE storage = 0;
        NCRYPT_KEY_HANDLE key = 0;
        check(NCryptOpenStorageProvider(&storage, MS_KEY_STORAGE_PROVIDER, 0));
        const auto name = L"pw-2FA:passkey:v1:" + hex(id);
        const auto result = NCryptOpenKey(storage, &key, name.c_str(), 0, NCRYPT_SILENT_FLAG);
        NCryptFreeObject(storage);
        check(result);
        DWORD policy = 1;
        DWORD size = 0;
        const auto gotPolicy = NCryptGetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY,
            reinterpret_cast<BYTE*>(&policy), sizeof(policy), &size, 0);
        DWORD encodedSize = 0;
        const auto privateExport = NCryptExportKey(key, 0, BCRYPT_ECCPRIVATE_BLOB, nullptr,
            nullptr, 0, &encodedSize, 0);
        NCryptFreeObject(key);
        require(gotPolicy == ERROR_SUCCESS && policy == 0 && privateExport != ERROR_SUCCESS,
            "Private-key export denied");
    }

    bool stored(const Entry& entry) {
        const auto records = entries();
        return std::any_of(records.begin(), records.end(), [&](const Entry& item) {
            return item.id == entry.id && item.rp == entry.rp && item.userId == entry.userId && item.user == entry.user;
        });
    }
}

int main() {
    Entry entry{randomId(), "example.test", {0, 3, 255}, L"Test account"};
    try {
        const auto cose = makeKey(entry);
        save(entry);
        require(stored(entry), "Passkey metadata round trip");
        auto auth = authenticatorData(entry.rp, false);
        require(auth.size() == 37 && auth[32] == 0x05, "Assertion UP and UV flags");
        require(authenticatorData(entry.rp, true)[32] == 0x45, "Registration UP, UV and AT flags");
        const auto digest = sha256(auth.data(), static_cast<DWORD>(auth.size()));
        auto signature = sign(entry.id, digest);
        validateSignature(cose, digest, signature);
        validateExportPolicy(entry.id);
        require(registrationResponse(entry, cose).size > 0, "Windows encoded a none-attestation response");
        require(assertionResponse(entry, auth, signature).size > 0, "Windows encoded an assertion response");
        erase(entry.id);
        require(!stored(entry), "Passkey metadata removed");
        try {
            sign(entry.id, digest);
            throw std::runtime_error("Deleted key could still sign");
        } catch (HRESULT hr) {
            require(hr == NTE_BAD_KEYSET || hr == NTE_NOT_FOUND, "CNG signing key removed");
        }
    } catch (HRESULT hr) {
        erase(entry.id);
        std::cerr << "Windows API error 0x" << std::hex << hr << '\n';
        return 1;
    } catch (const std::exception& error) {
        erase(entry.id);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
