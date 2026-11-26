#include "plugin_api.h"
#include <bcrypt.h>
#include <ncrypt.h>
#include <pluginauthenticator.h>
#include <shellapi.h>
#include <wrl/implements.h>
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <memory>
#include <mutex>
#include <optional>

namespace {
    using namespace passkeys;
    using Microsoft::WRL::ClassicCom;
    using Microsoft::WRL::Make;
    using Microsoft::WRL::RuntimeClass;
    using Microsoft::WRL::RuntimeClassFlags;
    constexpr wchar_t title[] = L"pw-2FA Passkeys";
    HANDLE serverDone = nullptr;
    template<typename Action>
    HRESULT boundary(Action action) noexcept {
        try {
            action();
            return S_OK;
        } catch (HRESULT hr) {
            return hr;
        } catch (const std::bad_alloc&) {
            return E_OUTOFMEMORY;
        } catch (...) {
            return E_FAIL;
        }
    }

    void verify(const Id& digest, BYTE* blob, DWORD blobSize, BYTE* signature, DWORD signatureSize) {
        if (!blob || blobSize < sizeof(BCRYPT_KEY_BLOB) || !signature || !signatureSize) check(E_INVALIDARG);
        NCRYPT_PROV_HANDLE storage = 0;
        NCRYPT_KEY_HANDLE key = 0;
        check(NCryptOpenStorageProvider(&storage, MS_KEY_STORAGE_PROVIDER, 0));
        const HRESULT imported = NCryptImportKey(storage, 0, BCRYPT_PUBLIC_KEY_BLOB, nullptr, &key, blob, blobSize, 0);
        NCryptFreeObject(storage);
        check(imported);
        ULONG magic = 0;
        memcpy(&magic, blob, sizeof(magic));
        BCRYPT_PSS_PADDING_INFO pss{BCRYPT_SHA256_ALGORITHM, 32};
        const bool rsa = magic == BCRYPT_RSAPUBLIC_MAGIC;
        const HRESULT result = NCryptVerifySignature(key, rsa ? &pss : nullptr, const_cast<BYTE*>(digest.data()),
            static_cast<DWORD>(digest.size()), signature, signatureSize, rsa ? NCRYPT_PAD_PSS_FLAG : 0);
        NCryptFreeObject(key);
        check(result);
    }

    Id verifyRequest(PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request) {
        if (!request || request->requestType != WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR ||
            !request->pbEncodedRequest || !request->cbEncodedRequest || request->cbEncodedRequest > 65536) {
            check(E_INVALIDARG);
        }
        const auto digest = sha256(request->pbEncodedRequest, request->cbEncodedRequest);
        BYTE* blob = nullptr;
        DWORD size = 0;
        const HRESULT result = api().WebAuthNPluginGetOperationSigningPublicKey(providerId, &size, &blob);
        const std::unique_ptr<BYTE, decltype(&::WebAuthNPluginFreePublicKeyResponse)> cleanup(
            blob, api().WebAuthNPluginFreePublicKeyResponse);
        check(result);
        verify(digest, blob, size, request->pbRequestSignature, request->cbRequestSignature);
        return digest;
    }

    void hello(PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request, const Id& digest, const Entry& entry, bool creating) {
        BYTE* key = nullptr;
        DWORD keySize = 0;
        const auto keyResult = api().WebAuthNPluginGetUserVerificationPublicKey(providerId, &keySize, &key);
        const std::unique_ptr<BYTE, decltype(&::WebAuthNPluginFreePublicKeyResponse)> keyCleanup(
            key, api().WebAuthNPluginFreePublicKeyResponse);
        check(keyResult);
        const auto hint = std::wstring(creating ? L"Save a passkey for " : L"Sign in to ") + wide(entry.rp);
        WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST verification{
            request->hWnd, request->transactionId, entry.user.c_str(), hint.c_str()
        };
        BYTE* response = nullptr;
        DWORD size = 0;
        const auto result = api().WebAuthNPluginPerformUserVerification(&verification, &size, &response);
        const std::unique_ptr<BYTE, decltype(&::WebAuthNPluginFreeUserVerificationResponse)> cleanup(
            response, api().WebAuthNPluginFreeUserVerificationResponse);
        check(result);
        verify(digest, key, keySize, response, size);
    }

    std::string rpId(const BYTE* bytes, DWORD size) {
        if (!bytes || size > 253 || !size) check(E_INVALIDARG);
        std::string rp(reinterpret_cast<const char*>(bytes), size);
        if (!validRp(rp)) check(E_INVALIDARG);
        return rp;
    }

    bool contains(const WEBAUTHN_CREDENTIAL_LIST& list, const Id& id) {
        if (list.cCredentials && !list.ppCredentials) check(E_INVALIDARG);
        for (DWORD i = 0; i < list.cCredentials; ++i) {
            const auto* entry = list.ppCredentials[i];
            if (entry && entry->pbId && entry->cbId == id.size() &&
                std::equal(id.begin(), id.end(), entry->pbId)) return true;
        }
        return false;
    }

    bool supportsEs256(const WEBAUTHN_COSE_CREDENTIAL_PARAMETERS& parameters) {
        if (!parameters.pCredentialParameters) return false;
        for (DWORD i = 0; i < parameters.cCredentialParameters; ++i) {
            const auto& parameter = parameters.pCredentialParameters[i];
            if (parameter.lAlg == -7 && parameter.pwszCredentialType &&
                wcscmp(parameter.pwszCredentialType, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY) == 0) return true;
        }
        return false;
    }

    std::wstring accountName(PCWSTR name) {
        std::wstring text = name ? std::wstring(name).substr(0, 128) : L"";
        if (!text.empty() && text.back() >= 0xd800 && text.back() <= 0xdbff) text.pop_back();
        for (auto& c : text) {
            if (c < 32 || (c >= 127 && c <= 159) || (c >= 0x202a && c <= 0x202e) ||
                (c >= 0x2066 && c <= 0x2069)) c = L' ';
        }
        return text.empty() ? L"Website account" : text;
    }

    void updateCache(const Entry& entry, bool add) {
        const auto domain = wide(entry.rp);
        WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS details{static_cast<DWORD>(entry.id.size()), entry.id.data(),
            domain.c_str(), domain.c_str(), static_cast<DWORD>(entry.userId.size()), entry.userId.data(),
            entry.user.c_str(), entry.user.c_str()};
        if (add) check(api().WebAuthNPluginAuthenticatorAddCredentials(providerId, 1, &details));
        else {
            const auto result = api().WebAuthNPluginAuthenticatorRemoveCredentials(providerId, 1, &details);
            if (result != NTE_NOT_FOUND) check(result);
        }
    }

    class Operations {
        std::mutex mutex;
        std::optional<GUID> active;
        bool canceled = false;

    public:
        class Transaction {
            Operations& owner;
        public:
            Transaction(Operations& operations, const GUID& id) : owner(operations) {
                const std::lock_guard lock(owner.mutex);
                if (owner.active) check(HRESULT_FROM_WIN32(ERROR_BUSY));
                owner.active = id;
                owner.canceled = false;
            }
            ~Transaction() {
                const std::lock_guard lock(owner.mutex);
                owner.active.reset();
            }
            template<typename Action>
            void complete(Action action) {
                const std::lock_guard lock(owner.mutex);
                if (owner.canceled) check(NTE_USER_CANCELLED);
                action();
            }
        };

        void cancel(const GUID& id) {
            const std::lock_guard lock(mutex);
            if (!active || *active != id) check(NTE_NOT_FOUND);
            canceled = true;
        }
    } operations;

    class Authenticator final : public RuntimeClass<RuntimeClassFlags<ClassicCom>, IPluginAuthenticator> {
    public:
        Authenticator() { CoAddRefServerProcess(); }
        ~Authenticator() override {
            if (!CoReleaseServerProcess()) SetEvent(serverDone);
        }

        HRESULT STDMETHODCALLTYPE MakeCredential(PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request,
            PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept override {
            if (!response) return E_POINTER;
            *response = {};
            return boundary([&] {
                const auto digest = verifyRequest(request);
                Operations::Transaction transaction(operations, request->transactionId);
                PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST decoded = nullptr;
                const auto read = api().WebAuthNDecodeMakeCredentialRequest(request->cbEncodedRequest,
                    request->pbEncodedRequest, &decoded);
                const std::unique_ptr<WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST,
                    decltype(&::WebAuthNFreeDecodedMakeCredentialRequest)> data(decoded, api().WebAuthNFreeDecodedMakeCredentialRequest);
                check(read);
                if (!data || !data->pUserInformation || !data->pUserInformation->pbId ||
                    !data->pUserInformation->cbId || data->pUserInformation->cbId > 64) check(E_INVALIDARG);
                if (!supportsEs256(data->WebAuthNCredentialParameters)) check(NTE_NOT_SUPPORTED);
                if (data->dwEnterpriseAttestation || data->dwCredProtect > 3) check(NTE_NOT_SUPPORTED);
                const auto& user = *data->pUserInformation;
                Entry entry{randomId(), rpId(data->pbRpId, data->cbRpId),
                    Bytes(user.pbId, user.pbId + user.cbId), accountName(user.pwszName)};
                hello(request, digest, entry, true);
                transaction.complete([&] {
                    for (const auto& record : entries()) {
                        if (record.rp == entry.rp && contains(data->CredentialList, record.id)) check(NTE_EXISTS);
                    }
                    auto cose = makeKey(entry);
                    try {
                        auto encoded = registrationResponse(entry, cose);
                        save(entry);
                        updateCache(entry, true);
                        response->cbEncodedResponse = encoded.size;
                        response->pbEncodedResponse = encoded.bytes.release();
                    } catch (...) {
                        erase(entry.id);
                        throw;
                    }
                });
            });
        }

        HRESULT STDMETHODCALLTYPE GetAssertion(PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request,
            PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept override {
            if (!response) return E_POINTER;
            *response = {};
            return boundary([&] {
                const auto digest = verifyRequest(request);
                Operations::Transaction transaction(operations, request->transactionId);
                PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST decoded = nullptr;
                const auto read = api().WebAuthNDecodeGetAssertionRequest(request->cbEncodedRequest,
                    request->pbEncodedRequest, &decoded);
                const std::unique_ptr<WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST,
                    decltype(&::WebAuthNFreeDecodedGetAssertionRequest)> data(decoded, api().WebAuthNFreeDecodedGetAssertionRequest);
                check(read);
                if (!data || data->cbClientDataHash != 32 || !data->pbClientDataHash) check(E_INVALIDARG);
                const auto rp = rpId(data->pbRpId, data->cbRpId);
                auto candidates = entries();
                candidates.erase(std::remove_if(candidates.begin(), candidates.end(), [&](const Entry& entry) {
                    return entry.rp != rp || (data->CredentialList.cCredentials && !contains(data->CredentialList, entry.id));
                }), candidates.end());
                if (candidates.empty()) check(NTE_NOT_FOUND);
                auto selected = candidates.begin();
                if (candidates.size() > 1) {
                    for (; selected != candidates.end(); ++selected) {
                        const auto prompt = L"Sign in to " + wide(rp) + L" as " + selected->user + L"?";
                        const int choice = MessageBoxW(request->hWnd, prompt.c_str(), title, MB_YESNOCANCEL |
                            MB_ICONQUESTION | MB_DEFBUTTON2);
                        if (choice == IDYES) break;
                        if (choice != IDNO) check(NTE_USER_CANCELLED);
                    }
                    if (selected == candidates.end()) check(NTE_USER_CANCELLED);
                }
                hello(request, digest, *selected, false);
                transaction.complete([&] {
                    auto auth = authenticatorData(rp, false);
                    auto signedBytes = auth;
                    signedBytes.insert(signedBytes.end(), data->pbClientDataHash, data->pbClientDataHash + 32);
                    auto signature = sign(selected->id, sha256(signedBytes.data(), static_cast<DWORD>(signedBytes.size())));
                    auto encoded = assertionResponse(*selected, auth, signature);
                    response->cbEncodedResponse = encoded.size;
                    response->pbEncodedResponse = encoded.bytes.release();
                });
            });
        }

        HRESULT STDMETHODCALLTYPE CancelOperation(PCWEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST request) noexcept override {
            if (!request) return E_POINTER;
            return boundary([&] { operations.cancel(request->transactionId); });
        }

        HRESULT STDMETHODCALLTYPE GetLockStatus(PLUGIN_LOCK_STATUS* status) noexcept override {
            if (!status) return E_POINTER;
            *status = PluginLocked;
            return S_OK;
        }
    };

    class Factory final : public RuntimeClass<RuntimeClassFlags<ClassicCom>, IClassFactory> {
    public:
        HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID iid, void** object) noexcept override {
            if (!object) return E_POINTER;
            *object = nullptr;
            if (outer) return CLASS_E_NOAGGREGATION;
            return boundary([&] {
                auto provider = Make<Authenticator>();
                if (!provider) check(E_OUTOFMEMORY);
                check(provider.CopyTo(iid, object));
            });
        }
        HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) noexcept override {
            if (lock) CoAddRefServerProcess();
            else if (!CoReleaseServerProcess()) SetEvent(serverDone);
            return S_OK;
        }
    };

    void runServer() {
        serverDone = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!serverDone) check(HRESULT_FROM_WIN32(GetLastError()));
        auto factory = Make<Factory>();
        DWORD cookie = 0;
        const auto result = factory ? CoRegisterClassObject(providerId, factory.Get(), CLSCTX_LOCAL_SERVER,
            REGCLS_MULTIPLEUSE, &cookie) : E_OUTOFMEMORY;
        if (SUCCEEDED(result)) {
            WaitForSingleObject(serverDone, INFINITE);
            CoRevokeClassObject(cookie);
        }
        CloseHandle(serverDone);
        check(result);
    }

    void registerProvider() {
        const auto info = authenticatorInfo();
        const WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS options{title, providerId, nullptr, nullptr, nullptr,
            static_cast<DWORD>(info.size()), info.data(), 0, nullptr};
        PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE response = nullptr;
        const HRESULT result = api().WebAuthNPluginAddAuthenticator(&options, &response);
        api().WebAuthNPluginFreeAddAuthenticatorResponse(response);
        check(result);
    }

    void manage() {
        AUTHENTICATOR_STATE status{};
        const HRESULT state = api().WebAuthNPluginGetAuthenticatorState(providerId, &status);
        if (state == NTE_NOT_FOUND) {
            if (MessageBoxW(nullptr, L"Register pw-2FA as a Windows passkey provider for this account?",
                title, MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) return;
            registerProvider();
            status = AuthenticatorState_Disabled;
        } else {
            check(state);
        }
        if (status == AuthenticatorState_Disabled) {
            ShellExecuteW(nullptr, L"open", L"ms-settings:passkeys", nullptr, nullptr, SW_SHOWNORMAL);
            MessageBoxW(nullptr, L"Enable pw-2FA under Settings > Accounts > Passkeys > Advanced options.",
                title, MB_OK | MB_ICONINFORMATION);
            return;
        }
        auto records = entries();
        if (records.empty()) {
            MessageBoxW(nullptr, L"No passkeys saved. Choose pw-2FA when a website offers to create a passkey.",
                title, MB_OK | MB_ICONINFORMATION);
            return;
        }
        for (const auto& entry : records) {
            const auto prompt = L"Delete the local passkey for " + wide(entry.rp) + L" (" + entry.user +
                L")? Make sure you can still sign in to the website before deleting it.";
            const int choice = MessageBoxW(nullptr, prompt.c_str(), title, MB_YESNOCANCEL | MB_ICONQUESTION |
                MB_DEFBUTTON2);
            if (choice == IDCANCEL || !choice) break;
            if (choice == IDYES) {
                erase(entry.id);
                updateCache(entry, false);
            }
        }
    }
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR command, int) {
    const bool activated = wcscmp(command, L"--provider") == 0 || wcscmp(command, L"-Embedding") == 0;
    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    HRESULT result = initialized;
    if (SUCCEEDED(initialized)) {
        result = boundary([&] {
            if (activated) runServer();
            else manage();
        });
        CoUninitialize();
    }
    if (FAILED(result) && !activated) {
        wchar_t detail[100]{};
        swprintf_s(detail, L"Windows could not complete the passkey operation (0x%08lX).",
            static_cast<unsigned long>(result));
        MessageBoxW(nullptr, detail, title, MB_OK | MB_ICONERROR);
    }
    return FAILED(result) ? 1 : 0;
}
