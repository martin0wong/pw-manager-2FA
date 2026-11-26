#pragma once

#include "protocol.h"

namespace passkeys {
    class PluginApi {
        struct Module {
            HMODULE handle = LoadLibraryExW(L"webauthn.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
            ~Module() { if (handle) FreeLibrary(handle); }
        } module;

        template<typename Function>
        Function get(const char* name) {
            const auto address = module.handle ? GetProcAddress(module.handle, name) : nullptr;
            if (!address) check(HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED));
            // GetProcAddress is intentionally converted to the matching SDK declaration.
#pragma warning(suppress: 4191)
            return reinterpret_cast<Function>(address);
        }
    public:
#define LOAD_PLUGIN_API(name) decltype(&::name) name = get<decltype(&::name)>(#name)
        LOAD_PLUGIN_API(WebAuthNPluginGetAuthenticatorState);
        LOAD_PLUGIN_API(WebAuthNPluginAddAuthenticator);
        LOAD_PLUGIN_API(WebAuthNPluginFreeAddAuthenticatorResponse);
        LOAD_PLUGIN_API(WebAuthNPluginAuthenticatorAddCredentials);
        LOAD_PLUGIN_API(WebAuthNPluginAuthenticatorRemoveCredentials);
        LOAD_PLUGIN_API(WebAuthNPluginPerformUserVerification);
        LOAD_PLUGIN_API(WebAuthNPluginFreeUserVerificationResponse);
        LOAD_PLUGIN_API(WebAuthNPluginGetUserVerificationPublicKey);
        LOAD_PLUGIN_API(WebAuthNPluginGetOperationSigningPublicKey);
        LOAD_PLUGIN_API(WebAuthNPluginFreePublicKeyResponse);
        LOAD_PLUGIN_API(WebAuthNEncodeMakeCredentialResponse);
        LOAD_PLUGIN_API(WebAuthNDecodeMakeCredentialRequest);
        LOAD_PLUGIN_API(WebAuthNFreeDecodedMakeCredentialRequest);
        LOAD_PLUGIN_API(WebAuthNDecodeGetAssertionRequest);
        LOAD_PLUGIN_API(WebAuthNFreeDecodedGetAssertionRequest);
        LOAD_PLUGIN_API(WebAuthNEncodeGetAssertionResponse);
#undef LOAD_PLUGIN_API
    };

    inline const PluginApi& api() {
        static const PluginApi instance;
        return instance;
    }
}
