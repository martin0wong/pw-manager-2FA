#include "plugin_api.h"

namespace {
    template<typename Encoder, typename Response>
    passkeys::Encoded encode(Encoder encoder, const Response& response) {
        DWORD size = 0;
        BYTE* raw = nullptr;
        const auto result = encoder(&response, &size, &raw);
        passkeys::Buffer bytes(raw, CoTaskMemFree);
        passkeys::check(result);
        if (!raw || !size) passkeys::check(E_UNEXPECTED);
        return {size, std::move(bytes)};
    }
}

passkeys::Encoded passkeys::registrationResponse(const Entry& entry, const Bytes& publicKey) {
    auto auth = authenticatorData(entry.rp, true);
    auth.insert(auth.end(), aaguid.begin(), aaguid.end());
    auth.insert(auth.end(), {0, static_cast<BYTE>(entry.id.size())});
    auth.insert(auth.end(), entry.id.begin(), entry.id.end());
    auth.insert(auth.end(), publicKey.begin(), publicKey.end());
    WEBAUTHN_CREDENTIAL_ATTESTATION value{};
    value.dwVersion = WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION;
    value.pwszFormatType = WEBAUTHN_ATTESTATION_TYPE_NONE;
    value.cbAuthenticatorData = static_cast<DWORD>(auth.size());
    value.pbAuthenticatorData = auth.data();
    return encode(api().WebAuthNEncodeMakeCredentialResponse, value);
}

passkeys::Encoded passkeys::assertionResponse(Entry& entry, Bytes& auth, Bytes& signature) {
    WEBAUTHN_USER_ENTITY_INFORMATION user{};
    user.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
    user.cbId = static_cast<DWORD>(entry.userId.size());
    user.pbId = entry.userId.data();
    WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE response{};
    auto& value = response.WebAuthNAssertion;
    value.dwVersion = WEBAUTHN_ASSERTION_CURRENT_VERSION;
    value.Credential = {WEBAUTHN_CREDENTIAL_CURRENT_VERSION, static_cast<DWORD>(entry.id.size()),
        entry.id.data(), WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY};
    value.cbAuthenticatorData = static_cast<DWORD>(auth.size());
    value.pbAuthenticatorData = auth.data();
    value.cbSignature = static_cast<DWORD>(signature.size());
    value.pbSignature = signature.data();
    value.cbUserId = user.cbId;
    value.pbUserId = user.pbId;
    response.pUserInformation = &user;
    response.dwNumberOfCredentials = 1;
    return encode(api().WebAuthNEncodeGetAssertionResponse, response);
}
