#pragma once

#include "passkeys.h"
#include <objbase.h>
#include <webauthn.h>
#include <webauthnplugin.h>
#include <memory>

namespace passkeys {
    using Buffer = std::unique_ptr<BYTE, decltype(&CoTaskMemFree)>;
    struct Encoded {
        DWORD size;
        Buffer bytes;
    };

    Encoded registrationResponse(const Entry& entry, const Bytes& publicKey);
    Encoded assertionResponse(Entry& entry, Bytes& authenticatorData, Bytes& signature);
}
