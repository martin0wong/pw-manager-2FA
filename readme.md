# Password Manager & 2FA Authenticator

> **Personal passion project.** This is a legacy side project shared for learning and experimentation. It is not an actively maintained password manager or authenticator. Use test credentials and keep real accounts in a maintained password manager.

A local Windows command-line app for generating passwords, storing credentials, and displaying time-based one-time codes.

## Build and test

Use Windows 10 or 11, a C++17 compiler with the Windows SDK, CMake 3.20 or newer, and Ninja. For MSVC, run these commands from an x64 Developer Command Prompt. In Visual Studio, you can also open the repository as a CMake folder.

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
.\build\pw-2FA.exe
```

Run the app in an interactive Windows console. The credential-store test creates and removes temporary test entries in your Windows Credential Manager. All test secrets are generated for testing or come from public RFC vectors.

## Use the app

- **Generate password** uses Windows cryptographic randomness. The default is 24 characters using lowercase, uppercase, digits, and symbols. Keep that default or choose the length and character sets an account accepts.
- **Manage passwords** lets you save, replace, list, reveal, and delete passwords. Type a password with input hidden or generate one directly into storage. Use a label such as `example.com / username`. Labels are case-insensitive and can contain up to 120 printable ASCII characters.
- **Authenticator** accepts the manual Base32 setup key from a service. It supports six-digit HMAC-SHA-1 codes with 30-second periods. [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238)

## Local website passkeys (preview)

The optional **pw-2FA Passkeys** app is a Windows WebAuthn provider. Sites create and use passkeys through the browser’s Windows prompt. The provider stores P-256 signing keys in the Windows software key store with export disabled and saves account metadata separately. It requests Windows Hello verification for each browser operation. Keys stay on this device and there is no sync or export. Software running as your Windows user is within the trust boundary of the software key store. [Microsoft WebAuthn plugin documentation](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis)

Build in an x64 Visual Studio Developer Command Prompt with an updated Windows SDK that includes `webauthnplugin.h`. Use Windows 11 24H2 build 26100.6725 or newer with Windows Hello configured. Launch a Windows PowerShell session from the same directory for the staging steps. The unsigned development folder requires Windows Developer Mode to register.

```powershell
cmake -S . -B build/passkeys -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_PASSKEY_PROVIDER=ON
cmake --build build/passkeys
ctest --test-dir build/passkeys --output-on-failure
.\passkeys\Stage-Passkeys.ps1 -Executable .\build\passkeys\pw-2FA-passkeys.exe -Destination .\build\passkey-package
Add-AppxPackage -Register (Resolve-Path .\build\passkey-package\AppxManifest.xml)
```

Open **pw-2FA Passkeys** from Start, register it, then enable it under **Settings > Accounts > Passkeys > Advanced options**. Use a disposable account at a WebAuthn test site to create a credential, restart the browser, sign in with it, and delete it from the app. Keep another sign-in or recovery method before deleting a passkey. Package installation and browser sign-in have not been verified on the development machine. [Microsoft passkey provider setup](https://learn.microsoft.com/en-us/windows/apps/develop/security/third-party)

## Security and recovery

- Windows Credential Manager stores the passwords and setup keys under your Windows user account on the current device. The app has no separate unlock step. Software running under your account can access those credentials. Entry labels are visible in Credential Manager. [Microsoft credential storage documentation](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw)
- Secret entry uses hidden console input, and the app blocks secret operations when input or output is redirected. A password or current code appears on screen when you request it. It can remain in terminal scrollback or be captured by recording software.
- Keep service-provided recovery codes independently of this app. If you keep a password and its TOTP setup key under the same Windows login, compromise of that login can expose both. For accounts that need phishing-resistant sign-in, use a passkey or security key where the service supports it. [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
- The project has been tested against published TOTP vectors and Windows credential storage APIs. It has no independent security audit or compliance certification.
