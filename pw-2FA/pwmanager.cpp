#include "pwmanager.h"
#include "console.h"
#include "pwgen.h"
#include "totp.h"
#include <ctime>
#include <iostream>
#include <stdexcept>

namespace {
    using vault::Kind;

    void save(Kind kind, std::string_view label) {
        Secret value;
        if (kind == Kind::authenticator) {
            Secret setupKey;
            if (!console::secret("Base32 setup key (hidden, Esc to cancel): ", setupKey)) {
                return;
            }
            if (!totp::decodeBase32(setupKey.view(), value)) {
                throw std::runtime_error("Enter a valid Base32 setup key encoding 16 to 64 bytes.");
            }
        } else {
            std::string source;
            if (!console::line("1. Type password   2. Generate password   0. Cancel: ", source) || source == "0") {
                return;
            }
            if (source == "1") {
                if (!console::secret("Password (hidden, Esc to cancel): ", value)) {
                    return;
                }
            } else if (source == "2") {
                if (!pwgen::prompt(value)) {
                    return;
                }
            } else {
                std::cout << "Choose an option from the menu.\n";
                return;
            }
        }
        vault::save(kind, label, value);
        std::cout << "Saved.\n";
    }

    void show(Kind kind, std::string_view label) {
        Secret value;
        if (!vault::read(kind, label, value)) {
            std::cout << "Entry not found.\n";
            return;
        }
        if (kind == Kind::password) {
            console::reveal(value);
            return;
        }
        const auto now = std::time(nullptr);
        if (now < 0) {
            throw std::runtime_error("Could not read the system clock.");
        }
        const auto seconds = static_cast<std::uint64_t>(now);
        Secret code;
        totp::code(value, seconds, code);
        std::cout << "Code (changes in " << totp::period - seconds % totp::period << "s): ";
        console::reveal(code);
    }
}

void pwManager::startManager(vault::Kind kind) {
    if (!console::interactive()) {
        throw std::runtime_error("Managing credentials requires an interactive Windows console.");
    }
    const bool password = kind == vault::Kind::password;
    std::string choice;
    while (console::line(password
        ? "\nPasswords\n1. Save or replace  2. List  3. Reveal password  4. Delete  0. Back\nOption: "
        : "\nAuthenticator\n1. Save or replace  2. List  3. Show code  4. Delete  0. Back\nOption: ", choice)) {
        if (choice == "0" || choice == "-1") {
            return;
        }

        try {
            if (choice == "2") {
                const auto labels = vault::list(kind);
                if (labels.empty()) {
                    std::cout << "No entries saved.\n";
                }
                for (const auto& label : labels) {
                    std::cout << "  " << label << '\n';
                }
                continue;
            }
            if (choice != "1" && choice != "3" && choice != "4") {
                std::cout << "Choose an option from the menu.\n";
                continue;
            }

            std::string label;
            if (!console::line("Entry label (for example, site / username, Enter to cancel): ", label)) {
                return;
            }
            if (label.empty()) {
                continue;
            }
            if (!vault::validLabel(label)) {
                std::cout << "Use up to 120 printable ASCII characters with no leading or trailing spaces.\n";
                continue;
            }
            if (choice == "1") {
                save(kind, label);
            } else if (choice == "3") {
                show(kind, label);
            } else {
                std::string confirm;
                if (console::line("Permanently delete this entry? Type yes to confirm: ", confirm) && confirm == "yes") {
                    std::cout << (vault::remove(kind, label) ? "Deleted.\n" : "Entry not found.\n");
                }
            }
        } catch (const std::exception& error) {
            std::cerr << error.what() << '\n';
        }
    }
}
