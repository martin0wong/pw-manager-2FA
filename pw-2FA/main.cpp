#include "console.h"
#include "pwgen.h"
#include "pwmanager.h"
#include <iostream>

int main() {
    std::string option;
    while (console::line("\n1. Generate password  2. Manage passwords  3. Authenticator  0. Exit\nOption: ", option)) {
        try {
            if (option == "0" || option == "-1") {
                return 0;
            }
            if (option == "1") {
                pwgen::getNewPassword();
            } else if (option == "2") {
                pwManager::startManager(vault::Kind::password);
            } else if (option == "3") {
                pwManager::startManager(vault::Kind::authenticator);
            } else {
                std::cout << "Choose an option from the menu.\n";
            }
        } catch (const std::exception& error) {
            std::cerr << error.what() << '\n';
        }
    }
}
