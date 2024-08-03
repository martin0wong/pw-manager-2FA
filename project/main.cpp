#include <iostream>
#include <string>
#include "pwgen.h"
using namespace pwgen;

int main() {
    int sel = 0;
    int option = -1;
    while (sel > -1) {
        cout << "Enter option number to proceed:" << endl;
        cout << "\t 1. Manage password";
        // loop until valid options are chosen

        getNewPassword();
    }
    return 0;
}
