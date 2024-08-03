#include <iostream>
#include <string>
#include "pwgen.h"
using namespace pwgen;
using namespace std;

int option = 0;
int getOption() {
    bool validOption = false;
    // loop until valid options are chosen
    while (!validOption) {
        // display options
        cout << "Enter option number to proceed:" << endl;
        cout << "\t 1. Generate password" << endl;
        cout << "\t 2. Manage passwords" << endl;
        cout << "\t 3. Exit (enter -1)" << endl;
        cout << "Option: ";

        // take input
        string optionInput;
        getline(cin, optionInput);

        try {
            // convert input to int
            int option = stoi(optionInput);
            validOption = true;
            return option;
        } catch (const exception& e) {
            cout << "Invalid entry. Please enter a number." << endl;
        }
    }
    return 0;
}

int main() {
    while (option > -1) {
        option = getOption();
        switch (option) {
        case 1:
            getNewPassword();
            break;
        case 2:
            managePasswords();
            break;
        case -1:
            cout << "Exiting program..." << endl;
			break;
        default:
            cout << "Invalid entry. Please enter a valid option." << endl;
			break;
		}
    }
    return 0;
}