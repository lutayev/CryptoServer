#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include "cryptoprocontroller.h"
#include "util.h"
#include "server.h"


int main(int argc, char *argv[])
{
    Server server(10001, ServerType::defaultServer);

    if (!server.isOk()) {
        std::cout << "Error bind or listen" << std::endl;
        return EXIT_FAILURE;
    }

    server.acceptClients();

    return 0;
}
