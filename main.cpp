#include <iostream>
#include "server.h"
#include "cryptoprocontroller.h"
#include "configcontroller.h"
#include "util.h"


int main(int argc, char *argv[])
{

    int port = ConfigController::getValue<int>("server_port");

    Server server(port, ServerType::defaultServer);

    if (!server.isOk()) {
        std::cout << "Error bind or listen" << std::endl;
        return EXIT_FAILURE;
    }

    server.acceptClients();

    return 0;
}
