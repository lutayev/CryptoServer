#include "server.h"

Server::Server(unsigned short port, ServerType type)
    : m_portListenClients(port), m_serverType(type)
{

#ifdef _WIN32
    //Warmup windows socket system
    WSADATA WSAData;
    if (WSAStartup (MAKEWORD(1,1), &WSAData)!=0) {
        std::cout << "WSAStartup faild. Error:" << WSAGetLastError();
        m_ok = false;
        return;
    }
#endif
    if ((m_srvSock = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        std::cout <<"socket failed\n";
        m_ok = false;
        return;
    }

    m_addrListenClients.sin_family = AF_INET;
    m_addrListenClients.sin_port = htons(m_portListenClients);
    m_addrListenClients.sin_addr.s_addr = INADDR_ANY;

    //Bind
    if (bind(m_srvSock, reinterpret_cast<sockaddr*>(&m_addrListenClients), sizeof(m_addrListenClients)) != 0) {
        printf("Bind error #%d\n", errno);
        m_ok = false;
        return;
    }

    m_ok = true;
}

Server::~Server()
{
    std::cout << "Server shutdown" << std::endl;
    std::lock_guard<std::mutex> guard(m_mtxClientsMap);
    m_clients.clear();
    if (m_srvSock)
        close(m_srvSock);
}

void Server::acceptClients() {

    //Listen
    if (listen(m_srvSock, 2) != 0) {
        printf("ListenError #%d\n", errno);
        m_ok = false;
        return;
    }

    struct sockaddr_in from;
#ifdef __linux__
    socklen_t fromlen = sizeof (from);
#elif _WIN32
    int fromlen = sizeof(from);
#endif

    //Infinite loop of accepts untill stop flag is set
    while(true) {
        //Select
        int selRes;
        struct timeval tv;
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(m_srvSock, &rfds);
        tv.tv_sec = 15;
        tv.tv_usec = 0;
        selRes = select(m_srvSock + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv);

        //Accept
        if(selRes > 0) {
            unsigned short clientSocket = -1;
            clientSocket = accept(m_srvSock, reinterpret_cast<sockaddr*>(&from), &fromlen);
            std::thread(&Server::addClient, this, clientSocket).detach();
        }

        //Stop
        if (stop) {
            return;
        }
    }
}

void Server::addClient(unsigned short clientSocket)
{
    Connection* client;
    client = new Connection(clientSocket);
    std::cout << "Start Default server" << std::endl;

    //Remember client
    m_mtxClientsMap.lock();
    m_clients.insert(std::pair<unsigned int, Connection*>(clientSocket, client));
    m_mtxClientsMap.unlock();

    //While client is alive, it communicates (infinite loop)
    client->communicate();

    //Client disconnected, delete it
    m_mtxClientsMap.lock();
    delete client;
    m_clients.erase(clientSocket);
    m_mtxClientsMap.unlock();
}

bool Server::isOk()
{
    return m_ok;
}

void Server::printClientInfo(unsigned int socket)
{
    struct sockaddr_in from;
#ifdef __linux__
    socklen_t fromlen = sizeof (from);
#elif _WIN32
    int fromlen = sizeof(from);
#endif

    getpeername(socket, reinterpret_cast<sockaddr*>(&from), &fromlen);
    char *connected_ip = inet_ntoa(from.sin_addr);
    int port = ntohs(from.sin_port);
    std::cout << "\nNew connection from:\t" << connected_ip << ":" << port << std::endl;
}
