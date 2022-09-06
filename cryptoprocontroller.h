#ifndef CRYPTOPROCONTROLLER_H
#define CRYPTOPROCONTROLLER_H

#include <windows.h>
#include <cryptuiapi.h>
#include <wincrypt.h>
#include <string>
#include <vector>

//Создание самоподписанного сертификата КриптоПРО
//csptest -keyset -newkeyset -makecert -container test -keytype exchange
//  -exportable (если нужно чтобы ключ был экспортируемым)


class CryptoproController
{
public:
    CryptoproController() = delete;
    ~CryptoproController() = default;
    static bool openStore();
    static bool closeStore();
    static std::vector<std::string> listCertificates();
    static PCCERT_CONTEXT getCertificateBySerial(const std::string& serialHex);
    static bool encryptMessage(const std::string& decrypted, std::string& encrypted, const std::string& certSerial);
    static bool decryptMessage(const std::string& encrypted, std::string& decrypted);

private:
    static void handleError(const char* err);

    static HCRYPTPROV m_hCryptProv;        // дескриптор CSP
    static HCERTSTORE m_hStoreHandle;      // дескриптор хранилища сертификатов

};

#endif // CRYPTOPROCONTROLLER_H
