#include <iostream>
#include <cstring>
#include <vector>

#include "cryptoprocontroller.h"
#include "util.h"

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

#define PROV_GOST_2001_DH 75
#define szOID_CP_GOST_28147 "1.2.643.2.2.21"


HCRYPTPROV CryptoproController::m_hCryptProv = 0;
HCERTSTORE CryptoproController::m_hStoreHandle = NULL;


bool CryptoproController::openStore()
{
    if (m_hCryptProv || m_hStoreHandle) {
        closeStore();
    }

    if(!CryptAcquireContext(
                &m_hCryptProv,          // Адрес возврашаемого дескриптора.
                0,                      // Используется имя текущего зарегестрированного пользователя.
                NULL,                   // Используется провайдер по умолчанию.
                PROV_GOST_2001_DH,      // Необходимо для зашифрования и подписи.
                CRYPT_VERIFYCONTEXT)) { // Никакие флаги не нужны.
        handleError("Cryptographic context could not be acquired.");
        return false;
    }

    //std::cout << "CSP has been acquired. \n";
    // Открытие системного хранилища сертификатов.
    m_hStoreHandle = CertOpenSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, "My");

    if(!m_hStoreHandle) {
        handleError( "Error getting store handle.");
        return false;
    }
    //std::cout << "The MY store is open. \n";
    return true;
}


bool CryptoproController::closeStore()
{
    bool ok = false;
    if (m_hStoreHandle) {
        ok = CertCloseStore(m_hStoreHandle, 0);
    }

    if (m_hCryptProv) {
        ok = ok && CryptReleaseContext(m_hCryptProv, 0);
    }

    m_hStoreHandle = NULL;
    m_hCryptProv = 0;
    return ok;
}


std::vector<std::string> CryptoproController::listCertificates()
{
    if (!m_hStoreHandle) {
        openStore();
    }
    std::vector<std::string> certs;
    PCCERT_CONTEXT pCert = NULL;
    while((pCert = CertEnumCertificatesInStore(m_hStoreHandle, pCert))) {
        std::string serial((char*)pCert->pCertInfo->SerialNumber.pbData, pCert->pCertInfo->SerialNumber.cbData);
        std::string subjId((char*)pCert->pCertInfo->SubjectUniqueId.pbData, pCert->pCertInfo->SubjectUniqueId.cbData);
        std::string subjPubKeyInfo((char*)pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData);


//        std::cout << "\nNext cert." << "\n\tSerial: " << binToHex(serial)
//                  << "\n\tSubject unique ID: " << subjId
//                  << "\n\tSubject public key info: " << subjPubKeyInfo
//                  << std::endl;
        certs.push_back(base64_encode((BYTE*)serial.c_str(), serial.size()));
    }

    return certs;
}


PCCERT_CONTEXT CryptoproController::getCertificateBySerial(const std::string &serialHex)
{
    if (!m_hStoreHandle) {
        openStore();
    }

    PCCERT_CONTEXT pCert = NULL;
    while((pCert = CertEnumCertificatesInStore(m_hStoreHandle, pCert))) {
        std::string current((char*)pCert->pCertInfo->SerialNumber.pbData, pCert->pCertInfo->SerialNumber.cbData);
        current = binToHex(current);
        if (str_toupper(current) == str_toupper(serialHex)) {
            return pCert;
        }
    }

    handleError(("Can't find certificate with serial " + serialHex).c_str());
    return NULL;
}


//https://cpdn.cryptopro.ru/content/csp39/html/group___crypt_example_CryptMessagesExample.html
bool CryptoproController::encryptMessage(const std::string &decrypted, std::string& encrypted, const std::string& certSerial)
{
    if (!m_hStoreHandle) {
        if (!openStore()) {
            return false;
        }
    }

    // Объявление и инициализация переменных. Они получают указатель на сообщение, которое будет зашифровано.
    BYTE* pbContent = (BYTE*)decrypted.c_str();   // Сообщение
    DWORD cbContent = decrypted.size() + 1;       // Длина сообщения, включая конечный 0

    CRYPT_ALGORITHM_IDENTIFIER EncryptAlgorithm;
    CRYPT_ENCRYPT_MESSAGE_PARA EncryptParams;

    BYTE*    pbEncryptedBlob = NULL;
    DWORD    cbEncryptedBlob;

    // Получение указателя на сертификат получателя
    PCCERT_CONTEXT pRecipientCert = getCertificateBySerial(certSerial);

    if(!pRecipientCert) {
        printf("No certificate with a CERT_KEY_CONTEXT_PROP_ID \n");
        printf("property and an AT_KEYEXCHANGE private key available. \n");
        handleError( "No Certificate with AT_KEYEXCHANGE key in store.");
        return false;
    }

    // Инициализация структуры с нулем.
    memset(&EncryptAlgorithm, 0, sizeof(CRYPT_ALGORITHM_IDENTIFIER));
    EncryptAlgorithm.pszObjId = (char*)szOID_CP_GOST_28147;

    // Инициализация структуры CRYPT_ENCRYPT_MESSAGE_PARA.
    memset(&EncryptParams, 0, sizeof(CRYPT_ENCRYPT_MESSAGE_PARA));
    EncryptParams.cbSize =  sizeof(CRYPT_ENCRYPT_MESSAGE_PARA);
    EncryptParams.dwMsgEncodingType = MY_ENCODING_TYPE;
    EncryptParams.hCryptProv = m_hCryptProv;
    EncryptParams.ContentEncryptionAlgorithm = EncryptAlgorithm;

    // Первый вызов функции CryptEncryptMessage для определения размера возвращаемых данных
    if(!CryptEncryptMessage(
                &EncryptParams,
                1,
                &pRecipientCert,
                pbContent,
                cbContent,
                NULL,
                &cbEncryptedBlob)) {
        handleError( "Getting EncrypBlob size failed.");
        CertFreeCertificateContext(pRecipientCert);
        return false;
    }

    // Распределение памяти под возвращаемый BLOB.
    pbEncryptedBlob = (BYTE*)malloc(cbEncryptedBlob);

    if(!pbEncryptedBlob) {
        handleError("Memory allocation error while encrypting.");
        CertFreeCertificateContext(pRecipientCert);
        return false;
    }

    // Повторный вызов функции CryptEncryptMessage для зашифрования содержимого.
    if(!CryptEncryptMessage(
                &EncryptParams,
                1,
                &pRecipientCert,
                pbContent,
                cbContent,
                pbEncryptedBlob,
                &cbEncryptedBlob)) {
        handleError("Encryption failed.");
        CertFreeCertificateContext(pRecipientCert);
        free(pbEncryptedBlob);
        return false;
    }

    for (int i = 0; i < cbEncryptedBlob; ++i) {
        encrypted += ((char*)pbEncryptedBlob)[i];
    }
    free (pbEncryptedBlob);
    CertFreeCertificateContext(pRecipientCert);

    return true;
}


bool CryptoproController::decryptMessage(const std::string& encrypted, std::string& decrypted)
{
    if (!m_hStoreHandle) {
        if (!openStore()) {
            return false;
        }
    }

    DWORD cbDecryptedMessage = 0;
    CRYPT_DECRYPT_MESSAGE_PARA  decryptParams;

    BYTE*  pbDecryptedMessage = NULL;

    //   Инициализация структуры CRYPT_DECRYPT_MESSAGE_PARA.
    memset(&decryptParams, 0, sizeof(CRYPT_DECRYPT_MESSAGE_PARA));
    decryptParams.cbSize = sizeof(CRYPT_DECRYPT_MESSAGE_PARA);
    decryptParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    decryptParams.cCertStore = 1;
    decryptParams.rghCertStore = &m_hStoreHandle;


    //  Расшифрование сообщения
    //  Вызов фнукции CryptDecryptMessage для получения возвращаемого размера данных.
    if(!CryptDecryptMessage(
                &decryptParams,
                (const BYTE*)encrypted.c_str(),
                encrypted.size(),
                NULL,
                &cbDecryptedMessage,
                NULL)) {
        handleError( "Error getting decrypted message size");
        return false;
    }

    // Выделение памяти под возвращаемые расшифрованные данные.
    pbDecryptedMessage = (BYTE*)malloc(cbDecryptedMessage);
    if(!pbDecryptedMessage) {
        handleError("Memory allocation error while decrypting");
        return false;
    }

    // Вызов функции CryptDecryptMessage для расшифрования данных.
    if(!CryptDecryptMessage(
                &decryptParams,
                (const BYTE*)encrypted.c_str(),
                encrypted.size(),
                pbDecryptedMessage,
                &cbDecryptedMessage,
                NULL)) {
        free(pbDecryptedMessage);
        handleError("Error decrypting the message");
        return false;
    }

    for (int i = 0; i < cbDecryptedMessage; ++i) {
        decrypted += ((char*)pbDecryptedMessage)[i];
    }

    free(pbDecryptedMessage);
    return true;
}




void CryptoproController::handleError(const char* err) {
    std::cout << err << std::endl;
}
