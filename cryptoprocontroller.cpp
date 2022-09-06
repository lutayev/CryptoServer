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

static void CleanUp(void);
static void HandleError(const char *s);
static PCCERT_CONTEXT GetRecipientCert(HCERTSTORE hCertStore);
static void DecryptMessage(BYTE *pbEncryptedBlob, DWORD cbEncryptedBlob);
static void GetCertDName(PCERT_NAME_BLOB pNameBlob, char **pszName);

CryptoproController::CryptoproController()
{

}


CryptoproController::~CryptoproController()
{

}


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
                CRYPT_VERIFYCONTEXT))   // Никакие флаги не нужны.
    {
        HandleError("Cryptographic context could not be acquired.");
        return false;
    }

    //std::cout << "CSP has been acquired. \n";
    // Открытие системного хранилища сертификатов.
    m_hStoreHandle = CertOpenSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, "My");

    if(!m_hStoreHandle)
    {
        HandleError( "Error getting store handle.");
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
    while((pCert = CertEnumCertificatesInStore(m_hStoreHandle, pCert)))
    {
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
    while((pCert = CertEnumCertificatesInStore(m_hStoreHandle, pCert)))
    {
        std::string current((char*)pCert->pCertInfo->SerialNumber.pbData, pCert->pCertInfo->SerialNumber.cbData);
        current = binToHex(current);
        if (str_toupper(current) == str_toupper(serialHex)) {
            return pCert;
        }
    }

    HandleError(("Can't find certificate with serial " + serialHex).c_str());
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

    if(!pRecipientCert)
    {
        printf("No certificate with a CERT_KEY_CONTEXT_PROP_ID \n");
        printf("property and an AT_KEYEXCHANGE private key available. \n");
        HandleError( "No Certificate with AT_KEYEXCHANGE key in store.");
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

    // Вызов функции CryptEncryptMessage.
    if(!CryptEncryptMessage(
                &EncryptParams,
                1,
                &pRecipientCert,
                pbContent,
                cbContent,
                NULL,
                &cbEncryptedBlob))
    {
        HandleError( "Getting EncrypBlob size failed.");
        CertFreeCertificateContext(pRecipientCert);
        return false;
    }

    // Распределение памяти под возвращаемый BLOB.
    pbEncryptedBlob = (BYTE*)malloc(cbEncryptedBlob);

    if(!pbEncryptedBlob) {
        HandleError("Memory allocation error while encrypting.");
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
                &cbEncryptedBlob))
    {
        HandleError("Encryption failed.");
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
                NULL))
    {
        HandleError( "Error getting decrypted message size");
        return false;
    }

    // Выделение памяти под возвращаемые расшифрованные данные.
    pbDecryptedMessage = (BYTE*)malloc(cbDecryptedMessage);
    if(!pbDecryptedMessage)
    {
        HandleError("Memory allocation error while decrypting");
        return false;
    }

    // Вызов функции CryptDecryptMessage для расшифрования данных.
    if(!CryptDecryptMessage(
                &decryptParams,
                (const BYTE*)encrypted.c_str(),
                encrypted.size(),
                pbDecryptedMessage,
                &cbDecryptedMessage,
                NULL))
    {
        free(pbDecryptedMessage);
        HandleError("Error decrypting the message");
        return false;
    }

    for (int i = 0; i < cbDecryptedMessage; ++i) {
        decrypted += ((char*)pbDecryptedMessage)[i];
    }

    free(pbDecryptedMessage);
    return true;
}



// GetRecipientCert перечисляет сертификаты в хранилище и находит
// первый сертификат, обладающий ключем AT_EXCHANGE. Если сертификат
// сертификат найден, то возвращается указатель на него.
PCCERT_CONTEXT GetRecipientCert(HCERTSTORE hCertStore)
{
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL bCertNotFind = TRUE;
    DWORD dwSize = 0;
    CRYPT_KEY_PROV_INFO* pKeyInfo = NULL;
    DWORD PropId = CERT_KEY_PROV_INFO_PROP_ID;
    HCRYPTPROV hProv = 0;
    DWORD dwKeySpec = 0;
    BOOL  fFreeProv = FALSE;

    if(!hCertStore) {
        std::cout << "No hCertStore in GetRecipientCert" << std::endl;
        return NULL;
    }

    do
    {
        // Поиск сертификатов в хранилище до тех пор, пока не будет достигнут
        // конец хранилища, или сертификат с ключем AT_KEYEXCHANGE не будет найден.
        pCertContext = CertFindCertificateInStore(
                    hCertStore, // Дескриптор хранилища, в котором будет осуществлен поиск.
                    MY_ENCODING_TYPE,
                    0,
                    CERT_FIND_SUBJECT_STR,
                    L"test",
                    NULL);
        if ( !pCertContext )
            break;

        // Для простоты в этом коде реализован только поиск первого
        // вхождения ключа AT_KEYEXCHANGE. Во многих случаях, помимо
        // поиска типа ключа, осуществляется также поиск определенного
        // имени субъекта.

        // Однократный вызов функции CertGetCertificateContextProperty
        // для получения возврашенного размера структуры.
        if(!(CertGetCertificateContextProperty(
                 pCertContext,
                 CERT_KEY_PROV_INFO_PROP_ID,
                 NULL,
                 &dwSize)))
        {
            printf("Error getting key property.\n");
            return NULL;
        }

        //--------------------------------------------------------------
        // распределение памяти под возвращенную структуру.

        if(pKeyInfo)
            free(pKeyInfo);

        pKeyInfo = (CRYPT_KEY_PROV_INFO*)malloc(dwSize);

        if(!pKeyInfo)
        {
            HandleError("Error allocating memory for pKeyInfo.");
        }

        //--------------------------------------------------------------
        // Получение структуры информации о ключе.

        if(!(CertGetCertificateContextProperty(
                 pCertContext,
                 CERT_KEY_PROV_INFO_PROP_ID,
                 pKeyInfo,
                 &dwSize)))
        {
            HandleError("The second call to the function failed.");
        }

        //-------------------------------------------
        // Проверка члена dwKeySpec на расширенный ключ и типа провайдера
        if(pKeyInfo->dwKeySpec == AT_KEYEXCHANGE && pKeyInfo->dwProvType == PROV_GOST_2001_DH)
        {
            //-------------------------------------------
            //попробуем открыть провайдер
            fFreeProv = FALSE;
            if ( CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_COMPARE_KEY_FLAG, NULL, &hProv, &dwKeySpec, &fFreeProv))
            {
                HCRYPTKEY hKey = 0;
                if (CryptGetUserKey( hProv, dwKeySpec, &hKey ))
                {
                    bCertNotFind = FALSE;
                    CryptDestroyKey( hKey );
                }
                if (fFreeProv)
                    CryptReleaseContext( hProv, 0 );
            }
        }
    } while(bCertNotFind && pCertContext);

    if(pKeyInfo)
        free(pKeyInfo);

    if (bCertNotFind) {
        std::cout << "bCertNotFound in GetRecipientCert" << std::endl;
        return NULL;
    }
    else
        return (pCertContext);
} // Конец определения GetRecipientCert


//----------------------------------------------------------------------------
// Получение имени из CERT_NAME_BLOB
void GetCertDName(PCERT_NAME_BLOB pNameBlob, char **pszName) {
    DWORD       cbName;

    wchar_t **pszNameW;

    cbName = CertNameToStr(
                X509_ASN_ENCODING, pNameBlob,
                CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                NULL, 0);
    if (cbName <= 1)
        HandleError("CertNameToStr(NULL)");

    *pszName = (char *)malloc(cbName * sizeof(char));
    if (!*pszName)
        HandleError("Out of memory.");

    cbName = CertNameToStr(
                X509_ASN_ENCODING, pNameBlob,
                CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                *pszName, cbName);
    if (cbName <= 1)
        HandleError("CertNameToStr(pbData)");
}


void HandleError(const char* err) {
    std::cout << err << std::endl;
}
