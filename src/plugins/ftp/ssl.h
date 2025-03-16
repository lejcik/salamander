// SPDX-FileCopyrightText: 2023 Open Salamander Authors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

// SSL 2.0 has security flaws and is disabled in current Firefox, Windows, etc.
#define OPENSSL_NO_SSL2

#include <openssl/ssl.h>
#include <openssl/x509.h>

//#include <CryptDlg.h>
#include <cryptuiapi.h>

#define SSLCONERR_NOERROR 0        // no error (also when SSL is not used)
#define SSLCONERR_CANRETRY 1       // unable to encrypt connection + retrying can help
#define SSLCONERR_DONOTRETRY 2     // unable to encrypt connection + it has no sense to retry
#define SSLCONERR_UNVERIFIEDCERT 3 // server's certificate was not verified nor previously accepted by user

class CCertificate
{
public:
    CCertificate(BYTE* pDERCert, int DERCertLen, BYTE* pPKCS7Cert, int PKCS7CertLen, bool bValid, LPCSTR host);
    LONG AddRef();
    LONG Release();
    void ShowCertificate(HWND hParent);
    bool CheckCertificate(LPTSTR buf, int maxlen);

    // POZOR: metoda meni data certifikatu, volajici si musi zajistit, ze se data nepouzivaji
    //        zaroven v jinem threadu (idealne volat dokud je tohle jediny odkaz na objekt)
    void SetVerified(bool verified) { bVerified = verified; };

    bool IsSame(BYTE* pDERCert, int DERCertLen, BYTE* pPKCS7Cert, int PKCS7CertLen);
    bool IsVerified() { return bVerified; };
    LPCWSTR GetHostName() { return Host; };

private:
    ~CCertificate();

    LONG nRefCount;
    BYTE *pDERData, *pPKCS7Data;
    int nDERDataLen, nPKCS7DataLen;
    bool bVerified; // false when accepted once, true if verified and valid
    LPWSTR Host;
};

class CCertificateErrDialog : public CCenteredDialog
{
protected:
    const char* ErrorStr;

public:
    CCertificateErrDialog(HWND hParent, const char* errorStr);

protected:
    virtual INT_PTR DialogProc(UINT uMsg, WPARAM wParam, LPARAM lParam);
};

typedef struct sSSLLib
{
    const SSL_METHOD* Meth;
    SSL_CTX* Ctx;
    HANDLE* Locks;
} sSSLLib;

extern sSSLLib SSLLib;

bool InitSSL(int logUID, int* errorID);
// loadStatus: 0 = lib was fully initialized,
//             1 = only DLLs may be loaded (probably not both DLLs are loaded),
//             2 = DLLs were loaded + lib init called (SSL_library_init() and others)
void FreeSSL(int loadStatus = 0);
void SSLThreadLocalCleanup();

int SSLtoWS2Error(int err);
