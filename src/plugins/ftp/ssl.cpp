// SPDX-FileCopyrightText: 2023 Open Salamander Authors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "precomp.h"
#include <openssl/err.h>
#include <openssl/rand.h>

#define SSL_CTRL_OPTIONS 32

#define MAX_DER_CERT_SIZE 5120 // Is 5KB enough?

#define SizeOf(x) (sizeof(x) / sizeof(x[0]))

sSSLLib SSLLib;

static bool bSSLInited = false;

BYTE hex(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return 0;
}

static void AddNewLine(char*& buf, int& maxlen)
{
    if (maxlen > 0 && buf[0])
    {
        int len = (int)_tcslen(buf);
        maxlen -= len;
        buf += len;
        if (maxlen && (buf[-1] != '\n') && (buf[-1] != '\r'))
        {
            _tcscpy(buf, _T("\n"));
            maxlen--;
            buf++;
        }
    }
} /* AddNewLine */

static bool CheckCertificate(BYTE* pCert, int certLen, LPTSTR buf, int maxlen, const char* host,
                             LPCWSTR hostW)
{
    CALL_STACK_MESSAGE5("CheckCertificate(0x%p, %d, %s, %ls)", pCert, certLen, host, hostW);
    CERT_CHAIN_PARA ChainPara;
    PCCERT_CHAIN_CONTEXT pChainContext = NULL;
    CERT_CHAIN_POLICY_PARA PolicyPara;
    CERT_CHAIN_POLICY_STATUS PolicyStatus;
    HTTPSPolicyCallbackData polHttps;
    PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pCert, certLen);
    WCHAR PeerName[128];

    if (maxlen > 0)
        buf[0] = 0;
    if (!pCertContext)
    {
        lstrcpyn(buf, SalamanderGeneral->GetErrorText(GetLastError()), maxlen);
        return false;
    }

    bool checkRevocation = true;

CHECK_CERT_AGAIN:

    memset(&ChainPara, 0, sizeof(ChainPara));
    ChainPara.cbSize = sizeof(ChainPara);
    if (!CertGetCertificateChain(NULL,
                                 pCertContext,
                                 NULL,
                                 NULL,
                                 &ChainPara,
                                 (checkRevocation ? CERT_CHAIN_REVOCATION_CHECK_CHAIN : 0) | // Revocation checking is done on all of the certificates in every chain.
                                     CERT_CHAIN_CACHE_END_CERT |                             // When this flag is set, the end certificate is cached, which might speed up the chain-building process. By default, the end certificate is not cached, and it would need to be verified each time a chain is built for it.
                                     CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE,               // Inhibits the auto update of third-party roots from the Windows Update Web Server
                                 NULL,
                                 &pChainContext))
    {
        lstrcpyn(buf, SalamanderGeneral->GetErrorText(GetLastError()), maxlen);
        CertFreeCertificateContext(pCertContext);
        return false;
    }
    memset(&polHttps, 0, sizeof(HTTPSPolicyCallbackData));
    polHttps.cbStruct = sizeof(HTTPSPolicyCallbackData);
    polHttps.dwAuthType = AUTHTYPE_SERVER;
    polHttps.fdwChecks = 0;
    if (host != NULL)
        MultiByteToWideChar(CP_ACP, 0, host, -1, PeerName, SizeOf(PeerName));
    else
    {
        if (hostW != NULL)
            lstrcpynW(PeerName, hostW, SizeOf(PeerName));
    }
    polHttps.pwszServerName = PeerName;

    memset(&PolicyPara, 0, sizeof(PolicyPara));
    PolicyPara.cbSize = sizeof(PolicyPara);
    PolicyPara.pvExtraPolicyPara = &polHttps;

    memset(&PolicyStatus, 0, sizeof(PolicyStatus));
    PolicyStatus.cbSize = sizeof(PolicyStatus);

    if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL,
                                          pChainContext, &PolicyPara, &PolicyStatus))
    {
        lstrcpyn(buf, SalamanderGeneral->GetErrorText(GetLastError()), maxlen);
        CertFreeCertificateChain(pChainContext);
        CertFreeCertificateContext(pCertContext);
        return false;
    }

    bool ok = true;

    if (PolicyStatus.dwError)
    {
        if (checkRevocation && PolicyStatus.dwError == CRYPT_E_NO_REVOCATION_CHECK)
        { // The revocation function was unable to check revocation for the certificate. OK, so try it without checking revocation (MS probably also skips it because they accept the same certificate at the same time on the same machine).
            CertFreeCertificateChain(pChainContext);
            pChainContext = NULL;
            checkRevocation = false;
            goto CHECK_CERT_AGAIN;
        }
        else
        {
            ok = false;
            lstrcpyn(buf, SalamanderGeneral->GetErrorText(PolicyStatus.dwError), maxlen);
        }
    }
    int res = CertVerifyTimeValidity(NULL, pCertContext->pCertInfo);
    if (res != 0)
    {
        ok = false;
        AddNewLine(buf, maxlen);
        lstrcpyn(buf, LoadStr((res < 0) ? IDS_SSL_ERR_NOTYETVALID : IDS_SSL_ERR_EXPIRED), maxlen);
    }
    // Whatever flag is used, revocation check fails on most servers :-/
    /*int i;
  for (i = 0; i < pChainContext->cChain; i++)
  {
    CERT_REVOCATION_STATUS  revStat;

    revStat.cbSize = sizeof(CERT_REVOCATION_STATUS);
    if (!CertVerifyRevocation(X509_ASN_ENCODING,
                              CERT_CONTEXT_REVOCATION_TYPE,
                              1,
                              (void**)&pChainContext->rgpChain[i]->rgpElement[0]->pCertContext,
                              //CERT_VERIFY_CACHE_ONLY_BASED_REVOCATION/
                              CERT_VERIFY_REV_SERVER_OCSP_FLAG
                              //CERT_VERIFY_REV_CHAIN_FLAG,
                              NULL,
                              &revStat))
    {
      ok = false;
      AddNewLine(buf, maxlen);
      lstrcpyn(buf, SalamanderGeneral->GetErrorText(revStat.dwError), maxlen);
      break;
    }
  }*/

    CertFreeCertificateChain(pChainContext);
    CertFreeCertificateContext(pCertContext);
    return ok;
} /* CheckCertificate */

static bool ViewCertificate(HWND hParent, BYTE* pCertData, int CertDataLen, BYTE* pPKCS7Cert, int PKCS7CertLen, LPCWSTR pTitle)
{
    CALL_STACK_MESSAGE5("ViewCertificate(0x%p, 0x%p, %d, %ls)", hParent, pCertData, CertDataLen, pTitle);
    CRYPTUI_VIEWCERTIFICATE_STRUCTW cvi;
    PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pCertData, CertDataLen);
    if (!pCertContext)
    {
        const char* errStr = SalamanderGeneral->GetErrorText(GetLastError());
        SalamanderGeneral->SalMessageBox(hParent, errStr, LoadStr(IDS_FTPPLUGINTITLE), MB_OK | MB_ICONSTOP);
        return false;
    }

    // Put all other certificates provided by the server, possibly untrusted, to hCertStore
    CRYPT_INTEGER_BLOB blob = {(DWORD)PKCS7CertLen, pPKCS7Cert};
    HCERTSTORE hCertStore = CertOpenStore(CERT_STORE_PROV_PKCS7, PKCS_7_ASN_ENCODING, NULL, 0, &blob);

    memset(&cvi, 0, sizeof(cvi));
    cvi.dwSize = sizeof(cvi);
    cvi.hwndParent = hParent;
    cvi.dwFlags = CRYPTUI_DISABLE_EDITPROPERTIES;
    cvi.szTitle = pTitle;
    cvi.pCertContext = pCertContext;
    if (hCertStore)
    {
        cvi.cStores = 1;
        cvi.rghStores = &hCertStore;
    }

    if (!CryptUIDlgViewCertificateW(&cvi, NULL))
    {
        DWORD err = GetLastError();
        if (ERROR_CANCELLED != err)
        {
            const char* errStr = SalamanderGeneral->GetErrorText(err);
            CertFreeCertificateContext(pCertContext);
            if (hCertStore)
                CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);
            SalamanderGeneral->SalMessageBox(hParent, errStr, LoadStr(IDS_FTPPLUGINTITLE), MB_OK | MB_ICONSTOP);
            return false;
        }
    }
    if (hCertStore)
        CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);
    CertFreeCertificateContext(pCertContext);
    return true;
} /* ViewCertificate */

#ifdef _DEBUG
static void InfoCallback(const SSL* s, int where, int ret)
{
    const char* str;
    int w;
    char buf[512];

    w = where & ~SSL_ST_MASK;
    buf[0] = 0;

    if (w & SSL_ST_CONNECT)
        str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
        str = "SSL_accept";
    else
        str = "undefined";

    if (where & SSL_CB_LOOP)
    {
        sprintf(buf, "%s:%s\n", str, SSL_state_string_long(s));
    }
    else if (where & SSL_CB_ALERT)
    {
        str = (where & SSL_CB_READ) ? "read" : "write";
        sprintf(buf, "SSL3 alert %s:%s:%s\n", str,
                SSL_alert_type_string_long(ret),
                SSL_alert_desc_string_long(ret));
    }
    else if (where & SSL_CB_EXIT)
    {
        if (ret == 0)
        {
            sprintf(buf, "%s:failed in %s\n", str, SSL_state_string_long(s));
        }
        else if (ret < 0)
        {
            sprintf(buf, "%s:error %d in %s\n", str, ret, SSL_state_string_long(s));
        }
    }
    if (buf[0])
    {
        OutputDebugString(buf);
        TRACE_I(buf);
    }
}
#endif

void WriteSSLErrorStackToLog(int logUID, const char* errSrc)
{
    // log OpenSSL error stack
    int err2;
    char buffer[256]; // documentation says: at least 120 bytes
    while ((err2 = ERR_get_error()) != 0)
    {
        ERR_error_string(err2, buffer);
        Logs.LogMessage(logUID, "SSL ERROR: ", -1);
        Logs.LogMessage(logUID, errSrc, -1);
        Logs.LogMessage(logUID, ": ", -1);
        Logs.LogMessage(logUID, buffer, -1);
        Logs.LogMessage(logUID, "\r\n", -1);
    }
}

BOOL CSocket::EncryptSocket(int logUID, int* sslErrorOccured, CCertificate** unverifiedCert,
                            int* errorID, char* errorBuf, int errorBufLen, CSocket* conForReuse)
{
    int err;
    SSL* Conn;
    char buffer[256], name[200];

    CALL_STACK_MESSAGE3("CSocket::EncryptSocket(%d, , , , , , 0x%p)", logUID, conForReuse);
    if (errorID != NULL)
        *errorID = -1;
    if (errorBufLen > 0)
        errorBuf[0] = 0;
    if (unverifiedCert != NULL)
        *unverifiedCert = NULL;
    if (sslErrorOccured != NULL)
        *sslErrorOccured = SSLConn != NULL ? SSLCONERR_NOERROR : SSLCONERR_DONOTRETRY;
    if (SSLConn != NULL)
        return TRUE; // socket has already been encrypted
    if (!bSSLInited)
        return FALSE;
    WriteSSLErrorStackToLog(logUID, "unknown source");
    Conn = SSL_new(SSLLib.Ctx);
    if (Conn)
    {
        HWND hWnd = SocketsThread->GetHiddenWindow();
        u_long argp = 0;

        WSAAsyncSelect(Socket, hWnd, 0, 0);
        err = ioctlsocket(Socket, FIONBIO, &argp);
        // On x64, SOCKET is a 64-bit value, but the OpenSSL developers assume it never exceeds 2^32
        // see http://comments.gmane.org/gmane.comp.encryption.openssl.devel/13621
        // http://msdn.microsoft.com/en-us/library/ms724485%28VS.85%29.aspx
        // if that happens and this condition starts failing, perhaps an x64 version of SSL will already exist
        if (Socket > 0x00000000ffffffff)
        {
            DWORD* crash = NULL;
            *crash = 0;
        }
        if (!SSL_set_fd(Conn, (int)Socket))
            WriteSSLErrorStackToLog(logUID, "SSL_set_fd");
        SSL_set_verify(Conn, 0, NULL);

#ifdef _DEBUG
        SSL_set_info_callback(Conn, InfoCallback);
        Logs.LogMessage(logUID, "SSL DEBUG INFO: See Trace Server for messages from information callback for this SSL connection.\r\n", -1);
#endif

        BOOL testReuseSSLSession = FALSE;
        if (conForReuse != NULL && conForReuse->SSLConn != NULL && conForReuse->ReuseSSLSession != 2 /* no */)
        {
            SSL_SESSION* ssl_sessionid = SSL_get1_session(conForReuse->SSLConn); // sessionid.addref()
            if (ssl_sessionid == NULL)
                Logs.LogMessage(logUID, "SSL ERROR: SSL_get1_session returns NULL!\r\n", -1);
            else
            {
                if (!SSL_set_session(Conn, ssl_sessionid))
                    WriteSSLErrorStackToLog(logUID, "SSL_set_session");
                else
                    testReuseSSLSession = TRUE;
                SSL_SESSION_free(ssl_sessionid); // sessionid.release()
            }
        }

        TRACE_I("SSL_connect: begin");
        {
            CALL_STACK_MESSAGE1("CSocket::EncryptSocket::SSL_connect()");
            err = SSL_connect(Conn);
        }
        TRACE_I("SSL_connect: end");

        if (err > 0)
        {
            if (testReuseSSLSession)
            {
                if (SSL_session_reused(Conn))
                {
                    Logs.LogMessage(logUID, "SSL INFO: SSL session reused for data-connection\r\n", -1);
                    if (conForReuse->ReuseSSLSession == 0 /* try */)
                        conForReuse->ReuseSSLSession = 1 /* yes */;
                }
                else // SSL session not reused
                {
                    if (conForReuse->ReuseSSLSession == 0 /* try */) // do not try again for future data-connections (or it will fail)
                    {
                        Logs.LogMessage(logUID, "SSL INFO: SSL session was NOT reused, will not try for future data-connections...\r\n", -1);
                        conForReuse->ReuseSSLSession = 2 /* no */;
                    }
                    else // try for all future data-cons to set ReuseSSLSessionFailed to TRUE and so reconnect ctrl-con (except if this is keep-alive data-con)
                    {
                        Logs.LogMessage(logUID, "SSL INFO: SSL session was NOT reused, it has expired in server session cache, reconnect of control connection is needed...\r\n", -1);
                        conForReuse->ReuseSSLSessionFailed = TRUE; // To open the data connection, reuse is probably necessary, but it reports an error; the only solution is to reconnect the control connection.
                    }
                }
            }

            const SSL_CIPHER* ssl_cipher;
            const char* ssl_version;
            const char* cipher_name;
            int ssl_bits;
            X509* peerCert;
            STACK_OF(X509) * certStack;
            BYTE *DERCert, *PKCS7Cert = NULL, *tmp;
            int DERCertLen, PKCS7CertLen;
            int verRes = SSL_get_verify_result(Conn);

            wsprintf(buffer, LoadStr(IDS_SSL_LOG_OSSL_CERT_VERIFY), verRes);
            Logs.LogMessage(logUID, buffer, -1);
#ifdef _DEBUG
            const char* str = X509_verify_cert_error_string(verRes);
#endif

            peerCert = SSL_get_peer_certificate(Conn);
            X509_NAME_oneline(X509_get_subject_name(peerCert), name, sizeof(name));
            wsprintf(buffer, LoadStr(IDS_SSL_LOG_SUBJECT), name);
            Logs.LogMessage(logUID, buffer, -1);
            X509_NAME_oneline(X509_get_issuer_name(peerCert), name, sizeof(name));
            wsprintf(buffer, LoadStr(IDS_SSL_LOG_ISSUER), name);
            Logs.LogMessage(logUID, buffer, -1);

            // Obtain entire certificate chain upto root certificate
            certStack = SSL_get_peer_cert_chain(Conn);
            if (certStack)
            {
                PKCS7* p7 = PKCS7_new();
                if (p7)
                {
                    PKCS7_SIGNED* p7s = PKCS7_SIGNED_new();
                    if (p7s)
                    {
                        p7->type = OBJ_nid2obj(NID_pkcs7_signed);
                        p7->d.sign = p7s;
                        //p7s->contents = PKCS7_content_new(NID_pkcs7_data);
                        p7s->contents->type = OBJ_nid2obj(NID_pkcs7_data);
                        ASN1_INTEGER_set(p7s->version, 1);
                        p7s->cert = certStack;
                        p7s->crl = sk_X509_CRL_new_null();
                        p7s->signer_info = sk_PKCS7_SIGNER_INFO_new_null();
                        PKCS7CertLen = i2d_PKCS7(p7, NULL);
                        tmp = PKCS7Cert = (BYTE*)malloc(PKCS7CertLen);
                        i2d_PKCS7(p7, &tmp);
                    }
                }
                p7->d.sign->cert = NULL; // Avoid freeing it
                PKCS7_free(p7);
            }

            DERCertLen = i2d_X509(peerCert, NULL);
            tmp = DERCert = (BYTE*)malloc(DERCertLen);
            i2d_X509(peerCert, &tmp);
            X509_free(peerCert);

            ssl_version = SSL_CIPHER_get_version(SSL_get_current_cipher(Conn));
            ssl_cipher = SSL_get_current_cipher(Conn);
            SSL_CIPHER_get_bits(ssl_cipher, &ssl_bits);
            cipher_name = SSL_CIPHER_get_name(ssl_cipher);
            wsprintf(buffer, LoadStr(IDS_SSL_LOG_ALGO), ssl_version, cipher_name, ssl_bits);
            Logs.LogMessage(logUID, buffer, -1);

            BOOL certAcceptedOrVerified = FALSE;
            if (pCertificate)
            {
                if (pCertificate->IsSame(DERCert, DERCertLen, PKCS7Cert, PKCS7CertLen))
                {
                    Logs.LogMessage(logUID, LoadStr(pCertificate->IsVerified() ? IDS_SSL_LOG_CERTVERIFIED : IDS_SSL_LOG_CERTACCEPTED), -1, TRUE);
                    certAcceptedOrVerified = TRUE;
                }
                else // The certificate has changed.
                {
                    Logs.LogMessage(logUID, LoadStr(IDS_SSL_LOG_CERTCHANGED), -1, TRUE);
                    pCertificate->Release();
                    pCertificate = NULL;
                }
            }
            if (!certAcceptedOrVerified)
            {
                if (CheckCertificate(DERCert, DERCertLen, errorBuf, errorBufLen, HostAddress, NULL))
                {
                    Logs.LogMessage(logUID, LoadStr(IDS_SSL_LOG_CERTVERIFIED), -1, TRUE);
                    pCertificate = new CCertificate(DERCert, DERCertLen, PKCS7Cert, PKCS7CertLen, true, HostAddress);
                    certAcceptedOrVerified = TRUE; // Passed
                }
                else
                    Logs.LogMessage(logUID, LoadStr(IDS_SSL_LOG_CERTNOTVERIFIED), -1, TRUE);
            }
            if (!certAcceptedOrVerified)
            {
                // The certificate was not verified and had not previously been accepted by the user, so the user should accept
                // it before any further use of this socket.
                if (unverifiedCert != NULL)
                    *unverifiedCert = new CCertificate(DERCert, DERCertLen, PKCS7Cert, PKCS7CertLen, false, HostAddress);
                else
                {
                    SSL_shutdown(Conn);
                    SSL_free(Conn);
                    if (PKCS7Cert)
                        free(PKCS7Cert);
                    free(DERCert);
                    if (sslErrorOccured != NULL)
                        *sslErrorOccured = SSLCONERR_UNVERIFIEDCERT; // The certificate was not verified and was not previously accepted by the user.
                    return FALSE;
                }
            }
            if (PKCS7Cert)
                free(PKCS7Cert);
            free(DERCert);
            WSAAsyncSelect(Socket, hWnd, Msg, FD_READ | FD_CLOSE | FD_WRITE);
            SSLConn = Conn;
            if (sslErrorOccured != NULL)
                *sslErrorOccured = SSLCONERR_NOERROR; // But the certificate must not have been verified or previously accepted by the user.
            return TRUE;
        }
        else
        {
            /*      ERR_STATE *es = ERR_get_state();
      fd_set  fs;
      timeval tv = {0,10};
      FD_ZERO(&fs);
      FD_SET(Socket, &fs);
      select(1, NULL, NULL, &fs, &tv);*/
            err = SSL_get_error(Conn, err);
            //      err = ERR_get_error();
            //      err = GetLastError();

            sprintf(buffer, LoadStr(IDS_SSL_ERR_CONNECT_LOG), err, ERR_error_string(err, name));
            Logs.LogMessage(logUID, buffer, -1, TRUE);
            WriteSSLErrorStackToLog(logUID, "SSL_connect");

            if (errorID != NULL)
                *errorID = IDS_SSL_ERR_CONNECT;
            if (errorBufLen > 0)
                _snprintf_s(errorBuf, errorBufLen, _TRUNCATE, LoadStr(IDS_SSL_ERR_CONNECT_ERR), err, name);
            SSL_free(Conn);
            if (sslErrorOccured != NULL)
                *sslErrorOccured = SSLCONERR_CANRETRY;
        }
    }
    else
    {
        Logs.LogMessage(logUID, LoadStr(IDS_SSL_ERR_NEW_LOG), -1, TRUE);
        if (errorID != NULL)
            *errorID = IDS_SSL_ERR_NEW;
        WriteSSLErrorStackToLog(logUID, "SSL_new");
    }
    return FALSE;
}

void FreeSSL(int loadStatus)
{
    if (bSSLInited || loadStatus != 0)
    {
        if (SSLLib.Locks)
        {
            CRYPTO_set_locking_callback(NULL);
            for (int i = 0; i < CRYPTO_num_locks(); i++)
                if (SSLLib.Locks[i])
                    CloseHandle(SSLLib.Locks[i]);
            free(SSLLib.Locks);
        }
        if (SSLLib.Ctx)
            SSL_CTX_free(SSLLib.Ctx);

        if (loadStatus == 0 || loadStatus == 2)
        {
            // Petr: OpenSSL left a bunch of memory leaks, so I added this block

            // thread-local cleanup
            //ERR_remove_state(0);

            // thread-safe cleanup
            //ENGINE_cleanup();
            CONF_modules_finish();
            CONF_modules_free();
            CONF_modules_unload(1);

            // global application exit cleanup (after all SSL activity is shutdown)
            ERR_free_strings();
            EVP_cleanup();
            CRYPTO_cleanup_all_ex_data();

            // The stack with compression methods probably cannot be released "legally", so it is handled manually
            //STACK_OF(SSL_COMP)* comp_sk = SSL_COMP_get_compression_methods();
            //sk_free(CHECKED_STACK_OF(SSL_COMP, comp_sk));
            SSL_COMP_free_compression_methods();

            // Petr: end of block
        }
        bSSLInited = false;
    }
}

void SSLThreadLocalCleanup()
{
    //if (bSSLInited)
    //    ERR_remove_state(0);
        
}

static void LockingCallback(int mode, int type, const char* file, int line)
{
    if (mode & CRYPTO_LOCK)
    {
        WaitForSingleObject(SSLLib.Locks[type], INFINITE);
    }
    else
    {
        ReleaseMutex(SSLLib.Locks[type]);
    }
}

bool InitSSL(int logUID, int* errorID)
{
    if (errorID != NULL)
        *errorID = -1;
    if (bSSLInited)
        return true;

    CALL_STACK_MESSAGE2("InitSSL(%d,)", logUID);

    memset(&SSLLib, 0, sizeof(SSLLib));

    bool ret = false;
    char dir[MAX_PATH];
    int loadStatus = 1;
    if (GetModuleFileName(NULL, dir, _countof(dir)) &&
        SalamanderGeneral->CutDirectory(dir) &&
        SalamanderGeneral->SalPathAppend(dir, "utils", _countof(dir)))
    {
        ret = true;
    }

    if (ret)
    {
        loadStatus = 2;
        sprintf(dir, "SSL INFO: Version: %s \r\nSSL INFO: Compile flags: ", SSLeay_version(SSLEAY_VERSION));
        Logs.LogMessage(logUID, dir, -1);
        Logs.LogMessage(logUID, SSLeay_version(SSLEAY_CFLAGS), -1);
        Logs.LogMessage(logUID, "\r\n", -1);
        // NOTE: There are no unload counterparts for SSL_library_init & SSL_load_error_strings
        SSL_library_init();
        SSL_load_error_strings();
        DWORD seed = GetTickCount();
        RAND_seed(&seed, sizeof(seed));
        int locksCount = CRYPTO_num_locks();
        SSLLib.Locks = (HANDLE*)malloc(locksCount * sizeof(HANDLE));
        if (SSLLib.Locks)
        {
            for (int i = 0; i < locksCount; i++)
            {
                SSLLib.Locks[i] = !ret ? NULL : CreateMutex(NULL, FALSE, NULL);
                if (ret && SSLLib.Locks[i] == NULL)
                    ret = false;
            }
        }
        else
            ret = false;
        if (!ret)
        {
            sprintf(dir, "SSL Err: Unable to alloc %d locks\r\n", locksCount);
            Logs.LogMessage(logUID, dir, -1);
        }

        if (ret)
        {
            CRYPTO_set_locking_callback(/*(void (*)(int,int,const char *,int))*/ LockingCallback);

            // NOTE: do not free the pointer returned by SSLv23_client_method()
            //
            // SSLv23_client_method() is the default method used in OpenSSL.exe and CURL.
            // The unsafe SSL2 protocol is disabled by the OPENSSL_NO_SSL2 define.
            // SSLv3_client_method() did not work with the wedos server: https://forum.altap.cz/viewtopic.php?f=2&t=6667
            //    SSLLib.Meth = SSLv3_client_method();
            SSLLib.Meth = SSLv23_client_method();
            if (SSLLib.Meth)
            {
                SSLLib.Ctx = SSL_CTX_new(SSLLib.Meth);
                if (SSLLib.Ctx)
                {
                    /* also enable all the interoperability and bug
                     * workarounds so that we can communicate with implementations
                     * that cannot read poorly written specs
                     */
                    SSL_CTX_ctrl(SSLLib.Ctx, SSL_CTRL_OPTIONS, SSL_OP_ALL, NULL);
                    bSSLInited = true;
                    return true;
                }
            } // if Meth != NULL
        }
    }
    FreeSSL(loadStatus);
    memset(&SSLLib, 0, sizeof(SSLLib)); // clean up, everything is freed
    if (errorID != NULL)
        *errorID = IDS_SSL_ERR_OPENSSLNOTFOUND;
    Logs.LogMessage(logUID, LoadStr(IDS_SSL_ERR_OPENSSLNOTFOUND), -1);
    Logs.LogMessage(logUID, "\r\n", -1);
    return false;
} /* InitSSL */

int SSLtoWS2Error(int err)
{
    switch (err)
    {
    case SSL_ERROR_WANT_READ:
        return WSAEWOULDBLOCK;
    case SSL_ERROR_WANT_WRITE:
        return WSAEWOULDBLOCK;
        //    case SSL_ERROR_SYSCALL:     return WSAECONNCLOSED;
        //    case SSL_ERROR_ZERO_RETURN: return WSAECONNCLOSED;
    default:
        return err;
    }
}

//////////////////////// CCertificateErrDialog ////////////////////////
CCertificateErrDialog::CCertificateErrDialog(HWND hParent, const char* errorStr)
    : CCenteredDialog(HLanguage, IDD_CERTIFICATE, hParent), ErrorStr(errorStr)
{
}

INT_PTR CCertificateErrDialog::DialogProc(UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    CALL_STACK_MESSAGE4("CCertificateErrDialog::DialogProc(0x%X, 0x%IX, 0x%IX)", uMsg, wParam, lParam);
    switch (uMsg)
    {
    case WM_INITDIALOG:
        SetDlgItemText(HWindow, IDT_CERTIFICATE_ERROR, ErrorStr);
        break;
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDB_CERTIFICATE_VIEW:
            if (HIWORD(wParam) == BN_CLICKED)
            {
                EndDialog(HWindow, IDB_CERTIFICATE_VIEW);
            }
            break;
        }
    }
    return CCenteredDialog::DialogProc(uMsg, wParam, lParam);
}

//////////////////////// CCertificate ////////////////////////
CCertificate::CCertificate(BYTE* pDERCert, int DERCertLen, BYTE* pPKCS7Cert, int PKCS7CertLen, bool bValid, LPCSTR host)
{
    CALL_STACK_MESSAGE7("CCertificate::ctor(0x%p, %d, 0x%p, %d, %d, %s)", pDERCert, DERCertLen, pPKCS7Cert, PKCS7CertLen, bValid, host);
    bVerified = bValid;
    pDERData = (BYTE*)malloc(DERCertLen);
    if (pDERData)
    {
        nDERDataLen = DERCertLen;
        memcpy(pDERData, pDERCert, nDERDataLen);
    }
    else
    {
        nDERDataLen = 0;
    }
    pPKCS7Data = (BYTE*)malloc(PKCS7CertLen);
    if (pPKCS7Data)
    {
        nPKCS7DataLen = PKCS7CertLen;
        memcpy(pPKCS7Data, pPKCS7Cert, nPKCS7DataLen);
    }
    else
    {
        nPKCS7DataLen = 0;
    }
    if (host)
    {
        Host = (LPWSTR)malloc(sizeof(WCHAR) * (strlen(host) + 1));
        if (Host)
        {
            LPWSTR out = Host;
            while (*host)
                *out++ = *host++;
            *out = 0;
        }
    }
    else
    {
        Host = NULL;
    }
    nRefCount = 1;
}

CCertificate::~CCertificate()
{
    if (Host)
        free(Host);
    if (pDERData)
        free(pDERData);
    if (pPKCS7Data)
        free(pPKCS7Data);
}

LONG CCertificate::AddRef()
{
    return InterlockedIncrement(&nRefCount);
}

LONG CCertificate::Release()
{
    LONG ret = InterlockedDecrement(&nRefCount);

    if (!ret)
        delete this;
    return ret;
}

void CCertificate::ShowCertificate(HWND hParent)
{
    ViewCertificate(hParent, pDERData, nDERDataLen, pPKCS7Data, nPKCS7DataLen, Host);
}

bool CCertificate::CheckCertificate(LPTSTR buf, int maxlen)
{
    return ::CheckCertificate(pDERData, nDERDataLen, buf, maxlen, NULL, Host);
}

bool CCertificate::IsSame(BYTE* pDERCert, int DERCertLen, BYTE* pPKCS7Cert, int PKCS7CertLen)
{
    if (DERCertLen != nDERDataLen)
        return false;
    if (PKCS7CertLen != nPKCS7DataLen)
        return false;
    if (memcmp(pDERData, pDERCert, nDERDataLen))
        return false;
    return memcmp(pPKCS7Data, pPKCS7Cert, nPKCS7DataLen) ? false : true;
}
