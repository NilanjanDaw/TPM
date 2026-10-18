//** Description
// Integration test suite for TPM2_CertifyIntegrated (0x000001B2),
// TPM_RH_INTEGRATED (0x4000000E), TPMI_RH_INTEGRATED,
// TPM2B_INTEGRATED_ATTEST, TPM_ST_ATTEST_INTEGRATED (0x801E),
// TPM_PT_MAX_INTEGRATED_ATTEST (0x00000132), and the platform
// Integrated Signer interface.

#include "Tpm.h"
#include "CertifyIntegrated_fp.h"
#include <prototypes/platform_public_interface.h>
#include <platform_interface/tpm_to_platform_interface.h>
#include <platform_interface/platform_to_tpm_interface.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ASSERT(cond, msg)                                                \
    do {                                                                      \
        if(!(cond)) {                                                         \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); \
            exit(1);                                                          \
        }                                                                     \
    } while(0)

static void PutU8(BYTE** p, UINT8 v) { **p = v; (*p) += 1; }
static void PutU16(BYTE** p, UINT16 v) { UINT16_TO_BYTE_ARRAY(v, *p); (*p) += 2; }
static void PutU32(BYTE** p, UINT32 v) { UINT32_TO_BYTE_ARRAY(v, *p); (*p) += 4; }
static void PutBytes(BYTE** p, const void* src, size_t len)
{
    if(len > 0 && src != NULL)
        memcpy(*p, src, len);
    else if(len > 0)
        memset(*p, 0, len);
    (*p) += len;
}
static void Put2B(BYTE** p, const void* src, UINT16 len)
{
    PutU16(p, len);
    PutBytes(p, src, len);
}
static void PutPwSession(BYTE** p, const void* pw, UINT16 pwLen)
{
    PutU32(p, (UINT32)(9 + pwLen));
    PutU32(p, TPM_RS_PW);
    PutU16(p, 0);
    PutU8(p, 0x01);  // continueSession
    Put2B(p, pw, pwLen);
}

static UINT8 GetU8(const BYTE** p, const BYTE* end)
{
    TEST_ASSERT(*p + 1 <= end, "Buffer underflow in GetU8");
    return *((*p)++);
}
static UINT16 GetU16(const BYTE** p, const BYTE* end)
{
    UINT16 v;
    TEST_ASSERT(*p + 2 <= end, "Buffer underflow in GetU16");
    v = BYTE_ARRAY_TO_UINT16(*p);
    (*p) += 2;
    return v;
}
static UINT32 GetU32(const BYTE** p, const BYTE* end)
{
    UINT32 v;
    TEST_ASSERT(*p + 4 <= end, "Buffer underflow in GetU32");
    v = BYTE_ARRAY_TO_UINT32(*p);
    (*p) += 4;
    return v;
}

static TPM_RC RunTpmCommand(
    BYTE* cmdBuf, uint32_t cmdSize, BYTE** respBufOut, uint32_t* respSizeOut)
{
    static BYTE    s_respStorage[MAX_RESPONSE_SIZE];
    unsigned char* respPtr  = s_respStorage;
    uint32_t       respSize = sizeof(s_respStorage);
    const BYTE*    rp;
    const BYTE*    rend;
    UINT32         totalSize;
    TPM_RC         rc;

    UINT32_TO_BYTE_ARRAY(cmdSize, cmdBuf + 2);
    _plat__LocalitySet(0);
    _plat__RunCommand(cmdSize, cmdBuf, &respSize, &respPtr);
    TEST_ASSERT(respSize >= 10, "Response smaller than 10-byte header");

    rp        = respPtr;
    rend      = respPtr + respSize;
    (void)GetU16(&rp, rend);
    totalSize = GetU32(&rp, rend);
    rc        = GetU32(&rp, rend);
    TEST_ASSERT(totalSize == respSize, "Response size header mismatch");
    if(respBufOut != NULL) *respBufOut = respPtr;
    if(respSizeOut != NULL) *respSizeOut = respSize;
    return rc;
}

static TPM_RC SendHierarchyChangeAuth(
    TPM_HANDLE authHandle, const void* curAuth, UINT16 curAuthSize,
    const void* newAuth, UINT16 newAuthSize)
{
    BYTE  cmd[MAX_COMMAND_SIZE];
    BYTE* cp = cmd;

    PutU16(&cp, TPM_ST_SESSIONS);
    PutU32(&cp, 0);
    PutU32(&cp, TPM_CC_HierarchyChangeAuth);
    PutU32(&cp, authHandle);
    PutPwSession(&cp, curAuth, curAuthSize);
    Put2B(&cp, newAuth, newAuthSize);
    return RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL);
}

#if CC_CertifyIntegrated && SIMULATION

static UINT64 GetU64(const BYTE** p, const BYTE* end)
{
    UINT64 v;
    TEST_ASSERT(*p + 8 <= end, "Buffer underflow in GetU64");
    v = BYTE_ARRAY_TO_UINT64(*p);
    (*p) += 8;
    return v;
}
static void GetBytes(const BYTE** p, const BYTE* end, void* dst, size_t len)
{
    TEST_ASSERT(*p + len <= end, "Buffer underflow in GetBytes");
    if(len > 0 && dst != NULL)
        memcpy(dst, *p, len);
    (*p) += len;
}

static int g_customSignerCalls = 0;

static uint32_t CustomTestIntegratedSigner(
    uint16_t hashAlg, const uint8_t* signerInputDigest, uint16_t signerInputDigestSize,
    const uint8_t* signerParams, uint16_t signerParamsSize,
    uint16_t maxAttestSize, uint8_t* attestBuffer, uint16_t* attestSize)
{
    const char prefix[]  = "CUSTOM_SIGNER_V1:";
    uint16_t   prefixLen = (uint16_t)(sizeof(prefix) - 1);
    uint16_t   totalLen  = prefixLen + 2 + signerInputDigestSize + signerParamsSize;

    g_customSignerCalls++;
    if(signerParamsSize == 5 && memcmp(signerParams, "RETRY", 5) == 0)
        return PLAT_INTEGRATED_ATTEST_RETRY;
    if(signerParamsSize == 6 && memcmp(signerParams, "VENDOR", 6) == 0)
        return 0x0000052Au;
    if(signerParamsSize == 4 && memcmp(signerParams, "WARN", 4) == 0)
        return 0x00000D2Au;
    if(signerParamsSize == 4 && memcmp(signerParams, "RESV", 4) == 0)
        return 0x00000700u;
    if(signerParamsSize == 7 && memcmp(signerParams, "BADSIZE", 7) == 0)
        return PLAT_INTEGRATED_ATTEST_INVALID_SIZE;
    if(signerParamsSize == 5 && memcmp(signerParams, "EMPTY", 5) == 0)
    {
        *attestSize = 0;
        return PLAT_INTEGRATED_ATTEST_SUCCESS;
    }
    if(signerParamsSize == 7 && memcmp(signerParams, "MAXSIZE", 7) == 0)
    {
        memset(attestBuffer, 0x5A, maxAttestSize);
        *attestSize = maxAttestSize;
        return PLAT_INTEGRATED_ATTEST_SUCCESS;
    }
    if(signerParamsSize == 7 && memcmp(signerParams, "OVERMAX", 7) == 0)
    {
        *attestSize = (uint16_t)(maxAttestSize + 1u);
        return PLAT_INTEGRATED_ATTEST_SUCCESS;
    }
    if(attestSize == NULL || attestBuffer == NULL || totalLen > maxAttestSize)
        return PLAT_INTEGRATED_ATTEST_UNAVAILABLE;
    memcpy(attestBuffer, prefix, prefixLen);
    UINT16_TO_BYTE_ARRAY(hashAlg, attestBuffer + prefixLen);
    memcpy(attestBuffer + prefixLen + 2, signerInputDigest, signerInputDigestSize);
    if(signerParamsSize > 0 && signerParams != NULL)
        memcpy(attestBuffer + prefixLen + 2 + signerInputDigestSize, signerParams, signerParamsSize);
    *attestSize = totalLen;
    return PLAT_INTEGRATED_ATTEST_SUCCESS;
}

static TPM_RC SendCertifyIntegratedAuth(
    TPM_HANDLE signHandle, const void* authPw, UINT16 authPwSize,
    TPM_HANDLE objectHandle, const void* qualData, UINT16 qualDataSize,
    const BYTE* creationHash, UINT16 creationHashSize, const TPMT_TK_CREATION* ticket,
    const void* signerParams, UINT16 signerParamsSize, BYTE** respBufOut, uint32_t* respSizeOut)
{
    BYTE  cmd[MAX_COMMAND_SIZE];
    BYTE* cp = cmd;

    PutU16(&cp, TPM_ST_SESSIONS);
    PutU32(&cp, 0);
    PutU32(&cp, TPM_CC_CertifyIntegrated);
    PutU32(&cp, signHandle);
    PutU32(&cp, objectHandle);
    PutPwSession(&cp, authPw, authPwSize);
    Put2B(&cp, qualData, qualDataSize);
    Put2B(&cp, creationHash, creationHashSize);
    PutU16(&cp, ticket->tag);
    PutU32(&cp, ticket->hierarchy);
    Put2B(&cp, ticket->digest.t.buffer, ticket->digest.t.size);
    Put2B(&cp, signerParams, signerParamsSize);
    return RunTpmCommand(cmd, (uint32_t)(cp - cmd), respBufOut, respSizeOut);
}

static TPM_RC SendCertifyIntegrated(
    TPM_HANDLE objectHandle, const void* qualData, UINT16 qualDataSize,
    const BYTE* creationHash, UINT16 creationHashSize, const TPMT_TK_CREATION* ticket,
    const void* signerParams, UINT16 signerParamsSize, BYTE** respBufOut, uint32_t* respSizeOut)
{
    return SendCertifyIntegratedAuth(TPM_RH_INTEGRATED, NULL, 0, objectHandle,
                                     qualData, qualDataSize, creationHash, creationHashSize,
                                     ticket, signerParams, signerParamsSize, respBufOut, respSizeOut);
}

static void ParseCertifyIntegratedResponseAlg(
    TPM_ALG_ID hashAlg, UINT16 digestSize, const BYTE* respBuf, uint32_t respSize,
    const BYTE** certifyInfoPtr, UINT16* certifyInfoSize,
    const BYTE** attestPtr, UINT16* attestSize, BYTE* expectedDigestOut)
{
    const BYTE* rp        = respBuf + 10;
    const BYTE* rend      = respBuf + respSize;
    UINT32      paramSize = GetU32(&rp, rend);
    const BYTE* pend      = rp + paramSize;

    TEST_ASSERT(pend <= rend, "parameterSize exceeds response buffer");
    *certifyInfoSize = GetU16(&rp, pend);
    *certifyInfoPtr  = rp;
    GetBytes(&rp, pend, NULL, *certifyInfoSize);
    *attestSize = GetU16(&rp, pend);
    *attestPtr  = rp;
    GetBytes(&rp, pend, NULL, *attestSize);
    TEST_ASSERT(rp == pend, "Trailing bytes in CertifyIntegrated parameters");
    CryptHashBlock(hashAlg, *certifyInfoSize, *certifyInfoPtr, digestSize, expectedDigestOut);
}

static void ParseCertifyIntegratedResponse(
    const BYTE* respBuf, uint32_t respSize, const BYTE** certifyInfoPtr, UINT16* certifyInfoSize,
    const BYTE** attestPtr, UINT16* attestSize, BYTE expectedDigestOut[32])
{
    ParseCertifyIntegratedResponseAlg(TPM_ALG_SHA256, 32, respBuf, respSize,
                                      certifyInfoPtr, certifyInfoSize,
                                      attestPtr, attestSize, expectedDigestOut);
}

typedef struct
{
    TPM_HANDLE       handle;
    BYTE             creationHash[64];
    UINT16           creationHashSize;
    TPMT_TK_CREATION ticket;
    BYTE             name[68];
    UINT16           nameSize;
    TPM_ALG_ID       nameAlg;
} CREATED_PRIMARY_OBJ;

static void CreatePrimaryKeyedHash(
    TPM_HANDLE hierarchy, TPM_ALG_ID nameAlg, const char* uniqueStr, CREATED_PRIMARY_OBJ* outObj)
{
    BYTE        cmd[MAX_COMMAND_SIZE];
    BYTE*       cp = cmd;
    BYTE*       respBuf = NULL;
    uint32_t    respSize = 0;
    const BYTE* rp;
    const BYTE* rend;
    UINT16      uniqueLen = (UINT16)strlen(uniqueStr);

    PutU16(&cp, TPM_ST_SESSIONS);
    PutU32(&cp, 0);
    PutU32(&cp, TPM_CC_CreatePrimary);
    PutU32(&cp, hierarchy);
    PutPwSession(&cp, NULL, 0);
    PutU16(&cp, 4); PutU16(&cp, 0); PutU16(&cp, 0);
    PutU16(&cp, (UINT16)(16 + uniqueLen));
    PutU16(&cp, TPM_ALG_KEYEDHASH);
    PutU16(&cp, nameAlg);
    PutU32(&cp, 0x00040072);
    PutU16(&cp, 0);
    PutU16(&cp, TPM_ALG_HMAC);
    PutU16(&cp, TPM_ALG_SHA256);
    Put2B(&cp, uniqueStr, uniqueLen);
    Put2B(&cp, "creation-freshness-nonce", 24);
    PutU32(&cp, 0);
    TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize) == TPM_RC_SUCCESS,
                "TPM2_CreatePrimary failed");

    rp       = respBuf + 10;
    rend     = respBuf + respSize;
    outObj->handle = GetU32(&rp, rend);
    (void)GetU32(&rp, rend);
    GetBytes(&rp, rend, NULL, GetU16(&rp, rend));  // outPublic
    GetBytes(&rp, rend, NULL, GetU16(&rp, rend));  // creationData
    outObj->creationHashSize = GetU16(&rp, rend);
    GetBytes(&rp, rend, outObj->creationHash, outObj->creationHashSize);
    outObj->ticket.tag           = GetU16(&rp, rend);
    outObj->ticket.hierarchy     = GetU32(&rp, rend);
    outObj->ticket.digest.t.size = GetU16(&rp, rend);
    GetBytes(&rp, rend, outObj->ticket.digest.t.buffer, outObj->ticket.digest.t.size);
    outObj->nameSize = GetU16(&rp, rend);
    GetBytes(&rp, rend, outObj->name, outObj->nameSize);
    outObj->nameAlg = nameAlg;
}

static void HmacSha256(
    const BYTE* key, UINT16 keyLen, const BYTE* msg, UINT32 msgLen, BYTE outHmac[32])
{
    BYTE   k[64];
    BYTE   inner[32];
    BYTE*  buf = (BYTE*)malloc(64 + msgLen + 32);
    size_t i;

    TEST_ASSERT(buf != NULL, "malloc failed in HmacSha256");
    memset(k, 0, sizeof(k));
    if(keyLen > 64)
        CryptHashBlock(TPM_ALG_SHA256, keyLen, key, 32, k);
    else if(keyLen > 0 && key != NULL)
        memcpy(k, key, keyLen);
    for(i = 0; i < 64; i++) buf[i] = (BYTE)(k[i] ^ 0x36u);
    memcpy(buf + 64, msg, msgLen);
    CryptHashBlock(TPM_ALG_SHA256, 64 + msgLen, buf, 32, inner);
    for(i = 0; i < 64; i++) buf[i] = (BYTE)(k[i] ^ 0x5cu);
    memcpy(buf + 64, inner, 32);
    CryptHashBlock(TPM_ALG_SHA256, 64 + 32, buf, 32, outHmac);
    free(buf);
}

static TPM_HANDLE StartAuthSessionSimple(
    TPM_SE sessionType, BYTE nonceTPMOut[32], UINT16* nonceTPMLenOut)
{
    BYTE        cmd[128];
    BYTE*       cp = cmd;
    BYTE        nonceCaller[16];
    BYTE*       respBuf = NULL;
    uint32_t    respSize = 0;
    const BYTE* rp;
    const BYTE* rend;
    TPM_HANDLE  sessionHandle;

    memset(nonceCaller, 0x11, sizeof(nonceCaller));
    PutU16(&cp, TPM_ST_NO_SESSIONS);
    PutU32(&cp, 0);
    PutU32(&cp, TPM_CC_StartAuthSession);
    PutU32(&cp, TPM_RH_NULL);
    PutU32(&cp, TPM_RH_NULL);
    Put2B(&cp, nonceCaller, sizeof(nonceCaller));
    PutU16(&cp, 0);
    PutU8(&cp, sessionType);
    PutU16(&cp, TPM_ALG_NULL);
    PutU16(&cp, TPM_ALG_SHA256);
    TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize) == TPM_RC_SUCCESS,
                "TPM2_StartAuthSession failed");
    rp                = respBuf + 10;
    rend              = respBuf + respSize;
    sessionHandle     = GetU32(&rp, rend);
    *nonceTPMLenOut   = GetU16(&rp, rend);
    GetBytes(&rp, rend, nonceTPMOut, *nonceTPMLenOut);
    return sessionHandle;
}

static void FlushContextHandle(TPM_HANDLE handle)
{
    BYTE  cmd[32];
    BYTE* cp = cmd;

    PutU16(&cp, TPM_ST_NO_SESSIONS);
    PutU32(&cp, 0);
    PutU32(&cp, TPM_CC_FlushContext);
    PutU32(&cp, handle);
    TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL) == TPM_RC_SUCCESS,
                "TPM2_FlushContext failed");
}

static uint32_t BuildHmacAuthArea(
    BYTE* outAuth, TPM_HANDLE sessionHandle, const BYTE* nonceCaller, UINT16 nonceCallerLen,
    const BYTE* nonceTPM, UINT16 nonceTPMLen, TPM_CC commandCode,
    const BYTE* handleNames, UINT32 handleNamesLen, const BYTE* params, UINT32 paramsLen,
    const BYTE* authVal, UINT16 authLen, BYTE sessionAttrs)
{
    BYTE   cpBuf[MAX_COMMAND_SIZE];
    BYTE*  p = cpBuf;
    BYTE   cpHash[32];
    BYTE   hmacMsg[256];
    BYTE   hmac[32];
    UINT32 msgLen = 0;
    UINT16 trimmedLen = authLen;
    BYTE*  ap = outAuth;

    while(trimmedLen > 0 && authVal[trimmedLen - 1] == 0)
        trimmedLen--;
    PutU32(&p, commandCode);
    PutBytes(&p, handleNames, handleNamesLen);
    PutBytes(&p, params, paramsLen);
    CryptHashBlock(TPM_ALG_SHA256, (UINT32)(p - cpBuf), cpBuf, 32, cpHash);

    memcpy(hmacMsg + msgLen, cpHash, 32); msgLen += 32;
    memcpy(hmacMsg + msgLen, nonceCaller, nonceCallerLen); msgLen += nonceCallerLen;
    memcpy(hmacMsg + msgLen, nonceTPM, nonceTPMLen); msgLen += nonceTPMLen;
    hmacMsg[msgLen++] = sessionAttrs;
    HmacSha256(authVal, trimmedLen, hmacMsg, msgLen, hmac);

    PutU32(&ap, (UINT32)(4 + 2 + nonceCallerLen + 1 + 2 + 32));
    PutU32(&ap, sessionHandle);
    Put2B(&ap, nonceCaller, nonceCallerLen);
    PutU8(&ap, sessionAttrs);
    Put2B(&ap, hmac, 32);
    return (uint32_t)(ap - outAuth);
}

static BOOL VerifyResponseHmac(
    const BYTE* respBuf, uint32_t respSize, TPM_CC commandCode,
    const BYTE* nonceCaller, UINT16 nonceCallerLen, const BYTE* authVal, UINT16 authLen)
{
    const BYTE* rp        = respBuf + 10;
    const BYTE* rend      = respBuf + respSize;
    UINT32      paramSize = GetU32(&rp, rend);
    const BYTE* params    = rp;
    const BYTE* ap        = params + paramSize;
    UINT16      nonceTPMLen;
    const BYTE* nonceTPM;
    BYTE        sessionAttrs;
    UINT16      hmacLen;
    const BYTE* respHmac;
    BYTE*       rpBuf;
    BYTE        rpHash[32];
    BYTE        hmacMsg[256];
    BYTE        calcHmac[32];
    UINT32      msgLen = 0;
    UINT16      trimmedLen = authLen;

    rp          = ap;
    nonceTPMLen = GetU16(&rp, rend);
    nonceTPM    = rp;
    GetBytes(&rp, rend, NULL, nonceTPMLen);
    sessionAttrs = GetU8(&rp, rend);
    hmacLen      = GetU16(&rp, rend);
    respHmac     = rp;
    GetBytes(&rp, rend, NULL, hmacLen);

    while(trimmedLen > 0 && authVal[trimmedLen - 1] == 0)
        trimmedLen--;
    rpBuf = (BYTE*)malloc(8 + paramSize);
    TEST_ASSERT(rpBuf != NULL, "malloc failed in VerifyResponseHmac");
    UINT32_TO_BYTE_ARRAY(TPM_RC_SUCCESS, rpBuf);
    UINT32_TO_BYTE_ARRAY(commandCode, rpBuf + 4);
    if(paramSize > 0)
        memcpy(rpBuf + 8, params, paramSize);
    CryptHashBlock(TPM_ALG_SHA256, 8 + paramSize, rpBuf, 32, rpHash);
    free(rpBuf);

    memcpy(hmacMsg + msgLen, rpHash, 32); msgLen += 32;
    memcpy(hmacMsg + msgLen, nonceTPM, nonceTPMLen); msgLen += nonceTPMLen;
    memcpy(hmacMsg + msgLen, nonceCaller, nonceCallerLen); msgLen += nonceCallerLen;
    hmacMsg[msgLen++] = sessionAttrs;
    HmacSha256(authVal, trimmedLen, hmacMsg, msgLen, calcHmac);
    return (hmacLen == 32 && memcmp(calcHmac, respHmac, 32) == 0);
}

static TPM_HANDLE StartAuthSessionEx(
    TPM_HANDLE bindHandle, TPM_SE sessionType, TPM_ALG_ID symAlg,
    UINT16 symKeyBits, TPM_ALG_ID symMode, const BYTE* nonceCaller,
    UINT16 nonceCallerLen, BYTE nonceTPMOut[32], UINT16* nonceTPMLenOut)
{
    BYTE        cmd[128];
    BYTE*       cp = cmd;
    BYTE*       respBuf = NULL;
    uint32_t    respSize = 0;
    const BYTE* rp;
    const BYTE* rend;
    TPM_HANDLE  sessionHandle;

    PutU16(&cp, TPM_ST_NO_SESSIONS);
    PutU32(&cp, 0);
    PutU32(&cp, TPM_CC_StartAuthSession);
    PutU32(&cp, TPM_RH_NULL);
    PutU32(&cp, bindHandle);
    Put2B(&cp, nonceCaller, nonceCallerLen);
    PutU16(&cp, 0);
    PutU8(&cp, sessionType);
    PutU16(&cp, symAlg);
    if(symAlg != TPM_ALG_NULL && symAlg != TPM_ALG_XOR)
    {
        PutU16(&cp, symKeyBits);
        PutU16(&cp, symMode);
    }
    else if(symAlg == TPM_ALG_XOR)
    {
        PutU16(&cp, TPM_ALG_SHA256);
    }
    PutU16(&cp, TPM_ALG_SHA256);
    TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize) == TPM_RC_SUCCESS,
                "TPM2_StartAuthSession (Ex) failed");
    rp              = respBuf + 10;
    rend            = respBuf + respSize;
    sessionHandle   = GetU32(&rp, rend);
    *nonceTPMLenOut = GetU16(&rp, rend);
    GetBytes(&rp, rend, nonceTPMOut, *nonceTPMLenOut);
    return sessionHandle;
}

static uint32_t BuildHmacAuthAreaNoSize(
    BYTE* outAuth, TPM_HANDLE sessionHandle, const BYTE* nonceCaller, UINT16 nonceCallerLen,
    const BYTE* nonceTPM, UINT16 nonceTPMLen, TPM_CC commandCode,
    const BYTE* handleNames, UINT32 handleNamesLen, const BYTE* params, UINT32 paramsLen,
    const BYTE* authVal, UINT16 authLen, BYTE sessionAttrs)
{
    BYTE   tmp[128];
    UINT32 fullLen = BuildHmacAuthArea(tmp, sessionHandle, nonceCaller, nonceCallerLen,
                                       nonceTPM, nonceTPMLen, commandCode,
                                       handleNames, handleNamesLen, params, paramsLen,
                                       authVal, authLen, sessionAttrs);
    memcpy(outAuth, tmp + 4, fullLen - 4);
    return fullLen - 4;
}

static void RunAdversarialProbes(
    TPM_HANDLE objectHandle, const BYTE* creationHash, UINT16 creationHashSize,
    const TPMT_TK_CREATION* creationTicketPtr, const BYTE* objectName, UINT16 objectNameSize)
{
    BYTE             cmd[MAX_COMMAND_SIZE];
    BYTE*            cp;
    BYTE*            respBuf  = NULL;
    uint32_t         respSize = 0;
    TPM_RC           rc;
    TPMT_TK_CREATION creationTicket = *creationTicketPtr;

    // Probe 1: Parameter Encryption & Decryption (TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT)
    // on Session 0 (authorizing TPM_RH_INTEGRATED) with XOR
    {
        const char  intAuth[] = "xor-enc-dec-auth-key";
        BYTE        startNonceCaller[16];
        BYTE        cmdNonceCaller[16];
        BYTE        nonceTPM[32];
        UINT16      nonceTPMLen = 0;
        TPM_HANDLE  sess;
        TPM2B_DATA  sessionKey;
        TPM2B_NONCE nCaller2B, nTpm2B;
        BYTE        plainQd[20];
        BYTE        encQd[20];
        BYTE        handleNames[4 + 68];
        BYTE        paramsEnc[512];
        BYTE        authArea[128];
        BYTE*       hp;
        BYTE*       pp;
        UINT32      authLen;
        const BYTE* rp;
        const BYTE* rend;
        UINT32      paramSize;
        const BYTE* wireParams;
        UINT16      certInfoSize;
        BYTE        decCertInfo[512];
        const BYTE* ap;
        const BYTE* aend;
        const BYTE* respAuthPtr;
        UINT16      respNonceTPMLen;

        rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, NULL, 0,
                                     intAuth, (UINT16)(sizeof(intAuth) - 1));
        TEST_ASSERT(rc == TPM_RC_SUCCESS, "Adv1: Set integratedAuth failed");

        memset(startNonceCaller, 0x41, sizeof(startNonceCaller));
        memset(cmdNonceCaller, 0x42, sizeof(cmdNonceCaller));
        sess = StartAuthSessionEx(TPM_RH_NULL, TPM_SE_HMAC, TPM_ALG_XOR, 0, TPM_ALG_NULL,
                                  startNonceCaller, sizeof(startNonceCaller),
                                  nonceTPM, &nonceTPMLen);

        sessionKey.t.size = (UINT16)(sizeof(intAuth) - 1);
        memcpy(sessionKey.t.buffer, intAuth, sessionKey.t.size);
        nCaller2B.t.size = sizeof(cmdNonceCaller);
        memcpy(nCaller2B.t.buffer, cmdNonceCaller, sizeof(cmdNonceCaller));
        nTpm2B.t.size = nonceTPMLen;
        memcpy(nTpm2B.t.buffer, nonceTPM, nonceTPMLen);

        memcpy(plainQd, "secret-qual-data-20!", 20);
        CryptKDFa(TPM_ALG_SHA256, &sessionKey.b, XOR_KEY, &nCaller2B.b, &nTpm2B.b,
                  20 * 8, encQd, NULL, FALSE);
        {
            size_t i;
            for(i = 0; i < 20; i++)
                encQd[i] ^= plainQd[i];
        }

        hp = handleNames;
        PutU32(&hp, TPM_RH_INTEGRATED);
        PutBytes(&hp, objectName, objectNameSize);

        pp = paramsEnc;
        Put2B(&pp, encQd, 20);
        Put2B(&pp, creationHash, creationHashSize);
        PutU16(&pp, creationTicket.tag);
        PutU32(&pp, creationTicket.hierarchy);
        Put2B(&pp, creationTicket.digest.t.buffer, creationTicket.digest.t.size);
        Put2B(&pp, NULL, 0);

        // Session attributes: continueSession(0x01) | decrypt(0x20) | encrypt(0x40) = 0x61
        authLen = BuildHmacAuthArea(authArea, sess, cmdNonceCaller, sizeof(cmdNonceCaller),
                                    nonceTPM, nonceTPMLen, TPM_CC_CertifyIntegrated,
                                    handleNames, (UINT32)(hp - handleNames),
                                    paramsEnc, (UINT32)(pp - paramsEnc),
                                    (const BYTE*)intAuth, (UINT16)(sizeof(intAuth) - 1), 0x61);

        cp = cmd;
        PutU16(&cp, TPM_ST_SESSIONS);
        PutU32(&cp, 0);
        PutU32(&cp, TPM_CC_CertifyIntegrated);
        PutU32(&cp, TPM_RH_INTEGRATED);
        PutU32(&cp, objectHandle);
        PutBytes(&cp, authArea, authLen);
        PutBytes(&cp, paramsEnc, (size_t)(pp - paramsEnc));

        rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize);
        TEST_ASSERT(rc == TPM_RC_SUCCESS,
                    "Adv1: CertifyIntegrated with XOR DECRYPT|ENCRYPT session failed");
        TEST_ASSERT(VerifyResponseHmac(respBuf, respSize, TPM_CC_CertifyIntegrated,
                                       cmdNonceCaller, sizeof(cmdNonceCaller),
                                       (const BYTE*)intAuth, (UINT16)(sizeof(intAuth) - 1)),
                    "Adv1: Response HMAC over encrypted parameters failed");

        rp           = respBuf + 10;
        rend         = respBuf + respSize;
        paramSize    = GetU32(&rp, rend);
        wireParams   = rp;
        certInfoSize = GetU16(&rp, rend);
        TEST_ASSERT(certInfoSize <= sizeof(decCertInfo), "Adv1: certInfoSize too large");

        respAuthPtr     = wireParams + paramSize;
        respNonceTPMLen = GetU16(&respAuthPtr, rend);
        nTpm2B.t.size   = respNonceTPMLen;
        memcpy(nTpm2B.t.buffer, respAuthPtr, respNonceTPMLen);

        CryptKDFa(TPM_ALG_SHA256, &sessionKey.b, XOR_KEY, &nTpm2B.b, &nCaller2B.b,
                  certInfoSize * 8, decCertInfo, NULL, FALSE);
        {
            size_t i;
            for(i = 0; i < certInfoSize; i++)
                decCertInfo[i] ^= rp[i];
        }

        ap   = decCertInfo;
        aend = decCertInfo + certInfoSize;
        TEST_ASSERT(GetU32(&ap, aend) == TPM_GENERATED_VALUE,
                    "Adv1: Decrypted certifyInfo magic != TPM_GENERATED_VALUE");
        TEST_ASSERT(GetU16(&ap, aend) == TPM_ST_ATTEST_INTEGRATED,
                    "Adv1: Decrypted certifyInfo type != TPM_ST_ATTEST_INTEGRATED");
        TEST_ASSERT(GetU16(&ap, aend) == 4 && GetU32(&ap, aend) == TPM_RH_INTEGRATED,
                    "Adv1: Decrypted qualifiedSigner != TPM_RH_INTEGRATED");
        TEST_ASSERT(GetU16(&ap, aend) == 20 && memcmp(ap, plainQd, 20) == 0,
                    "Adv1: Decrypted extraData != plaintext qualifyingData");

        FlushContextHandle(sess);
        rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, intAuth, (UINT16)(sizeof(intAuth) - 1),
                                     NULL, 0);
        TEST_ASSERT(rc == TPM_RC_SUCCESS, "Adv1: Reset integratedAuth failed");
    }

    // Probe 2: 2-Session AES-128-CFB Parameter Decryption & Encryption on Session 1
    // alongside Authorizing Session 0 (TPM_RH_INTEGRATED)
    {
        const char  intAuth[] = "sess0-integrated-auth";
        BYTE        nc0[16], nc1[16], snc0[16], snc1[16];
        BYTE        nt0[32], nt1[32];
        UINT16      nt0Len = 0, nt1Len = 0;
        TPM_HANDLE  sess0, sess1;
        TPM2B_NONCE nCaller1, nTpm1;
        TPM2B_AUTH  emptyKey;
        TPM2B_IV    iv2B;
        BYTE        keyIv[32];
        BYTE        plainQd[16];
        BYTE        encQd[16];
        BYTE        handleNames[4 + 68];
        BYTE        paramsEnc[512];
        BYTE        auth0[128], auth1[128];
        UINT32      auth0Len, auth1Len;
        BYTE*       hp;
        BYTE*       pp;
        const BYTE* rp;
        const BYTE* rend;
        UINT16      wireCertSize;

        rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, NULL, 0,
                                     intAuth, (UINT16)(sizeof(intAuth) - 1));
        TEST_ASSERT(rc == TPM_RC_SUCCESS, "Adv2: Set integratedAuth failed");

        memset(snc0, 0x51, 16);
        memset(snc1, 0x52, 16);
        memset(nc0, 0x53, 16);
        memset(nc1, 0x54, 16);
        sess0 = StartAuthSessionEx(TPM_RH_NULL, TPM_SE_HMAC, TPM_ALG_NULL, 0, TPM_ALG_NULL,
                                   snc0, 16, nt0, &nt0Len);
        sess1 = StartAuthSessionEx(TPM_RH_NULL, TPM_SE_HMAC, TPM_ALG_AES, 128, TPM_ALG_CFB,
                                   snc1, 16, nt1, &nt1Len);

        nCaller1.t.size = 16;
        memcpy(nCaller1.t.buffer, nc1, 16);
        nTpm1.t.size = nt1Len;
        memcpy(nTpm1.t.buffer, nt1, nt1Len);
        emptyKey.t.size = 0;

        memcpy(plainQd, "aes128cfb-qd-16!", 16);
        CryptKDFa(TPM_ALG_SHA256, &emptyKey.b, CFB_KEY, &nCaller1.b, &nTpm1.b,
                  256, keyIv, NULL, FALSE);
        iv2B.t.size = 16;
        memcpy(iv2B.t.buffer, keyIv + 16, 16);
        CryptSymmetricEncrypt(encQd, TPM_ALG_AES, 128, keyIv, &iv2B, TPM_ALG_CFB, 16, plainQd);

        hp = handleNames;
        PutU32(&hp, TPM_RH_INTEGRATED);
        PutBytes(&hp, objectName, objectNameSize);

        pp = paramsEnc;
        Put2B(&pp, encQd, 16);
        Put2B(&pp, creationHash, creationHashSize);
        PutU16(&pp, creationTicket.tag);
        PutU32(&pp, creationTicket.hierarchy);
        Put2B(&pp, creationTicket.digest.t.buffer, creationTicket.digest.t.size);
        Put2B(&pp, NULL, 0);

        // Session 0: authorizing TPM_RH_INTEGRATED, continueSession (0x01).
        // Per TPM 2.0 Part 1 (ComputeCommandHMAC), Session 0 includes nonceTPMdecrypt (nt1).
        {
            BYTE nt0And1[64];
            memcpy(nt0And1, nt0, nt0Len);
            memcpy(nt0And1 + nt0Len, nt1, nt1Len);
            auth0Len = BuildHmacAuthAreaNoSize(
                auth0, sess0, nc0, 16, nt0And1, (UINT16)(nt0Len + nt1Len),
                TPM_CC_CertifyIntegrated,
                handleNames, (UINT32)(hp - handleNames), paramsEnc, (UINT32)(pp - paramsEnc),
                (const BYTE*)intAuth, (UINT16)(sizeof(intAuth) - 1), 0x01);
        }
        // Session 1: non-authorizing encrypt/decrypt session, continue|decrypt|encrypt (0x61)
        auth1Len = BuildHmacAuthAreaNoSize(
            auth1, sess1, nc1, 16, nt1, nt1Len, TPM_CC_CertifyIntegrated,
            handleNames, (UINT32)(hp - handleNames), paramsEnc, (UINT32)(pp - paramsEnc),
            NULL, 0, 0x61);

        cp = cmd;
        PutU16(&cp, TPM_ST_SESSIONS);
        PutU32(&cp, 0);
        PutU32(&cp, TPM_CC_CertifyIntegrated);
        PutU32(&cp, TPM_RH_INTEGRATED);
        PutU32(&cp, objectHandle);
        PutU32(&cp, auth0Len + auth1Len);
        PutBytes(&cp, auth0, auth0Len);
        PutBytes(&cp, auth1, auth1Len);
        PutBytes(&cp, paramsEnc, (size_t)(pp - paramsEnc));

        rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize);
        TEST_ASSERT(rc == TPM_RC_SUCCESS,
                    "Adv2: 2-session AES-128-CFB DECRYPT|ENCRYPT failed");

        rp   = respBuf + 10;
        rend = respBuf + respSize;
        (void)GetU32(&rp, rend);
        wireCertSize = GetU16(&rp, rend);
        TEST_ASSERT(wireCertSize > 20 && memcmp(rp, "\xff\x54\x43\x47", 4) != 0,
                    "Adv2: Wire certifyInfo was not encrypted by AES-128-CFB");

        FlushContextHandle(sess0);
        FlushContextHandle(sess1);
        rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, intAuth, (UINT16)(sizeof(intAuth) - 1),
                                     NULL, 0);
        TEST_ASSERT(rc == TPM_RC_SUCCESS, "Adv2: Reset integratedAuth failed");
    }

    // Probe 3: Command Audit (TPM2_SetCommandCodeAuditStatus + TPM2_GetCommandAuditDigest)
    // and Session Audit (TPMA_SESSION_AUDIT)
    {
        const BYTE* rp;
        const BYTE* rend;
        UINT16      attLen;
        const BYTE* ap;
        const BYTE* aend;
        BYTE        auditDigestBefore[32];
        BYTE        auditDigestAfter[32];
        BYTE        snc[16], nc[16], nt[32];
        UINT16      ntLen = 0;
        TPM_HANDLE  auditSess;
        BYTE        handleNames[4 + 68];
        BYTE        paramsBuf[512];
        BYTE        authArea[128];
        UINT32      authLen;
        BYTE*       hp;
        BYTE*       pp;

        // Set command audit hash algorithm to TPM_ALG_SHA256 first (empty setList/clearList)
        cp = cmd;
        PutU16(&cp, TPM_ST_SESSIONS);
        PutU32(&cp, 0);
        PutU32(&cp, TPM_CC_SetCommandCodeAuditStatus);
        PutU32(&cp, TPM_RH_OWNER);
        PutPwSession(&cp, NULL, 0);
        PutU16(&cp, TPM_ALG_SHA256);
        PutU32(&cp, 0);
        PutU32(&cp, 0);
        rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL);
        TEST_ASSERT(rc == TPM_RC_SUCCESS,
                    "Adv3: SetCommandCodeAuditStatus(auditAlg=SHA256) failed");

        // Enable command audit for TPM_CC_CertifyIntegrated (0x000001B2)
        cp = cmd;
        PutU16(&cp, TPM_ST_SESSIONS);
        PutU32(&cp, 0);
        PutU32(&cp, TPM_CC_SetCommandCodeAuditStatus);
        PutU32(&cp, TPM_RH_OWNER);
        PutPwSession(&cp, NULL, 0);
        PutU16(&cp, TPM_ALG_SHA256);
        PutU32(&cp, 1);
        PutU32(&cp, TPM_CC_CertifyIntegrated);
        PutU32(&cp, 0);
        rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL);
        TEST_ASSERT(rc == TPM_RC_SUCCESS,
                    "Adv3: SetCommandCodeAuditStatus(enable) failed");

        // Read CommandAuditDigest before running CertifyIntegrated
        cp = cmd;
        PutU16(&cp, TPM_ST_SESSIONS);
        PutU32(&cp, 0);
        PutU32(&cp, TPM_CC_GetCommandAuditDigest);
        PutU32(&cp, TPM_RH_ENDORSEMENT);
        PutU32(&cp, TPM_RH_NULL);
        PutU32(&cp, 18);
        PutU32(&cp, TPM_RS_PW); PutU16(&cp, 0); PutU8(&cp, 0x01); PutU16(&cp, 0);
        PutU32(&cp, TPM_RS_PW); PutU16(&cp, 0); PutU8(&cp, 0x01); PutU16(&cp, 0);
        PutU16(&cp, 0);
        PutU16(&cp, TPM_ALG_NULL);
        rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize);
        TEST_ASSERT(rc == TPM_RC_SUCCESS, "Adv3: GetCommandAuditDigest(before) failed");
        rp     = respBuf + 10;
        rend   = respBuf + respSize;
        (void)GetU32(&rp, rend);
        attLen = GetU16(&rp, rend);
        ap     = rp;
        aend   = rp + attLen;
        (void)GetU32(&ap, aend);
        TEST_ASSERT(GetU16(&ap, aend) == TPM_ST_ATTEST_COMMAND_AUDIT,
                    "Adv3: Expected TPM_ST_ATTEST_COMMAND_AUDIT");
        GetBytes(&ap, aend, NULL, GetU16(&ap, aend));
        GetBytes(&ap, aend, NULL, GetU16(&ap, aend));
        (void)GetU64(&ap, aend);
        (void)GetU32(&ap, aend);
        (void)GetU32(&ap, aend);
        (void)GetU8(&ap, aend);
        (void)GetU64(&ap, aend);
        (void)GetU64(&ap, aend);
        (void)GetU16(&ap, aend);
        TEST_ASSERT(GetU16(&ap, aend) == 32, "Adv3: auditDigest size != 32");
        GetBytes(&ap, aend, auditDigestBefore, 32);

        // Execute TPM2_CertifyIntegrated with an AUDIT HMAC session (TPMA_SESSION_AUDIT = 0x80)
        memset(snc, 0x61, 16);
        memset(nc, 0x62, 16);
        auditSess = StartAuthSessionEx(TPM_RH_NULL, TPM_SE_HMAC, TPM_ALG_NULL, 0, TPM_ALG_NULL,
                                       snc, 16, nt, &ntLen);
        hp = handleNames;
        PutU32(&hp, TPM_RH_INTEGRATED);
        PutBytes(&hp, objectName, objectNameSize);
        pp = paramsBuf;
        Put2B(&pp, "audit-qd", 8);
        Put2B(&pp, creationHash, creationHashSize);
        PutU16(&pp, creationTicket.tag);
        PutU32(&pp, creationTicket.hierarchy);
        Put2B(&pp, creationTicket.digest.t.buffer, creationTicket.digest.t.size);
        Put2B(&pp, NULL, 0);
        // Session attributes: continueSession(0x01) | audit(0x80) = 0x81
        authLen = BuildHmacAuthArea(authArea, auditSess, nc, 16, nt, ntLen,
                                    TPM_CC_CertifyIntegrated,
                                    handleNames, (UINT32)(hp - handleNames),
                                    paramsBuf, (UINT32)(pp - paramsBuf),
                                    NULL, 0, 0x81);
        cp = cmd;
        PutU16(&cp, TPM_ST_SESSIONS);
        PutU32(&cp, 0);
        PutU32(&cp, TPM_CC_CertifyIntegrated);
        PutU32(&cp, TPM_RH_INTEGRATED);
        PutU32(&cp, objectHandle);
        PutBytes(&cp, authArea, authLen);
        PutBytes(&cp, paramsBuf, (size_t)(pp - paramsBuf));
        rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize);
        TEST_ASSERT(rc == TPM_RC_SUCCESS,
                    "Adv3: CertifyIntegrated with AUDIT session failed");
        TEST_ASSERT(VerifyResponseHmac(respBuf, respSize, TPM_CC_CertifyIntegrated,
                                       nc, 16, NULL, 0),
                    "Adv3: AUDIT session response HMAC failed");
        FlushContextHandle(auditSess);

        // Read CommandAuditDigest after running CertifyIntegrated
        cp = cmd;
        PutU16(&cp, TPM_ST_SESSIONS);
        PutU32(&cp, 0);
        PutU32(&cp, TPM_CC_GetCommandAuditDigest);
        PutU32(&cp, TPM_RH_ENDORSEMENT);
        PutU32(&cp, TPM_RH_NULL);
        PutU32(&cp, 18);
        PutU32(&cp, TPM_RS_PW); PutU16(&cp, 0); PutU8(&cp, 0x01); PutU16(&cp, 0);
        PutU32(&cp, TPM_RS_PW); PutU16(&cp, 0); PutU8(&cp, 0x01); PutU16(&cp, 0);
        PutU16(&cp, 0);
        PutU16(&cp, TPM_ALG_NULL);
        rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize);
        TEST_ASSERT(rc == TPM_RC_SUCCESS, "Adv3: GetCommandAuditDigest(after) failed");
        rp     = respBuf + 10;
        rend   = respBuf + respSize;
        (void)GetU32(&rp, rend);
        attLen = GetU16(&rp, rend);
        ap     = rp;
        aend   = rp + attLen;
        (void)GetU32(&ap, aend);
        (void)GetU16(&ap, aend);
        GetBytes(&ap, aend, NULL, GetU16(&ap, aend));
        GetBytes(&ap, aend, NULL, GetU16(&ap, aend));
        (void)GetU64(&ap, aend);
        (void)GetU32(&ap, aend);
        (void)GetU32(&ap, aend);
        (void)GetU8(&ap, aend);
        (void)GetU64(&ap, aend);
        (void)GetU64(&ap, aend);
        (void)GetU16(&ap, aend);
        TEST_ASSERT(GetU16(&ap, aend) == 32, "Adv3: auditDigestAfter size != 32");
        GetBytes(&ap, aend, auditDigestAfter, 32);
        TEST_ASSERT(memcmp(auditDigestBefore, auditDigestAfter, 32) != 0,
                    "Adv3: CommandAuditDigest did not change after TPM2_CertifyIntegrated");

        // Clear command audit for TPM_CC_CertifyIntegrated
        cp = cmd;
        PutU16(&cp, TPM_ST_SESSIONS);
        PutU32(&cp, 0);
        PutU32(&cp, TPM_CC_SetCommandCodeAuditStatus);
        PutU32(&cp, TPM_RH_OWNER);
        PutPwSession(&cp, NULL, 0);
        PutU16(&cp, TPM_ALG_SHA256);
        PutU32(&cp, 0);
        PutU32(&cp, 1);
        PutU32(&cp, TPM_CC_CertifyIntegrated);
        rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL);
        TEST_ASSERT(rc == TPM_RC_SUCCESS,
                    "Adv3: SetCommandCodeAuditStatus(disable) failed");
    }

    // Probe 4: Bound Session Cross-Entity Check (session bound to TPM_RH_OWNER
    // used to authorize TPM_RH_INTEGRATED when ownerAuth == integratedAuth)
    {
        const char  sharedAuth[] = "shared-bound-auth";
        BYTE        snc[16], nc[16], nt[32];
        UINT16      ntLen = 0;
        TPM_HANDLE  boundSess;
        TPM2B_DATA  bindKey;
        TPM2B_NONCE nCaller2B, nTpm2B;
        BYTE        sessKey[32];
        BYTE        hmacKey[32 + sizeof(sharedAuth)];
        BYTE        handleNames[4 + 68];
        BYTE        paramsBuf[512];
        BYTE        authArea[128];
        UINT32      authLen;
        BYTE*       hp;
        BYTE*       pp;

        rc = SendHierarchyChangeAuth(TPM_RH_OWNER, NULL, 0,
                                     sharedAuth, (UINT16)(sizeof(sharedAuth) - 1));
        TEST_ASSERT(rc == TPM_RC_SUCCESS, "Adv4: Set ownerAuth failed");
        rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, NULL, 0,
                                     sharedAuth, (UINT16)(sizeof(sharedAuth) - 1));
        TEST_ASSERT(rc == TPM_RC_SUCCESS, "Adv4: Set integratedAuth failed");

        memset(snc, 0x71, 16);
        memset(nc, 0x72, 16);
        boundSess = StartAuthSessionEx(TPM_RH_OWNER, TPM_SE_HMAC, TPM_ALG_NULL, 0, TPM_ALG_NULL,
                                       snc, 16, nt, &ntLen);

        // Compute sessionKey derived from bind=TPM_RH_OWNER
        bindKey.t.size = (UINT16)(sizeof(sharedAuth) - 1);
        memcpy(bindKey.t.buffer, sharedAuth, bindKey.t.size);
        nCaller2B.t.size = 16;
        memcpy(nCaller2B.t.buffer, snc, 16);
        nTpm2B.t.size = ntLen;
        memcpy(nTpm2B.t.buffer, nt, ntLen);
        CryptKDFa(TPM_ALG_SHA256, &bindKey.b, SESSION_KEY, &nTpm2B.b, &nCaller2B.b,
                  256, sessKey, NULL, FALSE);

        // Because TPM_RH_INTEGRATED != TPM_RH_OWNER, IsSessionBindEntity() is FALSE,
        // so the TPM appends integratedAuth to sessionKey when computing the HMAC.
        memcpy(hmacKey, sessKey, 32);
        memcpy(hmacKey + 32, sharedAuth, sizeof(sharedAuth) - 1);

        hp = handleNames;
        PutU32(&hp, TPM_RH_INTEGRATED);
        PutBytes(&hp, objectName, objectNameSize);
        pp = paramsBuf;
        Put2B(&pp, NULL, 0);
        Put2B(&pp, creationHash, creationHashSize);
        PutU16(&pp, creationTicket.tag);
        PutU32(&pp, creationTicket.hierarchy);
        Put2B(&pp, creationTicket.digest.t.buffer, creationTicket.digest.t.size);
        Put2B(&pp, NULL, 0);

        authLen = BuildHmacAuthArea(authArea, boundSess, nc, 16, nt, ntLen,
                                    TPM_CC_CertifyIntegrated,
                                    handleNames, (UINT32)(hp - handleNames),
                                    paramsBuf, (UINT32)(pp - paramsBuf),
                                    hmacKey, (UINT16)(32 + sizeof(sharedAuth) - 1), 0x00);
        cp = cmd;
        PutU16(&cp, TPM_ST_SESSIONS);
        PutU32(&cp, 0);
        PutU32(&cp, TPM_CC_CertifyIntegrated);
        PutU32(&cp, TPM_RH_INTEGRATED);
        PutU32(&cp, objectHandle);
        PutBytes(&cp, authArea, authLen);
        PutBytes(&cp, paramsBuf, (size_t)(pp - paramsBuf));
        rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize);
        TEST_ASSERT(rc == TPM_RC_SUCCESS,
                    "Adv4: CertifyIntegrated with OWNER-bound session failed");
        TEST_ASSERT(VerifyResponseHmac(respBuf, respSize, TPM_CC_CertifyIntegrated,
                                       nc, 16, hmacKey, (UINT16)(32 + sizeof(sharedAuth) - 1)),
                    "Adv4: OWNER-bound session response HMAC mismatch");

        rc = SendHierarchyChangeAuth(TPM_RH_OWNER, sharedAuth, (UINT16)(sizeof(sharedAuth) - 1),
                                     NULL, 0);
        TEST_ASSERT(rc == TPM_RC_SUCCESS, "Adv4: Reset ownerAuth failed");
        rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, sharedAuth, (UINT16)(sizeof(sharedAuth) - 1),
                                     NULL, 0);
        TEST_ASSERT(rc == TPM_RC_SUCCESS, "Adv4: Reset integratedAuth failed");
    }

    // Probe 5: Disabled Hierarchy Tickets (TPM2_HierarchyControl), Bad Ticket Tag (0x397),
    // qualifyingData & creationHash Boundaries, and 3-Session Max Response
    {
        TPMT_TK_CREATION badTicket;
        BYTE             maxQd[sizeof(TPMT_HA)];
        BYTE             overQd[sizeof(TPMT_HA) + 1];
        BYTE             overCh[sizeof(TPMU_HA) + 1];

        // 5a. Bad ticket tag != TPM_ST_CREATION -> TPM_RCS_TAG + RC_CertifyIntegrated_creationTicket (0x397)
        badTicket     = creationTicket;
        badTicket.tag = TPM_ST_VERIFIED;
        rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                   &badTicket, NULL, 0, &respBuf, &respSize);
        TEST_ASSERT(rc == (TPM_RCS_TAG + RC_CertifyIntegrated_creationTicket),
                    "Adv5a: Expected TPM_RCS_TAG + P3 (0x397) for ticket.tag != TPM_ST_CREATION");

        // 5b. qualifyingData at max size sizeof(TPMT_HA) succeeds; sizeof(TPMT_HA) + 1 fails with 0x1D5
        memset(maxQd, 0xAA, sizeof(maxQd));
        rc = SendCertifyIntegrated(objectHandle, maxQd, (UINT16)sizeof(maxQd),
                                   creationHash, creationHashSize,
                                   &creationTicket, NULL, 0, &respBuf, &respSize);
        TEST_ASSERT(rc == TPM_RC_SUCCESS,
                    "Adv5b: qualifyingData of max size sizeof(TPMT_HA) failed");

        memset(overQd, 0xBB, sizeof(overQd));
        rc = SendCertifyIntegrated(objectHandle, overQd, (UINT16)sizeof(overQd),
                                   creationHash, creationHashSize,
                                   &creationTicket, NULL, 0, &respBuf, &respSize);
        TEST_ASSERT(rc == (TPM_RCS_SIZE + RC_CertifyIntegrated_qualifyingData),
                    "Adv5b: qualifyingData of sizeof(TPMT_HA)+1 did not return 0x1D5");

        // 5c. creationHash of DIGEST_SIZE + 1 bytes fails unmarshaling with 0x2D5
        memset(overCh, 0xCC, sizeof(overCh));
        rc = SendCertifyIntegrated(objectHandle, NULL, 0, overCh, (UINT16)sizeof(overCh),
                                   &creationTicket, NULL, 0, &respBuf, &respSize);
        TEST_ASSERT(rc == (TPM_RCS_SIZE + RC_CertifyIntegrated_creationHash),
                    "Adv5c: creationHash of DIGEST_SIZE+1 did not return 0x2D5");

        // 5d. Disable EH via TPM2_HierarchyControl; ticket with hierarchy=TPM_RH_ENDORSEMENT -> 0x3A1
        cp = cmd;
        PutU16(&cp, TPM_ST_SESSIONS); PutU32(&cp, 0); PutU32(&cp, TPM_CC_HierarchyControl);
        PutU32(&cp, TPM_RH_PLATFORM);
        PutPwSession(&cp, NULL, 0);
        PutU32(&cp, TPM_RH_ENDORSEMENT);
        PutU8(&cp, NO);
        TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL) == TPM_RC_SUCCESS,
                    "Adv5d: HierarchyControl(EH, NO) failed");

        badTicket           = creationTicket;
        badTicket.hierarchy = TPM_RH_ENDORSEMENT;
        rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                   &badTicket, NULL, 0, &respBuf, &respSize);
        TEST_ASSERT(rc == (TPM_RCS_TICKET + RC_CertifyIntegrated_creationTicket),
                    "Adv5d: Expected TPM_RCS_TICKET + P3 (0x3A1) when ticket hierarchy mismatches");

        cp = cmd;
        PutU16(&cp, TPM_ST_SESSIONS); PutU32(&cp, 0); PutU32(&cp, TPM_CC_HierarchyControl);
        PutU32(&cp, TPM_RH_PLATFORM);
        PutPwSession(&cp, NULL, 0);
        PutU32(&cp, TPM_RH_ENDORSEMENT);
        PutU8(&cp, YES);
        TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL) == TPM_RC_SUCCESS,
                    "Adv5d: HierarchyControl(EH, YES) failed");

        // 5e. Create object in EH, disable EH via TPM2_HierarchyControl (flushing EH objects),
        // and verify CertifyIntegrated on the flushed handle returns TPM_RC_REFERENCE_H0 + 1 (0x901)
        {
            CREATED_PRIMARY_OBJ ehTempObj;
            CreatePrimaryKeyedHash(TPM_RH_ENDORSEMENT, TPM_ALG_SHA256, "eh-temp-key", &ehTempObj);

            cp = cmd;
            PutU16(&cp, TPM_ST_SESSIONS); PutU32(&cp, 0); PutU32(&cp, TPM_CC_HierarchyControl);
            PutU32(&cp, TPM_RH_PLATFORM);
            PutPwSession(&cp, NULL, 0);
            PutU32(&cp, TPM_RH_ENDORSEMENT);
            PutU8(&cp, NO);
            TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL) == TPM_RC_SUCCESS,
                        "Adv5e: HierarchyControl(EH, NO) failed");

            rc = SendCertifyIntegrated(ehTempObj.handle, NULL, 0,
                                       ehTempObj.creationHash, ehTempObj.creationHashSize,
                                       &ehTempObj.ticket, NULL, 0, &respBuf, &respSize);
            TEST_ASSERT(rc == (TPM_RC_REFERENCE_H0 + 1),
                        "Adv5e: Expected TPM_RC_REFERENCE_H1 (0x901) when EH is disabled");

            cp = cmd;
            PutU16(&cp, TPM_ST_SESSIONS); PutU32(&cp, 0); PutU32(&cp, TPM_CC_HierarchyControl);
            PutU32(&cp, TPM_RH_PLATFORM);
            PutPwSession(&cp, NULL, 0);
            PutU32(&cp, TPM_RH_ENDORSEMENT);
            PutU8(&cp, YES);
            TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL) == TPM_RC_SUCCESS,
                        "Adv5e: HierarchyControl(EH, YES) failed");
        }

        // 5f. 3 concurrent sessions (MAX_SESSION_NUM = 3: 1 PW + 1 Audit HMAC + 1 Encrypt HMAC)
        // with 2048-byte MAX_INTEGRATED_ATTEST_SIZE report
        {
            BYTE       snc1[16], snc2[16], nc1[16], nc2[16], nt1[32], nt2[32];
            UINT16     nt1Len = 0, nt2Len = 0;
            TPM_HANDLE s1, s2;
            BYTE       handleNames[4 + 68];
            BYTE       paramsBuf[512];
            BYTE       a1[128], a2[128];
            UINT32     a1Len, a2Len;
            BYTE*      hp;
            BYTE*      pp;

            _plat__RegisterIntegratedSigner(CustomTestIntegratedSigner);
            memset(snc1, 0x81, 16);
            memset(snc2, 0x82, 16);
            memset(nc1, 0x83, 16);
            memset(nc2, 0x84, 16);
            s1 = StartAuthSessionEx(TPM_RH_NULL, TPM_SE_HMAC, TPM_ALG_NULL, 0, TPM_ALG_NULL,
                                    snc1, 16, nt1, &nt1Len);
            s2 = StartAuthSessionEx(TPM_RH_NULL, TPM_SE_HMAC, TPM_ALG_XOR, 0, TPM_ALG_NULL,
                                    snc2, 16, nt2, &nt2Len);

            hp = handleNames;
            PutU32(&hp, TPM_RH_INTEGRATED);
            PutBytes(&hp, objectName, objectNameSize);
            pp = paramsBuf;
            Put2B(&pp, maxQd, (UINT16)sizeof(maxQd));
            Put2B(&pp, creationHash, creationHashSize);
            PutU16(&pp, creationTicket.tag);
            PutU32(&pp, creationTicket.hierarchy);
            Put2B(&pp, creationTicket.digest.t.buffer, creationTicket.digest.t.size);
            Put2B(&pp, "MAXSIZE", 7);

            a1Len = BuildHmacAuthAreaNoSize(
                a1, s1, nc1, 16, nt1, nt1Len, TPM_CC_CertifyIntegrated,
                handleNames, (UINT32)(hp - handleNames),
                paramsBuf, (UINT32)(pp - paramsBuf), NULL, 0, 0x80);
            a2Len = BuildHmacAuthAreaNoSize(
                a2, s2, nc2, 16, nt2, nt2Len, TPM_CC_CertifyIntegrated,
                handleNames, (UINT32)(hp - handleNames),
                paramsBuf, (UINT32)(pp - paramsBuf), NULL, 0, 0x40);

            cp = cmd;
            PutU16(&cp, TPM_ST_SESSIONS);
            PutU32(&cp, 0);
            PutU32(&cp, TPM_CC_CertifyIntegrated);
            PutU32(&cp, TPM_RH_INTEGRATED);
            PutU32(&cp, objectHandle);
            PutU32(&cp, 9 + a1Len + a2Len);
            PutU32(&cp, TPM_RS_PW); PutU16(&cp, 0); PutU8(&cp, 0x01); PutU16(&cp, 0);
            PutBytes(&cp, a1, a1Len);
            PutBytes(&cp, a2, a2Len);
            PutBytes(&cp, paramsBuf, (size_t)(pp - paramsBuf));

            rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize);
            TEST_ASSERT(rc == TPM_RC_SUCCESS && respSize <= MAX_RESPONSE_SIZE,
                        "Adv5f: 3-session MAXSIZE (2048B) CertifyIntegrated failed");
            _plat__UseDefaultIntegratedSigner();
        }
    }

    // Probe 6: 64-byte SHA-512 digest handling in SimIntegratedSigner
    {
        uint8_t                sha512Digest[65];
        uint8_t                outBuf[MAX_INTEGRATED_ATTEST_SIZE];
        uint16_t               outSize = 0;
        uint32_t               sRc;
        PLAT_SIM_ATTEST_REPORT simRep;
        size_t                 i;

        for(i = 0; i < sizeof(sha512Digest); i++)
            sha512Digest[i] = (uint8_t)(0xA0u + (uint8_t)i);

        _plat__UseDefaultIntegratedSigner();
        sRc = _plat__GetIntegratedAttestation(
            TPM_ALG_SHA512, sha512Digest, 64, NULL, 0, sizeof(outBuf), outBuf, &outSize);
        TEST_ASSERT(sRc == PLAT_INTEGRATED_ATTEST_SUCCESS && outSize == sizeof(PLAT_SIM_ATTEST_REPORT),
                    "Adv6a: SimIntegratedSigner failed on 64-byte SHA-512 digest");
        memcpy(&simRep, outBuf, sizeof(simRep));
        TEST_ASSERT(simRep.hashAlg == TPM_ALG_SHA512 && simRep.digestSize == 64
                    && memcmp(simRep.signerInputDigest, sha512Digest, 64) == 0,
                    "Adv6a: SimIntegratedSigner 64-byte SHA-512 digest mismatch");

        // Reject digestSize == 0 and digestSize == 65
        sRc = _plat__GetIntegratedAttestation(
            TPM_ALG_SHA512, sha512Digest, 0, NULL, 0, sizeof(outBuf), outBuf, &outSize);
        TEST_ASSERT(sRc == PLAT_INTEGRATED_ATTEST_UNAVAILABLE,
                    "Adv6a: SimIntegratedSigner must reject digestSize == 0");
        sRc = _plat__GetIntegratedAttestation(
            TPM_ALG_SHA512, sha512Digest, 65, NULL, 0, sizeof(outBuf), outBuf, &outSize);
        TEST_ASSERT(sRc == PLAT_INTEGRATED_ATTEST_UNAVAILABLE,
                    "Adv6a: SimIntegratedSigner must reject digestSize == 65");

#if ALG_SHA512
        {
            CREATED_PRIMARY_OBJ sha512Obj;
            const BYTE *        certPtr, *attPtr;
            UINT16              certLen, attLen;
            BYTE                expDig[64];

            CreatePrimaryKeyedHash(TPM_RH_OWNER, TPM_ALG_SHA512, "owner-sha512-obj", &sha512Obj);
            TEST_ASSERT(sha512Obj.creationHashSize == 64, "Adv6b: Expected 64-byte SHA-512 creationHash");
            rc = SendCertifyIntegrated(sha512Obj.handle, "sha512-qd", 9,
                                       sha512Obj.creationHash, sha512Obj.creationHashSize,
                                       &sha512Obj.ticket, NULL, 0, &respBuf, &respSize);
            TEST_ASSERT(rc == TPM_RC_SUCCESS, "Adv6b: SimIntegratedSigner on SHA-512 object failed");
            ParseCertifyIntegratedResponseAlg(TPM_ALG_SHA512, 64, respBuf, respSize,
                                              &certPtr, &certLen, &attPtr, &attLen, expDig);
            memcpy(&simRep, attPtr, sizeof(simRep));
            TEST_ASSERT(simRep.digestSize == 64 && memcmp(simRep.signerInputDigest, expDig, 64) == 0,
                        "Adv6b: SHA-512 SimIntegratedSigner report digest mismatch");
            FlushContextHandle(sha512Obj.handle);
        }
#endif
    }
}

#endif  // CC_CertifyIntegrated

int main(void)
{
    BYTE        cmd[MAX_COMMAND_SIZE];
    BYTE*       cp;
    BYTE*       respBuf  = NULL;
    uint32_t    respSize = 0;
    const BYTE* rp;
    const BYTE* rend;
    TPM_RC      rc;

    printf("=== TPM2_CertifyIntegrated Integration Test Suite (TDM=%d, CC=%d) ===\n",
           TABLE_DRIVEN_MARSHAL, CC_CertifyIntegrated);

    // 1. Manufacture and Startup the TPM
    _plat__NVEnable(NULL, 0);
    TEST_ASSERT(TPM_Manufacture(MANUF_FIRST_TIME) == MANUF_OK, "TPM_Manufacture failed");
    _plat__Signal_PowerOn();
    _plat__Signal_Reset();
    _plat__SetNvAvail();

    cp = cmd;
    PutU16(&cp, TPM_ST_NO_SESSIONS);
    PutU32(&cp, 0);
    PutU32(&cp, TPM_CC_Startup);
    PutU16(&cp, TPM_SU_CLEAR);
    TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize) == TPM_RC_SUCCESS,
                "TPM2_Startup(TPM_SU_CLEAR) failed");

#if !CC_CertifyIntegrated || !SIMULATION
    // F3/S1: When CC_CertifyIntegrated == CC_NO or SIMULATION == 0 (no default
    // signer registered), TPM_PT_MAX_INTEGRATED_ATTEST must be 0.
    cp = cmd;
    PutU16(&cp, TPM_ST_NO_SESSIONS);
    PutU32(&cp, 0);
    PutU32(&cp, TPM_CC_GetCapability);
    PutU32(&cp, TPM_CAP_TPM_PROPERTIES);
    PutU32(&cp, TPM_PT_MAX_INTEGRATED_ATTEST);
    PutU32(&cp, 1);
    TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize) == TPM_RC_SUCCESS,
                "TPM2_GetCapability(TPM_PT_MAX_INTEGRATED_ATTEST) failed");
    rp   = respBuf + 10;
    rend = respBuf + respSize;
    (void)GetU8(&rp, rend);
    TEST_ASSERT(GetU32(&rp, rend) == TPM_CAP_TPM_PROPERTIES, "Cap mismatch");
    TEST_ASSERT(GetU32(&rp, rend) == 1, "Property count != 1");
    TEST_ASSERT(GetU32(&rp, rend) == TPM_PT_MAX_INTEGRATED_ATTEST, "Property ID mismatch");
    TEST_ASSERT(GetU32(&rp, rend) == 0, "Expected TPM_PT_MAX_INTEGRATED_ATTEST == 0");

#  if !CC_CertifyIntegrated
    rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, NULL, 0, "x", 1);
    TEST_ASSERT(rc == (TPM_RCS_VALUE + TPM_RC_H + TPM_RC_1),
                "Expected TPM_RC_VALUE + H1 for TPM_RH_INTEGRATED when CC_NO");
#  else
    rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, NULL, 0, "x", 1);
    TEST_ASSERT(rc == TPM_RC_SUCCESS,
                "Expected HierarchyChangeAuth(TPM_RH_INTEGRATED) to succeed when SIMULATION=0");
#  endif

    _plat__NVDisable((void*)TRUE, 0);
    printf("=== ALL TPM2_CertifyIntegrated (CC_NO / SIMULATION=0) TESTS PASSED ===\n");
    return 0;
#else
    {
        CREATED_PRIMARY_OBJ ownerSha256Obj;
        CREATED_PRIMARY_OBJ nullSha256Obj;
        CREATED_PRIMARY_OBJ ownerSha384Obj;
        TPM_HANDLE          objectHandle;
        BYTE*               creationHash;
        UINT16              creationHashSize;
        TPMT_TK_CREATION    creationTicket;
        BYTE*               objectName;
        UINT16              objectNameSize;

        // 2. Verify TPM2_GetCapability(TPM_PT_MAX_INTEGRATED_ATTEST) when signer available vs unavailable (S1/F3)
        _plat__UseDefaultIntegratedSigner();
        cp = cmd;
        PutU16(&cp, TPM_ST_NO_SESSIONS);
        PutU32(&cp, 0);
        PutU32(&cp, TPM_CC_GetCapability);
        PutU32(&cp, TPM_CAP_TPM_PROPERTIES);
        PutU32(&cp, TPM_PT_MAX_INTEGRATED_ATTEST);
        PutU32(&cp, 1);
        TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize) == TPM_RC_SUCCESS,
                    "TPM2_GetCapability(TPM_PT_MAX_INTEGRATED_ATTEST) failed");
        rp   = respBuf + 10;
        rend = respBuf + respSize;
        (void)GetU8(&rp, rend);
        TEST_ASSERT(GetU32(&rp, rend) == TPM_CAP_TPM_PROPERTIES, "Cap mismatch");
        TEST_ASSERT(GetU32(&rp, rend) == 1, "Property count != 1");
        TEST_ASSERT(GetU32(&rp, rend) == TPM_PT_MAX_INTEGRATED_ATTEST, "Property ID mismatch");
        TEST_ASSERT(GetU32(&rp, rend) == MAX_INTEGRATED_ATTEST_SIZE && MAX_INTEGRATED_ATTEST_SIZE == 2048,
                    "Expected TPM_PT_MAX_INTEGRATED_ATTEST == 2048 when signer available");

        _plat__SetIntegratedSignerAvailable(FALSE);
        cp = cmd;
        PutU16(&cp, TPM_ST_NO_SESSIONS);
        PutU32(&cp, 0);
        PutU32(&cp, TPM_CC_GetCapability);
        PutU32(&cp, TPM_CAP_TPM_PROPERTIES);
        PutU32(&cp, TPM_PT_MAX_INTEGRATED_ATTEST);
        PutU32(&cp, 1);
        TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize) == TPM_RC_SUCCESS,
                    "TPM2_GetCapability(TPM_PT_MAX_INTEGRATED_ATTEST) unavailable check failed");
        rp   = respBuf + 10;
        rend = respBuf + respSize;
        (void)GetU8(&rp, rend);
        (void)GetU32(&rp, rend);
        (void)GetU32(&rp, rend);
        (void)GetU32(&rp, rend);
        TEST_ASSERT(GetU32(&rp, rend) == 0,
                    "Expected TPM_PT_MAX_INTEGRATED_ATTEST == 0 when signer unavailable");
        _plat__SetIntegratedSignerAvailable(TRUE);

        // 2a. G3: Verify TPM_CAP_HANDLES lists TPM_RH_INTEGRATED (0x4000000E) and TPM_CAP_AUTH_POLICIES excludes it
        {
            UINT32 count, i;
            BOOL   foundHandle = FALSE;
            BOOL   foundPolicy = FALSE;

            cp = cmd;
            PutU16(&cp, TPM_ST_NO_SESSIONS);
            PutU32(&cp, 0);
            PutU32(&cp, TPM_CC_GetCapability);
            PutU32(&cp, TPM_CAP_HANDLES);
            PutU32(&cp, TPM_RH_FIRST);
            PutU32(&cp, 64);
            TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize) == TPM_RC_SUCCESS,
                        "GetCapability(TPM_CAP_HANDLES) failed");
            rp   = respBuf + 10;
            rend = respBuf + respSize;
            (void)GetU8(&rp, rend);
            TEST_ASSERT(GetU32(&rp, rend) == TPM_CAP_HANDLES, "TPM_CAP_HANDLES mismatch");
            count = GetU32(&rp, rend);
            for(i = 0; i < count; i++)
            {
                if(GetU32(&rp, rend) == TPM_RH_INTEGRATED)
                    foundHandle = TRUE;
            }
            TEST_ASSERT(foundHandle, "G3: TPM_CAP_HANDLES did not include TPM_RH_INTEGRATED (0x4000000E)");

            cp = cmd;
            PutU16(&cp, TPM_ST_NO_SESSIONS);
            PutU32(&cp, 0);
            PutU32(&cp, TPM_CC_GetCapability);
            PutU32(&cp, TPM_CAP_AUTH_POLICIES);
            PutU32(&cp, TPM_RH_FIRST);
            PutU32(&cp, 64);
            TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize) == TPM_RC_SUCCESS,
                        "GetCapability(TPM_CAP_AUTH_POLICIES) failed");
            rp   = respBuf + 10;
            rend = respBuf + respSize;
            (void)GetU8(&rp, rend);
            TEST_ASSERT(GetU32(&rp, rend) == TPM_CAP_AUTH_POLICIES, "TPM_CAP_AUTH_POLICIES mismatch");
            count = GetU32(&rp, rend);
            for(i = 0; i < count; i++)
            {
                TPM_HANDLE h   = GetU32(&rp, rend);
                TPM_ALG_ID alg = GetU16(&rp, rend);
                if(h == TPM_RH_INTEGRATED)
                    foundPolicy = TRUE;
                GetBytes(&rp, rend, NULL, CryptHashGetDigestSize(alg));
            }
            TEST_ASSERT(!foundPolicy, "G3: TPM_CAP_AUTH_POLICIES must not include TPM_RH_INTEGRATED");
        }

        // 2b. Test integratedAuth lifecycle across TPM_SU_STATE (preserved) and TPM_SU_CLEAR (reset)
        {
            const char auth1[] = "state-preserved-auth";

            rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, NULL, 0, auth1, (UINT16)(sizeof(auth1) - 1));
            TEST_ASSERT(rc == TPM_RC_SUCCESS, "HierarchyChangeAuth(TPM_RH_INTEGRATED) failed");

            // Shutdown(TPM_SU_STATE) -> Reset -> Startup(TPM_SU_STATE): integratedAuth must be preserved
            cp = cmd;
            PutU16(&cp, TPM_ST_NO_SESSIONS); PutU32(&cp, 0); PutU32(&cp, TPM_CC_Shutdown); PutU16(&cp, TPM_SU_STATE);
            TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL) == TPM_RC_SUCCESS, "Shutdown(STATE) failed");
            _plat__Signal_Reset();
            cp = cmd;
            PutU16(&cp, TPM_ST_NO_SESSIONS); PutU32(&cp, 0); PutU32(&cp, TPM_CC_Startup); PutU16(&cp, TPM_SU_STATE);
            TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL) == TPM_RC_SUCCESS, "Startup(STATE) failed");

            // Empty auth must fail after TPM_SU_STATE resume
            rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, NULL, 0, NULL, 0);
            TEST_ASSERT(rc == (TPM_RC_BAD_AUTH + TPM_RC_S + TPM_RC_1),
                        "integratedAuth was not preserved across TPM_SU_STATE");

            // Shutdown(TPM_SU_STATE) -> Reset -> Startup(TPM_SU_CLEAR): integratedAuth must reset to Empty Buffer
            cp = cmd;
            PutU16(&cp, TPM_ST_NO_SESSIONS); PutU32(&cp, 0); PutU32(&cp, TPM_CC_Shutdown); PutU16(&cp, TPM_SU_STATE);
            TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL) == TPM_RC_SUCCESS, "Shutdown(STATE) 2 failed");
            _plat__Signal_Reset();
            cp = cmd;
            PutU16(&cp, TPM_ST_NO_SESSIONS); PutU32(&cp, 0); PutU32(&cp, TPM_CC_Startup); PutU16(&cp, TPM_SU_CLEAR);
            TEST_ASSERT(RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL) == TPM_RC_SUCCESS, "Startup(CLEAR) 2 failed");

            // Empty auth must succeed after TPM_SU_CLEAR
            rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, NULL, 0, NULL, 0);
            TEST_ASSERT(rc == TPM_RC_SUCCESS, "integratedAuth was not reset to Empty Buffer on TPM_SU_CLEAR");
        }

        // 2c. G8: Test HierarchyChangeAuth(TPM_RH_INTEGRATED) max size (48B), oversized (49B), and trailing zeros
        {
            BYTE maxAuth[CONTEXT_INTEGRITY_HASH_SIZE + 1];

            memset(maxAuth, 0x31, sizeof(maxAuth));
            rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, NULL, 0, maxAuth, CONTEXT_INTEGRITY_HASH_SIZE);
            TEST_ASSERT(rc == TPM_RC_SUCCESS, "G8: newAuth of CONTEXT_INTEGRITY_HASH_SIZE (48B) failed");

            rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, maxAuth, CONTEXT_INTEGRITY_HASH_SIZE,
                                         maxAuth, CONTEXT_INTEGRITY_HASH_SIZE + 1);
            TEST_ASSERT(rc == (TPM_RCS_SIZE + TPM_RC_P + TPM_RC_1),
                        "G8: newAuth of CONTEXT_INTEGRITY_HASH_SIZE + 1 (49B) did not return 0x1D5");

            rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, maxAuth, CONTEXT_INTEGRITY_HASH_SIZE,
                                         "abc\0\0", 5);
            TEST_ASSERT(rc == TPM_RC_SUCCESS, "G8: newAuth with trailing zeros failed");

            // Verify trailing zeros were stripped by authenticating with "abc" (3 bytes)
            rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, "abc", 3, NULL, 0);
            TEST_ASSERT(rc == TPM_RC_SUCCESS, "G8: trailing zeros were not stripped from integratedAuth");
        }

        // 3. Create primary objects (OWNER/SHA256, NULL/SHA256, OWNER/SHA384)
        CreatePrimaryKeyedHash(TPM_RH_OWNER, TPM_ALG_SHA256, "owner-sha256-obj", &ownerSha256Obj);
        CreatePrimaryKeyedHash(TPM_RH_NULL, TPM_ALG_SHA256, "null-sha256-obj", &nullSha256Obj);
        CreatePrimaryKeyedHash(TPM_RH_OWNER, TPM_ALG_SHA384, "owner-sha384-obj", &ownerSha384Obj);
        TEST_ASSERT(ownerSha256Obj.creationHashSize == 32, "Expected 32-byte SHA-256 creationHash");
        TEST_ASSERT(ownerSha384Obj.creationHashSize == 48, "Expected 48-byte SHA-384 creationHash");

        objectHandle     = ownerSha256Obj.handle;
        creationHash     = ownerSha256Obj.creationHash;
        creationHashSize = ownerSha256Obj.creationHashSize;
        creationTicket   = ownerSha256Obj.ticket;
        objectName       = ownerSha256Obj.name;
        objectNameSize   = ownerSha256Obj.nameSize;

        // 4. Test TPM2_CertifyIntegrated with Default Simulator Integrated Signer (SHA-256 and G7 SHA-384)
        {
            const BYTE             qualData[]   = "attest-qualifying-nonce-01";
            PLAT_SIM_SIGNER_PARAMS simParams    = {PLAT_SIM_PARAMS_VER, 0, 0x0001u};
            PLAT_SIM_SIGNER_PARAMS badSimParams = {99u, 0, 0x0001u};
            BYTE                   badSizeParams[3] = {1, 0, 1};
            const BYTE *           certifyInfoPtr, *attestPtr, *ap, *aend;
            UINT16                 certifyInfoSize, attestSize;
            BYTE                   expectedDigest[48];
            PLAT_SIM_ATTEST_REPORT simReport;

            _plat__UseDefaultIntegratedSigner();
            rc = SendCertifyIntegrated(objectHandle, qualData, sizeof(qualData) - 1,
                                       creationHash, creationHashSize, &creationTicket,
                                       &simParams, sizeof(simParams), &respBuf, &respSize);
            TEST_ASSERT(rc == TPM_RC_SUCCESS, "TPM2_CertifyIntegrated (Default Signer) failed");
            ParseCertifyIntegratedResponse(respBuf, respSize, &certifyInfoPtr, &certifyInfoSize,
                                           &attestPtr, &attestSize, expectedDigest);

            ap   = certifyInfoPtr;
            aend = certifyInfoPtr + certifyInfoSize;
            TEST_ASSERT(GetU32(&ap, aend) == TPM_GENERATED_VALUE, "TPMS_ATTEST.magic mismatch");
            TEST_ASSERT(GetU16(&ap, aend) == TPM_ST_ATTEST_INTEGRATED, "TPMS_ATTEST.type != 0x801E");
            TEST_ASSERT(GetU16(&ap, aend) == 4 && GetU32(&ap, aend) == TPM_RH_INTEGRATED,
                        "qualifiedSigner != TPM_RH_INTEGRATED (0x4000000E)");
            TEST_ASSERT(GetU16(&ap, aend) == sizeof(qualData) - 1, "extraData size mismatch");
            TEST_ASSERT(memcmp(ap, qualData, sizeof(qualData) - 1) == 0, "extraData mismatch");
            ap += sizeof(qualData) - 1;
            (void)GetU64(&ap, aend);
            TEST_ASSERT(GetU32(&ap, aend) == gp.resetCount, "resetCount was obfuscated");
            TEST_ASSERT(GetU32(&ap, aend) == gr.restartCount, "restartCount was obfuscated");
            (void)GetU8(&ap, aend);
            TEST_ASSERT(GetU64(&ap, aend) == ((((UINT64)gp.firmwareV1) << 32) + gp.firmwareV2),
                        "firmwareVersion was obfuscated");
            TEST_ASSERT(GetU16(&ap, aend) == objectNameSize && memcmp(ap, objectName, objectNameSize) == 0,
                        "objectName mismatch");
            ap += objectNameSize;
            TEST_ASSERT(GetU16(&ap, aend) == creationHashSize && memcmp(ap, creationHash, creationHashSize) == 0,
                        "creationHash mismatch");
            ap += creationHashSize;
            TEST_ASSERT(ap == aend, "Trailing bytes in TPMS_ATTEST");

            TEST_ASSERT(attestSize == sizeof(PLAT_SIM_ATTEST_REPORT), "Sim report size mismatch");
            memcpy(&simReport, attestPtr, sizeof(simReport));
            TEST_ASSERT(simReport.magic == PLAT_SIM_ATTEST_MAGIC && simReport.version == PLAT_SIM_PARAMS_VER,
                        "Sim report header mismatch");
            TEST_ASSERT(simReport.flags == 0x0001u && simReport.hashAlg == TPM_ALG_SHA256 && simReport.digestSize == 32,
                        "Sim report metadata mismatch");
            TEST_ASSERT(memcmp(simReport.signerInputDigest, expectedDigest, 32) == 0,
                        "Sim signerInputDigest mismatch");

            // F1: Wrong-size signerParams must return TPM_RCS_SIZE + RC_CertifyIntegrated_signerParams (0x4D5)
            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &creationTicket, badSizeParams, sizeof(badSizeParams),
                                       &respBuf, &respSize);
            TEST_ASSERT(rc == (TPM_RCS_SIZE + RC_CertifyIntegrated_signerParams),
                        "F1: Expected TPM_RCS_SIZE + RC_CertifyIntegrated_signerParams (0x4D5) for wrong-size Sim params");

            // Invalid field value in signerParams must return TPM_RCS_VALUE + RC_CertifyIntegrated_signerParams (0x4C4)
            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &creationTicket, &badSimParams, sizeof(badSimParams),
                                       &respBuf, &respSize);
            TEST_ASSERT(rc == (TPM_RCS_VALUE + RC_CertifyIntegrated_signerParams),
                        "Expected TPM_RCS_VALUE + RC_CertifyIntegrated_signerParams (0x4C4) for invalid Sim params");

            // G7: Certify SHA-384 nameAlg object (digestSize == 48)
            rc = SendCertifyIntegrated(ownerSha384Obj.handle, qualData, sizeof(qualData) - 1,
                                       ownerSha384Obj.creationHash, ownerSha384Obj.creationHashSize,
                                       &ownerSha384Obj.ticket, &simParams, sizeof(simParams),
                                       &respBuf, &respSize);
            TEST_ASSERT(rc == TPM_RC_SUCCESS, "G7: TPM2_CertifyIntegrated on SHA-384 object failed");
            ParseCertifyIntegratedResponseAlg(TPM_ALG_SHA384, 48, respBuf, respSize,
                                              &certifyInfoPtr, &certifyInfoSize,
                                              &attestPtr, &attestSize, expectedDigest);
            memcpy(&simReport, attestPtr, sizeof(simReport));
            TEST_ASSERT(simReport.hashAlg == TPM_ALG_SHA384 && simReport.digestSize == 48
                        && memcmp(simReport.signerInputDigest, expectedDigest, 48) == 0,
                        "G7: SHA-384 Sim signerInputDigest mismatch");
        }

        // 7. Test Custom Runtime-Registered Integrated Signer (RETRY, Vendor RCs, S3, S4, S5/F5, F1)
        {
            const BYTE  qualData[]     = "custom-qual";
            const BYTE  customParams[] = "custom-param-payload";
            const BYTE *certifyInfoPtr, *attestPtr;
            UINT16      certifyInfoSize, attestSize;
            BYTE        expectedDigest[32];

            _plat__RegisterIntegratedSigner(CustomTestIntegratedSigner);
            TEST_ASSERT(_plat__GetIntegratedSigner() == CustomTestIntegratedSigner, "Callback getter mismatch");
            rc = SendCertifyIntegrated(objectHandle, qualData, sizeof(qualData) - 1,
                                       creationHash, creationHashSize, &creationTicket,
                                       customParams, sizeof(customParams) - 1, &respBuf, &respSize);
            TEST_ASSERT(rc == TPM_RC_SUCCESS, "TPM2_CertifyIntegrated (Custom Signer) failed");
            ParseCertifyIntegratedResponse(respBuf, respSize, &certifyInfoPtr, &certifyInfoSize,
                                           &attestPtr, &attestSize, expectedDigest);
            TEST_ASSERT(attestSize == 17 + 2 + 32 + (sizeof(customParams) - 1)
                        && memcmp(attestPtr, "CUSTOM_SIGNER_V1:", 17) == 0
                        && memcmp(attestPtr + 19, expectedDigest, 32) == 0,
                        "Custom signer attestation or digest mismatch");

            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &creationTicket, "RETRY", 5, &respBuf, &respSize);
            TEST_ASSERT(rc == TPM_RC_RETRY, "Expected TPM_RC_RETRY from busy Integrated Signer");

            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &creationTicket, "VENDOR", 6, &respBuf, &respSize);
            TEST_ASSERT(rc == (TPM_RC)0x0000052Au, "Expected vendor Format-Zero RC 0x0000052A");

            // S3: Warning-class Format-Zero vendor RC (0xD2A) and reserved-bit 0x700 must NOT pass through
            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &creationTicket, "WARN", 4, &respBuf, &respSize);
            TEST_ASSERT(rc == TPM_RC_NO_RESULT, "S3: Expected TPM_RC_NO_RESULT for warning-class 0xD2A");

            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &creationTicket, "RESV", 4, &respBuf, &respSize);
            TEST_ASSERT(rc == TPM_RC_NO_RESULT, "S3: Expected TPM_RC_NO_RESULT for reserved-bit 0x700");

            // F1: PLAT_INTEGRATED_ATTEST_INVALID_SIZE -> 0x4D5
            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &creationTicket, "BADSIZE", 7, &respBuf, &respSize);
            TEST_ASSERT(rc == (TPM_RCS_SIZE + RC_CertifyIntegrated_signerParams),
                        "F1: Expected 0x4D5 for PLAT_INTEGRATED_ATTEST_INVALID_SIZE");

            // S5 / F5: attestSize == 0 -> TPM_RC_NO_RESULT
            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &creationTicket, "EMPTY", 5, &respBuf, &respSize);
            TEST_ASSERT(rc == TPM_RC_NO_RESULT, "S5: Expected TPM_RC_NO_RESULT when attestSize == 0");

            // S4: attestSize == maxAttestSize (2048) -> TPM_RC_SUCCESS
            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &creationTicket, "MAXSIZE", 7, &respBuf, &respSize);
            TEST_ASSERT(rc == TPM_RC_SUCCESS, "S4: Expected TPM_RC_SUCCESS when attestSize == maxAttestSize");
            ParseCertifyIntegratedResponse(respBuf, respSize, &certifyInfoPtr, &certifyInfoSize,
                                           &attestPtr, &attestSize, expectedDigest);
            TEST_ASSERT(attestSize == MAX_INTEGRATED_ATTEST_SIZE && respSize <= MAX_RESPONSE_SIZE,
                        "S4: Expected 2048-byte attestation within MAX_RESPONSE_SIZE");

            // S4: attestSize == maxAttestSize + 1 -> TPM_RC_NO_RESULT
            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &creationTicket, "OVERMAX", 7, &respBuf, &respSize);
            TEST_ASSERT(rc == TPM_RC_NO_RESULT, "S4: Expected TPM_RC_NO_RESULT when attestSize > maxAttestSize");

            _plat__UseDefaultIntegratedSigner();
        }

        // 8. Test G1, G2, G4, G5, G6, Policy Session Rejection, DA Exemption, and S6
        {
            const char       newAuth[] = "integrated-signer-auth";
            UINT32           triesBefore;
            TPMT_TK_CREATION badTicket;
            BYTE             oversizedSignerParams[MAX_DIGEST_BUFFER + 1];

            // G1: Valid NULL-hierarchy primary object with its NULL-hierarchy ticket succeeds
            rc = SendCertifyIntegrated(nullSha256Obj.handle, NULL, 0,
                                       nullSha256Obj.creationHash, nullSha256Obj.creationHashSize,
                                       &nullSha256Obj.ticket, NULL, 0, &respBuf, &respSize);
            TEST_ASSERT(rc == TPM_RC_SUCCESS, "G1: NULL-hierarchy primary certification failed");

            // G1: creationTicket.hierarchy = TPM_RH_FW_OWNER on TPM_RH_OWNER object -> 0x3E0
            badTicket           = creationTicket;
            badTicket.hierarchy = TPM_RH_FW_OWNER;
            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &badTicket, NULL, 0, &respBuf, &respSize);
            TEST_ASSERT(rc == (TPM_RCS_TICKET + RC_CertifyIntegrated_creationTicket),
                        "G1: Expected 0x3E0 for TPM_RH_FW_OWNER hierarchy mismatch");

            // G1: creationTicket.hierarchy = TPM_RH_SVN_OWNER with svn > current -> TPM_RC_SVN_LIMITED (0x0A9)
            badTicket           = creationTicket;
            badTicket.hierarchy = TPM_RH_SVN_OWNER_BASE + _plat__GetTpmFirmwareSvn() + 1u;
            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &badTicket, NULL, 0, &respBuf, &respSize);
            TEST_ASSERT(rc == TPM_RC_SVN_LIMITED,
                        "G1: Expected TPM_RC_SVN_LIMITED (0x0A9) for SVN > currentSvn");

            // G2: creationTicket.hierarchy = TPM_RH_INTEGRATED -> 0x3C4
            badTicket           = creationTicket;
            badTicket.hierarchy = TPM_RH_INTEGRATED;
            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &badTicket, NULL, 0, &respBuf, &respSize);
            TEST_ASSERT(rc == (TPM_RCS_VALUE + RC_CertifyIntegrated_creationTicket),
                        "G2: Expected 0x3C4 for creationTicket.hierarchy == TPM_RH_INTEGRATED");

            // Change integratedAuth and verify bad auth returns TPM_RC_BAD_AUTH without DA increment
            rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, NULL, 0,
                                         newAuth, (UINT16)(sizeof(newAuth) - 1));
            TEST_ASSERT(rc == TPM_RC_SUCCESS, "HierarchyChangeAuth(TPM_RH_INTEGRATED) failed");

            triesBefore = gp.failedTries;
            rc          = SendCertifyIntegratedAuth(TPM_RH_INTEGRATED, "wrong-auth", 10, objectHandle,
                                           NULL, 0, creationHash, creationHashSize,
                                           &creationTicket, NULL, 0, &respBuf, &respSize);
            TEST_ASSERT(rc == (TPM_RC_BAD_AUTH + TPM_RC_S + TPM_RC_1),
                        "Expected TPM_RC_BAD_AUTH for wrong integratedAuth");
            TEST_ASSERT(gp.failedTries == triesBefore, "failedTries incremented for DA-exempt TPM_RH_INTEGRATED");

            // Correct integratedAuth succeeds
            rc = SendCertifyIntegratedAuth(TPM_RH_INTEGRATED, newAuth, (UINT16)(sizeof(newAuth) - 1),
                                           objectHandle, NULL, 0, creationHash, creationHashSize,
                                           &creationTicket, NULL, 0, &respBuf, &respSize);
            TEST_ASSERT(rc == TPM_RC_SUCCESS, "CertifyIntegrated with updated integratedAuth failed");

            // Reset integratedAuth back to empty
            rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, newAuth, (UINT16)(sizeof(newAuth) - 1),
                                         NULL, 0);
            TEST_ASSERT(rc == TPM_RC_SUCCESS, "Resetting integratedAuth to empty failed");

            // G4: HMAC session on HierarchyChangeAuth(TPM_RH_INTEGRATED) and CertifyIntegrated
            {
                BYTE       nonceTPM[32];
                UINT16     nonceTPMLen = 0;
                BYTE       nonceCaller[16];
                TPM_HANDLE hmacSession;
                BYTE       handleNames[4 + 68];
                BYTE       paramsBuf[512];
                BYTE       authArea[128];
                BYTE*      hp;
                BYTE*      pp;
                UINT32     authAreaLen;
                const char hmacAuth[] = "hmac-session-auth";

                memset(nonceCaller, 0x22, sizeof(nonceCaller));
                hmacSession = StartAuthSessionSimple(TPM_SE_HMAC, nonceTPM, &nonceTPMLen);
                hp = handleNames;
                PutU32(&hp, TPM_RH_INTEGRATED);
                pp = paramsBuf;
                Put2B(&pp, hmacAuth, (UINT16)(sizeof(hmacAuth) - 1));
                authAreaLen = BuildHmacAuthArea(authArea, hmacSession, nonceCaller, sizeof(nonceCaller),
                                                nonceTPM, nonceTPMLen, TPM_CC_HierarchyChangeAuth,
                                                handleNames, 4, paramsBuf, (UINT32)(pp - paramsBuf),
                                                NULL, 0, 0x00);
                cp = cmd;
                PutU16(&cp, TPM_ST_SESSIONS);
                PutU32(&cp, 0);
                PutU32(&cp, TPM_CC_HierarchyChangeAuth);
                PutU32(&cp, TPM_RH_INTEGRATED);
                PutBytes(&cp, authArea, authAreaLen);
                PutBytes(&cp, paramsBuf, (size_t)(pp - paramsBuf));
                rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize);
                TEST_ASSERT(rc == TPM_RC_SUCCESS, "G4: HierarchyChangeAuth with HMAC session failed");
                TEST_ASSERT(VerifyResponseHmac(respBuf, respSize, TPM_CC_HierarchyChangeAuth,
                                               nonceCaller, sizeof(nonceCaller),
                                               (const BYTE*)hmacAuth, (UINT16)(sizeof(hmacAuth) - 1)),
                            "G4: HierarchyChangeAuth response HMAC not keyed with new integratedAuth");
                TEST_ASSERT(!VerifyResponseHmac(respBuf, respSize, TPM_CC_HierarchyChangeAuth,
                                                nonceCaller, sizeof(nonceCaller), NULL, 0),
                            "G4: HierarchyChangeAuth response HMAC unexpectedly matched old integratedAuth");

                // Now run TPM2_CertifyIntegrated using an HMAC session keyed with hmacAuth
                hmacSession = StartAuthSessionSimple(TPM_SE_HMAC, nonceTPM, &nonceTPMLen);
                hp = handleNames;
                PutU32(&hp, TPM_RH_INTEGRATED);
                PutBytes(&hp, objectName, objectNameSize);
                pp = paramsBuf;
                Put2B(&pp, "hmac-qd", 7);
                Put2B(&pp, creationHash, creationHashSize);
                PutU16(&pp, creationTicket.tag);
                PutU32(&pp, creationTicket.hierarchy);
                Put2B(&pp, creationTicket.digest.t.buffer, creationTicket.digest.t.size);
                Put2B(&pp, NULL, 0);
                authAreaLen = BuildHmacAuthArea(authArea, hmacSession, nonceCaller, sizeof(nonceCaller),
                                                nonceTPM, nonceTPMLen, TPM_CC_CertifyIntegrated,
                                                handleNames, (UINT32)(hp - handleNames),
                                                paramsBuf, (UINT32)(pp - paramsBuf),
                                                (const BYTE*)hmacAuth, (UINT16)(sizeof(hmacAuth) - 1), 0x00);
                cp = cmd;
                PutU16(&cp, TPM_ST_SESSIONS);
                PutU32(&cp, 0);
                PutU32(&cp, TPM_CC_CertifyIntegrated);
                PutU32(&cp, TPM_RH_INTEGRATED);
                PutU32(&cp, objectHandle);
                PutBytes(&cp, authArea, authAreaLen);
                PutBytes(&cp, paramsBuf, (size_t)(pp - paramsBuf));
                rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize);
                TEST_ASSERT(rc == TPM_RC_SUCCESS, "G4: CertifyIntegrated with HMAC session failed");
                TEST_ASSERT(VerifyResponseHmac(respBuf, respSize, TPM_CC_CertifyIntegrated,
                                               nonceCaller, sizeof(nonceCaller),
                                               (const BYTE*)hmacAuth, (UINT16)(sizeof(hmacAuth) - 1)),
                            "G4: CertifyIntegrated response HMAC invalid");

                rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, hmacAuth, (UINT16)(sizeof(hmacAuth) - 1),
                                             NULL, 0);
                TEST_ASSERT(rc == TPM_RC_SUCCESS, "Resetting integratedAuth after G4 failed");
            }

            // Policy session on signHandle = TPM_RH_INTEGRATED must return TPM_RC_AUTH_UNAVAILABLE (0x12F)
            {
                BYTE       nonceTPM[32];
                UINT16     nonceTPMLen = 0;
                BYTE       nonceCaller[16];
                TPM_HANDLE policySession = StartAuthSessionSimple(TPM_SE_POLICY, nonceTPM, &nonceTPMLen);

                memset(nonceCaller, 0x33, sizeof(nonceCaller));
                cp = cmd;
                PutU16(&cp, TPM_ST_SESSIONS);
                PutU32(&cp, 0);
                PutU32(&cp, TPM_CC_CertifyIntegrated);
                PutU32(&cp, TPM_RH_INTEGRATED);
                PutU32(&cp, objectHandle);
                PutU32(&cp, 4 + 2 + 16 + 1 + 2);
                PutU32(&cp, policySession);
                Put2B(&cp, nonceCaller, 16);
                PutU8(&cp, 0x01);
                PutU16(&cp, 0);
                Put2B(&cp, NULL, 0);
                Put2B(&cp, creationHash, creationHashSize);
                PutU16(&cp, creationTicket.tag);
                PutU32(&cp, creationTicket.hierarchy);
                Put2B(&cp, creationTicket.digest.t.buffer, creationTicket.digest.t.size);
                Put2B(&cp, NULL, 0);
                rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize);
                TEST_ASSERT(rc == TPM_RC_AUTH_UNAVAILABLE,
                            "Expected TPM_RC_AUTH_UNAVAILABLE (0x12F) for policy session on TPM_RH_INTEGRATED");
                FlushContextHandle(policySession);
            }

            // Invalid signHandle (e.g. TPM_RH_OWNER or TPM_RH_NULL) must fail with TPM_RC_VALUE on H1
            rc = SendCertifyIntegratedAuth(TPM_RH_OWNER, NULL, 0, objectHandle,
                                           NULL, 0, creationHash, creationHashSize,
                                           &creationTicket, NULL, 0, &respBuf, &respSize);
            TEST_ASSERT(rc == (TPM_RCS_VALUE + RC_CertifyIntegrated_signHandle),
                        "Expected TPM_RCS_VALUE + RC_CertifyIntegrated_signHandle for TPM_RH_OWNER");

            rc = SendCertifyIntegratedAuth(TPM_RH_NULL, NULL, 0, objectHandle,
                                           NULL, 0, creationHash, creationHashSize,
                                           &creationTicket, NULL, 0, &respBuf, &respSize);
            TEST_ASSERT(rc == (TPM_RCS_VALUE + RC_CertifyIntegrated_signHandle),
                        "Expected TPM_RCS_VALUE + RC_CertifyIntegrated_signHandle for TPM_RH_NULL");

            // Reject TPM_RH_INTEGRATED as bind in TPM2_StartAuthSession (TPMI_DH_ENTITY, H2)
            cp = cmd;
            PutU16(&cp, TPM_ST_NO_SESSIONS); PutU32(&cp, 0); PutU32(&cp, TPM_CC_StartAuthSession);
            PutU32(&cp, TPM_RH_NULL);        // tpmKey
            PutU32(&cp, TPM_RH_INTEGRATED);  // bind (invalid TPMI_DH_ENTITY)
            PutU16(&cp, 16);                 // nonceCaller size
            memset(cp, 0xAA, 16); cp += 16;
            PutU16(&cp, 0);                  // encryptedSalt
            PutU8(&cp, TPM_SE_HMAC);
            PutU16(&cp, TPM_ALG_NULL);
            PutU16(&cp, TPM_ALG_SHA256);
            rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL);
            TEST_ASSERT(rc == (TPM_RCS_VALUE + TPM_RC_H + TPM_RC_2),
                        "Expected TPM_RCS_VALUE + H2 for StartAuthSession(bind=TPM_RH_INTEGRATED)");

            // Reject TPM_RH_INTEGRATED as authHandle in TPM2_PolicySecret (TPMI_DH_ENTITY, H1)
            cp = cmd;
            PutU16(&cp, TPM_ST_SESSIONS); PutU32(&cp, 0); PutU32(&cp, TPM_CC_PolicySecret);
            PutU32(&cp, TPM_RH_INTEGRATED);  // authHandle (invalid TPMI_DH_ENTITY)
            PutU32(&cp, 0x03000000);         // policySession
            PutPwSession(&cp, NULL, 0);
            PutU16(&cp, 0); PutU16(&cp, 0); PutU16(&cp, 0); PutU32(&cp, 0);
            rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL);
            TEST_ASSERT(rc == (TPM_RCS_VALUE + TPM_RC_H + TPM_RC_1),
                        "Expected TPM_RCS_VALUE + H1 for PolicySecret(authHandle=TPM_RH_INTEGRATED)");

            badTicket = creationTicket;
            badTicket.digest.t.buffer[0] ^= 0xFF;
            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &badTicket, NULL, 0, &respBuf, &respSize);
            TEST_ASSERT(rc == (TPM_RCS_TICKET + RC_CertifyIntegrated_creationTicket),
                        "Expected TPM_RCS_TICKET + RC_CertifyIntegrated_creationTicket");

            memset(oversizedSignerParams, 0x42, sizeof(oversizedSignerParams));
            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &creationTicket, oversizedSignerParams,
                                       (UINT16)sizeof(oversizedSignerParams), &respBuf, &respSize);
            TEST_ASSERT(rc == (TPM_RCS_SIZE + RC_CertifyIntegrated_signerParams),
                        "Expected TPM_RCS_SIZE + RC_CertifyIntegrated_signerParams");

            _plat__SetIntegratedSignerAvailable(FALSE);
            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &creationTicket, NULL, 0, &respBuf, &respSize);
            TEST_ASSERT(rc == TPM_RC_NO_RESULT, "Expected TPM_RC_NO_RESULT");
            _plat__SetIntegratedSignerAvailable(TRUE);

            // S6: Verify NV availability is checked before invoking the hardware Integrated Signer
            // when gp.orderlyState is orderly
            _plat__RegisterIntegratedSigner(CustomTestIntegratedSigner);
            g_customSignerCalls = 0;
            gp.orderlyState     = TPM_SU_CLEAR;
            _plat__ClearNvAvail();
            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &creationTicket, NULL, 0, &respBuf, &respSize);
            _plat__SetNvAvail();
            gp.orderlyState = SU_NONE_VALUE;
            _plat__UseDefaultIntegratedSigner();
            TEST_ASSERT(rc == TPM_RC_NV_UNAVAILABLE && g_customSignerCalls == 0,
                        "S6: Expected TPM_RC_NV_UNAVAILABLE before invoking Integrated Signer");

            // G5: Regression test for FillInAttestInfo via TPM2_GetTime(signHandle=TPM_RH_NULL)
            {
                const BYTE* ap;
                const BYTE* aend;
                UINT16      attLen;
                UINT16      qsLen;
                TPM_HANDLE  qsHandle;
                UINT32      rstCount;
                UINT32      rstartCount;
                UINT64      fwVer;

                cp = cmd;
                PutU16(&cp, TPM_ST_SESSIONS);
                PutU32(&cp, 0);
                PutU32(&cp, TPM_CC_GetTime);
                PutU32(&cp, TPM_RH_ENDORSEMENT);
                PutU32(&cp, TPM_RH_NULL);
                PutU32(&cp, 18);
                PutU32(&cp, TPM_RS_PW); PutU16(&cp, 0); PutU8(&cp, 0x01); PutU16(&cp, 0);
                PutU32(&cp, TPM_RS_PW); PutU16(&cp, 0); PutU8(&cp, 0x01); PutU16(&cp, 0);
                Put2B(&cp, "q", 1);
                PutU16(&cp, TPM_ALG_NULL);
                rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), &respBuf, &respSize);
                TEST_ASSERT(rc == TPM_RC_SUCCESS, "G5: TPM2_GetTime(signHandle=TPM_RH_NULL) failed");
                rp     = respBuf + 10;
                rend   = respBuf + respSize;
                (void)GetU32(&rp, rend);
                attLen = GetU16(&rp, rend);
                ap     = rp;
                aend   = rp + attLen;
                TEST_ASSERT(GetU32(&ap, aend) == TPM_GENERATED_VALUE, "G5: magic mismatch");
                TEST_ASSERT(GetU16(&ap, aend) == TPM_ST_ATTEST_TIME, "G5: type mismatch");
                qsLen    = GetU16(&ap, aend);
                qsHandle = GetU32(&ap, aend);
                TEST_ASSERT(qsLen == 4 && qsHandle == TPM_RH_NULL,
                            "G5: qualifiedSigner != TPM_RH_NULL (0x40000007)");
                GetBytes(&ap, aend, NULL, GetU16(&ap, aend));  // extraData
                (void)GetU64(&ap, aend);                       // clock
                rstCount    = GetU32(&ap, aend);
                rstartCount = GetU32(&ap, aend);
                (void)GetU8(&ap, aend);                        // safe
                fwVer       = GetU64(&ap, aend);
                TEST_ASSERT(rstCount != gp.resetCount && rstartCount != gr.restartCount
                            && fwVer != ((((UINT64)gp.firmwareV1) << 32) + gp.firmwareV2),
                            "G5: TPM_RH_NULL counters/firmwareVersion were not obfuscated");
            }

            // G6: Real TPM2_ReadOnlyControl command test
#  if CC_ReadOnlyControl
            cp = cmd;
            PutU16(&cp, TPM_ST_SESSIONS);
            PutU32(&cp, 0);
            PutU32(&cp, TPM_CC_ReadOnlyControl);
            PutU32(&cp, TPM_RH_PLATFORM);
            PutPwSession(&cp, NULL, 0);
            PutU8(&cp, YES);
            rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL);
            TEST_ASSERT(rc == TPM_RC_SUCCESS, "G6: TPM2_ReadOnlyControl(YES) failed");

            rc = SendHierarchyChangeAuth(TPM_RH_INTEGRATED, NULL, 0, "ro", 2);
            TEST_ASSERT(rc == TPM_RC_READ_ONLY,
                        "G6: Expected TPM_RC_READ_ONLY (0x156) for HierarchyChangeAuth in Read-Only mode");

            rc = SendCertifyIntegrated(objectHandle, NULL, 0, creationHash, creationHashSize,
                                       &creationTicket, NULL, 0, &respBuf, &respSize);
            TEST_ASSERT(rc == TPM_RC_SUCCESS,
                        "G6: TPM2_CertifyIntegrated failed in Read-Only mode");

            cp = cmd;
            PutU16(&cp, TPM_ST_SESSIONS);
            PutU32(&cp, 0);
            PutU32(&cp, TPM_CC_ReadOnlyControl);
            PutU32(&cp, TPM_RH_PLATFORM);
            PutPwSession(&cp, NULL, 0);
            PutU8(&cp, NO);
            rc = RunTpmCommand(cmd, (uint32_t)(cp - cmd), NULL, NULL);
            TEST_ASSERT(rc == TPM_RC_SUCCESS, "G6: TPM2_ReadOnlyControl(NO) failed");
#  endif

            // 9. Run Adversarial Probes (XOR/AES-128-CFB param enc/dec, Audit, Bound Session,
            // Disabled Hierarchy, 3-Session Max Response, and 64-byte SHA-512 Digest)
            FlushContextHandle(nullSha256Obj.handle);
            RunAdversarialProbes(objectHandle, creationHash, creationHashSize,
                                 &creationTicket, objectName, objectNameSize);
        }
    }

    _plat__NVDisable((void*)TRUE, 0);
    printf("=== ALL TPM2_CertifyIntegrated TESTS PASSED ===\n");
    return 0;
#endif  // CC_CertifyIntegrated
}
