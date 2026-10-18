#define IO_BUFFER_C
#include "Tpm.h"
#include "Attest_spt_fp.h"
#include "CertifyIntegrated_fp.h"

#if CC_CertifyIntegrated  // Conditional expansion of this file

// Compile-time bounds verification for CertifyIntegrated I/O and response buffers.
TPM_STATIC_ASSERT(((sizeof(CertifyIntegrated_In) + 7u) & ~7u)
                      + sizeof(CertifyIntegrated_Out)
                  < sizeof(s_actionIoBuffer));
TPM_STATIC_ASSERT(10u + sizeof(UINT32) + sizeof(UINT16)
                      + offsetof(TPMS_ATTEST, attested) + sizeof(TPMS_CREATION_INFO)
                      + sizeof(UINT16) + MAX_INTEGRATED_ATTEST_SIZE
                      + (MAX_SESSION_NUM * sizeof(TPMS_AUTH_RESPONSE))
                  <= MAX_RESPONSE_SIZE);

/*(See part 3 specification)
// Prove the association between an object and its creation data using
// an Integrated Signer
*/
//  Return Type: TPM_RC
//      TPM_RC_RETRY        Integrated Signer is temporarily busy
//      TPM_RC_SIZE         'signerParams' has an invalid size for the
//                          Integrated Signer
//      TPM_RC_TICKET       'creationTicket' does not match 'objectHandle' and
//                          'creationHash'
//      TPM_RC_VALUE        'signerParams' contains an unsupported or invalid
//                          value for the Integrated Signer
//      TPM_RC_NO_RESULT    Integrated Signer is unavailable or failed to
//                          generate the attestation
TPM_RC
TPM2_CertifyIntegrated(CertifyIntegrated_In*  in,  // IN: input parameter list
                       CertifyIntegrated_Out* out  // OUT: output parameter list
)
{
    TPM_RC           result = TPM_RC_SUCCESS;
    TPMT_TK_CREATION ticket;
    TPMS_ATTEST      certifyInfo;
    TPM2B_DIGEST     signerInputDigest;
    BYTE*            buffer;
    UINT32           responseOverhead;
    UINT16           maxAttestSize;
    UINT16           attestSize = 0;
    uint32_t         platStatus;
    OBJECT*          certified = HandleToObject(in->objectHandle);

    pAssert_RC(certified != NULL);

    // Re-compute creation ticket
    result = TicketComputeCreation(
        in->creationTicket.hierarchy, &certified->name, &in->creationHash, &ticket);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Compare ticket
    if(!MemoryEqual2B(&ticket.digest.b, &in->creationTicket.digest.b))
        return TPM_RCS_TICKET + RC_CertifyIntegrated_creationTicket;

    // Ensure NV is available to clear orderly state before invoking the
    // hardware Integrated Signer.
    if(NV_IS_ORDERLY)
        RETURN_IF_NV_IS_NOT_AVAILABLE;

    // Command Output
    // Fill in attest information with signHandle == TPM_RH_INTEGRATED
    // (sets qualifiedSigner to 0x4000000E and leaves clockInfo.resetCount,
    // clockInfo.restartCount, and firmwareVersion unobfuscated).
    FillInAttestInfo(in->signHandle, NULL, &in->qualifyingData, &certifyInfo);

    // CertifyIntegrated specific fields
    certifyInfo.type                             = TPM_ST_ATTEST_INTEGRATED;
    certifyInfo.attested.integrated.objectName   = certified->name;
    certifyInfo.attested.integrated.creationHash = in->creationHash;

    // Marshal TPMS_ATTEST structure into out->certifyInfo
    buffer                  = out->certifyInfo.t.attestationData;
    out->certifyInfo.t.size = TPMS_ATTEST_Marshal(&certifyInfo, &buffer, NULL);

    // Compute signerInputDigest := H_{objectHandle->nameAlg}(certifyInfo.attestationData)
    signerInputDigest.t.size = CryptHashBlock(certified->publicArea.nameAlg,
                                              out->certifyInfo.t.size,
                                              out->certifyInfo.t.attestationData,
                                              sizeof(signerInputDigest.t.buffer),
                                              signerInputDigest.t.buffer);
    if(signerInputDigest.t.size == 0)
        return TPM_RC_NO_RESULT;

    // Bound maxAttestSize by both the TPM2B_INTEGRATED_ATTEST buffer and the
    // remaining capacity in MAX_RESPONSE_SIZE after header, parameterSize,
    // certifyInfo, attestation.t.size, and worst-case session responses.
    responseOverhead = 10u + sizeof(UINT32) + sizeof(UINT16)
                       + (UINT32)out->certifyInfo.t.size + sizeof(UINT16)
                       + (UINT32)(MAX_SESSION_NUM * sizeof(TPMS_AUTH_RESPONSE));
    if(responseOverhead >= MAX_RESPONSE_SIZE)
        return TPM_RC_NO_RESULT;
    maxAttestSize = (UINT16)sizeof(out->attestation.t.buffer);
    if((UINT32)maxAttestSize > (UINT32)(MAX_RESPONSE_SIZE - responseOverhead))
        maxAttestSize = (UINT16)(MAX_RESPONSE_SIZE - responseOverhead);

    // Invoke Integrated Signer via platform interface
    platStatus = _plat__GetIntegratedAttestation(certified->publicArea.nameAlg,
                                                 signerInputDigest.t.buffer,
                                                 signerInputDigest.t.size,
                                                 in->signerParams.t.buffer,
                                                 in->signerParams.t.size,
                                                 maxAttestSize,
                                                 out->attestation.t.buffer,
                                                 &attestSize);
    if(platStatus == PLAT_INTEGRATED_ATTEST_INVALID_SIZE)
        return TPM_RCS_SIZE + RC_CertifyIntegrated_signerParams;
    if(platStatus == PLAT_INTEGRATED_ATTEST_INVALID_PARAMS)
        return TPM_RCS_VALUE + RC_CertifyIntegrated_signerParams;
    if(platStatus == PLAT_INTEGRATED_ATTEST_RETRY)
        return TPM_RC_RETRY;
    if(platStatus == PLAT_INTEGRATED_ATTEST_UNAVAILABLE)
        return TPM_RC_NO_RESULT;
    // Allow only error-class vendor-specific Format-Zero response codes
    // (0x00000500..0x0000057F: RC_VER1=0x100 and T=0x400 set, RC_WARN=0x800,
    // reserved bit 9=0x200, and Format-One bit 7=0x80 all clear).
    if((platStatus & 0xFFFFFF80u) == 0x00000500u)
        return (TPM_RC)platStatus;
    if(platStatus != PLAT_INTEGRATED_ATTEST_SUCCESS || attestSize == 0
       || attestSize > maxAttestSize)
        return TPM_RC_NO_RESULT;

    out->attestation.t.size = attestSize;

    // Command uses the clock so clear the orderly state if it is set
    return NvClearOrderly();
}

#endif  // CC_CertifyIntegrated
