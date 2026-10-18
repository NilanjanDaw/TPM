#if CC_CertifyIntegrated  // Command must be enabled

#  ifndef _TPM_INCLUDE_PRIVATE_PROTOTYPES_CERTIFYINTEGRATED_FP_H_
#    define _TPM_INCLUDE_PRIVATE_PROTOTYPES_CERTIFYINTEGRATED_FP_H_

// Input structure definition
typedef struct
{
    TPMI_RH_INTEGRATED signHandle;
    TPMI_DH_OBJECT     objectHandle;
    TPM2B_DATA         qualifyingData;
    TPM2B_DIGEST       creationHash;
    TPMT_TK_CREATION   creationTicket;
    TPM2B_MAX_BUFFER   signerParams;
} CertifyIntegrated_In;

// Output structure definition
typedef struct
{
    TPM2B_ATTEST            certifyInfo;
    TPM2B_INTEGRATED_ATTEST attestation;
} CertifyIntegrated_Out;

// Response code modifiers
#    define RC_CertifyIntegrated_signHandle     (TPM_RC_H + TPM_RC_1)
#    define RC_CertifyIntegrated_objectHandle   (TPM_RC_H + TPM_RC_2)
#    define RC_CertifyIntegrated_qualifyingData (TPM_RC_P + TPM_RC_1)
#    define RC_CertifyIntegrated_creationHash   (TPM_RC_P + TPM_RC_2)
#    define RC_CertifyIntegrated_creationTicket (TPM_RC_P + TPM_RC_3)
#    define RC_CertifyIntegrated_signerParams   (TPM_RC_P + TPM_RC_4)

// Function prototype
TPM_RC
TPM2_CertifyIntegrated(CertifyIntegrated_In* in, CertifyIntegrated_Out* out);

#  endif  // _TPM_INCLUDE_PRIVATE_PROTOTYPES_CERTIFYINTEGRATED_FP_H_
#endif    // CC_CertifyIntegrated
