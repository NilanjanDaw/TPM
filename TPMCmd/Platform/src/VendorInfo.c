//** Introduction
// Provide vendor-specific version and identifiers to core TPM library for
// return in capabilities.  These may not be compile time constants and therefore
// are provided by platform callbacks.  These platform functions are expected to
// always be available, even in failure mode.
//
//** Includes
#include <string.h>
#include "Platform.h"

// In this sample platform, these are compile time constants, but are not required to be.
#define MANUFACTURER    "XYZ "
#define VENDOR_STRING_1 "xCG "
#define VENDOR_STRING_2 "fTPM"
#define VENDOR_STRING_3 "\0\0\0\0"
#define VENDOR_STRING_4 "\0\0\0\0"
#define FIRMWARE_V1     (0x20250320)
#define FIRMWARE_V2     (0x00000000)
#define MAX_SVN         255

static uint32_t currentHash = FIRMWARE_V2;
static uint16_t currentSvn  = 10;

// Similar to the Core Library's ByteArrayToUint32, but usable in Platform code.
static uint32_t StringToUint32(char s[4])
{
    uint8_t* b = (uint8_t*)s;  // Avoid promotion to a signed integer type
    return (((uint32_t)b[0] << 8 | b[1]) << 8 | b[2]) << 8 | b[3];
}

// return the 4 character Manufacturer Capability code.  This
// should come from the platform library since that is provided by the manufacturer
LIB_EXPORT uint32_t _plat__GetManufacturerCapabilityCode()
{
    return StringToUint32(MANUFACTURER);
}

// return the 4 character VendorStrings for Capabilities.
// Index is ONE-BASED, and may be in the range [1,4] inclusive.
// Any other index returns all zeros. The return value will be interpreted
// as an array of 4 ASCII characters (with no null terminator)
LIB_EXPORT uint32_t _plat__GetVendorCapabilityCode(int index)
{
    switch(index)
    {
        case 1:
            return StringToUint32(VENDOR_STRING_1);
        case 2:
            return StringToUint32(VENDOR_STRING_2);
        case 3:
            return StringToUint32(VENDOR_STRING_3);
        case 4:
            return StringToUint32(VENDOR_STRING_4);
    }
    return 0;
}

// return the most-significant 32-bits of the TPM Firmware Version reported by
// getCapability.
LIB_EXPORT uint32_t _plat__GetTpmFirmwareVersionHigh()
{
    return FIRMWARE_V1;
}

// return the least-significant 32-bits of the TPM Firmware Version reported by
// getCapability.
LIB_EXPORT uint32_t _plat__GetTpmFirmwareVersionLow()
{
    return FIRMWARE_V2;
}

// return the TPM Firmware SVN reported by getCapability.
LIB_EXPORT uint16_t _plat__GetTpmFirmwareSvn(void)
{
    return currentSvn;
}

// return the TPM Firmware maximum SVN reported by getCapability.
LIB_EXPORT uint16_t _plat__GetTpmFirmwareMaxSvn(void)
{
    return MAX_SVN;
}

// Called by the simulator to set the TPM Firmware SVN reported by
// getCapability.
LIB_EXPORT void _plat__SetTpmFirmwareHash(uint32_t hash)
{
    currentHash = hash;
}

// Called by the simulator to set the TPM Firmware SVN reported by
// getCapability.
LIB_EXPORT void _plat__SetTpmFirmwareSvn(uint16_t svn)
{
    currentSvn = MIN(svn, MAX_SVN);
}

#if SVN_LIMITED_SUPPORT
// Dummy implmenentation for obtaining a Firmware SVN Secret bound
// to the given SVN.
LIB_EXPORT int _plat__GetTpmFirmwareSvnSecret(uint16_t  svn,
                                              uint16_t  secret_buf_size,
                                              uint8_t*  secret_buf,
                                              uint16_t* secret_size)
{
    int i;

    if(svn > currentSvn)
    {
        return -1;
    }

    // INSECURE dummy implementation: repeat the SVN into the secret buffer.
    for(i = 0; i < secret_buf_size; ++i)
    {
        secret_buf[i] = ((uint8_t*)&svn)[i % sizeof(svn)];
    }

    *secret_size = secret_buf_size;

    return 0;
}
#endif  // SVN_LIMITED_SUPPORT

#if FW_LIMITED_SUPPORT
// Dummy implmenentation for obtaining a Firmware Secret bound
// to the current firmware image.
LIB_EXPORT int _plat__GetTpmFirmwareSecret(
    uint16_t secret_buf_size, uint8_t* secret_buf, uint16_t* secret_size)
{
    int i;

    // INSECURE dummy implementation: repeat the firmware hash into the
    // secret buffer.
    for(i = 0; i < secret_buf_size; ++i)
    {
        secret_buf[i] = ((uint8_t*)&currentHash)[i % sizeof(currentHash)];
    }

    *secret_size = secret_buf_size;

    return 0;
}
#endif  // FW_LIMITED_SUPPORT

// return the TPM Type returned by TPM_PT_VENDOR_TPM_TYPE
LIB_EXPORT uint32_t _plat__GetVendorTpmType()
{
    return 1;  // just the value the reference code has returned in the past.
}

LIB_EXPORT void _plat_GetSpecCapabilityValue(SPEC_CAPABILITY_VALUE* returnData)
{
    // clang-format off
    // this is on the title page of part1 of the TPM spec
    returnData->tpmSpecLevel      = 0;
    // these come from part2 of the TPM spec
    returnData->tpmSpecVersion    = 184;
    returnData->tpmSpecYear       = 2025;
    returnData->tpmSpecDayOfYear  = 79; // March 20
    // these come from the PC Client Platform TPM Profile Specification
    returnData->platformFamily    = 1;
    returnData->platfromLevel     = 0;
    // The platform spec version is recorded such that 0x00000101 means version 1.01
    // Note this differs from some TPM/TCG specifications, but matches the behavior of Windows.
    // more recent TCG specs have discontinued using this field, but Windows displays it, so we
    // retain it using the historical encoding.
    returnData->platformRevision  = 0x105;
    returnData->platformYear      = 0;
    returnData->platformDayOfYear = 0;
    // clang-format on
    return;
}

//** Integrated Signer Platform Implementation
// Supports runtime registration of platform-specific Integrated Signers as well
// as a keyed simulator-only reference signer when built with SIMULATION.

#if SIMULATION

// Non-public simulator-only internal secret key for reference report tags.
// Keyed with 256 bits of internal secret state so tags cannot be recomputed or
// forged from the public report fields (firmwareV2, firmwareSvn).
static const uint32_t s_simSignerSecretKey[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};
static const uint64_t s_simSignerBootSecret = 0xD6E8FEB86659FD93ULL;

// Keyed mixing helper for simulator-only reference report signature tags
static void ComputeDeterministicTag(const uint8_t* domainLabel,
                                    size_t         domainLen,
                                    const uint8_t* payload,
                                    size_t         payloadLen,
                                    uint8_t*       outTag,
                                    size_t         outTagLen)
{
    uint32_t bootLo = (uint32_t)(s_simSignerBootSecret & 0xFFFFFFFFu);
    uint32_t bootHi = (uint32_t)(s_simSignerBootSecret >> 32);
    uint32_t acc    = 0x811C9DC5u ^ s_simSignerSecretKey[0] ^ bootLo
                   ^ currentHash ^ ((uint32_t)currentSvn << 16);
    size_t i;
    size_t j;

    for(i = 0; i < outTagLen; ++i)
    {
        uint32_t keyWord = s_simSignerSecretKey[i & 7u] ^ bootHi;
        uint32_t lane    = acc ^ keyWord ^ (uint32_t)(i * 0x9E3779B9u);
        for(j = 0; j < domainLen; ++j)
        {
            lane ^= domainLabel[j];
            lane *= 0x01000193u;
        }
        for(j = 0; j < payloadLen; ++j)
        {
            lane ^= (uint32_t)payload[j] + (uint32_t)j + s_simSignerSecretKey[j & 7u];
            lane = (lane << 5) | (lane >> 27);
            lane *= 0x01000193u;
        }
        lane ^= s_simSignerSecretKey[(i + 3u) & 7u] ^ bootLo;
        lane *= 0x85EBCA6Bu;
        acc       = lane;
        outTag[i] = (uint8_t)((lane >> ((i & 3u) * 8u)) & 0xFFu);
    }
}

// Default simulator Integrated Signer implementation (SIMULATION only)
static uint32_t SimIntegratedSigner(uint16_t       hashAlg,
                                    const uint8_t* digest,
                                    uint16_t       digestSize,
                                    const uint8_t* signerParams,
                                    uint16_t       signerParamsSize,
                                    uint16_t       maxAttestSize,
                                    uint8_t*       attestBuf,
                                    uint16_t*      attestSize)
{
    static const uint8_t   kSimDomain[] = "TPM2_SIM_INTEGRATED_SIGNER_V1";
    PLAT_SIM_ATTEST_REPORT report;
    uint16_t               flags = 0;

    if(digest == NULL || attestBuf == NULL || attestSize == NULL || digestSize == 0
       || digestSize > sizeof(report.signerInputDigest)
       || maxAttestSize < sizeof(report))
    {
        return PLAT_INTEGRATED_ATTEST_UNAVAILABLE;
    }

    if(signerParamsSize != 0)
    {
        PLAT_SIM_SIGNER_PARAMS params;
        if(signerParams == NULL)
        {
            return PLAT_INTEGRATED_ATTEST_INVALID_PARAMS;
        }
        if(signerParamsSize != sizeof(params))
        {
            return PLAT_INTEGRATED_ATTEST_INVALID_SIZE;
        }
        memcpy(&params, signerParams, sizeof(params));
        if(params.version != PLAT_SIM_PARAMS_VER || params.reserved != 0
           || (params.flags & (uint16_t)~PLAT_SIM_VALID_FLAGS) != 0)
        {
            return PLAT_INTEGRATED_ATTEST_INVALID_PARAMS;
        }
        flags = params.flags;
    }

    memset(&report, 0, sizeof(report));
    report.magic       = PLAT_SIM_ATTEST_MAGIC;
    report.version     = PLAT_SIM_PARAMS_VER;
    report.flags       = flags;
    report.hashAlg     = hashAlg;
    report.digestSize  = digestSize;
    report.firmwareV1  = FIRMWARE_V1;
    report.firmwareV2  = currentHash;
    report.firmwareSvn = currentSvn;
    memcpy(report.signerInputDigest, digest, digestSize);

    ComputeDeterministicTag(kSimDomain,
                            sizeof(kSimDomain) - 1,
                            (const uint8_t*)&report,
                            offsetof(PLAT_SIM_ATTEST_REPORT, signature),
                            report.signature,
                            sizeof(report.signature));

    memcpy(attestBuf, &report, sizeof(report));
    *attestSize = (uint16_t)sizeof(report);
    return PLAT_INTEGRATED_ATTEST_SUCCESS;
}

static _plat__IntegratedSignerFn s_integratedSignerCallback  = SimIntegratedSigner;
static int                       s_integratedSignerAvailable = 1;

LIB_EXPORT void _plat__UseDefaultIntegratedSigner(void)
{
    s_integratedSignerCallback  = SimIntegratedSigner;
    s_integratedSignerAvailable = 1;
}

#else  // !SIMULATION

static _plat__IntegratedSignerFn s_integratedSignerCallback  = NULL;
static int                       s_integratedSignerAvailable = 0;

#endif  // SIMULATION

LIB_EXPORT void _plat__RegisterIntegratedSigner(_plat__IntegratedSignerFn callback)
{
    s_integratedSignerCallback = callback;
}

LIB_EXPORT _plat__IntegratedSignerFn _plat__GetIntegratedSigner(void)
{
    return s_integratedSignerCallback;
}

LIB_EXPORT void _plat__SetIntegratedSignerAvailable(int available)
{
    s_integratedSignerAvailable = available;
}

LIB_EXPORT int _plat__IsIntegratedSignerAvailable(void)
{
    return s_integratedSignerAvailable && (s_integratedSignerCallback != NULL);
}

LIB_EXPORT uint32_t _plat__GetIntegratedAttestation(
    uint16_t       hashAlg,
    const uint8_t* digest,
    uint16_t       digestSize,
    const uint8_t* signerParams,
    uint16_t       signerParamsSize,
    uint16_t       maxAttestSize,
    uint8_t*       attestBuf,
    uint16_t*      attestSize)
{
    if(!_plat__IsIntegratedSignerAvailable())
    {
        return PLAT_INTEGRATED_ATTEST_UNAVAILABLE;
    }

    return s_integratedSignerCallback(hashAlg,
                                      digest,
                                      digestSize,
                                      signerParams,
                                      signerParamsSize,
                                      maxAttestSize,
                                      attestBuf,
                                      attestSize);
}
