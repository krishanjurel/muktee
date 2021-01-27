#ifndef __IEEE_1609DOT2CERT_HPP__
#define __IEEE_1609DOT2CERT_HPP__
#include <iostream>
#include "ieee1609dot2common.hpp"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"
#include <openssl/bn.h>

#ifdef _cplusplus
extern "C"
{
#endif

typedef enum {
    CertTypeExplicit,
    CertTypeImplicit
}CertType;



/* certifiicate issuer */
/* 6.4.7 */

typedef enum
{
    IssuerIdentifierTypeHashId,
    IssuerIdentifierTypeHashAlgo,
}IssuerIdentifierType;

typedef union 
{
    HashedId8 hashId;
    HashAlgorithmType algo;
}IssuerIdentifier;

/* 6.4.13 */
typedef struct 
{
    uint8_t length;
    char *name;
}HostName;

/* 6.4.16 */
typedef enum{
    DurationTypeMicroSeconds,
    DurationTypeMilliSeconds,
    DurationTypeSeconds,
    DurationTypeMinutes,
    DurationTypeSixtyHours,
    DurationTypeYears
}DurationType;

union duration
{
    uint16_t microSeconds;
    uint16_t milliseconds;
    uint16_t seconds;
    uint16_t minutes;
    uint16_t hours;
    uint16_t sixtyHours;
    uint16_t years;   
};
#define DURATION_HOURS      duration.hours
#define DURATION_MINUTES    duration.minutes
typedef union duration Duration;

/* 6.4.14 */
struct validityPeriod
{
    time_t start;
    Duration duration;
};
typedef struct validityPeriod ValidityPeriod;

/*6.4.10 */
typedef struct linkageValue{uint8_t x[9];}LinkageValue;
struct linkageData
{
    uint16_t iCert;
    LinkageValue linkageValue;
};
typedef struct linkageData LinkageData;

/* 6.4.9 */
typedef enum
{
    CertificateIdTypeLinkageData,
    CertificateIdTypeName,
    CertificateIdTypeBinaryId,
    CertificateIdTypeNone
}CertificateIdType;

union certificateId
{
    LinkageData linkageData;
    HostName hostName;
    OctetString binaryId;
};
typedef union certificateId CertificateId;
/*6.4.35 */
typedef enum
{
    VerificationKeyIndicatorTypeKey, /* key , */
    VerificationKeyIndicatorTypeRecValue /* reconstruction value */
}VerificationKeyIndicatorType;

/* 6..4.36 */
typedef enum
{
    PublicVerificationKeyTypEecdsaNistP256S,
    PublicVerificationKeyTypeEcdsaBrainpoolP256r1
}PublicVerificationKeyType;

typedef union {
    EccP256CurvPoint ecdsaNistP256S;
    EccP256CurvPoint ecdsaBrainpoolP256r1;
}PublicVerificationKey;

typedef union
{
    PublicVerificationKey verificationKey;
    EccP256CurvPoint recValue;
}VerificationKeyIndicator;

/*6.4.28 */
struct PsidSsp
{
    int psid;
    OctetString ssp;
};
typedef struct PsidSsp PsidSsp;

struct SequenceOfPsidSsp
{
    int length;
    PsidSsp psidSsp[0];
};

typedef struct SequenceOfPsidSsp SequenceOfPsidSsp;

/* 6.4.8 */
struct ToBeSignedCertificate
{
    CertificateIdType certificateIdType;
    DurationType durationType;
    VerificationKeyIndicatorType verificationKeyIndicatorType;
    CertificateId id;
    HashedId3 cracaId;
    uint16_t crlSeries;
    ValidityPeriod validityPeriod;
    SequenceOfPsidSsp appPermisions;
    PublicVerificationKeyType publicVerificationKeyType;
    VerificationKeyIndicator verifyKeyIndicator;
};
typedef struct ToBeSignedCertificate ToBeSignedCertificate;

/* 6.4.3*/
struct certificateBase
{
    uint8_t   version;
    CertType   certType;
    IssuerIdentifierType issuerType;
    IssuerIdentifier issuer;
    ToBeSignedCertificate toBeSignedCertificate;
};
typedef struct certificateBase CertificateBase;


/*6.4.2*/
struct SequenceOfCertificate
{
    int length;     /* number of certs */
    CertificateBase certs[0];
};
typedef struct SequenceOfCertificate SequenceOfCertificate;


/* 6.3.24 */
typedef enum 
{
    SignerIdentifierTypeDigest,
    SignerIdentifierTypeCert,
    SignerIdentifierTypeSelf
}SignerIdentifierType;

union SignerIdentifier
{
    HashedId8 digest;
    SequenceOfCertificate certificate;
    int self;
};
typedef union SignerIdentifier SignerIdentifier;

#ifdef _cplusplus
}
#endif

namespace ctp
{
    /* cert class */
    class cert
    {
        std::vector<SequenceOfCertificate *> certs;
        EC_KEY *ecKey;
        public:
            void create();

            //void encode();
            //void decode();

            explicit cert();
            /* no copy constructure */
            cert(const cert&) = delete;
            /* no copy assignment */
            const cert& operator=(const cert&) = delete;
            /* no move constructor */
            cert(const cert&&) = delete;
            ~cert();

    };

} /* namespace ctp */









#endif // __IEEE_1609DOT2CERT_HPP__