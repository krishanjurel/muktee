#ifndef __IEEE_1609DOT2CERT_HPP__
#define __IEEE_1609DOT2CERT_HPP__
#include <iostream>
#include "ieee1609dot2common.hpp"

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
typedef union 
{
    HashedId8 hashId;
}IssuerIdentifier;

/* 6.4.13 */
typedef struct 
{
    uint8_t length;
    char *name;
}HostName;

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
typedef union duration Duration;


/* 6.4.14 */
struct validityPeriod
{
    uint32_t start;
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
union certificateId
{
    LinkageData linkageData;
    HostName hostName;
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
    CertificateId id;
    HashedId3 cracaId;
    uint16_t crlSeries;
    ValidityPeriod validityPeriod;
    SequenceOfPsidSsp appPermisions;
    PublicVerificationKeyType publicVerificationKeyType;
    VerificationKeyIndicatorType verifyKeyIndicatorType;
    VerificationKeyIndicator verifyKeyIndicator;
};
typedef struct ToBeSignedCertificate ToBeSignedCertificate;

/* 6.4.3*/
struct certificateBase
{
    uint8_t   version;
    CertType   certType;
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


#endif // __IEEE_1609DOT2CERT_HPP__