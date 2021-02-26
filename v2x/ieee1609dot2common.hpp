#ifndef __IEEE_1609DOT2COMMON_HPP__
#define __IEEE_1609DOT2COMMON_HPP__
#include <iostream>


#ifdef __cplusplus
extern "C"
{
#endif
extern void *buf_alloc(size_t len);
extern void *buf_realloc(void *ptr, size_t len);
extern void *buf_calloc(size_t num, size_t size);
#ifdef __cplusplus
}
#endif





/* 
    All data type is represented in upper camel case, with no underscores.
    All variables are declared in lower camel case, with no underscores.

    The Data Type and variable names are kept, as much as possible, as described in IEEE 1609.2-2016 spec, unless the name is of generic type.

*/

/* general definitions */
/* a variable length octet string */

typedef struct 
{
    uint8_t length;
    uint8_t octets[0];
}OctetString;


/*6.3.25 */
typedef struct {char x[3];}HashedId3;
/* 6.3.26 */
typedef struct {char x[8];}HashedId8;
/* 6.3.27 */
typedef struct {char x[10];}HashedId10;

/*6.3.8*/
typedef struct {char x[32];}HashedData32;

/*6.3.5 */
typedef enum
{
    HashAlgorithmTypeSha256
}HashAlgorithmType;


/* 6.3.23 */
typedef enum 
{
    EccP256CurvPointXOnly,
    EccP256CurvPointFill,
    EccP256CurvPointCompressedy0,
    EccP256CurvPointCompressedy1,
    EccP256CurvPointUncompressed
}EccP256CurvPointType;


typedef struct 
{
    EccP256CurvPointType type;
    union 
    {
        HashedData32 xonly;
        HashedData32 fill; /* figure it out */
        HashedData32 compressedy0;
        HashedData32 compressedy1;
        struct {
            HashedData32 x;
            HashedData32 y;
        }uncompressed;
#define  uncompressedx   uncompressed.x 
#define  uncompressedy   uncompressed.y
    }point;
}EccP256CurvPoint;

/*6.3.29*/
struct EcdsaP256Signature
{
    EccP256CurvPoint r;
    HashedData32 s;
};
typedef struct EcdsaP256Signature EcdsaP256Signature;

/*6.3.28 */
typedef enum 
{
    ecdsaNistP256Signature,
    ecdsaBrainpoolP256r1Signature,
}SignatureType;

struct Signature
{
    SignatureType type;
    union
    { 
        EcdsaP256Signature ecdsaP256Signature;
        EcdsaP256Signature ecdsaBrainpoolP256r1Signature;
    }signature;
};
typedef struct Signature Signature;






/* certificate definitions */


typedef enum {
    CertTypeExplicit,
    CertTypeImplicit
}CertType;



/* certifiicate issuer */
/* 6.4.7 */

typedef enum
{
    IssuerIdentifierTypeHashId,
    IssuerIdentifierTypeSelf,
}IssuerIdentifierType;

typedef union 
{
    HashedId8 hashId;
    HashAlgorithmType algo;
}IssuerIdentifier;

/* structure encpasulating the isuer identifier */
typedef struct {
    IssuerIdentifierType type;
    IssuerIdentifier issuer;
}Issuer;

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

typedef struct 
{
    DurationType type;
    union
    {
        uint16_t microSeconds;
        uint16_t milliseconds;
        uint16_t seconds;
        uint16_t minutes;
        uint16_t hours;
        uint16_t sixtyHours;
        uint16_t years;
    }duration;
#define DURATION_HOURS      duration.hours
#define DURATION_MINUTES    duration.minutes
}Duration;


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
typedef union certificateId CertId;


typedef struct {
    CertificateIdType type;
    CertId id;
}CertificateId;




/* 6..4.36 */
typedef enum
{
    PublicVerificationKeyTypEecdsaNistP256S,
    PublicVerificationKeyTypeEcdsaBrainpoolP256r1
}PublicVerificationKeyType;



typedef struct 
{
    PublicVerificationKeyType type;

    union {
        EccP256CurvPoint ecdsaNistP256S;
        EccP256CurvPoint ecdsaBrainpoolP256r1;
    }key;
}PublicVerificationKey;

/*6.4.35 */
typedef enum
{
    VerificationKeyIndicatorTypeKey, /* key , */
    VerificationKeyIndicatorTypeRecValue /* reconstruction value */
}VerificationKeyIndicatorType;

typedef struct 
{
    VerificationKeyIndicatorType type;
    union
    {
        PublicVerificationKey verificationKey;
        EccP256CurvPoint recValue;
    }indicator;
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
    Duration duration;
    ValidityPeriod validityPeriod;
    SequenceOfPsidSsp appPermisions;
    VerificationKeyIndicator verifyKeyIndicator;
};
typedef struct ToBeSignedCertificate ToBeSignedCertificate;


/* 6.4.3*/
struct certificateBase
{
    uint8_t   version;
    CertType   certType;
    Issuer issuer;
    ToBeSignedCertificate toBeSignedCertificate;
    Signature signature;
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




/* data content related definitions */




/* contains SPDU  data structures and definitions */ 

/* 
    All data type is represented in upper camel case, with no underscores.
    All variables are declared in lower camel case, with no underscores.

    The Data Type and variable names are kept, as much as possible, as described in IEEE 1609.2-2016 spec, unless the name is of generic type.

*/
/* defined 1609.3 */

/* 6.3.9 */
struct HeaderInfo
{
    int psid;
};
typedef struct HeaderInfo HeaderInfo;

/* 6.3.7 */
struct SignedDataPayload
{
    /* this is the data has to be sent */
    OctetString data;
    HashedData32 extDataHash;
};
typedef struct SignedDataPayload SignedDataPayload;

/*6.3.6 */
struct ToBeSignedData
{
    SignedDataPayload signedDataPayload;
    HeaderInfo headerInfo;
    
};
typedef struct ToBeSignedData ToBeSignedData;


/*6.3.4 */
struct SignedData
{
    HashAlgorithmType HashAlgorithm;
    ToBeSignedData toBeSignedData;
    SignerIdentifierType signerType;
    SignerIdentifier signer;
    SignatureType signatureType;
    Signature signature;
};

/* 6.3.3 */
typedef enum
{
    Ieee1609Dot2ContentUnsecuredData,
    Ieee1609Dot2ContentSignedData,
    Ieee1609Dot2ContentEncrData,
    Ieee1609Dot2ContentSignedCertReq,
}Ieee1609Dot2ContentType;

union ieee1609Dot2Content
{
    OctetString unsecuredData;
    SignedData signedData;
    /* TBD: add the types of encrypted data and signed cert request */   
};
typedef union ieee1609Dot2Content Ieee1609Dot2Content;

struct Ieee1609Dot2Data
{
    uint8_t protocolVersion;
    Ieee1609Dot2ContentType contentType;
    Ieee1609Dot2Content content;
};
typedef struct Ieee1609Dot2Data Ieee1609Dot2Data;




#endif //__IEEE_1609DOT2COMMON_HPP__
