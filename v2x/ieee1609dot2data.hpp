#ifndef __IEEE_1609DOT2DATA_HPP__
#define __IEEE_1609DOT2DATA_HPP__

#include "ieee1609dot2common.hpp"
#include "ieee1609dot2cert.hpp"

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


#endif //__IEEE_1609DOT2DATA_HPP__
