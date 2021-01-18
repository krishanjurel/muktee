#ifndef __IEEE_1609DOT2COMMON_HPP__
#define __IEEE_1609DOT2COMMON_HPP__
#include <iostream>

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

union EccP256CurvPoint
{
    HashedData32 xonly;
    HashedData32 fill; /* figure it out */
    HashedData32 compressedy0;
    HashedData32 compressedy1;
    struct {
        HashedData32 x;
        HashedData32 y;
    }uncompressed;
};
typedef union EccP256CurvPoint EccP256CurvPoint;

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

union Signature
{
    EcdsaP256Signature ecdsaNistP256Signature;
    EcdsaP256Signature ecdsaBrainpoolP256r1Signature;
};
typedef union Signature Signature;


#endif //__IEEE_1609DOT2COMMON_HPP__
