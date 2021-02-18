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


#endif //__IEEE_1609DOT2COMMON_HPP__
