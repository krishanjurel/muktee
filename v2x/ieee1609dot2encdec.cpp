/*
    file to encode/decode 1609.2 packets, C-OER only 
*/

#include "ieee1609dot2.hpp"
#include "ieee1609dot2cert.hpp"
#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <iostream>
#include <fstream>


namespace ctp
{

    /* encode certificate identifier */
    int Ieee1609Encode::CertId(const CertificateId& id)
    {
        return 0;
    }
    /* encode crl series */
    int Ieee1609Encode::CrlSeries(const uint16_t series)
    {
         /* its two bytes */
        int len = encLen + 2;
        encBuf = (uint8_t *)realloc(encBuf, len);

        uint8_t *buf = (uint8_t *)&series;
        /* copy in the network byte order */
        encBuf[encLen++] = buf[1];
        encBuf[encLen++] = *buf;
        std::cout << "Ieee1609Encode::CrlSeries " << encLen << std::endl;
        return encLen;
    }
    /* encode hashid3 */
    int Ieee1609Encode::HashId3(const uint8_t* hash, size_t len)
    {
        len_ = encLen + 3;
        /* just fill it with the hard coded a,b,c */
        encBuf = (uint8_t *)realloc(encBuf, len);
        {
            encBuf[encLen++] = *hash++;
            encBuf[encLen++] = *hash++;
            encBuf[encLen++] = *hash++;
        }
        std::cout << "Ieee1609Encode::HashId3 " << encLen << std::endl;
        return encLen;
        return 0;
    }
    /* encode the signature */
    int Ieee1609Encode::Sign(const Signature& signature)
    {
        return 0;

    }
    /* encode validity period */
    int Ieee1609Encode::VP(const ValidityPeriod& validityPeriod)
    {
        /* validity period consists of start time of 4 bytes */
        int len = 4;
        /* 1 byte for choice of duration */
        len += 1;
        /* and two bytes of duration */
        len += 2;

        /* update the length */
        len += encLen; 

        /* allocate the buffer for duration*/
        encBuf = (uint8_t *)realloc(encBuf, len);
        if(encBuf == nullptr)
        {
            throw std::bad_alloc();
        }

        /* copy the duration in the network byte order */
        uint8_t *buf = (uint8_t *)&validityPeriod.start;
        encBuf[encLen++] = buf[3];
        encBuf[encLen++] = buf[2];
        encBuf[encLen++] = buf[1];
        encBuf[encLen++] = buf[0];
        len -= 4;

        /* initialize the choice */
        uint8_t choice = 0x80 | (uint8_t)(validityPeriod.duration.type);
        len -= 1;
        encBuf[encLen++] = choice;
        buf = (uint8_t *)&validityPeriod.duration.duration.minutes;
        /* copy in the network byte order */
        encBuf[encLen++] = buf[1];
        encBuf[encLen++] = buf[0]; 
        len -= 2;
        std::cout << "Ieee1609Encode::VP " << encLen << std::endl;
        return encLen;
    }
    /* encode verfication key indicator */
    int Ieee1609Encode::Vki(const VerificationKeyIndicator& vki)
    {
               /* for hashing purposes, all the ecc points of toBeSigned data structure
           are used in the compressed form, i.e. compressed-[y0,y1]
        */
        /*FIXME, this is using the self-signed, we need to get the compressed form of 
          all our ecc points in the verification key identifier 
        */
        int len = 1; /* for choice indicator */
        /* next another choice public verification type */
        len += 1;
        /* next another choise of point type, which is compressed */
        len += 1;
        /* folllowed by 32 bytes of compressed point */
        len += 32;

        /* update the total encoding length */
        //len += encLen;

        /* reallocate the buffer */
        encBuf = (uint8_t *)buf_realloc(encBuf, (len + encLen));
        uint8_t choice = 0x80 | (uint8_t) (vki.type);
        encBuf[encLen++] = choice;
        len -= 1;
        /* choice of public verification */
        choice = (0x80) | (uint8_t)(vki.indicator.verificationKey.type);
        encBuf[encLen++] = choice;
        len -= 1;
        /*FIXME, choice of curve point-type*/
        choice = (0x80) | (uint8_t)(0x01);
        encBuf[encLen++] = choice;
        len -= 1;
        /* just take the y 0*/
        const uint8_t *key = (uint8_t *)vki.indicator.verificationKey.key.ecdsaNistP256S.point.compressedy0.x;
        while(len > 0)
        {
            encBuf[encLen++] = *key++;
            len -= 1;
        }

        std::cout << "Ieee1609Encode::Vki " << encLen << std::endl;

        return encLen;

    }

    int Ieee1609Encode::Signature_(const Signature *signature)
    {
        int len = 1; /* for signature choice */
        uint8_t choice = (0x80) | (signature->type);
        len += 1; /* choice of curve point type */

        len += 64; /* 64 maximum buffer for curve point, r of the signature */
        len += 32; /* 32 bytes for the s */

        try
        {
            encBuf = (uint8_t*)buf_realloc(encBuf, (encLen +  len));
        }catch (const std::bad_alloc& e)
        {
            LOG_ERR("cert::encode_sig::buf_realloc error allocation buffer ", 1);
            throw new std::runtime_error("cert::encode_sig::buf_realloc error allocation buffer ");
        }

        /* start encoding */
        encBuf[encLen++] = choice;
        len --;
        /* choice of curve point type */
        choice = (0x80) | (signature->signature.ecdsaP256Signature.r.type);
        encBuf[encLen++] = choice;
        len --;

        choice  = signature->signature.ecdsaP256Signature.r.type;

        uint8_t *pointBuf = nullptr;
        size_t pointLen = 0;
        if(choice == EccP256CurvPointXOnly){
            pointBuf = (uint8_t *)signature->signature.ecdsaP256Signature.r.point.xonly.x;
            pointLen = 32;
        }else if (choice == EccP256CurvPointCompressedy0)
        {
            pointBuf = (uint8_t *)signature->signature.ecdsaP256Signature.r.point.compressedy0.x;
            pointLen = 32;
        }else if (choice == EccP256CurvPointCompressedy1)
        {
            pointBuf = (uint8_t *)signature->signature.ecdsaP256Signature.r.point.compressedy1.x;
            pointLen = 32;
        }else if (choice == EccP256CurvPointUncompressed){
            pointBuf = (uint8_t *)signature->signature.ecdsaP256Signature.r.point.uncompressed.x.x;
            pointLen = 64;
        }


        /*encode the r points */
        while(pointLen)
        {
            encBuf[encLen++] = *pointBuf++;
            pointLen--;
            len --;
        }
        /* encode the s point */
        pointBuf = (uint8_t *)signature->signature.ecdsaP256Signature.s.x;
        pointLen = sizeof(signature->signature.ecdsaP256Signature.s.x);

        while(pointLen)
        {
            encBuf[encLen++] = *pointBuf++;
            pointLen--;
            len --;
        }
        //static_assert((len >= 0));
        log_info("cert::encode_sig", 1);
        std::cout << "cert::encode_sig remaining length (exp >= 0) "  << len << std::endl;
        std::cout << "cert::encode_sig encoded lenght (exp >= 0) "  << encLen << std::endl;
        return encLen;

    }

    int Ieee1609Encode::SignerIdentifier_(const SignerIdentifier& signer)
    {
        return 0;
    }

    int Ieee1609Encode::HashAlgo(const HashAlgorithmType type)
    {
        return 0;
    }


    int Ieee1609Encode::ToBesignedData_(const ToBeSignedData& tbsData)
    {
        return 0;
    }


    int Ieee1609Encode::get(uint8_t **buf)
    {
        /* copy the encoded buffer*/
        *buf = this->encBuf;
        return encLen;
    }

    



} /*namespace ctp */