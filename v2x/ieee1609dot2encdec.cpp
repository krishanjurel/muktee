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
#include <sstream>
#include <string>

#define MODULE 1


namespace ctp
{


    int Ieee1609Encode::clear()
    {
        /* clear whatever was in the encoded buffer */
        if(encBuf)
        {
            free(encBuf);
            encBuf = nullptr;
        }
        encLen = 0;
        return encLen; 
    }

    /* encode certificate identifier */
    int Ieee1609Encode::CertId(const CertificateId& id)
    {
        int len_ = 1;
        uint8_t choice = 0x80 | (uint8_t)(id.type);
        uint8_t *buf;

        switch(id.type)
        {
            case CertificateIdTypeName:
                len_ += id.id.hostName.length;
                buf = (uint8_t *)id.id.hostName.name;
                len_ += 1;
                break;
            default:
                LOG_ERR("Ieee1609Encode::CertId: unsupported cert id", 1);
                break;
        }

        std::cout << "Ieee1609Encode::CertId enter " << encLen << std::endl;

        encBuf = (uint8_t *)buf_realloc(encBuf, (len_ + encLen));
        encBuf[encLen++] = choice;
        len_ --;
        /* encode the length */
        encBuf[encLen++] = id.id.hostName.length;
        len_ --;
        /* copy the remainder of buffer into the encoded buffer */
        while(len_ > 0)
        {
            encBuf[encLen++] = *buf++;
            len_--;
        }
        std::cout << "Ieee1609Encode::CertId Exit " << encLen << std::endl;
        /* return the length */
        return encLen;
    }
    /* encode crl series */
    int Ieee1609Encode::CrlSeries(const uint16_t series)
    {
         /* its two bytes */
        int len = encLen + 2;
         std::cout << "Ieee1609Encode::CrlSeries enter " << encLen << " " << len << std::endl;
        encBuf = (uint8_t *)buf_realloc(encBuf, len);

        uint8_t *buf = (uint8_t *)&series;
        /* copy in the network byte order */
        encBuf[encLen++] = buf[1];
        encBuf[encLen++] = *buf;
        std::cout << "Ieee1609Encode::CrlSeries exit " << encLen << std::endl;
        return encLen;
    }
    /* encode hashid3 */
    int Ieee1609Encode::HashId3(const uint8_t* hash, size_t len)
    {
        std::cout << "Ieee1609Encode::HashId3 eenter " << encLen << std::endl;
        /* just fill it with the hard coded a,b,c */
        encBuf = (uint8_t *)buf_realloc(encBuf, (len+encLen));

        {
            encBuf[encLen++] = *hash++;
            encBuf[encLen++] = *hash++;
            encBuf[encLen++] = *hash++;
        }
        std::cout << "Ieee1609Encode::HashId3 exit" << encLen << std::endl;
        return encLen;
        return 0;
    }
    int Ieee1609Encode::Octets_(const uint8_t* octets, size_t len)
    {
        std::cout << "Ieee1609Encode::HashId3: enter  " << encLen << std::endl;
        len += encLen;
        encBuf = (uint8_t *)buf_realloc(encBuf, len);
        while(len--)
        {
            encBuf[encLen++] = *octets++;
        }

        std::cout << "Ieee1609Encode::HashId3: exit  " << encLen << std::endl;
        return encLen;
    }

    int Ieee1609Encode::IssuerIdentifier_(const IssuerIdentifier& issuer)
    {
        std::cout << "Ieee1609Encode::IssuerIdentifier_: enter  " << encLen << std::endl;
        const char *data =  nullptr;
        int len = 1; /* choice */
        if(issuer.type == IssuerIdentifierTypeHashId)
        {
            len += 8;
            data = issuer.issuer.hashId.x;
        }
        else {
            len += 1; /* just one for hash alogo type */
            data =  (char *)&issuer.issuer.algo;
        }
        encBuf = (uint8_t *)buf_realloc(encBuf, (len+encLen));
        encBuf[encLen++] = (uint8_t)((0x80) | issuer.type);
        len --;

        for(int i = 0; i < len; i++)
        {
            encBuf[encLen++] = *data++;
            len --;
        }
        std::cout << "Ieee1609Encode::IssuerIdentifier_: exit  " << encLen << std::endl;
        return encLen;

    }

    int Ieee1609Encode::SequenceOfPsid_(const SequenceOfPsidSsp& psid)
    {

        /* FIXME, only one psid with no ssp */
        /* length octet is one */
        int len = 1;
        /* there is only 1 sequence */
        len += 1;
        /* need one byte to encode sequence */
        len += 1;
        /* 1 byte for psid length encoding and 1 bytes for bsm psid (0x20) */
        len += 2;

        //len += encLen;

        encBuf = (uint8_t *)buf_realloc(encBuf, len+encLen);
        if(encBuf == nullptr)
        {
            throw std::bad_alloc();
        }

        std::cout << "Ieee1609Encode::SequenceOfPsid_: enter  " << encLen << std::endl;

        /* encode number of sequences */
        encBuf[encLen++] = 1; /* number of bytes to represent one sequence, 1 */
        len -= 1;
        encBuf[encLen++] = 1; /* number of sequences */
        len -= 1;
        encBuf[encLen++]  = 0x00; /* sequence with no optional ssp */
        len -= 1;
        encBuf[encLen++] = 1; /* number of bytes in the psid */
        len -= 1;
        encBuf[encLen++] = psid.psidSsp->psid;
        len -= 1;
         if (len != 0)
         {
             LOG_ERR("Ieee1609Encode::SequenceOfPsid_: rem length not zero", 1);
             throw new std::logic_error("cert::encode_sequenceofpsid(): rem length not zero ");
         }
         std::cout << "Ieee1609Encode::SequenceOfPsid_: exit  " << encLen << std::endl;
         return encLen;
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

       std::cout << "Ieee1609Encode::VP enter " << encLen << std::endl;

        /* allocate the buffer for duration*/
        encBuf = (uint8_t *)buf_realloc(encBuf, len+encLen);
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
        std::cout << "Ieee1609Encode::VP exit " << encLen << std::endl;
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

        std::cout << "Ieee1609Encode::Vki enter " << encLen << std::endl;

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

        std::cout << "Ieee1609Encode::Vki exit " << encLen << std::endl;

        return encLen;

    }

    /* encode the 1609Dot2 contents */
    int Ieee1609Encode::Ieee1609Dot2ContentType_(const Ieee1609Dot2ContentType type)
    {
        int len = 1; /* choice */
        std::cout << "Ieee1609Encode::Ieee1609Dot2ContentType_ enter " << encLen << std::endl;
        encBuf = (uint8_t *)buf_realloc(encBuf, (encLen +  len));
        encBuf[encLen++] = (uint8_t)((0x80) | type);
        len--;
        std::cout << "Ieee1609Encode::Ieee1609Dot2ContentType_ exit " << encLen << std::endl;
        return encLen;
    }

    int Ieee1609Encode::Signature_(const Signature *signature)
    {
        int len = 1; /* for signature choice */
        uint8_t choice = (0x80) | (signature->type);
        std::cout << "Ieee1609Encode::Signature_ enter " << encLen << std::endl;
        len += 1; /* choice of curve point type */

        len += 64; /* 64 maximum buffer for curve point, r of the signature */
        len += 32; /* 32 bytes for the s */

        try
        {
            encBuf = (uint8_t*)buf_realloc(encBuf, (encLen +  len));
        }catch (const std::bad_alloc& e)
        {
            LOG_ERR("Ieee1609Encode::Signature_::buf_realloc error allocation buffer ", 1);
            throw new std::runtime_error("Ieee1609Encode::Signature_::buf_realloc error allocation buffer ");
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
        std::stringbuf log_("Ieee1609Encode::Signature_", std::ios_base::out | std::ios_base::ate);
        std::ostream os(&log_);
        os << "Ieee1609Encode::Signature_ remaining length (exp >= 0) "  << len << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        std::cout << "Ieee1609Encode::Signature_ exit " << encLen << std::endl;
        return encLen;

    }


    int Ieee1609Encode::SequenceOfCerts_(const SequenceOfCertificate& certs)
    {
        return 0;
    }

    int Ieee1609Encode::SignerIdentifier_(Ieee1609Cert& signer, SignerIdentifierType type)
    {
        int len = 1; /* choice */
        uint8_t *buf = nullptr;
        size_t bufLen = 0;
        std::cout << "Ieee1609Encode::SignerIdentifier_ enter " << encLen << std::endl;
        if(type != SignerIdentifierTypeSelf)
        {
            /* encode the signer, i.e. the certificate */
            bufLen = signer.encode(&buf);
        }
    
        if(bufLen > 0)
        {
            len += bufLen;

            encBuf = (uint8_t *)buf_realloc(encBuf, (len+encLen));
            encBuf[encLen++] = (uint8_t)((0x80) | type);
            len --;
            while(len)
            {
                encBuf[encLen++] = *buf++;
                len --;
            }
        }
        std::cout << "Ieee1609Encode::SignerIdentifier_ exit " << encLen << std::endl;
        return encLen;
    }

    int Ieee1609Encode::OctectsFixed(const uint8_t *octets, size_t len)
    {
        std::cout << "Ieee1609Encode::OctectsFixed enter " << encLen << std::endl;
        encBuf = (uint8_t *)buf_realloc(encBuf, len+encLen);
        while(len)
        {
            encBuf[encLen++] = *octets++;
            len--;
        }
        std::cout << "Ieee1609Encode::OctectsFixed exit " << encLen << std::endl;
        return encLen;
    }

    int Ieee1609Encode::psid_(int psid, int bytes)
    {
        int len = 1 +  bytes; /* number of bytes */
        std::cout << "Ieee1609Encode::psid_ enter " << encLen << std::endl;
        encBuf = (uint8_t *)buf_realloc(encBuf, (encLen + len));
        uint8_t *buf = (uint8_t *)&psid;
        encBuf[encLen++] = bytes;
        len --;
        while(len)
        {
            encBuf[encLen++] = *buf++;
            len --;
        }
        std::cout << "Ieee1609Encode::psid_ exit " << encLen << std::endl;
        return encLen;
    }

    int Ieee1609Encode::HashAlgo(const HashAlgorithmType type)
    {
        int len = 1;
        std::cout << " Ieee1609Encode::HashAlgo enter " << encLen << std::endl;
        encBuf = (uint8_t *)buf_realloc(encBuf, (len+encLen));
        /* just encode the hash algo type */
        encBuf[encLen++] = type;
        std::cout << " Ieee1609Encode::HashAlgo exit " << encLen << std::endl;
        return 0;
    }

    int Ieee1609Encode::HeaderInfo_(const HeaderInfo& header)
    {
        /*FIXME, just psid only */
        int len  = 1; /* preamble */
        uint8_t preamble = 0x00;
        std::cout << " Ieee1609Encode::HeaderInfo_ enter " << encLen << std::endl;
        encBuf = (uint8_t *)buf_realloc(encBuf, len+encLen);
        encBuf[encLen++] = preamble;
        len --;
        len =  psid_(header.psid);
        std::cout << " Ieee1609Encode::HeaderInfo_ exit " << encLen << std::endl;
        return encLen;
    }

    int Ieee1609Encode::SignedDataPayload_(const Ieee1609Dot2Data& data)
    {
        std::cout << " Ieee1609Encode::SignedDataPayload_ enter " << encLen << std::endl;
        /* default option is one */
        /* the sequence preamble byte 00 */
        uint8_t preamble = 0x40; /* only first optional compoent */
        int len = 1;
        /* encoding of Ieee1609Dot2Data, 6.3.2 */
        len += 1; /* for the protcol version */
        len += 1; /* for choice opaque */
        len += 1; /* number of bytes in the lenght */
        len += 4; /* 4 bytes in the length */
        len += data.content.UNSECUREDDATA.length;

        encBuf = (uint8_t *)buf_realloc(encBuf, (encLen + len));


        /* preamble for signed Data payload option */
        encBuf[encLen++] = preamble;
        len--;
        /* protocol version */
        encBuf[encLen++] = data.protocolVersion; 
        len --;
        std::cout << "data.content.type " << (data.content.type) << std::endl;
        /* the choice for opaque data */
        encBuf[encLen++] = (uint8_t)((0x80) | (data.content.type));
        len --;

        /* encode the number of bytes , 4 */
        encBuf[encLen++] = 4; /* 4 integer bytes */
        len --;
        uint8_t *dataBuf = (uint8_t *)&data.content.UNSECUREDDATA.length;
        for (int i = 3; i >= 0; i--)
        {
            /* encode in network order */
            encBuf[encLen++] = dataBuf[i];
            len --;
        }
        /* copy the data */
        dataBuf = data.content.UNSECUREDDATA.octets;
        while(len)
        {
            encBuf[encLen++] = *dataBuf++;
            len--;
        }

        std::string _log("Ieee1609Encode::SignedDataPayload_  rem length(exp) ");
        _log.append(std::to_string(len));
        log_info(_log, MODULE);
        return encLen;

    }
    

    int Ieee1609Encode::ToBesignedData_(const ToBeSignedData& tbsData)
    {
        /* to be signd data is composed of
         1. sigend payload, and 
         2. header info
        */
       SignedDataPayload_(std::ref(*tbsData.payload.data));
       HeaderInfo_(tbsData.headerInfo);
        return 0;
    }

    int Ieee1609Encode::get(uint8_t **buf)
    {
       /* copy the encoded buffer*/
        *buf = this->encBuf;
        return encLen;
    }

    



} /*namespace ctp */