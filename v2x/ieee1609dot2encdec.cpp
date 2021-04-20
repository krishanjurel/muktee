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
#include <unistd.h>




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
        int len = 0;
        uint8_t choice = ASN1_COER_CHOICE_MASK_SET | (uint8_t)(id.type);
        uint8_t *buf;
        std::stringstream log_(std::ios_base::out);
        log_ << "Ieee1609Encode::CertId enter " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");

        len = 1; /* for choice */
        switch(id.type)
        {
            case CertificateIdTypeName:
                len += id.id.hostName.length;
                buf = (uint8_t *)id.id.hostName.name;
                len += 1; /* length encoding */
                break;
            default:
                LOG_ERR("Ieee1609Encode::CertId: unsupported cert id", MODULE);
                throw Exception(log_.str());
                break;
        }
        encBuf = (uint8_t *)buf_realloc(encBuf, (len + encLen));
        encBuf[encLen++] = choice;
        len --;
        /* encode the length */
        encBuf[encLen++] = id.id.hostName.length;
        len --;
        /* copy the remainder of buffer into the encoded buffer */
        while(len > 0)
        {
            encBuf[encLen++] = *buf++;
            len--;
        }
        log_ << "Ieee1609Encode::CertId Exit " << "rem len " << len << "enc len " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        /* return the length */
        return encLen;
    }
    /* encode crl series */
    int Ieee1609Encode::CrlSeries(const uint16_t series)
    {
        std::stringstream log_(std::ios_base::out);
         /* its two bytes */
        int len = 2;
        log_ << "Ieee1609Encode::CrlSeries enter encLen " << encLen << " len " << len << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        encBuf = (uint8_t *)buf_realloc(encBuf, (len+encLen));

        uint8_t *buf = (uint8_t *)&series;
        /* copy in the network byte order */
        encBuf[encLen++] = buf[1];
        encBuf[encLen++] = buf[0];
        len -= 2;
        log_ << "Ieee1609Encode::CrlSeries exit " << "rem len " << len << "enc len " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        return encLen;
    }
    /* encode hashid3 */
    int Ieee1609Encode::HashId3(const uint8_t* hash, size_t len)
    {
        std::stringstream log_(std::ios_base::out);
        log_ << "Ieee1609Encode::HashId3 enter " << encLen << " len " << len << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        /* just fill it with the hard coded a,b,c */
        encBuf = (uint8_t *)buf_realloc(encBuf, (len+encLen));

        {
            encBuf[encLen++] = *hash++;
            encBuf[encLen++] = *hash++;
            encBuf[encLen++] = *hash;
            len -= 3;
        }
        log_ << "Ieee1609Encode::HashId3 exit" << "rem len " << len << "enc len " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        return 0;
    }
    int Ieee1609Encode::Octets_(const uint8_t* octets, size_t len)
    {
        std::stringstream log_(std::ios_base::out);
        log_ << "Ieee1609Encode::Octets_: enter  encLen " << encLen << " len " << len << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        encBuf = (uint8_t *)buf_realloc(encBuf, (len + encLen));
        while(len--)
        {
            encBuf[encLen++] = *octets++;
        }

        log_ << "Ieee1609Encode::Octets_: exit  " << "rem len " << len << "enc len " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        return encLen;
    }

    int Ieee1609Encode::IssuerIdentifier_(const IssuerIdentifier& issuer)
    {
        std::stringstream log_(std::ios_base::out);
        log_ << "Ieee1609Encode::IssuerIdentifier_: enter  " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        const char *data =  nullptr;
        int len = 1; /* choice */
        if(issuer.type == IssuerIdentifierTypeHashId)
        {
            len += sizeof(HashedId8);
            data = issuer.issuer.hashId.x;
        }
        else {
            len += 1; /* just one for hash alogo type */
            data =  (char *)&issuer.issuer.algo;
        }
        encBuf = (uint8_t *)buf_realloc(encBuf, (len+encLen));
        encBuf[encLen++] = (uint8_t)(ASN1_COER_CHOICE_MASK_SET | issuer.type);
        len --;

        for(int i = 0; i < len; i++)
        {
            encBuf[encLen++] = *data++;
            len --;
        }
        log_ << "Ieee1609Encode::IssuerIdentifier_: exit  " << "rem len " << len << "enc len " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        return encLen;

    }

    /* sequence encoding is different than just length encoding, in terms, sequence of encoding always have 
        length determinant up-front 
    */
    int Ieee1609Encode::SequenceOf(size_t quantity)
    {
        std::stringstream log_(std::ios_base::out);
        log_ << " Ieee1609Encode::SequenceOf enter " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        /*reset the stream buffer */
        log_.str("");
        /* encode the length for quantity */
        size_t lenBytes = Length(quantity);
        OctetsFixed((uint8_t*)&quantity, lenBytes);
        log_ << " Ieee1609Encode::SequenceOf exit " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        return encLen;
    }
    int Ieee1609Encode::SequenceOfPsid_(const SequenceOfPsidSsp& psid)
    {
        std::stringstream log_(std::ios_base::out);
        log_ << " Ieee1609Encode::SequenceOfPsid_ enter " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        /* 1 byte to encode quatity*/
        int len = 0;
        SequenceOf(psid.quantity);
        /* number of bytes to encode sequence preamble for otional component */
        // len += psid.quantity;
        /* calculate the total length needed to encode the sequence of psids */
        // for(int i = 0; i < psid.quantity; i++)
        // {
        //     /* one byte for sequence preamble */
        //     len += 1;
        //     /* need one byte to encode the psid lenght*/
        //     len += 1;
        //     /* 4 bytes for encoding psid*/
        //     len += 4;
        //     /* FIXME, handle optional component SSP, for now none */
        // }
        // log_ << "Ieee1609Encode::SequenceOfPsid_: psid.quantity " << psid.quantity << " len "<< len << std::endl;
        // log_info(log_.str(), MODULE);
        // log_.str("");
        // encBuf = (uint8_t *)buf_realloc(encBuf, len+encLen);
        // if(encBuf == nullptr)
        // {
        //     throw std::bad_alloc();
        // }

        /* encode quantity of sequences, FIXME assumed fixed size quantity <= 127 */
        // encBuf[encLen++] = psid.quantity; /* number of bytes to represent one sequence, 1 */
        // len -= 1;

        /* iterate thru the number of available PsidSsps */
        PsidSsp *psidSsp = psid.psidSsp;
        for(int i = 0; i < psid.quantity; i++)
        {
            int psid_ = psidSsp->psid;
            len = 1;
            encBuf = (uint8_t *)buf_realloc(encBuf, len+encLen);
            /* encode the optinal mask */
            encBuf[encLen++] = 0x00;//FIXME, set it to actual value->psidSsp->optionalMask;
            len--;
            /* length encoding of psid */
            Length(sizeof(psid_));
            len = sizeof(psid_);
            encBuf = (uint8_t *)buf_realloc(encBuf, len+encLen);
            /* encode the psid in big endian format */
            uint8_t *buf_ = (uint8_t *)&psid_;
            for(int j = len; j > 0; j--)
            {
                encBuf[encLen++] = buf_[j-1];
                len--;
            }
            /* move to the next component */
            psidSsp += 1;
            /* FIXME, encode the optional ssps */
        }
         if (len != 0)
         {
            log_ << "Ieee1609Encode::SequenceOfPsid_: rem length not zero" << std::endl;
            LOG_ERR(log_.str(), MODULE);
            throw Exception("cert::encode_sequenceofpsid(): rem length not zero ");
         }
         log_ << "Ieee1609Encode::SequenceOfPsid_: exit  " << "rem len " << len << "enc len " << encLen << std::endl;
         log_info(log_.str(), MODULE);
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

        std::stringstream log_(std::ios_base::out);

       log_ << "Ieee1609Encode::VP enter " << encLen << std::endl;
       log_info(log_.str(), MODULE);
       log_.str("");
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
        uint8_t choice = ASN1_COER_CHOICE_MASK_SET | (uint8_t)(validityPeriod.duration.type);
        len -= 1;
        encBuf[encLen++] = choice;
        buf = (uint8_t *)&validityPeriod.duration.duration;
        /* copy in the network byte order */
        encBuf[encLen++] = buf[1];
        encBuf[encLen++] = buf[0]; 
        len -= 2;
        log_ << "Ieee1609Encode::VP exit " << "rem len " << len << "enc len " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        return encLen;
    }
    /* encode verfication key indicator */
    int Ieee1609Encode::Vki(const VerificationKeyIndicator& vki)
    {
        /* for hashing purposes, all the ecc points of toBeSigned data structure
           are used in the compressed form, i.e. compressed-[y0,y1]
        */
        int len = 1; /* for choice indicator */
        /* next another choice public verification type */
        len += 1;
        /* next another choise of point type, which is compressed */
        len += 1;
        /* folllowed by 32 bytes of compressed point */
        len += 32;

        std::stringstream log_(std::ios_base::out);
        log_ << "Ieee1609Encode::Vki enter " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        /* reallocate the buffer */
        encBuf = (uint8_t *)buf_realloc(encBuf, (len + encLen));
        uint8_t choice = ASN1_COER_CHOICE_MASK_SET | (uint8_t) (vki.type);

        encBuf[encLen++] = choice;
        len -= 1;
        /* choice of public verification */
        choice = ASN1_COER_CHOICE_MASK_SET | (uint8_t)(vki.indicator.verificationKey.type);
        encBuf[encLen++] = choice;
        len -= 1;
        const EccP256CurvPoint *point = &vki.indicator.verificationKey.key.ecdsaNistP256;
        choice = ASN1_COER_CHOICE_MASK_SET | (uint8_t)(point->type);
        encBuf[encLen++] = choice;
        len -= 1;
        /* just take the y 0*/
        const uint8_t *key = (uint8_t *)point->point.octets.x;
        while(len > 0)
        {
            encBuf[encLen++] = *key++;
            len -= 1;
        }
        log_ << "Ieee1609Encode::Vki exit " << "rem len " << len << "enc len " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        return encLen;
    }

    /* encode the 1609Dot2 contents */
    int Ieee1609Encode::ContentType_(const Ieee1609Dot2ContentType type)
    {
        int len = 1; /* choice */
        std::stringstream log_(std::ios_base::out);
        log_ << "Ieee1609Encode::Ieee1609Dot2ContentType_ enter " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        encBuf = (uint8_t *)buf_realloc(encBuf, (encLen +  len));
        encBuf[encLen++] = (uint8_t)(ASN1_COER_CHOICE_MASK_SET | type);
        len--;
        log_ << "Ieee1609Encode::Ieee1609Dot2ContentType_ exit " << "rem len " << len << "enc len " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        return encLen;
    }

    int Ieee1609Encode::Signature_(const Signature& signature)
    {
        int len = 0; 
        uint8_t type = 0;
        uint8_t choice = (0x80) | (signature.type);
        std::stringbuf log_( std::ios_base::out);
        std::ostream os(&log_);
        os << "Ieee1609Encode::Signature_ enter " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");

        len = 1; /* for signature choice */
        len += 1; /* choice of curve point type */
        len += 32; /* minimum 32 bytes for the s */

        type  = signature.signature.ecdsaP256Signature.r.type;

        uint8_t *pointBuf = nullptr;
        if(type == EccP256CurvPointTypeXOnly){
            pointBuf = (uint8_t *)signature.signature.ecdsaP256Signature.r.point.octets.x;
            len += 32;
        }else if (choice == EccP256CurvPointTypeCompressedy0)
        {
            pointBuf = (uint8_t *)signature.signature.ecdsaP256Signature.r.point.octets.x;
            len += 32;
        }else if (choice == EccP256CurvPointTypeCompressedy1)
        {
            pointBuf = (uint8_t *)signature.signature.ecdsaP256Signature.r.point.octets.x;
            len += 32;
        }else if (choice == EccP256CurvPointTypeUncompressed){
            pointBuf = (uint8_t *)signature.signature.ecdsaP256Signature.r.point.octets.x;
            len += 64;
        }
        try
        {
            encBuf = (uint8_t*)buf_realloc(encBuf, (encLen +  len));
        }catch (const std::bad_alloc& e)
        {
            os << "Ieee1609Encode::Signature_::buf_realloc error allocation buffer " << std::endl;
            LOG_ERR(log_.str(), MODULE);
            throw new std::runtime_error("Ieee1609Encode::Signature_::buf_realloc error allocation buffer ");
        }

        /* start encoding */
        encBuf[encLen++] = choice;
        len --;

        /* choice of curve point type */
        choice = ASN1_COER_CHOICE_MASK_SET | (signature.signature.ecdsaP256Signature.r.type);
        encBuf[encLen++] = choice;
        len --;

        int rLen = 32;
        /*encode the r points */
        while(rLen)
        {
            encBuf[encLen++] = *pointBuf++;
            len --;
            rLen--;
        }
        /* encode the s point */
        pointBuf = (uint8_t *)signature.signature.ecdsaP256Signature.s.x;
        //pointLen = sizeof(signature->signature.ecdsaP256Signature.s.x);
        int sLen = 32;
        while(sLen)
        {
            // int data;
            // snprintf((char *)&data, 4, "%c", *pointBuf);
            // std::cout << std::hex << data << ":";
            // if(len%4 ==0)
            //     std::cout << std::endl;
            encBuf[encLen++] = *pointBuf++;
            len --;
            sLen --;
        }
        os << "Ieee1609Encode::Signature_ exit " << "rem len " << len << "enc len " ;//<< encLen << std::endl;
        os << encLen << std::endl;
        log_info(log_.str(), MODULE);
        return encLen;

    }

    /* encoding sequence of certs */
    int Ieee1609Encode::SignerIdentifier_(Ieee1609Certs& certs, SignerIdentifierType type)
    {
        int len = 1; /* choice */
        uint8_t *buf = nullptr; /*FIXME, set this buffer to correct memory */
        size_t bufLen = 0;

        std::stringbuf log_(std::ios_base::out);
        std::ostream os(&log_);
        os << "Ieee1609Encode::SignerIdentifier_ enter " << encLen << std::endl;

        log_info(log_.str(), MODULE);
        log_.str("");
        if(type != SignerIdentifierTypeSelf)
        {
            /* encode the signer, i.e. the certificate */
            bufLen = certs.encode(&buf);
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
        os << "Ieee1609Encode::SignerIdentifier_ exit " << "rem len " << len << "enc len " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        return encLen;
    }


    int Ieee1609Encode::SignerIdentifier_(Ieee1609Cert& signer, SignerIdentifierType type)
    {
        int len = 1; /* choice */
        uint8_t *buf = nullptr; /*FIXME, set this buffer to correct memory */
        size_t bufLen = 0;

        std::stringbuf log_(std::ios_base::out);
        std::ostream os(&log_);
        os << "Ieee1609Encode::SignerIdentifier_ enter " << encLen << std::endl;

        log_info(log_.str(), MODULE);
        log_.str("");

        if(type != SignerIdentifierTypeSelf)
        {
            /* encode the signer, i.e. the certificate */
            bufLen = signer.encode(&buf);
        }
    
        if(bufLen > 0)
        {
            len += bufLen;

            encBuf = (uint8_t *)buf_realloc(encBuf, (len+encLen));
            encBuf[encLen++] = (uint8_t)(ASN1_COER_CHOICE_MASK_SET | type);
            len --;
            while(len)
            {
                encBuf[encLen++] = *buf++;
                len --;
            }
        }
        os << "Ieee1609Encode::SignerIdentifier_ exit " << "rem len " << len << "enc len " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        return encLen;
    }

    /* encode the number */
    int Ieee1609Encode::Length(size_t num)
    {
        return Length(nullptr, num);
    }

    int Ieee1609Encode::Length(const uint8_t *octets, size_t num)
    {
        uint32_t numBits = 0;
        uint32_t len = 0; /* 1 byte to encode the number of sequences */
        size_t len_ = 0; /* totatl encoding length for this number */
        // int lenBytes = 0;
        std::stringstream log_;
        log_ << "Ieee1609Encode::Length enter " << encLen << " number " << num << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        size_t back_ = num;
        /* take care of the zero */
        while(back_ != 0)
        {
            back_ = back_ >> 1;
            /* increment the num of bits */
            numBits ++;
        }
        uint8_t numBytes = numBits/ASN1_BITS_PER_BYTE;
        /* check is number of bytes are more than 8 , any more than 8 would require the length 
           determinant
        */

        if(numBytes != 0)
        {
            len = 1; /* one byte for length encoding */
        }
        /* take care of odd number bits */
        if(numBits % ASN1_BITS_PER_BYTE)
        {
            numBytes += 1;
        }
        len += numBytes;
        log_ << "Ieee1609Encode::Length number of bytes " << std::dec << (int) numBytes << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");

        len_ = len;

        encBuf = (uint8_t *)buf_realloc(encBuf, (len+encLen));
        if(numBytes > 1)
        {
            encBuf[encLen++] = (uint8_t)(ASN1_LENGTH_ENCODING_MASK | numBytes);
            len -= 1;
        }
        // /* copy the bytes in the big-endian order */
        uint8_t *buf_ = (uint8_t*)&num;

        while(len)
        {
            len--;
            encBuf[encLen++] = buf_[len];
        }
        log_ << "Ieee1609Encode::Length exit " << "rem len " << std::dec << len << "enc len " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        return len_;
    }

    int Ieee1609Encode::OctetsFixed(const uint8_t *octets, size_t len)
    {
        std::stringstream log_(std::ios_base::out);
        log_ << "Ieee1609Encode::OctectsFixed enter " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        encBuf = (uint8_t *)buf_realloc(encBuf, len+encLen);
        while(len)
        {
            encBuf[encLen++] = *octets++;
            len--;
        }
        log_ << "Ieee1609Encode::OctectsFixed exit " << "rem len " << len << "enc len " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        return encLen;
    }

    int Ieee1609Encode::psid_(int psid, int bytes)
    {
        int len;
        std::stringstream log_(std::ios_base::out);
        log_ << "Ieee1609Encode::psid_ enter " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        uint8_t *buf_ = (uint8_t *)&psid;
        Length(bytes);
        len = bytes;
        encBuf = (uint8_t *)buf_realloc(encBuf, (encLen + len));
        while(len)
        {
            /* copy in big endian */
            len--;
            encBuf[encLen++] = buf_[len];
        }
        log_ << "Ieee1609Encode::psid_ exit " << "rem len " << len << "enc len " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        return encLen;
    }

    int Ieee1609Encode::HashAlgo(const HashAlgorithmType type)
    {
        int len = 1;
        std::stringstream log_(std::ios_base::out);
        log_ << " Ieee1609Encode::HashAlgo enter " << encLen << std::endl;
        log_info(log_.str(),MODULE);
        log_.str("");
        encBuf = (uint8_t *)buf_realloc(encBuf, (len+encLen));
        /* just encode the hash algo type */
        encBuf[encLen++] = type;
        len --;
        log_ << " Ieee1609Encode::HashAlgo exit " << "rem len " << len << "enc len " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        return 0;
    }

    int Ieee1609Encode::HeaderInfo_(const HeaderInfo& header)
    {
        int len  = 1; /* preamble */
        uint8_t preamble = 0x00;
        std::stringstream log_(std::ios_base::out);
        log_ << " Ieee1609Encode::HeaderInfo_ enter " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        encBuf = (uint8_t *)buf_realloc(encBuf, len+encLen);
        encBuf[encLen++] = preamble;
        len --;
        psid_(header.psid,1);
        log_ << " Ieee1609Encode::HeaderInfo_ exit " << "rem len " << len << "enc len " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        return encLen;
    }

    int Ieee1609Encode::SignedDataPayload_(const Ieee1609Dot2Data& data)
    {
        std::stringstream log_;
        log_ << " Ieee1609Encode::SignedDataPayload_ enter " << encLen << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        /* default option is one */
        /* the sequence preamble byte 00 */
        uint8_t preamble = 0x40; /* only first optional compoent */
        int len = 1;
        /* encoding of Ieee1609Dot2Data, 6.3.2 */
        len += 1; /* for the protcol version */
        len += 1; /* for choice opaque */
        // len += 1; /* number of bytes in the lenght */
        // len += 4; /* 4 bytes in the length */
        len += data.content.UNSECUREDDATA.length;

        encBuf = (uint8_t *)buf_realloc(encBuf, (encLen + len));


        /* preamble for signed Data payload option */
        encBuf[encLen++] = preamble;
        len--;
        /* protocol version */
        encBuf[encLen++] = data.protocolVersion; 
        len --;
        log_ << " Ieee1609Encode::SignedDataPayload_ enter data.content.type " << (data.content.type) << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        /* the choice for opaque data */
        encBuf[encLen++] = (uint8_t)(ASN1_COER_CHOICE_MASK_SET | (data.content.type));
        len --;
        /* encode the length */
        Length(data.content.UNSECUREDDATA.length);

        /* encode the number of bytes , 4 */
        // encBuf[encLen++] = 4; /* 4 integer bytes */
        // len --;
        // uint8_t *dataBuf = (uint8_t *)&data.content.UNSECUREDDATA.length;
        // for (int i = 3; i >= 0; i--)
        // {
        //     /* encode in network order */
        //     encBuf[encLen++] = dataBuf[i];
        //     len --;
        // }
        /* copy the data */
        uint8_t *dataBuf = data.content.UNSECUREDDATA.octets;
        while(len)
        {
            encBuf[encLen++] = *dataBuf++;
            len--;
        }

        log_ << " Ieee1609Encode::SignedDataPayload_ exit " << "rem len " << len << "enc len " << encLen << std::endl;
        log_info(log_.str(), MODULE);
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


    /* decoding of SignedDataPayload:data, 6.3.7 */
    int Ieee1609Decode::Ieee1609Dot2Data_(Ieee1609Dot2Data& data)
    {
        uint8_t choice;
        uint8_t *tempPtr=nullptr;

        std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
        std::ostream os(&log_);
        os << " Ieee1609Decode::Ieee1609Dot2Data_ enter " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        data.protocolVersion = buf[offset++];
        /* read the choice data */
        choice = buf[offset++];
        // std::cout << "chpice " << choice << std::endl;
        choice = choice & ASN1_COER_CHOICE_MASK_CLR;
        /* store the content type */
        data.content.type = (Ieee1609Dot2ContentType)choice;
        if(choice == Ieee1609Dot2ContentUnsecuredData)
        {
            int lenBytes = 0;
            int len_ = 0;
            /* get the encoded length bytes */
            lenBytes = Length((uint8_t*)&len_, sizeof(int));
            /* number of length bytes are in lenBytes*/
            // std::cout << "number of bytes in the length " << lenBytes << std::endl;

            /* read the lenBytes */
            if(lenBytes > sizeof(int))
            {
                // std::cout << "Error: max lenght supported is 4 bytes " << std::endl;
                throw;
            }
            /* clear the log_ string */
            log_.str("");
            // std::cout << " the length of the data " << (int)len_ << std::endl;
            os << " Ieee1609Decode::Ieee1609Dot2Data_ unsecured length " << len_ << std::endl;
            // std::cout << " Ieee1609Decode::Ieee1609Dot2Data_ unsecured length " << len_ << std::endl;
            log_info(log_.str(), MODULE);
            os.clear(); 

            data.content.content.unsecuredData.length = len_;
            data.content.content.unsecuredData.octets = tempPtr =  (uint8_t *)buf_alloc(len_);

            /* copy the length into the buffer */
            while(len_)
            {
                len_--;
                *tempPtr++ = buf[offset++];
            }
        }else if (choice == Ieee1609Dot2ContentSignedData){
            SignedData(data);
        }
        else {
            log_.str("");
            os << " Ieee1609Decode::Ieee1609Dot2Data_ unspoorted choice " << choice << std::endl;
            LOG_ERR(log_.str(), MODULE);
            offset = 0;
        }
        log_.str("");
        os << " Ieee1609Decode::Ieee1609Dot2Data_ exit " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        return offset;
    }

    /* signer signer identifier is a cert , we decode it into the cert */
    int Ieee1609Decode::SignerIdentifier_(SignerIdentifier& signer)
    {
        std::stringbuf log_(std::ios_base::out);
        std::ostream os(&log_);
        os << " Ieee1609Decode::SignerIdentifier_ enter " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");

        uint8_t choice = buf[offset++] & ASN1_COER_CHOICE_MASK_CLR;
        if(choice == SignerIdentifierTypeCert ||
            choice == SignerIdentifierTypeDigest ||
            choice == SignerIdentifierTypeSelf)
            {
                signer.type = (SignerIdentifierType)choice;
            }
        else{
            os << " Ieee1609Decode::SignerIdentifier_ unrecognized choice " << choice << std::endl;
            log_info(log_.str(), MODULE);
            log_.str("");
            offset = 0;
        }
        os << " Ieee1609Decode::SignerIdentifier_ exit " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        return offset;
    }

    /* decode header info */
    int Ieee1609Decode::HeaderInfo_(HeaderInfo& header)
    {
        /* FIXME, no optional components */
        std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
        std::ostream os(&log_);
        os << " Ieee1609Decode::HeaderInfo_ enter " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        /* go past the optinal preamble of header info*/
        header.options =  (HeaderInfoOptionMask)buf[offset++];
        if(header.options)
        {
            os << " Unsupported Header Options " << std::hex << int(header.options) << std::endl;
            LOG_ERR(log_.str(), MODULE);
            throw ctp::Exception("Unsupported Header Options");
        }
        int len_ = 0;
        int numBytes = Length((uint8_t*)&len_, sizeof(int));
        uint8_t *ptr = (uint8_t *)&header.psid;
        while (len_)
        {
            len_--;
            ptr[len_] = buf[offset++];
        }
        os << " Ieee1609Decode::HeaderInfo_ psid is " << header.psid << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        os << " Ieee1609Decode::HeaderInfo_ exit " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        return offset;
    }

    int Ieee1609Decode::SignedDataPayload1(SignedDataPayload& payload)
    {
        int err_ = 0;
        std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
        std::ostream os(&log_);
        os << " Ieee1609Decode::SignedDataPayload1 enter " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");

        /* get the optional mask */
        uint8_t data_ = buf[offset++]; 
        payload.mask = (SignedDataPayloadOptionsMask)data_;
        if(data_ & SDP_OPTION_DATA_MASK)
        {
            /* decode the data */
            Ieee1609Dot2Data_(std::ref(*payload.data));
        }else{
            os << " Signed payload data type " << payload.mask << " is not supported " << std::endl;
            LOG_ERR(log_.str(), MODULE);
            offset = 0;
            err_ = 1;
        }
        os << " Ieee1609Decode::SignedDataPayload1 exit " <<  len << " offset " << offset << std::endl;
        if (err_)
        {
            LOG_ERR(log_.str(), MODULE);
        }else{
            log_info(log_.str(), MODULE);
        }
        return offset;
    }

    int Ieee1609Decode::ToBesignedData_(ToBeSignedData& tbsData)
    {
        std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
        std::ostream os(&log_);
        os << " Ieee1609Decode::ToBesignedData_ enter " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        log_.str("");

        /* decode payload, SignedDataPayload */
        SignedDataPayload1(std::ref(tbsData.payload));
        HeaderInfo_(std::ref(tbsData.headerInfo));

#if 0
        /* get the options mask */
        SignedDataPayloadOptionsMask mask = (SignedDataPayloadOptionsMask)buf[offset++];
        // tbsData.payload.mask = (SignedDataPayloadOptionsMask)buf[offset++];
        /* both options are avaialble */
        if (mask & SDP_OPTION_ALL)
        {
            os.clear();
            os << " Ieee1609Decode::ToBesignedData_ all options are not supported ";
            LOG_ERR(log_.str(), MODULE);

        }else if(mask & SDP_OPTION_DATA_MASK)
        {
            /* if data is present */
            /* allocate the buffer for data structure */
            tbsData.payload.data = (Ieee1609Dot2Data*)buf_alloc(sizeof(Ieee1609Dot2Data));
        }else if (mask & SDP_OPTION_EXT_DATA_HASH)
        {
            /* if extra hash mask is present */
        }
#endif
        os << " Ieee1609Decode::ToBesignedData_ exit " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        return offset;
    }



    int Ieee1609Decode::SignedData(Ieee1609Dot2Data& data)
    {
        uint8_t *srcBuf, *dstBuf;
        size_t bufLen = 0;

        std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
        std::ostream os(&log_);
        os << " Ieee1609Decode::SignedData enter " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        data.content.content.signedData.hashAlgorithm = (HashAlgorithmType)buf[offset++];
        ToBesignedData_(std::ref(data.content.content.signedData.toBeSignedData));
        log_.str("");
        os << " Ieee1609Decode::SignedData exit " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        return offset;
    }

    /* 6.3.28 */
    int Ieee1609Decode::Signature_(Signature& signature)
    {
        uint8_t *srcBuf, *dstBuf;
        size_t bufLen;

        std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
        std::ostream os(&log_);
        os << " Ieee1609Decode::Signature_ enter " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        log_.str("");
        /* get the signature type */
        uint8_t data = buf[offset++] & ASN1_COER_CHOICE_MASK_CLR;
        signature.type = (SignatureType)data;

        // std::cout << "signature type " << (int)signature.type;

        /* decode r */
        //if(signature.type == ecdsaNistP256Signature)
        {
            EccP256CurvPointType type = (EccP256CurvPointType)(buf[offset++] & ASN1_COER_CHOICE_MASK_CLR);
            signature.signature.ecdsaP256Signature.r.type = type;
            srcBuf = &buf[offset];
            switch(type)
            {
                case EccP256CurvPointTypeXOnly:
                case EccP256CurvPointTypeCompressedy0:
                case EccP256CurvPointTypeCompressedy1:
                    dstBuf = (uint8_t *)signature.signature.ecdsaP256Signature.r.point.octets.x;
                    bufLen = 32;
                break;

                case EccP256CurvPointTypeUncompressed:
                    dstBuf = (uint8_t *)signature.signature.ecdsaP256Signature.r.point.octets.x;
                    bufLen = 64;
                break;
                default:
                     bufLen = 0;
            }

            if(offset + bufLen > len)
            {
                os << " Ieee1609Decode::Signature_ r  not enough data" <<  len << " offset " << offset << std::endl;
                LOG_ERR(log_.str(), MODULE);
                throw Exception(log_.str());
                return 0;
            }

            while(bufLen)
            {
                *dstBuf++ = *srcBuf++;
                offset++;
                bufLen--;
            }
        }

        /* decode s */
        dstBuf = (uint8_t *)signature.signature.ecdsaP256Signature.s.x;
        bufLen = sizeof(HashedData32);
        if(bufLen + offset > len)
        {
             os << " Ieee1609Decode::Signature_ s not enough data" <<  len << " offset " << offset << std::endl;
            LOG_ERR(log_.str(), MODULE);
            throw Exception(log_.str());
            return 0;
        }
        log_.str("");

        /* copy s */
        srcBuf = &buf[offset];
        while(bufLen)
        {
            *dstBuf++ = *srcBuf++;
            offset++;
            bufLen--;
        }
        os << " Ieee1609Decode::Signature_ exit " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        return offset;
    }

    int Ieee1609Decode::HashId3(uint8_t* hash, size_t len_)
    {
        std::stringstream log_(std::ios_base::out);
        // std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
        std::ostream os(log_.rdbuf());
        os << " Ieee1609Decode::HashId3 enter " <<  len << " offset " << offset << std::endl;
         log_info(log_.str(), MODULE);
        log_.str("");

        if(offset + len_ > len)
        {
            os << " Ieee1609Decode::HashId3  not enough data " <<  len << " offset " << offset << std::endl;
            LOG_ERR(log_.str(), MODULE);
            throw Exception(log_.str());
        }

        int i=0;
        while(i < len_)
        {
            hash[i] = buf[offset++];
            i++;
        }
        log_.clear();
        log_.str("");
        os << " Ieee1609Decode::HashId3 exit " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        return offset;
    }



    /* decode the crl series */
    int Ieee1609Decode::CrlSeries(uint16_t& series)
    {
        std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
        std::ostream os(&log_);
        os << " Ieee1609Decode::CrlSeries enter " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        log_.str("");

        uint8_t *tempBuf = (uint8_t *)&series;
        *tempBuf++ = buf[offset++];
        *tempBuf++ = buf[offset++];

        os << " Ieee1609Decode::CrlSeries exit " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        return len;



    }
    /* decode the certificate id of the certificate */
    int Ieee1609Decode::CertId(CertificateId& id)
    {
        int len_=0;
        uint8_t *tempBuf;
        std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
        std::ostream os(&log_);
        os << " Ieee1609Decode::CertId enter " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        uint8_t data = buf[offset++]; /* get the choice */
        id.type = static_cast<CertificateIdType>(data & ASN1_COER_CHOICE_MASK_CLR); /* extract the id type */
        os << "Ieee1609Decode::CertId::id.type " <<  id.type << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        switch(id.type)
        {
            case CertificateIdTypeName:
                /* the length of the name */
                id.id.hostName.length = buf[offset++];
                id.id.hostName.name = (char *)buf_alloc(id.id.hostName.length+1);
                while (len_ < id.id.hostName.length)
                {
                    id.id.hostName.name[len_++] = buf[offset++];
                }
                id.id.hostName.name[len_] = '\0';
                os << "host name " << id.id.hostName.name << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
            break;

            default:
                os << "Ieee1609Decode::CertId  " << id.type << " is not supported " << std::endl;
                LOG_ERR(log_.str(), MODULE);
        }
        log_.str("");
        os << " Ieee1609Decode::CertId exit " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        return offset;
    }


    /* initialize the decoding engine buffers with the incoming data */
    void Ieee1609Decode::set(const uint8_t *buf, size_t len)
    {
        this->offset = 0;
        this->len = len;
        delete this->buf;
        this->buf = nullptr;
        this->buf = (uint8_t *)buf_realloc(this->buf, len);
        for (int i =0; i < len; i++)
        {
            this->buf[i] = buf[i];
        }
        unlink("testencode.txt");
        print_data("testencode.txt", this->buf, this->len);
    }

} /*namespace ctp */