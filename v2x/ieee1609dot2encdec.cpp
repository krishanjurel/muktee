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
        int len = 1;
        uint8_t choice = 0x80 | (uint8_t)(id.type);
        uint8_t *buf;

        switch(id.type)
        {
            case CertificateIdTypeName:
                len += id.id.hostName.length;
                buf = (uint8_t *)id.id.hostName.name;
                len += 1;
                break;
            default:
                LOG_ERR("Ieee1609Encode::CertId: unsupported cert id", 1);
                break;
        }

        std::cout << "Ieee1609Encode::CertId enter " << encLen << std::endl;

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
        std::cout << "Ieee1609Encode::CertId Exit " << "rem len " << len << "enc len " << encLen << std::endl;
        /* return the length */
        return encLen;
    }
    /* encode crl series */
    int Ieee1609Encode::CrlSeries(const uint16_t series)
    {
         /* its two bytes */
        int len = 2;
         std::cout << "Ieee1609Encode::CrlSeries enter " << encLen << " " << len << std::endl;
        encBuf = (uint8_t *)buf_realloc(encBuf, (len+encLen));

        uint8_t *buf = (uint8_t *)&series;
        /* copy in the network byte order */
        encBuf[encLen++] = buf[1];
        encBuf[encLen++] = *buf;
        len -= 2;
        std::cout << "Ieee1609Encode::CrlSeries exit " << "rem len " << len << "enc len " << encLen << std::endl;
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
            len -= 3;
        }
        std::cout << "Ieee1609Encode::HashId3 exit" << "rem len " << len << "enc len " << encLen << std::endl;
        return 0;
    }
    int Ieee1609Encode::Octets_(const uint8_t* octets, size_t len)
    {
        std::cout << "Ieee1609Encode::HashId3: enter  " << encLen << std::endl;
        //len += encLen;
        encBuf = (uint8_t *)buf_realloc(encBuf, (len + encLen));
        while(len--)
        {
            encBuf[encLen++] = *octets++;
        }

        std::cout << "Ieee1609Encode::HashId3: exit  " << "rem len " << len << "enc len " << encLen << std::endl;
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
        std::cout << "Ieee1609Encode::IssuerIdentifier_: exit  " << "rem len " << len << "enc len " << encLen << std::endl;
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
        std::cout << "Ieee1609Encode::SequenceOfPsid_: enter  " << encLen << std::endl;
        encBuf = (uint8_t *)buf_realloc(encBuf, len+encLen);
        if(encBuf == nullptr)
        {
            throw std::bad_alloc();
        }


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
         std::cout << "Ieee1609Encode::SequenceOfPsid_: exit  " << "rem len " << len << "enc len " << encLen << std::endl;
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
        std::cout << "Ieee1609Encode::VP exit " << "rem len " << len << "enc len " << encLen << std::endl;
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
        const uint8_t *key = (uint8_t *)vki.indicator.verificationKey.key.ecdsaNistP256S.point.octets.x;
        while(len > 0)
        {
            encBuf[encLen++] = *key++;
            len -= 1;
        }

        std::cout << "Ieee1609Encode::Vki exit " << "rem len " << len << "enc len " << encLen << std::endl;

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
        std::cout << "Ieee1609Encode::Ieee1609Dot2ContentType_ exit " << "rem len " << len << "enc len " << encLen << std::endl;
        return encLen;
    }

    int Ieee1609Encode::Signature_(const Signature& signature)
    {
        int len = 1; /* for signature choice */
        uint8_t type = 0;
        uint8_t choice = (0x80) | (signature.type);
        std::cout << "Ieee1609Encode::Signature_ enter " << encLen << std::endl;
        len += 1; /* choice of curve point type */
        len += 32; /* 32 bytes for the s */

        type  = signature.signature.ecdsaP256Signature.r.type;

        uint8_t *pointBuf = nullptr;
        if(type == EccP256CurvPointXOnly){
            pointBuf = (uint8_t *)signature.signature.ecdsaP256Signature.r.point.octets.x;
            len += 32;
        }else if (choice == EccP256CurvPointCompressedy0)
        {
            pointBuf = (uint8_t *)signature.signature.ecdsaP256Signature.r.point.octets.x;
            len += 32;
        }else if (choice == EccP256CurvPointCompressedy1)
        {
            pointBuf = (uint8_t *)signature.signature.ecdsaP256Signature.r.point.octets.x;
            len += 32;
        }else if (choice == EccP256CurvPointUncompressed){
            pointBuf = (uint8_t *)signature.signature.ecdsaP256Signature.r.point.octets.x;
            len += 64;
        }


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
        choice = (0x80) | (signature.signature.ecdsaP256Signature.r.type);
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
        std::stringbuf log_("Ieee1609Encode::Signature_", std::ios_base::out | std::ios_base::ate);
        std::ostream os(&log_);
        os << " remaining length (exp >= 0) "  << len << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        std::cout << "Ieee1609Encode::Signature_ exit " << "rem len " << len << "enc len " << encLen << std::endl;
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
        std::cout << "Ieee1609Encode::SignerIdentifier_ exit " << "rem len " << len << "enc len " << encLen << std::endl;
        return encLen;
    }

    int Ieee1609Encode::SequenceOf(const uint8_t *octets, size_t bytes)
    {
        int len = 1; /* 1 byte to encode the number of sequences */
        len += bytes; /* number of bytes */
        std::cout << "Ieee1609Encode::SequenceOf enter " << encLen << std::endl;
        encBuf = (uint8_t *)buf_realloc(encBuf, (len+encLen));
        encBuf[encLen++] = bytes;
        len --;
        while(len)
        {
            encBuf[encLen++] = *octets++;
            len --;
        }

        std::cout << "Ieee1609Encode::SequenceOf exit " << "rem len " << len << "enc len " << encLen << std::endl;
        return encLen;
    }

    int Ieee1609Encode::OctetsFixed(const uint8_t *octets, size_t len)
    {
        std::cout << "Ieee1609Encode::OctectsFixed enter " << encLen << std::endl;
        encBuf = (uint8_t *)buf_realloc(encBuf, len+encLen);
        while(len)
        {
            encBuf[encLen++] = *octets++;
            len--;
        }
        std::cout << "Ieee1609Encode::OctectsFixed exit " << "rem len " << len << "enc len " << encLen << std::endl;
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
        std::cout << "Ieee1609Encode::psid_ exit " << "rem len " << len << "enc len " << encLen << std::endl;
        return encLen;
    }

    int Ieee1609Encode::HashAlgo(const HashAlgorithmType type)
    {
        int len = 1;
        std::cout << " Ieee1609Encode::HashAlgo enter " << encLen << std::endl;
        encBuf = (uint8_t *)buf_realloc(encBuf, (len+encLen));
        /* just encode the hash algo type */
        encBuf[encLen++] = type;
        len --;
        std::cout << " Ieee1609Encode::HashAlgo exit " << "rem len " << len << "enc len " << encLen << std::endl;
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
        psid_(header.psid);
        std::cout << " Ieee1609Encode::HeaderInfo_ exit " << "rem len " << len << "enc len " << encLen << std::endl;
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

        std::cout << " Ieee1609Encode::SignedDataPayload_ exit " << "rem len " << len << "enc len " << encLen << std::endl;

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
        uint8_t data_;
        uint8_t *tempPtr=nullptr;

        std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
        std::ostream os(&log_);
        os << " Ieee1609Decode::SignedDataPayload2 enter " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();

        data.protocolVersion = buf[offset++];

        /* read the choice data */
        data_ = buf[offset++];
        data_ = data_ & ~ASN1_COER_CHOICE_MASK;
        if(data_ == Ieee1609Dot2ContentUnsecuredData)
        {
            uint8_t numLenBytes = buf[offset++];
            int len_ = 0;
             tempPtr = (uint8_t*)&len_;
            while(numLenBytes--)
            {
                *tempPtr++ = buf[offset++];
            }

            os << " Ieee1609Decode::SignedDataPayload2 unsecured length " << len_ << std::endl;
            log_info(log_.str(), MODULE);
            os.clear(); 

            data.content.content.unsecuredData.octets = tempPtr =  (uint8_t *)buf_alloc(len_);

            /* copy the length into the buffer */
            while(len_--)
            {
                *tempPtr++ = buf[offset++];
            }
        }else {
            os.clear();
            os << " Ieee1609Decode::SignedDataPayload2 unspoorted choice " << data_ << std::endl;
            LOG_ERR(log_.str(), MODULE);
            offset = 0;
        }
        os << " Ieee1609Decode::SignedDataPayload2 exit " <<  len << " offset " << offset << std::endl;
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
        os.clear();

        uint8_t bytes_ = buf[offset++];
        uint8_t *ptr = (uint8_t *)&header.psid;
        while (bytes_--)
        {
            *ptr++ = buf[offset++];
        }
        os << " Ieee1609Decode::HeaderInfo_ psid is " << header.psid << std::endl;
        log_info(log_.str(), MODULE);
        os << " Ieee1609Decode::HeaderInfo_ exit " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        return offset;
    }

    int Ieee1609Decode::SignedDataPayload1(SignedDataPayload& payload)
    {
        std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
        std::ostream os(&log_);
        os << " Ieee1609Decode::SignedDataPayload1 enter " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();

        /* get the optional mask */
        uint8_t data_ = buf[offset++]; 
        payload.mask = (SignedDataPayloadOptionsMask)data_;
        if(data_ & SDP_OPTION_DATA_MASK)
        {
            payload.data = (Ieee1609Dot2Data *)buf_alloc(sizeof(Ieee1609Dot2Data));
            /* decode the data */
            Ieee1609Dot2Data_(std::ref(*payload.data));
        }else{

            os << " Ieee1609Decode::SignedDataPayload1 exit " <<  len << " offset " << offset << std::endl;
            LOG_ERR(log_.str(), MODULE);
            offset = 0;
        }
        os << " Ieee1609Decode::SignedDataPayload1 exit " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        return offset;
    }

    int Ieee1609Decode::ToBesignedData_(ToBeSignedData& tbsData)
    {
        std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
        std::ostream os(&log_);
        os << " Ieee1609Decode::ToBesignedData_ enter " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();

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
        os << " Ieee1609Decode::SignedDataPayload_ enter " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        data.content.content.signedData.hashAlgorithm = (HashAlgorithmType)buf[offset++];
        ToBesignedData_(std::ref(data.content.content.signedData.toBeSignedData));
        os << " Ieee1609Decode::SignedDataPayload_ exit " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        return offset;
    }


    int Ieee1609Decode::Signature_(Signature& signature)
    {
        uint8_t *srcBuf, *dstBuf;
        size_t bufLen;

        std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
        std::ostream os(&log_);
        os << " Ieee1609Decode::Signature_ enter " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        /* get the signature type */
        uint8_t data = buf[offset++] & ASN1_COER_CHOICE_MASK;
        signature.type = (SignatureType)data;

        if(signature.type == ecdsaNistP256Signature)
        {
            EccP256CurvPointType type = (EccP256CurvPointType)(buf[offset++] & ASN1_COER_CHOICE_MASK);
            signature.signature.ecdsaP256Signature.r.type = type;
            srcBuf = &buf[offset];
            switch(type)
            {
                case EccP256CurvPointXOnly:
                case EccP256CurvPointCompressedy0:
                case EccP256CurvPointCompressedy1:
                    dstBuf = (uint8_t *)signature.signature.ecdsaP256Signature.r.point.octets.x;
                    bufLen = 32;
                break;

                case EccP256CurvPointUncompressed:
                    dstBuf = (uint8_t *)signature.signature.ecdsaP256Signature.r.point.octets.x;
                    bufLen = 64;
                break;
                default:
                     bufLen = 0;
            }

            if(offset + bufLen > len)
            {
                 os << " Ieee1609Decode::Signature_  not enough data" <<  len << " offset " << offset << std::endl;
                LOG_ERR(log_.str(), MODULE);
                return 0;
            }

            while(bufLen)
            {
                *dstBuf++ = *srcBuf++;
                offset++;
                bufLen--;
            }
        }

        os << " Ieee1609Decode::Signature_ exit " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();
        return offset;
    }


    int Ieee1609Decode::HashId3(uint8_t* hash, size_t len)
    {
        std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
        std::ostream os(&log_);
        os << " Ieee1609Decode::HashId3 enter " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();

        if(offset + 2 > len)
        {
             os << " Ieee1609Decode::HashId3  not enough data " <<  len << " offset " << offset << std::endl;
            LOG_ERR(log_.str(), MODULE);
            return 0;
        }

        *hash++ = buf[offset++];
        *hash++ = buf[offset++];

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
        uint8_t data = buf[offset++]; /* get the choice */
        id.type = static_cast<CertificateIdType>(data & ~ASN1_COER_CHOICE_MASK); /* extract the id type */
        std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
        std::ostream os(&log_);
        os << " Ieee1609Decode::CrlSeries enter " <<  len << " offset " << offset << std::endl;
        log_info(log_.str(), MODULE);
        os.clear();

        os << "Ieee1609Decode::CertId::id.type " <<  id.type << std::endl;
        log_info(log_.str(), MODULE);
        
        
        switch(id.type)
        {
            case CertificateIdTypeName:
                /* the length of the name */
                id.id.hostName.length = buf[offset++];
                id.id.hostName.name = (char *)buf_alloc(id.id.hostName.length);
                while (len_ < id.id.hostName.length)
                {
                    id.id.hostName.name[len_++] = buf[offset++];
                }
            break;
            default:
                std::cout << " the certificate id type " << id.type << " is not supported " << std::endl;
        }
        os << " Ieee1609Decode::CrlSeries exit " <<  len << " offset " << offset << std::endl;
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
        this->buf = (uint8_t *)buf_realloc(this->buf, len);
        memcpy(this->buf, buf, len);
    }

} /*namespace ctp */