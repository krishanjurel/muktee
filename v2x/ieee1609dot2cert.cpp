#include "ieee1609dot2.hpp"
#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <iostream>
#include <fstream>


#ifdef __cplusplus
extern "C"
{
#endif
    /* function returns the number of seconds from V2X start epoch
    till the give time
*/         
time_t start_time(struct tm *tm)
{
    struct tm epoch = {
        .tm_sec = 0,
        .tm_min=0,
        .tm_hour = 0,
        .tm_mday=1,
        .tm_mon = 0,
        .tm_year = 2004,
        .tm_isdst = 0
    };
    time_t t1 = mktime(&epoch);
    time_t t2 = mktime(tm);

    if(t1 < 0 || t2 < 0)
    {
        perror("start_time:mktime");
        t1  = -1;
    }else
    {
        t1 = t2-t1;
    }
    return t1;
}
void *buf_alloc(size_t len)
{
    return malloc(len);
}
void *buf_realloc(void *ptr, size_t len)
{
    return realloc(ptr, len);
}

void *buf_calloc(size_t num, size_t size)
{
    return calloc(num,size);
}
#ifdef __cplusplus
}
#endif





namespace ctp
{


    void TP::cert_mgr()
    {
        LOG_INFO("cert_mgr", 1);
    }

    void TP::cfg_mgr()
    {
        LOG_INFO("cfg_mgr", 1);
    }

    void TP::enrol_mgr()
    {
        LOG_INFO("enrol_mgr", 1);
    }

    void TP::crl_mgr()
    {
        LOG_INFO("crll_mgr", 1);
    }

    void TP::report_mgr()
    {
        LOG_INFO("log_mgr", 1);
    }

    int TP::sign()
    {
        log_info("sign", 1);
        return 0;
    }
     int TP::verify()
     {
         log_info("verify", 1);
         return 0;
     }
     int TP::encrypt ()
     {
         log_info("encrypt", 1);
         return 0;
     }

     int TP::decrypt()
     {
         log_info("decrypt",1);
         return 0;
     }

/* cert class implementation.
   the main purpose of this class is to store and keep certs, together with hashid 
*/
    cert::cert()
    {
        /* no certs */
        certs.clear();
        ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (ecKey == nullptr)
        {
            perror("<Main> Error associating key with a curve");
            std::terminate();
        }

        /* FIXME, creating the key at the object creation, this could be placed at a later stage, probably during cert::create
        */
        if(EC_KEY_generate_key(ecKey) != 1)
        {
            LOG_ERR("cert::cert() EC_KEY_generate_key", 1);
            EC_KEY_free(ecKey);
            std::terminate();
        }
        ecGroup = EC_KEY_get0_group(ecKey);

        /* allocate the memory for one cert first */
        seqOfCert = (SequenceOfCertificate *)malloc(sizeof(int) +  sizeof(certificateBase));
        
        /* initialize all the pointers */
        base = (CertificateBase *)((uint8_t *)seqOfCert + sizeof(int));
        /* add the cert into the queue */
        certs.push_back(base);
        issuer = &base->issuer;
        tbs = &base->toBeSignedCertificate;
        vki = &tbs->verifyKeyIndicator;
        /*pointer to the signature structure*/
        signature = &base->signature;
    }

    /* sign the certificate */
    int cert::sign(const uint8_t *buf, size_t len, SignatureType type)
    {
        int ret = 0;
        const BIGNUM *r;
        const BIGNUM *s;
        uint8_t *sign_r, *sign_s;
        // try
        // {
        //     sigBuf = static_cast<uint8_t *>(OPENSSL_malloc(sigBufLen));
        //     if (sigBuf == nullptr)
        //     {
        //         throw std::bad_alloc();
        //     }
        // }
        // catch(const std::exception& e)
        // {
        //     std::cerr << e.what() << '\n';
        //     std::terminate();
        // }
        sig = ECDSA_do_sign(buf,len,ecKey);
        if (sig == nullptr)
        {
            LOG_ERR("cert::sign : Error signing the message", 1);
            ret = -1;
            /*FIXME, try to avoid it */
            goto done;
        }


        r = ECDSA_SIG_get0_r(sig);
        s = ECDSA_SIG_get0_s(sig);
        //EC_POINT *point = EC_POINT_new(grp);

        // if(EC_POINT_bn2point(grp, r, point, nullptr) != point)
        // {
        //     LOG_ERR("cert::sign error EC_POINT_bn2point",1);
        //     ECDSA_SIG_free(sig);
        //     EC_POINT_free(point);
        //     sig = nullptr;
        // }
        /* signature r value for FIPS 186-4 takes only x-only */
        signature->signature.ecdsaP256Signature.r.type= EccP256CurvPointXOnly;
        sign_r = (uint8_t *)signature->signature.ecdsaP256Signature.r.point.xonly.x;
        sign_s = (uint8_t *)&signature->signature.ecdsaP256Signature.s.x[0];
        /* set the signature type */
        signature->type = type;

        /* convert the point to the buf for encoding */
        //EC_POINT_point2oct(grp, point, POINT_CONVERSION_COMPRESSED,xonly_r, sizeof(HashedData32), nullptr);

        if(BN_bn2bin(r, sign_r) != sizeof(HashedData32))
        {
            LOG_ERR("cert::sign BN_bn2bin(r, sign_r)", 1);
            ret = -1;
            /*FIXME, try to avoid it */
            goto done;
        }
        if(BN_bn2bin(s, sign_s) != sizeof(HashedData32))
        {
            LOG_ERR("cert::sign BN_bn2bin(r, sign_r)", 1);
            ret = -1;
            /*FIXME, try to avoid it */
            goto done;
        }
        done:
            if(ret ==  -1)
            {
                /* do cleanup during error */
                if(sig)
                    ECDSA_SIG_free(sig);
                sig = nullptr;
            }
        return ret;
    }

    /*        */
    int cert::encode_certid()
    {
        int len = 1;
        uint8_t choice = 0x80 | (uint8_t)(tbs->id.type);
        uint8_t *buf;

        switch(tbs->id.type)
        {
            case CertificateIdTypeName:
                len += tbs->id.id.hostName.length;
                buf = (uint8_t *)tbs->id.id.hostName.name;
                len += 1;
                break;
            default:
                LOG_ERR("cert::encode_certid: unsupported cert id", 1);
                break;
        }

        std::cout << "cert::encodecertid " << len << std::endl;

        encBuf = (uint8_t *)realloc(encBuf, len);
        encBuf[encLen++] = choice;
        len --;
        /* encode the length */
        encBuf[encLen++] = tbs->id.id.hostName.length;
        len --;
        /* copy the remainder of buffer into the encoded buffer */
        while(len > 0)
        {
            encBuf[encLen++] = *buf++;
            len--;
        }
        std::cout << "cert::encodecertid " << encLen << std::endl;
        /* return the length */
        return encLen;
    }

    int cert::encode_hashid3()
    {
        int len = encLen + 3;
        /* just fill it with the hard coded a,b,c */
        encBuf = (uint8_t *)realloc(encBuf, len);
        if(issuer->type == IssuerIdentifierTypeSelf)
        {
            encBuf[encLen++] = 0x00;
            encBuf[encLen++] = 0x00;
            encBuf[encLen++] = 0x00;
        }
        std::cout << "cert::encode_hashid3 " << encLen << std::endl;
        return encLen;
    }

    int cert::encode_crlseries()
    {
        /* its two bytes */
        int len = encLen + 2;
        encBuf = (uint8_t *)realloc(encBuf, len);

        uint8_t *buf = (uint8_t *)&tbs->crlSeries;
        /* copy in the network byte order */
        encBuf[encLen++] = buf[1];
        encBuf[encLen++] = *buf;
        std::cout << "cert::encode_crlseries " << encLen << std::endl;
        return encLen;
    }

    int cert::encode_validityperiod()
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
        uint8_t *buf = (uint8_t *)&tbs->validityPeriod.start;
        encBuf[encLen++] = buf[3];
        encBuf[encLen++] = buf[2];
        encBuf[encLen++] = buf[1];
        encBuf[encLen++] = buf[0];
        len -= 4;

        /* initialize the choice */
        uint8_t choice = 0x80 | (uint8_t)(tbs->validityPeriod.duration.type);
        len -= 1;
        encBuf[encLen++] = choice;
        buf = (uint8_t *)&tbs->validityPeriod.duration.duration.minutes;
        /* copy in the network byte order */
        encBuf[encLen++] = buf[1];
        encBuf[encLen++] = buf[0]; 
        len -= 2;
        std::cout << "cert::encode_validityperiod " << encLen << std::endl;
        return encLen;
    }
    /* this is encoding the sequence of psids */
    int cert::encode_sequenceofpsid()
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

        len += encLen;

        encBuf = (uint8_t *)realloc(encBuf, len);
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
        encBuf[encLen++] = 0x20; /*FIXME, define this somewhere BSM psid */
        len -= 1;
         if (len != 0)
         {
             LOG_ERR("cert::encode_sequenceofpsid(): rem length not zero", 1);
             //throw new std::logic_error("cert::encode_sequenceofpsid(): rem length not zero ");
         }
         std::cout << "cert::encode_sequenceofpsid " << encLen << std::endl;
         return encLen;
    }

    /* encode the verification key identifier */
    int cert::encode_vki()
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
        uint8_t choice = 0x80 | (uint8_t) (vki->type);
        encBuf[encLen++] = choice;
        len -= 1;
        /* choice of public verification */
        choice = (0x80) | (uint8_t)(vki->indicator.verificationKey.type);
        encBuf[encLen++] = choice;
        len -= 1;
        /*choice of curve point-type*/
        choice = (0x80) | (uint8_t)(keyType & 0x01);
        encBuf[encLen++] = choice;
        len -= 1;
        /* just take the y 0*/
        const uint8_t *key = (uint8_t *)vki->indicator.verificationKey.key.ecdsaNistP256S.point.compressedy0.x;
        while(len > 0)
        {
            encBuf[encLen++] = *key++;
            len -= 1;
        }

        std::cout << "cert::encode_vki " << encLen << std::endl;

        return encLen;
    }


    /* encode the toBeSigned field of the explicit certicate*/
    int cert:: encode()
    {
        /* reset the encoded buffer and length */
        encBuf = nullptr;
        encLen = 0;
        try
        {
            encode_certid();
            encode_hashid3();
            encode_crlseries();
            encode_validityperiod();
            encode_sequenceofpsid();
            encode_vki();
        }
        catch(const std::exception& e)
        {
            std::cout << e.what() << '\n';
        }
        catch (std::logic_error& e)
        {
            std::cout << e.what() << '\n';

        }
        return 0;
    }

    /* print the certificate into the file */
    int cert::print()
    {
        int i = 0;
        log_info("cert::print", 1);
        /* open the file in text mode */
        std::ofstream ofs("cert.txt");
        //std::stringbuf strbuf(encBuf);
        //std::string strng((const char *)encBuf, encLen);
        //std::istringstream istram(strng);
        std::streambuf *sbf = ofs.rdbuf();
        std::ostream os(sbf);
        std::cout << "the length of the encoded bffer" << encLen << std::endl;
        
        for(i=0; i < encLen; i++)
        {
           // char c[2];
           // istram >> c[0] >> c[1];
            int c;// = atoi(c);
            snprintf((char *)&c, sizeof(int), "%c", encBuf[i]);
            os << std::hex << (c&0xFF) ; 
            os << ':';
            if(i != 0 && i % 16 ==0)
            {
                os << std::endl;
            }
        }
        std::cout << std::endl;
        ofs.close();
        return 0;
    }


    /* gets the public key from the key object */
    int cert::public_key_get(point_conversion_form_t conv)
    {
        int i = 0;
        uint8_t *keyBuf = nullptr;
        size_t keylen = EC_KEY_key2buf(ecKey, conv, &keyBuf, nullptr);
        EccP256CurvPoint *point = &vki->indicator.verificationKey.key.ecdsaNistP256S;
        if(keylen == 0)
        {
            perror("cert::public_key_get()");
            LOG_ERR("cert::public_key_get", 1);
            std::terminate();
            return keylen;
        }
        point->type = EccP256CurvPointUncompressed;
        char *xPtr = point->point.uncompressedx.x;
        char *yPtr = point->point.uncompressedy.x;

        /* there will always be x-component, so lets copy that */
        for (i = 0; i < sizeof(HashedData32);)
        {
            *xPtr++ = keyBuf[++i];
        }
        /* copy whatever was there, remaining */
        for(; i < keylen;)
        {
            *yPtr++ = keyBuf[i++];
        }
        keyType = keyBuf[0];
        free(keyBuf);
        return keylen;
    }

    /* create a certificate */
    void cert::create()
    {   
        /* one cert */
        seqOfCert->length = 1;
        base->version = 3;
        base->certType = CertTypeExplicit;
        issuer->type = IssuerIdentifierTypeSelf;
        issuer->issuer.algo = HashAlgorithmTypeSha256; 
        tbs->id.type = CertificateIdTypeName;
        std::string *name = new std::string("Get the Host Name from Config File");
        tbs->id.id.hostName.name = (char *)name->c_str();
        tbs->id.id.hostName.length = name->size();
        /*FIXME, this is hard coded */
        tbs->crlSeries = 0x1234;
        time_t t = time(nullptr);
        struct tm *tm = localtime((const time_t *)&t);
        tbs->validityPeriod.start = start_time(tm);
        tbs->validityPeriod.duration.type = DurationTypeMinutes;
        tbs->validityPeriod.duration.duration.minutes = (7*24*60);/* for one week, read it form the config file */
        /* set the verification key indicator type */
        vki->type = VerificationKeyIndicatorTypeKey;
        /* default is uncompressed */
        public_key_get();

        /* FIXME, before signing, encode the certificate, for now keep
           it as blob of memory 
        */
        /* define and call the below API */ 
        encode();
        sign(encBuf, encLen,ecdsaNistP256Signature);
        print();
    }
} //namespace ctp








