#include "ieee1609dot2.hpp"
#include "ieee1609dot2cert.hpp"
#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <iomanip>


#ifdef __cplusplus
extern "C"
{
#endif
    /* function returns the number of seconds from V2X start epoch
    till the give time
*/         
time_t start_time(struct tm *tm)
{
    // struct tm epoch;
    struct tm epoch={0};
    // = {
    //     .tm_sec = 0,
    //     .tm_min=0,
    //     .tm_hour = 0,
    //     .tm_mday=1,
    //     .tm_mon = 0,
    //     .tm_year = 2004,
    //     .tm_isdst = 0
    // };
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
    //std::cout << "buf_realloc " << len << std::endl;
    return realloc(ptr, len);
}

void *buf_calloc(size_t num, size_t size)
{
    return calloc(num,size);
}
#ifdef __cplusplus
}
#endif

void print_data(const char* file, const uint8_t *buf, size_t len)
{
    int i = 0, j = 0;
    std::cout << "print" << std::endl;
    /* open the file in text mode */
    std::ofstream os(file);
    //std::ostream os(ofs.rdbuf());
    os << std::hex;
    for(i=0; i < len; i++)
    {
        // char c[2];
        // istram >> c[0] >> c[1];
        int c;// = atoi(c);
        snprintf((char *)&c, sizeof(int), "%c", buf[i]);
        os << std::setw(2) << (c&0xFF) ; 
        os << ':';
        j++;
        if(j % 16 == 0)
        {
            os << std::endl;
            j = 0;
        }
    }
    std::cout << std::endl;
    os.close();
}





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
    Ieee1609Cert::Ieee1609Cert()
    {
        /* create the instance of the encode onject */
        pEncObj = new Ieee1609Encode();
        /* no certs */
        // certs.clear();
        // certsPsidMap.clear();
        // certsHashIdMap.clear();
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
        // certs.push_back(base);
        // /*FIXed psid */
        // certsPsidMap.operator[](0x20) = this;
        issuer = &base->issuer;
        tbs = &base->toBeSignedCertificate;
        vki = &tbs->verifyKeyIndicator;
        /*pointer to the signature structure*/
        signature = &base->signature;
        /* allocate the buffer of single psid with no ssp */
        psidSsp = &tbs->appPermisions;
        /* psid psidssp only contains the psid , with no ssp */
        psidSsp->psidSsp = (PsidSsp *)buf_alloc(sizeof(PsidSsp));
        /* there is only item in this sequence */
        psidSsp->length = 1;
        /* FIXME, hardcoded psid, BSM */
        psidSsp->psidSsp->psid = 0x20;
        /* no ssp */
        psidSsp->psidSsp->ssp.length = 0;
        /* default, self-signed */
        issuer->type = IssuerIdentifierTypeSelf;

    }

    const SequenceOfPsidSsp& Ieee1609Cert::psid_get() const
    {
        return std::ref(*psidSsp);
    }

    int Ieee1609Cert::sign(const uint8_t *buf, size_t len, SignatureType type)
    {
        return _sign(buf, len, type);
    }

    const Signature* Ieee1609Cert::signEx(const uint8_t *buf, size_t len, SignatureType type)
    {
        int ret = _sign(buf, len, type);
        if(ret == 1)
        {
            return signature;
        }else{

            return nullptr;
        }
    }

    /* creates the Hash of the input data, and returns the result into hash with lentgh os hashLen
        return 1, on success, 
               0, on error
    */
    int Ieee1609Cert::Hash256(const uint8_t* tbHash, size_t len, uint8_t **hash)
    {
        SHA256_CTX ctx;
        int ret = 1;
        if (SHA256_Init(&ctx) != 1)
        {
            LOG_ERR("Ieee1609Cert::Hash SHA256_Init  failed", 1);
            ret = 0;
            return ret;

        }
        *hash = (uint8_t *)buf_alloc(32);

        if(SHA256_Update(&ctx, tbHash, len) == 0)
        {
            LOG_ERR("Ieee1609Cert::Hash SHA256_Update  failed", 1);
            ret = 0;
            goto done;
        }
        if(SHA256_Final(*hash, &ctx) == 0)
        {
            LOG_ERR("Ieee1609Cert::Hash SHA256_Update  failed", 1);
            ret = 0;
            goto done;
        }
        done:
            if(ret == 0 && *hash != nullptr)
            {
                free(*hash);
            }
        return ret;
    }

    /*status of the conversion */
    int Ieee1609Cert::SigToSignature(const ECDSA_SIG* sig, Signature& signature)
    {
        int ret = -1;
        const BIGNUM *r;
        const BIGNUM *s;
        uint8_t *sign_r, *sign_s;
#if (OPENSSL_VERSION_NUMBER == 0x1010100fL)
        r = ECDSA_SIG_get0_r(sig);
        s = ECDSA_SIG_get0_s(sig);
#else
        r = sig->r;
        s = sig->s;
#endif
        
        signature.signature.ecdsaP256Signature.r.type= EccP256CurvPointXOnly;
        sign_r = (uint8_t *)signature.signature.ecdsaP256Signature.r.point.xonly.x;
        sign_s = (uint8_t *)&signature.signature.ecdsaP256Signature.s.x[0];
        
        
        if(BN_bn2bin(r, sign_r) != sizeof(HashedData32))
        {
            LOG_ERR("Ieee1609Cert::SigToSignature BN_bn2bin(r, sign_r)", 1);
            ret = -1;
            /*FIXME, try to avoid it */
            goto done;
        }
        if(BN_bn2bin(s, sign_s) != sizeof(HashedData32))
        {
            LOG_ERR("Ieee1609Cert::SigToSignature BN_bn2bin(r, sign_r)", 1);
            ret = -1;
            /*FIXME, try to avoid it */
            goto done;
        }
        done:
            return ret;
    }

    const ECDSA_SIG* Ieee1609Cert::SignData(const uint8_t *buf, size_t len, SignatureType type)
    {
        /* use the only key for now */
        return  ECDSA_do_sign(buf,len,ecKey);
    }

    /* sign the certificate */
    int Ieee1609Cert::_sign(const uint8_t *buf, size_t len, SignatureType type)
    {
        int ret = 0;
        const BIGNUM *r;
        const BIGNUM *s;
        uint8_t *sign_r, *sign_s;
        ECDSA_SIG *sig;
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
#if (OPENSSL_VERSION_NUMBER == 0x1010100fL)
        r = ECDSA_SIG_get0_r(sig);
        s = ECDSA_SIG_get0_s(sig);
#else
        r = sig->r;
        s = sig->s;
#endif        
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
            /* do cleanup during error */
            if(sig)
                ECDSA_SIG_free(sig);
            sig = nullptr;
        return ret;
    }
#if 0
    /*        */
    int Ieee1609Cert::encode_certid()
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

    int Ieee1609Cert::encode_hashid3()
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

    int Ieee1609Cert::encode_crlseries()
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

    int Ieee1609Cert::encode_validityperiod()
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
    int Ieee1609Cert::encode_sequenceofpsid()
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
    int Ieee1609Cert::encode_vki()
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

    int Ieee1609Cert::encode_sign()
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
#endif    

    int Ieee1609Cert::encode(uint8_t **buf)
    {
        /* clear whatever was there */
        pEncObj->clear();
        EncodeCertBase(true);
        /* only encode the signature if it is of type explicit */
        if(base->certType == CertTypeExplicit &&  signature != nullptr)
            pEncObj->Signature_(signature);
        encLen = pEncObj->get(buf);
        return encLen;
    }

    /* the flag to control , whether to clear the memory or continue encoding */
    int Ieee1609Cert::EncodeToBeSigned(bool cont)
    {
        /* we are only using sequence of psids optional componets */
        uint8_t preample = 0x10; /* appPermissions are 3 optional components */
        try
        {
            /* if this is not continuous encoding, i.e. only tobesigned to be encoded */
            if(cont == false)
            {
                /* clear the buffer */
                pEncObj->clear();
            }
            /* preamble */
            pEncObj->OctectsFixed(&preample, 1);
            /* cert if */
            pEncObj->CertId(tbs->id);
            /* hashid3 */
            const uint8_t hashId[] = {0,0,0};
            pEncObj->HashId3(hashId, 3);
            //crlseries();
            pEncObj->CrlSeries(0x1234);
            //validityperiod();
            pEncObj->VP(tbs->validityPeriod);
            //app permissions
            pEncObj->SequenceOfPsid_(tbs->appPermisions);
            //verification key indicator
            pEncObj->Vki(tbs->verifyKeyIndicator);
        }catch (std::exception& e)
        {
            std::cout << "Ieee1609Cert::EncodeToBeSigned() exception "  << e.what() << std::endl;
            std::terminate();
        }
        return 0;
    }


    /* encode the toBeSigned field of the explicit certicate*/
    int Ieee1609Cert::EncodeCertBase(bool cont)
    {
        /* reset the encoded buffer and length */
        if(cont == false)
            pEncObj->clear();
        try
        {
            /* since we are using the explicit certificate, signature is present */
            uint8_t preample = 0;
            if (base->certType == CertTypeExplicit)
                preample = 0x40;
            pEncObj->OctectsFixed(&preample, 1);
            pEncObj->OctectsFixed(&base->version, 1);
            pEncObj->OctectsFixed((uint8_t *)&base->certType, 1);
            pEncObj->IssuerIdentifier_(std::ref(*issuer));
            /* continuous encoding */
            EncodeToBeSigned(true);
        }
        catch (std::logic_error& e)
        {
            std::cout << e.what() << '\n';

        }
        catch(const std::exception& e)
        {
            std::cout << e.what() << '\n';
        }
        
        return 0;
    }

    /* print the certificate into the file */
    int Ieee1609Cert::print()
    {
        encLen = encode(&encBuf);
        print_data("cert.txt", encBuf, encLen);
        return 0;
    }


    /* gets the public key from the key object */
    int Ieee1609Cert::public_key_get(point_conversion_form_t conv)
    {
        int i = 0;
        uint8_t *keyBuf = nullptr;
        size_t keylen = 0;//EC_KEY_key2buf(ecKey, conv, &keyBuf, nullptr);
        const EC_POINT *ecPoint = EC_KEY_get0_public_key(ecKey);

        /* get the x, y points from ecPoint */
        keylen = EC_POINT_point2oct(ecGroup, ecPoint, conv,nullptr,  keylen, nullptr);
        if(keylen == 0)
        {
            perror("cert::public_key_get()::EC_POINT_point2oct");
            LOG_ERR("cert::public_key_get::EC_POINT_point2oct", 1);
            std::terminate();
            return keylen;
        }

        std::cout << "public key length " << keylen << std::endl;

        try
        {
            keyBuf = (uint8_t *)buf_alloc(keylen);
        }
        catch(const std::bad_alloc &e)
        {
            std::cerr << e.what() << '\n';
            throw new std::runtime_error("error allocating buffer");
        }

        /* get the x, y points from ecPoint */
        keylen = EC_POINT_point2oct(ecGroup, ecPoint, conv,keyBuf,  keylen, nullptr);
        if(keylen == 0)
        {
            perror("cert::public_key_get()::EC_POINT_point2oct");
            LOG_ERR("cert::public_key_get::EC_POINT_point2oct", 1);
            std::terminate();
            return keylen;
        }
        EccP256CurvPoint *point = &vki->indicator.verificationKey.key.ecdsaNistP256S;


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
    void Ieee1609Cert::create()
    {   
        /* set the next tr to next */
        this->next = nullptr;
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

        /* define and call the below API */ 
        EncodeToBeSigned(false);
        encLen = pEncObj->get(&encBuf);
        sign(encBuf, encLen,ecdsaNistP256Signature);
        /* just to be sure clear the encode memory */
        pEncObj->clear();
        encBuf = nullptr;
        encLen = 0;
    }


    Ieee1609Cert* Ieee1609Cert::operator[](int psid)
    {
        /* return the certificate for the given psid */
        return nullptr;//certsPsidMap[psid];
    }

} //namespace ctp








