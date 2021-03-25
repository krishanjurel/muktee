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
    std::cout << "buf_realloc " << len << std::endl;
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
        pEncObj = std::shared_ptr<Ieee1609Encode>(new Ieee1609Encode(), [](Ieee1609Encode *p){delete p;});
        pDecObj = std::shared_ptr<Ieee1609Decode>(new Ieee1609Decode(), [](Ieee1609Decode *p){delete p;});
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
        //seqOfCert = (SequenceOfCertificate *)malloc(sizeof(int) +  sizeof(certificateBase));
        
        /* initialize all the pointers */
        base = (CertificateBase *)malloc(sizeof(CertificateBase));
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
        psidSsp->quantity = 1;
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
        *hash = (uint8_t *)buf_alloc(SHA256_DIGEST_LENGTH);

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
#if (OPENSSL_VERSION_NUMBER == 0x1010106fL)
        r = ECDSA_SIG_get0_r(sig);
        s = ECDSA_SIG_get0_s(sig);
#else
        r = sig->r;
        s = sig->s;
#endif
        
        signature.signature.ecdsaP256Signature.r.type= EccP256CurvPointXOnly;
        sign_r = (uint8_t *)signature.signature.ecdsaP256Signature.r.point.octets.x;
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
        sig = ECDSA_do_sign(buf,len,ecKey);
        if (sig == nullptr)
        {
            LOG_ERR("cert::sign : Error signing the message", 1);
            ret = -1;
            /*FIXME, try to avoid it */
            goto done;
        }
#if (OPENSSL_VERSION_NUMBER == 0x1010106fL)
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
        sign_r = (uint8_t *)signature->signature.ecdsaP256Signature.r.point.octets.x;
        sign_s = (uint8_t *)&signature->signature.ecdsaP256Signature.s.x[0];
        /* set the signature type */
        signature->type = type;

        /* convert the point to the buf for encoding */
        //EC_POINT_point2oct(grp, point, POINT_CONVERSION_COMPRESSED,xonly_r, sizeof(HashedData32), nullptr);

        std::cout << " BN_num_bytes(r) " << BN_num_bytes(r) << std::endl;

        if(BN_bn2bin(r, sign_r) != sizeof(HashedData32))
        {
            LOG_ERR("cert::sign BN_bn2bin(r, sign_r)", 1);
            ret = -1;
            /*FIXME, try to avoid it */
            goto done;
        }

        std::cout << " BN_num_bytes(s) " << BN_num_bytes(s) << std::endl;

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


    /* to utilize the previously created decode object */
    int Ieee1609Cert::decode(std::shared_ptr<Ieee1609Decode> ptr)
    {
        pDecObj.reset();
        pDecObj = ptr->GetPtr();
        try
        {
            /* decode version */
            pDecObj->Octets_((uint8_t *)&base->version, 1);
            /* decode cert type */
            pDecObj->Octets_((uint8_t *)&base->certType, 1);
            pDecObj->IssuerIdentifier_(std::ref(*issuer));
            DecodeToBeSigned();
        }catch(Exception& e)
        {
            throw; /*throw again from here */
        }
        return 0;
    }

    int Ieee1609Cert::decode(const uint8_t *buf, size_t len)
    {
        /* decode the type */
        // pDecObj->SignerIdentifier_(std::ref(signer));
        return 0;
        

    }






    int Ieee1609Cert::encode(uint8_t **buf)
    {
        /* clear whatever was there */
        pEncObj->clear();
        /* FIXME, use Ieee1609certs class object to encode the certs */
        uint8_t num = 1;
        /*FIXME, to be done encode the signer identifier choice */

        /* the type is cert */
        pEncObj->SequenceOf(&num, 1);
        EncodeCertBase(true);
        /* only encode the signature if it is of type explicit */
        if(base->certType == CertTypeExplicit &&  signature != nullptr)
            pEncObj->Signature_(std::ref(*signature));
        return pEncObj->get(buf);
    }

    /* decode tToBeSignedCertificate structure, 6.4.8 */
    int Ieee1609Cert::DecodeToBeSigned(bool cont)
    {
        /* decode the optional mask */
        /* FIXME, hard coded to have only non-extensible fixed size components */
        pDecObj->Octets_((uint8_t *)&tbs->optionsComps, 1);
        pDecObj->CertId(std::ref(tbs->id));
        pDecObj->CrlSeries(std::ref(tbs->crlSeries));
        pDecObj->VP(std::ref(tbs->validityPeriod));
        /* decode optional components */
        if(tbs->optionsComps & TBS_OPTIONAL_MASK(Region))
        {
            std::cout << "Ieee1609Cert::DecodeToBeSigned::tbs->optionsComps TBS_OPTIONAL_MASK(Region) not supported " << std::endl;
            throw Exception(" Ieee1609Cert::DecodeToBeSigned::tbs->optionsComps TBS_OPTIONAL_MASK(Region) not supported ");
        }

        if(tbs->optionsComps & TBS_OPTIONAL_MASK(AssuranceLevel))
        {
            std::cout << "Ieee1609Cert::DecodeToBeSigned::tbs->optionsComps TBS_OPTIONAL_MASK(AssuranceLevel) not supported " << std::endl;
            throw Exception(" Ieee1609Cert::DecodeToBeSigned::tbs->optionsComps TBS_OPTIONAL_MASK(AssuranceLevel) not supported ");
        }
        /* app permissions */
        if(tbs->optionsComps & TBS_OPTIONAL_MASK(AppPerm))
        {
            pDecObj->SequenceOfPsid_(std::ref(tbs->appPermisions));
        }
        if(tbs->optionsComps & TBS_OPTIONAL_MASK(CertIssuePerm))
        {
            std::cout << "Ieee1609Cert::DecodeToBeSigned::tbs->optionsComps TBS_OPTIONAL_MASK(CertIssuePerm) not supported " << std::endl;
            throw Exception(" Ieee1609Cert::DecodeToBeSigned::tbs->optionsComps TBS_OPTIONAL_MASK(CertIssuePerm) not supported ");
        }
        if(tbs->optionsComps & TBS_OPTIONAL_MASK(CertReqPerm))
        {
            std::cout << "Ieee1609Cert::DecodeToBeSigned::tbs->optionsComps TBS_OPTIONAL_MASK(CertReqPerm) not supported " << std::endl;
            throw Exception(" Ieee1609Cert::DecodeToBeSigned::tbs->optionsComps TBS_OPTIONAL_MASK(CertReqPerm) not supported ");
        }
        if(tbs->optionsComps & TBS_OPTIONAL_MASK(CanReqRoll))
        {
            std::cout << "Ieee1609Cert::DecodeToBeSigned::tbs->optionsComps TBS_OPTIONAL_MASK(CanReqRoll) not supported " << std::endl;
            throw Exception(" Ieee1609Cert::DecodeToBeSigned::tbs->optionsComps TBS_OPTIONAL_MASK(CanReqRoll) not supported ");
        }
        if(tbs->optionsComps & TBS_OPTIONAL_MASK(EncKey))
        {
            std::cout << "Ieee1609Cert::DecodeToBeSigned::tbs->optionsComps TBS_OPTIONAL_MASK(EncKey) not supported " << std::endl;
            throw Exception(" Ieee1609Cert::DecodeToBeSigned::tbs->optionsComps TBS_OPTIONAL_MASK(EncKey) not supported ");
        }
        /* decode verification key indicator */
        pDecObj->Vki(std::ref(tbs->verifyKeyIndicator));
        return 0;
    }

    /* the flag to control , whether to clear the memory or continue encoding */
    int Ieee1609Cert::EncodeToBeSigned(bool cont)
    {
        /* we are only using sequence of psids optional componets */
        uint8_t preample = 0x10; /* appPermissions are 3rd optional components */
        try
        {
            /* if this is not continuous encoding, i.e. only tobesigned to be encoded */
            if(cont == false)
            {
                /* clear the buffer */
                pEncObj->clear();
            }
            /* preamble */
            pEncObj->OctetsFixed(&preample, 1);
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
            pEncObj->OctetsFixed(&preample, 1);
            pEncObj->OctetsFixed(&base->version, 1);
            pEncObj->OctetsFixed((uint8_t *)&base->certType, 1);
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
        size_t len;
        uint8_t *buf = nullptr;
        len = encode(&buf);
        print_data("cert.txt", buf, len);
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
        int ret = 0;
        /* set the next tr to next */
        this->next = nullptr;
        /* one cert */
        //seqOfCert->length = 1;
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
        /* this buf is owned by the encoder, dont do anything with this */
        uint8_t *buf = nullptr;
        size_t len = 0;
        len = pEncObj->get(&buf);
        uint8_t *hash = nullptr;
        ret = Hash256(buf, len, &hash);
        if(ret == 0)
        {
            LOG_ERR(" Ieee1609Cert::create()::Hash256 ", 1);
            std::terminate();
        }
        sign(hash, SHA256_DIGEST_LENGTH,ecdsaNistP256Signature);
        /* just to be sure clear the encode memory */
        pEncObj->clear();
    }


    Ieee1609Cert* Ieee1609Cert::operator[](int psid)
    {
        /* return the certificate for the given psid */
        return nullptr;//certsPsidMap[psid];
    }

} //namespace ctp








