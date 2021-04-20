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
#if 0
void *buf_alloc(size_t num)
{
    /* return the num blocks of size 1 */ 
    return calloc(num,1);
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
#endif
#ifdef __cplusplus
}
#endif

void print_data(const char* file, const uint8_t *buf, size_t len)
{
    int i = 0, j = 0;
    std::ostream os(std::cout.rdbuf());
    std::ofstream ofs;
    /* open the file in text mode */
    if(file != nullptr)
    {
        ofs.open(file);
        /* set the buffer */
        os.rdbuf(ofs.rdbuf());
    }
    //std::ostream os(ofs.rdbuf());
    os << std::hex;
    for(i=0; i < len; i++)
    {
        // char c[2];
        // istram >> c[0] >> c[1];
        int c = (int)(buf[i]);
        //snprintf((char *)&c, sizeof(int), "%c", buf[i]);
        os << std::setw(2) << std::setfill('0') << std::hex << c;
        os << ':';
        j++;
        if(j % 16 == 0)
        {
            os << std::endl;
            j = 0;
        }
    }
    std::cout << std::endl;
    os.flush();
    if(file != nullptr)
    {
        ofs.close();
    }
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
        
        /* initialize all the pointers */
        base = (CertificateBase *)buf_alloc(sizeof(CertificateBase));
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
    }

    const SequenceOfPsidSsp& Ieee1609Cert::psid_get() const
    {
        return std::ref(*psidSsp);
    }

    int Ieee1609Cert::sign()
    {
        int ret = 0;
        if(pEncObj.operator bool() == false)
        {
            pEncObj = std::shared_ptr<Ieee1609Encode>(new Ieee1609Encode, [](Ieee1609Encode *p){delete p;});
        }
        EncodeToBeSigned(false);
        uint8_t *buf = nullptr;
        size_t len = 0;
        len = pEncObj->get(&buf);
        uint8_t *hash1 = nullptr; /* hash of tobesigned */
        uint8_t *hash2 = nullptr; /* hash of signer idetntifier */
        uint8_t *hash = nullptr;  /* total hash */
        ret = Hash256(buf, len, &hash1);
        if(ret == 0)
        {
            LOG_ERR(" Ieee1609Cert::sign()::Hash256 ", MODULE);
            throw Exception(" Ieee1609Cert::sign()::Hash256 ");
 
        }
        pEncObj->clear();
        if(base->issuer.type == IssuerIdentifierTypeSelf)
        {
            const uint8_t *nullstr = (const uint8_t*)"\0";
            ret = Hash256((uint8_t *)nullptr, 0, &hash2);
        }else if(base->issuer.type == IssuerIdentifierTypeHashId)
        {
            ret = Hash256((uint8_t *)base->issuer.issuer.hashId.x, sizeof(hashid8), &hash2);
        }

        if(ret == 0)
        {
            LOG_ERR(" Ieee1609Cert::sign()::Hash256 hash nullstr ", MODULE);
            throw Exception(" Ieee1609Cert::sign()::Hash256 hash nullstr ");
        }

        hash = (uint8_t *)buf_alloc(2*SHA256_DIGEST_LENGTH);
        /* copy the hash1 */
        memcpy(hash,hash1, SHA256_DIGEST_LENGTH);
        /* copy the hash 2*/
        memcpy(&hash[SHA256_DIGEST_LENGTH], hash2, SHA256_DIGEST_LENGTH);
        sign(hash, SHA256_DIGEST_LENGTH,ecdsaNistP256Signature);
        buf_free(hash);
        return 1;
    }

    int Ieee1609Cert::verify(const uint8_t *dgst, size_t dgst_len, const Signature& signature_)
    {
        int ret = 0;
        BIGNUM *r, *s;
        EC_POINT *point;
        uint8_t *sign_r, *sign_s;


        ECDSA_SIG *sig = ECDSA_SIG_new();

        /* get r and s from octet encoded signature values */
        sign_r = (uint8_t *)signature_.signature.ecdsaP256Signature.r.point.octets.x;
        sign_s = (uint8_t *)&signature_.signature.ecdsaP256Signature.s.x[0];

        std::cout << "Ieee1609Cert::verify: verification payload " << std::endl;
        print_data(nullptr, dgst, dgst_len);

        // /* signature */
        // for(int i = 0; i < 32; i++)
        // {
        //     if(i % 16 ==0)
        //         std::cout << std::endl;
            
        //     std::cout << std::hex << (int)sign_r[i] << ":";
        // }
        r = BN_new();
        s = BN_new();

        r = BN_bin2bn(sign_r,SHA256_DIGEST_LENGTH, r);
        if(r == nullptr)
        {
            throw Exception("Ieee1609Cert::verify::BN_bin2bn::r");
        }
        s = BN_bin2bn(sign_s,SHA256_DIGEST_LENGTH, s);
        if(s == nullptr)
        {
            throw Exception("Ieee1609Cert::verify::BN_bin2bn::s");
        }

        ret = ECDSA_SIG_set0(sig, r, s);
        if(ret == 0 )
        {
            throw Exception("Ieee1609Cert::verify::ECDSA_SIG_set0");
        }

        /* now get the public key of the signer */
        EC_KEY *key = nullptr;
        /* allocate the temporary buffer to specify the comporessed point of the key */
        /* allocate the max buffer including the compressed notification */
        size_t buf_len = SHA256_DIGEST_LENGTH*2+1;
        uint8_t *buf1_;
        uint8_t *buf2_ = (uint8_t*)buf_alloc(buf_len);
        
        if(vki->type == VerificationKeyIndicatorTypeKey)
        {
            if(vki->indicator.verificationKey.type == PublicVerificationKeyTypEecdsaNistP256S)
            {
                key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                buf2_[0] = (uint8_t )vki->indicator.verificationKey.key.ecdsaNistP256.type;
                if (vki->indicator.verificationKey.key.ecdsaNistP256.type == EccP256CurvPointTypeFill)
                {
                    buf_len = 0;
                }
                if(vki->indicator.verificationKey.key.ecdsaNistP256.type != EccP256CurvPointTypeUncompressed)
                {
                    buf1_ = (uint8_t *)&vki->indicator.verificationKey.key.ecdsaNistP256.point.octets.x[0];
                    buf_len = SHA256_DIGEST_LENGTH;
                }else
                {
                    buf1_= (uint8_t *)&vki->indicator.verificationKey.key.ecdsaNistP256.point.uncompressed;
                    buf_len = SHA256_DIGEST_LENGTH * 2;

                }
                /* key is needed */
                if(buf_len == 0)
                {
                    BN_free(r);
                    BN_free(s);
                    EC_KEY_free(key);
                    free(buf2_);
                    throw Exception("Ieee1609Cert::verify:: public key len 0");
                }
                memcpy(&buf2_[1], buf1_, buf_len);

                buf_len +=1;
                /* now get the point from the octet encode buffer */
                // if (key == nullptr ) std::cout << "no key " << std::endl;
                ret = EC_KEY_oct2key(key, buf2_, buf_len, nullptr);
                if(ret == 0)
                {
                    std::cout << "the key has failed " << std::endl;
                    BN_free(r);
                    BN_free(s);
                    EC_KEY_free(key);
                    free(buf2_);
                    throw Exception("Ieee1609Cert::verify::EC_KEY_oct2key");
                }
                /* now we got the key, verify the signature */
                ret = ECDSA_do_verify(dgst, dgst_len, sig, key);
                if(ret == 0)
                {
                    perror("Ieee1609Cert::verify::ECDSA_do_verify");
                    BN_free(r);
                    BN_free(s);
                    EC_KEY_free(key);
                    free(buf2_);
                    throw Exception("Ieee1609Cert::verify::ECDSA_do_verify");
                }
                std::cout << "14\n";
                BN_free(r);
                BN_free(s);
                EC_KEY_free(key);
                free(buf2_);
            }
        }
        return ret;


    }

    /* verify the signature on the given digest */
    int Ieee1609Cert::verify(const uint8_t *dgst, size_t dgst_len)
    {
        return verify(dgst, dgst_len, std::ref(*signature));
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
        std::stringstream log_(std::ios_base::out);
        log_ << " Ieee1609Cert::Hash256 enter length " << len << std::endl;
        log_info(log_.str(), MODULE);
        log_.str(""); 
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

        log_ << " Ieee1609Cert::Hash256 exit status " << ret << std::endl;
        log_info(log_.str(), MODULE);

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
        
        signature.signature.ecdsaP256Signature.r.type= EccP256CurvPointTypeXOnly;
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
        std::cout << "signed data " << std::endl;
        for(int i = 0; i < len; i++)
        {
            if(i%16 ==0)
                std::cout << std::endl;
            std::cout << std::hex << (int)buf[i] << ":";
        }
        std::cout << std::endl;

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

        std::cout << "_signed data " << std::endl;
        for(int i = 0; i < len; i++)
        {
            if(i%16 ==0)
                std::cout << std::endl;
            std::cout << std::hex << (int)buf[i] << ":";
        }
        std::cout << std::endl;

        //EC_POINT *point = EC_POINT_new(grp);

        // if(EC_POINT_bn2point(grp, r, point, nullptr) != point)
        // {
        //     LOG_ERR("cert::sign error EC_POINT_bn2point",1);
        //     ECDSA_SIG_free(sig);
        //     EC_POINT_free(point);
        //     sig = nullptr;
        // }
        /* signature r value for FIPS 186-4 takes only x-only */
        signature->signature.ecdsaP256Signature.r.type= EccP256CurvPointTypeXOnly;
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
        std::shared_ptr<Ieee1609Decode> temp = pDecObj->GetPtr();
        pDecObj = ptr->GetPtr();
        try
        {
            /* get the sequence preamble */
            pDecObj->Octets_(&base->options, 1);
            /* decode version */
            pDecObj->Octets_((uint8_t *)&base->version, 1);
            /* decode cert type */
            pDecObj->Octets_((uint8_t *)&base->certType, 1);
            pDecObj->IssuerIdentifier_(std::ref(*issuer));
            DecodeToBeSigned();
            /* decode the signature if available */
            if(base->options)
            {
                pDecObj->Signature_(std::ref(base->signature));
            }
        }catch(Exception& e)
        {
            throw; /*throw again from here */
        }
        pDecObj = temp;
        temp = nullptr;
        return 1;
    }

    int Ieee1609Cert::decode(const uint8_t *buf, size_t len)
    {
        std::stringstream log_(std::ios_base::out);
        pDecObj->set(buf, len);
        try
        {
            /* get the sequence preamble */
            pDecObj->Octets_(&base->options, 1);
            log_ << "base options " << std::to_string(base->options) << std::endl;
            log_info(log_.str(), MODULE);
            log_.str("");
            /* decode version */
            pDecObj->Octets_((uint8_t *)&base->version, 1);
            log_ << "base version " << std::to_string(base->version) << std::endl;
            log_info(log_.str(), MODULE);
            log_.str("");

            /* decode cert type */
            pDecObj->Octets_((uint8_t *)&base->certType, 1);
            log_ << "base cert type " << std::to_string(base->certType) << std::endl;
            log_info(log_.str(), MODULE);
            log_.str("");
            pDecObj->IssuerIdentifier_(std::ref(*issuer));
            DecodeToBeSigned();
            /* decode the signature if available */
            if(base->options)
            {
                pDecObj->Signature_(std::ref(base->signature));
            }
        }catch(Exception& e)
        {
            log_ << "Exception " << e.what() << std::endl;
            LOG_ERR(log_.str(), MODULE);
            throw; /*throw again from here */
        }
        return 0;
    }

    int Ieee1609Cert::encode(std::shared_ptr<Ieee1609Encode> ptr)
    {
        /* clear any buffer held by the previous encoder */
        std::shared_ptr<Ieee1609Encode> temp = pEncObj;
        /* acquire the new encoding object*/
        pEncObj = ptr->getPtr();
        /* encode the certificate base */
        EncodeCertBase(true);
        /* only encode the signature if it is of type explicit */
        if(base->certType == CertTypeExplicit &&  signature != nullptr)
            pEncObj->Signature_(std::ref(*signature));

        /* restore the encoder back */
        pEncObj = temp;
        return 1;
    }

    int Ieee1609Cert::encode(uint8_t **buf)
    {
        /* clear whatever was there */
        pEncObj->clear();
        /* encode the preamble for signature optional component */
        // if(base->certType == CertTypeExplicit)
        // {
        //     pEncObj->OctetsFixed((uint8_t *)&base->options, 1);
        // }
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
        pDecObj->HashId3((uint8_t*)tbs->cracaId.x, 3);
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
            pEncObj->OctetsFixed(&base->options, 1);
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
    int Ieee1609Cert::print_encoded(const std::string filename)
    {
        uint8_t *buf = nullptr;
        size_t len = pEncObj->get(&buf);
        print_data(filename.c_str(), buf, len);
        return 0;
    }

    int Ieee1609Cert::print_decoded(const std::string filename)
    {
        size_t len;
        /* open the file in text mode */
        std::ofstream os(filename.c_str(), std::ios::binary);

        os << " version " << std::to_string(base->version) << std::endl;
        os << "type " << std::to_string(base->certType) << std::endl;
        os << " issuer identifier " << std::to_string(issuer->type) << std::endl;
        if (issuer->type == IssuerIdentifierTypeHashId)
        {
            for (int i =0; i < 8; i++)
            {
                os << std::hex << std::to_string(issuer->issuer.hashId.x[i]) << ":" ; 
            }
            os << std::endl;
        }

        os << " options " << std::to_string(tbs->optionsComps) << std::endl;
        os << " hashId " << std::to_string(tbs->cracaId.x[0]) << std::to_string(tbs->cracaId.x[1]) << std::to_string(tbs->cracaId.x[2]) << std::endl;
        return 0;
    }

    /* gets the public key from the key object */
    int Ieee1609Cert::public_key_get(point_conversion_form_t conv)
    {
        int i = 0;
        uint8_t *keyBuf = nullptr;
        size_t keylen = 0;
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
        EccP256CurvPoint *point = &vki->indicator.verificationKey.key.ecdsaNistP256;

        /* get the point type from the first byte of the key type */
        point->type = (EccP256CurvPointType)keyBuf[0];
        char *xPtr = point->point.uncompressedx.x;
        char *yPtr = point->point.uncompressedy.x;

        /* there will always be x-component, so lets copy that */
        for (i = 1; i < keylen;i++)
        {
            std::cout << std::hex << (int)keyBuf[i] << ":";
            if(i%16 ==0)
                std::cout << std::endl;
            *xPtr++ = keyBuf[i];
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
    void Ieee1609Cert::create(int nid)
    {
        int ret = 0;
        ecKey = EC_KEY_new_by_curve_name(nid);
        if (ecKey == nullptr)
        {
            perror("<Main> Error associating key with a curve");
            std::terminate();
        }

        if(EC_KEY_generate_key(ecKey) != 1)
        {
            LOG_ERR("cert::cert() EC_KEY_generate_key", 1);
            EC_KEY_free(ecKey);
            std::terminate();
        }
        ecGroup = EC_KEY_get0_group(ecKey);

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
        tbs->validityPeriod.duration.duration = (uint16_t)(7*24*60);/* for one week, read it form the config file */
        /* set the verification key indicator type */
        vki->type = VerificationKeyIndicatorTypeKey;
        /* default is uncompressed */
        public_key_get();
        
        /* there is only item in this sequence */
        psidSsp->quantity = 1;
        /* psid psidssp only contains the psid , with no ssp */
        psidSsp->psidSsp = (PsidSsp *)buf_alloc(psidSsp->quantity * sizeof(PsidSsp));
        /* FIXME, hardcoded psid, BSM */
        psidSsp->psidSsp->psid = 0x20;
        /* No optional mask */
        psidSsp->psidSsp->optionalMask = 0;
        /* no ssp */
        psidSsp->psidSsp->ssp.length = 0;
        /* default, self-signed */
        issuer->type = IssuerIdentifierTypeSelf;
        /* every self-signed certificate is signed by default */
        sign();
        /* have the signature option */
        base->options = 0x80;
    }
} //namespace ctp








