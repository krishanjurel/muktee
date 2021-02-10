#include "ieee1609dot2.hpp"
#include <stdio.h>
#include <string.h>
#include <algorithm>

namespace ctp
{
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
#ifdef __cplusplus
}
#endif






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

        grp = EC_KEY_get0_group(ecKey);

        /* allocate the memory for one cert first */
        crt = (SequenceOfCertificate *)malloc(sizeof(int) +  sizeof(certificateBase));
        /* add the cert into the queue */
        certs.push_back(crt);
        /* initialize all the pointers */
        base = (CertificateBase *)((uint8_t *)crt + sizeof(int));
        tbs = &base->toBeSignedCertificate;
        vki = &tbs->verifyKeyIndicator;
        /*pointer to the signature structure*/
        signature = &base->signature;
    }

    /* sign the certificate */
    int cert::sign(SignatureType type)
    {
        uint8_t *dgst = static_cast<uint8_t *>((void *)tbs);
        size_t dgstlen = sizeof(ToBeSignedCertificate);
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
        sig = ECDSA_do_sign(dgst, dgstlen, ecKey);
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

        sign_r = (uint8_t *)&signature->signature.ecdsaP256Signature.r.xonly.x[0];
        sign_s = (uint8_t *)&signature->signature.ecdsaP256Signature.s.x[0];
        /* set the signature type */
        signature->signatureType = type;

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
    /* encode the certificate */
    int cert:: encode()
    {




        return 0;
    }


    /* gets the public key from the key object */
    int cert::public_key_get(point_conversion_form_t conv)
    {
        int i = 0;
        uint8_t *keyBuf = nullptr;
        size_t keylen = EC_KEY_key2buf(ecKey, conv, &keyBuf, nullptr);
        if(keylen == 0)
        {
            perror("cert::public_key_get()");
            LOG_ERR("cert::public_key_get", 1);
            std::terminate();
            return keylen;
        }
        char *xPtr = &vki->verificationKey.ecdsaNistP256S.uncompressedx.x[0];
        char *yPtr = &vki->verificationKey.ecdsaNistP256S.uncompressedy.x[0];

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
        crt->length = 1;
        base->version = 3;
        base->certType = CertTypeExplicit;
        base->issuerType = IssuerIdentifierTypeHashAlgo;
        base->issuer.algo = HashAlgorithmTypeSha256;
        tbs->certificateIdType = CertificateIdTypeName;
        tbs->id.hostName.name = "Get the Host Name from Config File";
        tbs->id.hostName.length = strlen(tbs->id.hostName.name);
        /*FIXME, this is hard coded */
        tbs->crlSeries = 0x1234;
        time_t t = time(nullptr);
        struct tm *tm = localtime((const time_t *)&t);
        tbs->validityPeriod.start = start_time(tm);
        tbs->durationType = DurationTypeMinutes; /* fixeme , read this also from the config file */
        tbs->validityPeriod.DURATION_MINUTES = (7*24*60);/* for one week, read it form the config file */
        tbs->verificationKeyIndicatorType = VerificationKeyIndicatorTypeKey;
        /* default is uncompressed */
        public_key_get();

        /* FIXME, before signing, encode the certificate, for now keep
           it as blob of memory 
        */
        /* define and call the below API */ 
        encode();




        sign(ecdsaNistP256Signature);
    }
} //namespace ctp








