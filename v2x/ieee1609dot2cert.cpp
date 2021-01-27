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
        // ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        // if (eckey == nullptr)
        // {
        //     perror("<Main> Error associating key with a curve");
        //     std::terminate();
        // }
    }

    /* create a certificate */
    void cert::create()
    {   
        SequenceOfCertificate *cert = (SequenceOfCertificate *)malloc(sizeof(int) +  sizeof(certificateBase));  
        /* one cert */
        cert->length = 1;
        CertificateBase *base = (CertificateBase *)((uint8_t *)cert + sizeof(int));
        base->version = 3;
        base->certType = CertTypeExplicit;
        base->issuerType = IssuerIdentifierTypeHashAlgo;
        base->issuer.algo = HashAlgorithmTypeSha256;
        ToBeSignedCertificate *tbs = &base->toBeSignedCertificate;
        tbs->certificateIdType = CertificateIdTypeName;
        tbs->id.hostName.name = "Get the Host Name from Config File";
        tbs->id.hostName.length = strlen(tbs->id.hostName.name);
        /*FIXME, this is hard coded */
        tbs->crlSeries = 0x1234;
        time_t t = time(nullptr);
        struct tm *tm = localtime((const time_t *)&t);
        tbs->validityPeriod.start = start_time(tm);
        tbs->durationType = DurationTypeMinutes; /* fixeme , read this also from the config file */
        tbs->validityPeriod.DURATION_HOURS = (7*24*60);/* for one week, read it form the config file */
        VerificationKeyIndicator *vki = &tbs->verifyKeyIndicator;
        tbs->verificationKeyIndicatorType = VerificationKeyIndicatorTypeKey;
        /*FIXME, read the key type */
        char *xPtr = &vki->verificationKey.ecdsaNistP256S.uncompressedx.x[0];
        char *yPtr = &vki->verificationKey.ecdsaNistP256S.uncompressedy.x[0];
        for(int i=0; i < 32; i++){
            *(xPtr+i) = (char)i;
            *(yPtr+i) = (char)i;
        }
        //vki->verificationKey.ecdsaNistP256S.uncompressedx.x[0] = "123456";
        //&vki->verificationKey.ecdsaNistP256S.uncompressedy.x[0] = "123456";
        
    }

























} //namespace ctp








