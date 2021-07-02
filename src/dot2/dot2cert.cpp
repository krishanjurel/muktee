#include "dot2cert.hpp"
// #include "dot2data.hpp"

// #include <stdio.h>
// #include <string.h>
// #include <algorithm>
// #include <iostream>
// #include <fstream>
// #include <iomanip>

// #include <fcntl.h>
// #include <unistd.h>
// #include <stdio.h>
// #include <stdlib.h>

    
namespace ctp
{
    

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
        seqOfPsidSsp = &tbs->appPermisions;
        seqOfPsidSsp->quantity = 0;
        seqOfPsidSsp->psidSsp=nullptr;
        ecKey = nullptr;
        certPath.clear();

        // /* encoded buffer is zero */
        encodedBuf = nullptr;
        encodedBufLen = 0;
    }

    const SequenceOfPsidSsp& Ieee1609Cert::psid_get() const
    {
        return std::ref(*seqOfPsidSsp);
    }

    int Ieee1609Cert::sign(SHARED_CERT signer)
    {
        int ret = 0;
        std::stringstream log_(std::ios_base::out);
        log_ << " Ieee1609Cert::sign() enter " << std::endl;
        log_dbg(log_.str(), MODULE);
        log_.str("");
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
        if (len)
        {
            ret = Hash256(buf, len, &hash1);
            if(ret == 0)
            {
                LOG_ERR(" Ieee1609Cert::sign()::Hash256 ", MODULE);
            }
        }

        log_.str("");
        len = 0;
        if(buf) buf_free(buf);
        buf = nullptr;
        pEncObj->clear();
        if(ret)
        {
            if(signer.get() == this)
            {
                const std::string nullstr{};
                ret = Hash256((uint8_t *)nullstr.c_str(), nullstr.size(), &hash2);
                log_ << "Ieee1609Cert::sign()::Hash256 hash nullstr " << std::endl;
            }else
            {
                len = signer->encode(&buf);
                ret = Hash256(buf, len, &hash2);
                log_ << "Ieee1609Cert::sign()::Hash256 hash issuer " << std::endl;
            }
        }

        if(ret)
        {

            hash = (uint8_t *)buf_alloc(2*SHA256_DIGEST_LENGTH);
            /* copy the hash1 */
            memcpy(hash,hash1, SHA256_DIGEST_LENGTH);
            /* copy the hash 2*/
            memcpy(&hash[SHA256_DIGEST_LENGTH], hash2, SHA256_DIGEST_LENGTH);

            ret = Hash256(hash,2*SHA256_DIGEST_LENGTH,&hash2);
            log_ << "Ieee1609Cert::sign()::Hash256 hash combined " << std::endl;
        }

        if(ret)
        {
            ret  = signer->sign(hash2, SHA256_DIGEST_LENGTH,ecdsaNistP256Signature);
            if(ret == 0)
            {
                log_ << "Ieee1609Cert::sign()::sign(..)" << std::endl;
            }
        }

        if(ret == 0)
        {
            LOG_ERR(log_.str(), MODULE);
        }

        if(buf)
            buf_free(buf);
        if(hash)
            buf_free(hash);
        if(hash1)
            buf_free(hash1);
        if(hash2)
            buf_free(hash2);

        log_.str("");
        log_ << " Ieee1609Cert::sign() exit " << std::endl;
        log_dbg(log_.str(), MODULE);
        return 1;
    }

    int Ieee1609Cert::verify(const uint8_t *dgst, size_t dgst_len, const Signature& signature_)
    {
        std::stringstream log_(std::ios_base::out);
        int ret = 1;
        BIGNUM *r, *s;
        uint8_t *sign_r, *sign_s;
        int nid = -1;

        size_t buf_len = SHA256_DIGEST_LENGTH*2+1;
        uint8_t *buf1_ = nullptr;
        uint8_t *buf2_ = nullptr;

        EC_KEY *key = nullptr;
        ECDSA_SIG *sig = nullptr;
        EC_GROUP *group = nullptr;


        log_ << "Ieee1609Cert::verify(...)" << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");

        switch(signature_.type)
        {
            case ecdsaNistP256Signature:
                nid = NID_X9_62_prime256v1;
                break;
            case ecdsaBrainpoolP256r1Signature:
                nid = NID_brainpoolP256r1;
            default:
                log_ << "Ieee1609Cert::verify(...) invalid signature-type  " << signature->type << std::endl;
                LOG_ERR(log_.str(), MODULE);
        }

        if( nid == -1)
        {
            ret = 0;
            goto done;
        }

        log_.str("");

        sig = ECDSA_SIG_new();
        group = EC_GROUP_new_by_curve_name(nid);
        /* set the group point as compressed form */
        EC_GROUP_set_point_conversion_form(group,POINT_CONVERSION_COMPRESSED);
        /* get r and s from octet encoded signature values */
        sign_r = (uint8_t *)signature_.signature.ecdsaP256Signature.r.point.octets.x;
        sign_s = (uint8_t *)&signature_.signature.ecdsaP256Signature.s.x[0];

        // std::cout << "Ieee1609Cert::verify: verification payload " << std::endl;
        // // print_data(nullptr, dgst, dgst_len);

        // /* signature */
        // for(int i = 0; i < dgst_len; i++)
        // {
        //     if(i % 16 ==0)
        //         std::cout << std::endl;
        //     std::cout << std::hex << (int)sign_r[i] << ":";
        // }
        // std::cout << std::endl;
        r = BN_new();
        s = BN_new();

        r = BN_bin2bn(sign_r,SHA256_DIGEST_LENGTH, r);
        if(r == nullptr)
        {
            ret = 0;
            BN_free(r);
            BN_free(s);
            log_ << "Ieee1609Cert::verify::BN_bin2bn::r" << std::endl;
            goto done;
        }
        s = BN_bin2bn(sign_s,SHA256_DIGEST_LENGTH, s);
        if(s == nullptr)
        {
            ret = 0;
            BN_free(r);
            BN_free(s);
            log_ << "Ieee1609Cert::verify::BN_bin2bn::s" << std::endl;
            goto done;
        }


#if (OPENSSL_VERSION_NUMBER >= 0x1010100fL)
        ret = ECDSA_SIG_set0(sig, r, s);
        if(ret == 0 )
        {
            ret = 0;
            BN_free(r);
            BN_free(s);
            log_ << "Ieee1609Cert::verify::ECDSA_SIG_set0" << std::endl;
        }
#else
        sig->r = r;
        sig->s = s;
#endif

        /* allocate the temporary buffer to specify the comporessed point of the key */
        /* allocate the max buffer including the compressed notification */
        
        buf2_ = (uint8_t*)buf_alloc(buf_len);
        if(vki->type == VerificationKeyIndicatorTypeKey)
        {
            if(vki->indicator.verificationKey.type == PublicVerificationKeyTypEecdsaNistP256S)
            {

                key = EC_KEY_new_by_curve_name(nid);
                EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);

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
                if(buf_len == 0 || key == nullptr)
                {
                    ret = 0;
                    BN_free(r);
                    BN_free(s);
                    EC_KEY_free(key);
                    buf_free(buf2_);
                    log_ << "Ieee1609Cert::verify:: public key len 0" << std::endl;
                    goto done;
                }
                memcpy(&buf2_[1], buf1_, buf_len);

                buf_len +=1;
#if (OPENSSL_VERSION_NUMBER == 0x1010106fL)
                ret = EC_KEY_oct2key(key, buf2_, buf_len, nullptr);
#else
                EC_POINT *point = EC_POINT_new(group);
                ret = EC_POINT_oct2point(group, point, buf2_, buf_len, nullptr);
                if(ret == 1)
                {
                    EC_KEY_set_public_key(key, point);
                }
#endif
                if(ret == 0)
                {
                    // std::cout << "the key has failed " << std::endl;
                    BN_free(r);
                    BN_free(s);
                    EC_KEY_free(key);
                    buf_free(buf2_);
                    log_ << "Ieee1609Cert::verify::EC_KEY_oct2key" << std::endl;
                    goto done;
                }
                /* now we got the key, verify the signature */
                ret = ECDSA_do_verify(dgst, dgst_len, sig, key);
                if(ret == 0 ||
                   ret ==  -1)
                {
                    ret = 0;
                    // perror("Ieee1609Cert::verify::ECDSA_do_verify");
                    BN_free(r);
                    BN_free(s);
                    EC_KEY_free(key);
                    buf_free(buf2_);
                    log_ << "Ieee1609Cert::verify::ECDSA_do_verify" << std::endl;
                    goto done;
                }
                BN_free(r);
                BN_free(s);
                EC_KEY_free(key);
                buf_free(buf2_);
            }
        }

        done:

        if(ret == 0) LOG_ERR(log_.str(), MODULE);
        log_.str("");
        log_ << "Ieee1609Cert::verify exit " << std::endl;
        log_info(log_.str(), MODULE);
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

    int Ieee1609Cert::ConsistencyCheck(const HeaderInfo& header)
    {
        int ret = 0;
        std::stringstream log_(std::ios_base::out);
        log_ << "Ieee1609Cert::ConsistencyCheck(const HeaderInfo& header) enter " << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        
        log_ << "Ieee1609Cert::ConsistencyCheck(const HeaderInfo& header) seqOfPsidSsp->quantity " << seqOfPsidSsp->quantity <<std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        // /* go thru the list of supported sequence of psids */
        for(int i=0; i < seqOfPsidSsp->quantity; i++)
        {
            PsidSsp *psidSsp = seqOfPsidSsp->psidSsp + i;

            if(header.psid == psidSsp->psid)
            {
                ret = 1;
                break;
            }
        }
        log_ << "Ieee1609Cert::ConsistencyCheck(const HeaderInfo& header) exit " << ret << std::endl;
        log_info(log_.str(), MODULE);
        return ret;
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
                buf_free(*hash);
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
#if (OPENSSL_VERSION_NUMBER >= 0x1010100fL)
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
        // std::cout << "signed data " << len << std::endl;
        // for(int i = 0; i < len; i++)
        // {
        //     if(i%16 ==0)
        //         std::cout << std::endl;
        //     std::cout << std::hex << (int)buf[i] << ":";
        // }
        // std::cout << std::endl;
        /* use the only key for now */
        return  ECDSA_do_sign(buf,len,ecKey);
    }

    /* sign the certificate */
    int Ieee1609Cert::_sign(const uint8_t *buf, size_t len, SignatureType type)
    {
        int ret = 1;
        const BIGNUM *r;
        const BIGNUM *s;
        uint8_t *sign_r, *sign_s;
        ECDSA_SIG *sig;

        std::stringstream log_(std::ios_base::out);
        log_ << " Ieee1609Cert::_sign() enter " << std::endl;
        log_dbg(log_.str(), MODULE);
        log_.str("");

        sig = ECDSA_do_sign(buf,len,ecKey);
        if (sig == nullptr)
        {
            LOG_ERR("cert::sign : Error signing the message", 1);
            ret = 0;
            /*FIXME, try to avoid it */
            goto done;
        }
#if (OPENSSL_VERSION_NUMBER >= 0x1010100fL)
        r = ECDSA_SIG_get0_r(sig);
        s = ECDSA_SIG_get0_s(sig);
#else
        r = sig->r;
        s = sig->s;
#endif   

        // std::cout << "_signed data " << std::endl;
        // for(int i = 0; i < len; i++)
        // {
        //     if(i%16 ==0)
        //         std::cout << std::endl;
        //     std::cout << std::hex << (int)buf[i] << ":";
        // }
        // std::cout << std::endl;

        /* signature r value for FIPS 186-4 takes only x-only */
        signature->signature.ecdsaP256Signature.r.type= EccP256CurvPointTypeXOnly;
        sign_r = (uint8_t *)signature->signature.ecdsaP256Signature.r.point.octets.x;
        sign_s = (uint8_t *)&signature->signature.ecdsaP256Signature.s.x[0];
        /* set the signature type */
        signature->type = type;

        // std::cout << " BN_num_bytes(r) " << BN_num_bytes(r) << std::endl;

        if(BN_bn2bin(r, sign_r) != sizeof(HashedData32))
        {
            LOG_ERR("cert::sign BN_bn2bin(r, sign_r)", 1);
            ret = 0;
            /*FIXME, try to avoid it */
            goto done;
        }

        // std::cout << " BN_num_bytes(s) " << BN_num_bytes(s) << std::endl;

        if(BN_bn2bin(s, sign_s) != sizeof(HashedData32))
        {
            LOG_ERR("cert::sign BN_bn2bin(r, sign_r)", 1);
            ret = 0;
            /*FIXME, try to avoid it */
            goto done;
        }
        done:
            /* do cleanup during error */
            if(sig)
                ECDSA_SIG_free(sig);
            sig = nullptr;
        log_ << " Ieee1609Cert::_sign() exit " << std::endl;
        log_dbg(log_.str(), MODULE);
        log_.str("");

        return ret;
    }

    int Ieee1609Cert::decode(std::string certdir, std::vector<SHARED_CERT>& certs)
    {
        std::stringstream log_(std::ios_base::out);
        int ret = 0;
        /* these are binary files */
        /* read the key */
        uint8_t *keyBuf_ = nullptr;
        size_t keyBufLen_ = 0;
        uint8_t *certBuf_ = nullptr;
        size_t certBufLen_ = 0;
        dirent *dent;
        std::string file_;
        size_t offset_;
        SHARED_CERT cert_ = nullptr;

        log_ << "Ieee1609Cert::decode " << certdir << " enter " << std::endl;
        log_info(log_.str(), MODULE);
        DIR *dir = opendir(certdir.c_str());
        if(dir == nullptr)
        {
            log_ << "Ieee1609Cert::decode error opendir " << certdir << std::endl;
            LOG_ERR(log_.str(), MODULE);
            return 0;
        }

        while((dent = readdir(dir)) != nullptr)
        {

            if(dent->d_name[0] == '.') continue;
            certBuf_ = nullptr;
            certBufLen_ = 0;
            keyBuf_ = nullptr;
            keyBufLen_= 0;
            if(strstr(dent->d_name, KEY_FILE_EXT) != nullptr) continue;

            if(strstr(dent->d_name, CERT_FILE_EXT) != nullptr)
            {
                file_ = certdir;
                file_.append("/");
                file_.append(dent->d_name);
                /* a cert has to have an associated key */
                file_read(file_.c_str(), &certBuf_, &certBufLen_);

                /* find the offset of the file extention in the certfile */
                /* find the first occurrence of extention marker*/

                offset_ = file_.find(std::string(CERT_FILE_EXT), 0);
                if(offset_ != std::string::npos)
                {
                    file_.erase(file_.begin()+offset_, file_.end());
                    /* append the .key extention to read the key */
                    /* for key, itsnamed as <certid>.key, where <certid> is filename without the extention*/
                    file_.append(KEY_FILE_EXT);
                    file_read(file_.c_str(), &keyBuf_, &keyBufLen_);
                }
            }

            log_.str("");
            /* files are not found, return with error */
            if(certBuf_ == nullptr ||
                keyBuf_ == nullptr)
            {
                log_ << "Ieee1609Cert::decode invalid or missing files " << std::endl;
                LOG_ERR(log_.str(), MODULE);
                if(certBuf_) free(certBuf_);
                if(keyBuf_) free(keyBuf_);
                continue;
            }
            cert_ = std::make_shared<Ieee1609Cert>();
            try
            {
                ret = cert_->decode(certBuf_, certBufLen_);
            }catch(ctp::Exception& e)
            {
                ret = 0;
            }
            if(ret)
            {
                ret = cert_->private_key_set(keyBuf_, keyBufLen_);
            }
            /* if all good so far ???*/
            if(ret >= 1)
            {
                /* set the encoded buffer*/
                // encodedBufLen = certBufLen_;
                // encodedBuf = (uint8_t *)buf_alloc(encodedBufLen);
                // memcpy(encodedBuf, certBuf_, encodedBufLen);
                certs.push_back(cert_);
            }
            if(certBuf_)
                free(certBuf_);
            if(keyBuf_)
                free(keyBuf_);
            continue;
        }
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
        int ret = 1;
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
            log_ << "base cert type " << (int)base->certType << std::endl;
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
            ret = 0;
        }
        return ret;
    }

    int Ieee1609Cert::encode(std::shared_ptr<Ieee1609Encode> ptr)
    {
		int ret = 1;
		std::stringstream log_(std::ios_base::out);
		log_ << "Ieee1609Cert::encode enter " << std::endl;
		log_info(log_.str(), MODULE);
        /* clear any buffer held by the previous encoder */
        std::shared_ptr<Ieee1609Encode> temp = pEncObj;
        /* acquire the new encoding object*/
        pEncObj = ptr->getPtr();
        /* encode the certificate base */
		try
		{
			pEncObj->OctetsFixed(&base->options, 1);
			pEncObj->OctetsFixed(&base->version, 1);
			pEncObj->OctetsFixed((uint8_t *)&base->certType, 1);
			pEncObj->IssuerIdentifier_(std::ref(*issuer));
			/* continuous encoding */
			EncodeToBeSigned(true);
			/* only encode the signature if it is of type explicit */
            if(base->certType == CertTypeExplicit &&  signature != nullptr)
            {
                pEncObj->Signature_(std::ref(*signature));
            }
		}catch (ctp::Exception& e)
		{
			ret = 0;
			log_ << "Ieee1609Cert::encode " << e.what() << std::endl;
			LOG_ERR(log_.str(), MODULE);
		}
        /* restore the encoder back */
        pEncObj = temp;
        return ret;
    }

    /* dont free the returned buffer */
    size_t Ieee1609Cert::encode(uint8_t **buf)
    {
        int ret = 0;
		std::string log_("Ieee1609Cert::encode");
		try
		{
            /* clear whatever was there */
            if(encodedBuf == nullptr)
            {
                pEncObj->clear();
                ret = encode(pEncObj);
                if(ret >= 0)
                {
                    encodedBufLen = pEncObj->get(&encodedBuf);
                }
            }
		}catch(ctp::Exception& e)
		{
			log_.append(e.what());
			log_.append("\n");
			LOG_ERR(log_, MODULE);
			encodedBufLen = 0;
		}catch(std::exception& e)
		{
			log_.append(e.what());
			log_.append("\n");
			LOG_ERR(log_, MODULE);
			encodedBufLen = 0;
		}

		if(encodedBufLen == 0 &&
		   encodedBuf == nullptr)
		{
			buf_free(encodedBuf);
			encodedBuf = nullptr;
		}

		if(encodedBufLen)
		{
			*buf = (uint8_t *)buf_alloc(encodedBufLen);
			memcpy(*buf, encodedBuf, encodedBufLen);
		}

		/* no need to allocate a seperate buffer, these calls are supposed to be part of trusted platform only */
		// *buf = encodedBuf;
        return encodedBufLen;
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
        return 1;
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
            throw;
        }
        return 1;
    }

    // /* encode the toBeSigned field of the explicit certicate*/
    // int Ieee1609Cert::EncodeCertBase(bool cont)
    // {
    //     int ret = 1;
    //     /* reset the encoded buffer and length */
    //     if(cont == false)
    //         pEncObj->clear();
    //     try
    //     {
    //         pEncObj->OctetsFixed(&base->options, 1);
    //         pEncObj->OctetsFixed(&base->version, 1);
    //         pEncObj->OctetsFixed((uint8_t *)&base->certType, 1);
    //         pEncObj->IssuerIdentifier_(std::ref(*issuer));
    //         /* continuous encoding */
    //         EncodeToBeSigned(true);
    //     }
    //     catch (std::logic_error& e)
    //     {
    //         ret = 0;
    //         std::cout << e.what() << '\n';
    //     }
    //     catch(const std::exception& e)
    //     {
    //         ret = 0;
    //         std::cout << e.what() << '\n';
    //     }
    //     return ret;
    // }

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
        // size_t len;
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

    /* set the private key, this is only called after successfully decoding the certificate body */
    int Ieee1609Cert::private_key_set(const uint8_t *keyBuf, size_t keyBufLen)
    {
        std::stringstream log_(std::ios_base::out);
        int nid = -1;
        log_ << "Ieee1609Cert::private_key_set(...) enter " << std::endl;
        log_info(log_.str(), MODULE);

        switch(signature->type)
        {
            case ecdsaNistP256Signature:
                nid = NID_X9_62_prime256v1;
                break;
            case ecdsaBrainpoolP256r1Signature:
                nid = NID_brainpoolP256r1;
            default:
                log_ << "Ieee1609Cert::private_key_set(...) invalid signature-type  " << signature->type << std::endl;
                LOG_ERR(log_.str(), MODULE);
        }

        if( nid == -1)
        {
            return 0;
        }

        log_.str("");

        ecGroup = EC_GROUP_new_by_curve_name(nid);
        EC_GROUP_set_point_conversion_form(ecGroup,POINT_CONVERSION_COMPRESSED);

        ecKey = EC_KEY_new_by_curve_name(nid);
        if (ecKey == nullptr)
        {
            log_ << "Ieee1609Cert::private_key_set::EC_KEY_new_by_curve_name(nid)" << std::endl;
            LOG_ERR(log_.str(), MODULE);
            return 0;
        }
        EC_KEY_set_conv_form(ecKey, POINT_CONVERSION_COMPRESSED);
        EC_KEY_set_group(ecKey, ecGroup);

        BIGNUM *bn = BN_new();
        bn = BN_bin2bn(keyBuf, keyBufLen, bn);
        if(bn == nullptr)
        {
            log_ << "Ieee1609Cert::private_key_set::BN_bin2bn" << std::endl;
            LOG_ERR(log_.str(), MODULE);
            BN_free(bn);
            return 0;
        }

        if(EC_KEY_set_private_key(ecKey, bn) == 0 )
        {
            log_ << "Ieee1609Cert::private_key_set::EC_KEY_oct2priv " << std::endl;
            LOG_ERR(log_.str(), MODULE);
            BN_free(bn);
            return 0;
        }
        log_ << "Ieee1609Cert::private_key_set(...) exit " << std::endl;
        log_info(log_.str(), MODULE);
        BN_free(bn);
        return 1;
    }

    /* gets the public key from the key object */
    int Ieee1609Cert::public_key_get(point_conversion_form_t conv)
    {
        size_t i = 0;
        uint8_t *keyBuf = nullptr;
        size_t keylen = 0;
        std::stringstream log_(std::ios_base::out);
        
        const EC_POINT *ecPoint = EC_KEY_get0_public_key(ecKey);

        /* get the x, y points from ecPoint */
        keylen = EC_POINT_point2oct(ecGroup, ecPoint, conv,nullptr,  keylen, nullptr);
        if(keylen == 0)
        {
            log_ << "cert::public_key_get()::EC_POINT_point2oct" << std::endl;
            LOG_ERR(log_.str(), MODULE);
            throw Exception(log_.str());
        }
        log_ << "public key length " << keylen << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");

        try
        {
            keyBuf = (uint8_t *)buf_alloc(keylen);
        }
        catch(const std::bad_alloc &e)
        {
            log_ << e.what() << std::endl;
            LOG_ERR(log_.str(), MODULE);
            throw Exception(log_.str());
        }

        /* get the x, y points from ecPoint */
        keylen = EC_POINT_point2oct(ecGroup, ecPoint, conv,keyBuf,  keylen, nullptr);
        if(keylen == 0)
        {
            log_ << "cert::public_key_get()::EC_POINT_point2oct" << std::endl;
            LOG_ERR(log_.str(), MODULE);
            buf_free(keyBuf);
            // perror("cert::public_key_get()::EC_POINT_point2oct");
            throw Exception(log_.str());
            return keylen;
        }
        EccP256CurvPoint *point = &vki->indicator.verificationKey.key.ecdsaNistP256;

        /* get the point type from the first byte of the key type */
        point->type = (EccP256CurvPointType)keyBuf[0];
        char *xPtr = point->point.uncompressedx.x;
        char *yPtr = point->point.uncompressedy.x;

        /* there will always be x-component, so lets copy that */
        for (i = 0; i < 32;i++)
        {
            // std::cout << std::hex << (int)keyBuf[i] << ":";
            // if(i%16 ==0)
            //     std::cout << std::endl;
            *xPtr++ = keyBuf[i+1];
        }
        /* copy whatever was there, remaining */
        for(; i < keylen;)
        {
            *yPtr++ = keyBuf[i+1];
            i++;
        }
        keyType = keyBuf[0];
        buf_free(keyBuf);
        return keylen;
    }

    int Ieee1609Cert::_create(const std::vector<int> psids, int nid)
    {
        std::stringstream log_(std::ios_base::out);
        log_ << "Ieee1609Cert::_create(int nid, const std::vector<int> psids) enter " << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        ecKey = EC_KEY_new_by_curve_name(nid);
        if (ecKey == nullptr)
        {
            log_ << "Ieee1609Cert::_create(...) " <<  "EC_KEY_new_by_curve_name(nid)" << std::endl;
            LOG_ERR(log_.str(), MODULE);
            return 0;
        }


        ecGroup = EC_GROUP_new_by_curve_name(nid);
        EC_GROUP_set_point_conversion_form(ecGroup,POINT_CONVERSION_COMPRESSED);

        if(EC_KEY_generate_key(ecKey) != 1)
        {
            EC_KEY_free(ecKey);
            log_ << "Ieee1609Cert::_create(...) " <<  "EC_KEY_generate_key" << std::endl;
            LOG_ERR(log_.str(), MODULE);
            return 0;
        }
        EC_KEY_set_group(ecKey, ecGroup);
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
        vki->indicator.verificationKey.type = PublicVerificationKeyTypEecdsaNistP256S;
        /* default is uncompressed */
        public_key_get();

        /* there is only item in this sequence */
        /* get the size of the psids array */
        seqOfPsidSsp->quantity = psids.size();
        /* psid psidssp only contains the psid , with no ssp */
        seqOfPsidSsp->psidSsp = (PsidSsp *)buf_alloc(seqOfPsidSsp->quantity * sizeof(PsidSsp));
        PsidSsp *psidSsp = seqOfPsidSsp->psidSsp;
        for(int i = 0; i < seqOfPsidSsp->quantity; i++)
        {
            /* No optional mask */
            psidSsp->optionalMask = 0;
            /* no ssp */
            psidSsp->ssp.length = 0;
            psidSsp->ssp.octets = nullptr;
            /* get the psid */
            psidSsp->psid = psids[i];
            /* move to the new psid ssp */
            psidSsp++;
        }
        log_.str("");
        log_ << "Ieee1609Cert::_create(int nid, const std::vector<int> psids) exit " << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        return 1;
    }


    int Ieee1609Cert::create(SHARED_CERT signer, int nid)
    {
        std::vector<int> psids{PSID_BSM};
        return create(psids,signer, nid);
    }

    int Ieee1609Cert::create(const std::vector<int> psids, SHARED_CERT signer, int nid)
    {
        int ret = 0;
        std::stringstream log_(std::ios_base::out);
        log_ << "Ieee1609Cert::create(int nid, const std::vector<int> psids) enter " << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");

        /* if this is a self signed certificate */
        if(signer.get() == this)
        {
            issuer->type = IssuerIdentifierTypeSelf;
        }else
        {
            issuer->type = IssuerIdentifierTypeHashId;
        }

        /* create the cert */
        ret = _create(psids, nid);
        if(ret == 1)
        {
            ret = sign(signer);
        }

        /* have the signature option */
        if(ret == 1 && base->certType == CertTypeExplicit)
            base->options = 0x80; /* there is no extentition and signature is always present */
        return ret;
    }

    /* the certs are created in the path, with folder name as the validity date.
       This is to be called after certificate has been successfully created, acquired
        and need to be stored for reuse.
    */
    int Ieee1609Cert::store(std::string path)
    {
        int ret = 1;
        std::stringstream log_(std::ios_base::out);
        /* checkk whether certificate is created or not ???*/
        if(base == nullptr)
        {
            ret = 0;
            return ret;
        }

        log_ << "Ieee1609Cert::store  " << path << " enter " << std::endl;
        log_info(log_.str(), MODULE);

        log_.str("");

        certPath = path;

        /* get the validity of the current certificate */
        unsigned long start = static_cast<unsigned long>(tbs->validityPeriod.start);
        std::string folder(path);
        /* check whether the path has forward slash */
        if(folder.back() != '/')
        {
            folder.append(1, '/');
        }
        /* append the start date at the end of the root path */
        folder.append(std::to_string(start));
        folder.append(1, '-');

        DurationType durationType = tbs->validityPeriod.duration.type;
        uint16_t duration = tbs->validityPeriod.duration.duration;

        size_t validity;

        /* even though the certs are issued weekly, but its ambiguous when the week starts,
           so we will track the validity by the hours 
        */
        if(durationType == DurationTypeMilliSeconds)
            validity = MILLSEC_TO_HOUR(duration);
        else if(durationType = DurationTypeSeconds)
            validity = SEC_TO_HOUR(duration);
        else if(durationType == DurationTypeMinutes)
            validity = MIN_TO_HOUR(duration);
        else if(durationType == DurationTypeSixtyHours)
            validity = SIXTYHOURS_TO_HOUR(duration);
        else if(durationType == DurationTypeYears)
            validity = YEAR_TO_HOUR(duration);
        else
            validity = duration;

        folder.append(std::to_string(validity));
        log_.str("");
        /* create the file path, only the folders */
        ret = file_path_create(folder);
        if(ret  ==  -1)
        {
            log_.str("");
            log_ << "Ieee1609Cert::store::file_path_create " << strerror(errno) << std::endl;
            LOG_ERR(log_.str(), MODULE);
            log_.str("");
            log_ << "Ieee1609Cert::store::file_path_create " << folder << std::endl;
            LOG_ERR(log_.str(), MODULE);
            return 0;
        }
        /* encode the certificate and store */
        uint8_t *buf_ = nullptr;
        size_t buflen_ = 0;
        std::string certfile = folder + "/cert" + CERT_FILE_EXT;
        std::string keyfile = folder + "/cert" +  KEY_FILE_EXT;
        try
        {
            buflen_ = encode(&buf_);
            if(buflen_ == 0)
            {
                log_.str("");
                log_ << "Ieee1609Cert::store::enoce " << std::endl;
                LOG_ERR(log_.str(), MODULE);
                return 0;
            }
            ret = file_write(certfile.c_str(), buf_, buflen_);
            buf_ = nullptr;
            /* check the file_Write status */
            if(ret == -1){
                log_ << "Ieee1609Cert::store::file_write " << certfile << " " << strerror(errno) << std::endl;
                return 0;
            }
            buflen_= EC_KEY_priv2oct(ecKey, buf_, buflen_);
            if(buflen_ == 0)
            {
                log_ << "Ieee1609Cert::store::EC_KEY_priv2oct fails " << std::endl;
                /* error computing the key buffer */
                /* delete the cert file */
                unlink(certfile.c_str());
                LOG_ERR(log_.str(), MODULE);
                return 0;
            }

            buf_ = (uint8_t *)buf_alloc(buflen_);
            if(buf_ ==  nullptr)
            {
                log_ << "Ieee1609Cert::store::EC_KEY_priv2oct::buf_alloc(...) fails " << std::endl;
                LOG_ERR(log_.str(), MODULE);
                unlink(certfile.c_str());
                return 0;
            }

            buflen_= EC_KEY_priv2oct(ecKey, buf_, buflen_);
            if(buflen_ == 0)
            {
                log_ << "Ieee1609Cert::store::EC_KEY_priv2oct fails " << std::endl;
                /* error computing the key buffer */
                /* delete the cert file */
                unlink(certfile.c_str());
                LOG_ERR(log_.str(), MODULE);
                buf_free(buf_);
                return 0;
            }

            ret = file_write(keyfile.c_str(), buf_, buflen_);
            buf_free(buf_);
            buf_ = nullptr;

            if(ret == -1){
                log_.str("");
                log_ << "Ieee1609Cert::store::file_write " << keyfile << " " << strerror(errno) << std::endl;
                LOG_ERR(log_.str(), MODULE);
                return 0;
            }
        }catch(ctp::Exception& e)
        {
            log_.str("");
            log_ << "Ieee1609Cert::store " << e.what() << std::endl;
            LOG_ERR(log_.str(), MODULE);
            unlink(certfile.c_str());
            unlink(keyfile.c_str());
            return 0;
        }
        log_ << "Ieee1609Cert::store  exit " << std::endl;
        log_info(log_.str(), MODULE);
        return ret;
    }


    Ieee1609Certs::Ieee1609Certs()
    {
        quantity = 0; 
        enc = SHARED_ENC(new Ieee1609Encode(), [this](const PTR_ENC p){log_dbg("Ieee1609Certs::Ieee1609Certs() delete enc\n", MODULE); delete p;});
        dec = SHARED_DEC(new Ieee1609Decode, [this](const PTR_DEC p){log_dbg("Ieee1609Certs::Ieee1609Certs() delete dec\n", MODULE);delete p;});
        certs.clear();
    }

    // void Ieee1609Certs::create(int nid)
    // {
    //     SHARED_CERT cert = nullptr;
    //     std::stringstream log_(std::ios_base::out);
    //     log_ << " Ieee1609Certs::create( " << std::dec << nid ;
    //     try
    //     {
    //         cert = SHARED_CERT(new Ieee1609Cert(), [this](const PTR_CERT p){log_dbg("Ieee1609Certs::Ieee1609Certs() delete cert\n", MODULE);delete p;});
    //         cert->create(nid);
    //         quantity++;
    //         certs.push_back(cert);
    //     }catch(ctp::Exception& e)
    //     {
    //         log_ << e.what() << std::endl;
    //         LOG_ERR(log_.str(), MODULE);
    //         cert.reset();
    //         certs.clear();
    //         throw;
    //     }
    // }


    // void Ieee1609Certs::create(std::vector<int> psids)
    // {
    //     create(NID_X9_62_prime256v1, psids);
    // }


    // void Ieee1609Certs::create(int nid, std::vector<int> psids)
    // {
    //     SHARED_CERT cert = nullptr;
    //     std::stringstream log_(std::ios_base::out);
    //     log_ << "Ieee1609Certs::create(int nid, std::vector<int> psids) enter" << std::endl;
    //     log_info(log_.str(), MODULE);
    //     log_.str("");

    //     try
    //     {
    //         /* clear any existing certs here */
    //         certs.clear();
    //         cert = SHARED_CERT(new Ieee1609Cert(), [this](const PTR_CERT p){log_dbg("Ieee1609Certs::Ieee1609Certs() delete cert\n", MODULE);delete p;});
    //         cert->create(psids, nullptr, nid);
    //         quantity++;
    //         certs.emplace_back(cert);
    //     }catch( std::exception& e){
    //         log_ << "Ieee1609Certs::create(int nid, std::vector<int> psids) " << e.what() << std::endl;
    //         LOG_ERR(log_.str(), MODULE);
    //         throw;
    //     }
    //     log_ << "Ieee1609Certs::create(int nid, std::vector<int> psids) exit" << std::endl;
    //     log_info(log_.str(), MODULE);
    //     log_.str("");
    // }


    /* encoded file */
    Ieee1609Certs::Ieee1609Certs(std::string& file)
    {
        std::stringstream log_(std::ios_base::out);
        log_ << "Ieee1609Certs::Ieee1609Certs(std::string& file) enter" << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");

        /* default */
        quantity = 0;
        // cert = SHARED_CERT(new Ieee1609Cert(), [](const PTR_CERT p){delete p;});
        enc = SHARED_ENC(new Ieee1609Encode(), [](const PTR_ENC p){ delete p;});
        dec = SHARED_DEC(new Ieee1609Decode, [](const PTR_DEC p){delete p;});

        log_ << "Ieee1609Certs::Ieee1609Certs(std::string& file) exit " << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
    }
    /* encoded buffer */
    Ieee1609Certs::Ieee1609Certs(const uint8_t *buffer)
    {
        std::stringstream log_(std::ios_base::out);
        log_ << "Ieee1609Certs::Ieee1609Certs(const uint8_t *buffer) enter" << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");

        quantity = 0;
        enc = SHARED_ENC(new Ieee1609Encode(), [](const PTR_ENC p){ delete p;});
        dec = SHARED_DEC(new Ieee1609Decode, [](const PTR_DEC p){delete p;});

        log_ << "Ieee1609Certs::Ieee1609Certs(const uint8_t *buffer) exit" << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
    }
    Ieee1609Certs::~Ieee1609Certs()
    {
        std::cout << "Ieee1609Certs::~Ieee1609Certs()" << std::endl;
        enc = nullptr;
        dec = nullptr;
        certs.clear();
    }

    const Ieee1609Cert* Ieee1609Certs::get() const
    {
        return certs[0].get();
    }

    /* encoded message of the signer, 
        used to create a Signature of the data packet 
    */
    int Ieee1609Certs::encode_signer(uint8_t **buf)
    {
        /* just take the first certificate */
        return certs[0]->encode(buf);
    }

    int Ieee1609Certs::encode(uint8_t **buf){

        size_t len = 0;
        try{
            /* encode the sequence of certs */
            enc->clear();
            /* only 1 byte is needed to encode the number seuqnce */
            enc->SequenceOf(quantity);
            /* get all the certificates in this chain */
            for(auto cert:certs)
            {
                cert->encode(enc);
            }
            len = enc->get(buf);
        }catch(Exception& e)
        {
            LOG_ERR(e.what(), MODULE);
            len = 0;

        }
        return len;
    }

    /* decode the buffer */
    int Ieee1609Certs::decode(const uint8_t *buf, size_t len)
    {
        int ret = 1;
        try
        {
            dec->clear();
            dec->set(buf, len);
            dec->SequenceOf((uint8_t*)&quantity, 4);
            for(int i= 0; i < quantity; i++)
            {
                SHARED_CERT cert = SHARED_CERT(new Ieee1609Cert(), [](const PTR_CERT p){delete p;});
                /* decode the certificate with the given decoder */
                cert->decode(dec);
                certs.push_back(cert);
            }
        }catch(Exception& e)
        {
            LOG_ERR(e.what(), MODULE);
            ret = 0;

        }
        return ret;
    }
    int Ieee1609Certs::decode (std::shared_ptr<Ieee1609Decode> ptr)
    {
        SHARED_DEC temp = dec->GetPtr();
        /* clear the exisiting pointer */
        dec.reset();
        dec = ptr->GetPtr();
        try
        {
            // dec->SignerIdentifier_(std::ref(signerIdentifier));
            /* maximmum 4 bytes */
            dec->SequenceOf((uint8_t *)&quantity, 4);
            for(int i =0; i < quantity; i++)
            {
                SHARED_CERT cert = SHARED_CERT(new Ieee1609Cert(), [](const PTR_CERT p){delete p;});
                /* decode the certificate with the given decoder */
                cert->decode(dec);
                certs.push_back(cert);
            }

        }catch(Exception& e)
        {
            std::cout << "Exception " << e.what() << std::endl;

        }
        dec = temp;
        temp = nullptr;
        return 0;                

    }

    int Ieee1609Certs::Hash256(const uint8_t* tbHash, size_t len, uint8_t **hash)
    {
        return certs[0]->Hash256(tbHash, len, hash);
    }

    int Ieee1609Certs::verify(const uint8_t *dgst, size_t dgst_len, const Signature& signature)
    {
        return certs[0]->verify(dgst, dgst_len, signature);
    }

    int Ieee1609Certs::verify(const uint8_t *dgst, size_t dgst_len)
    {
        return certs[0]->verify(dgst, dgst_len);
    }

    const ECDSA_SIG* Ieee1609Certs::SignData(const uint8_t *buf, size_t len, SignatureType type)
    {
        return certs[0]->SignData(buf, len, type);
    }
    int Ieee1609Certs::SigToSignature(const ECDSA_SIG* sig, Signature& signature)
    {
        return certs[0]->SigToSignature(sig, signature);
    }
    int Ieee1609Certs::ConsistencyCheck(const HeaderInfo& header)
    {
        return certs[0]->ConsistencyCheck(header);

    }

    void Ieee1609Certs::print()
    {
        uint8_t *buf = nullptr;
        size_t len = enc->get(&buf);
        print_data("certs.txt", buf, len);
    }
} //namespace ctp








