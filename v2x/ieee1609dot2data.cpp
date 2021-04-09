#include "ieee1609dot2data.hpp"
#include <stdlib.h>
#include <string.h>
#include <memory>
#include <iostream>
#include <string>
#include <fstream>
#include <iomanip>



//#define MOUDLE "1609DATA"
// #define MODULE 2

namespace ctp
{
    void Ieee1609Data::sign(int psid, const uint8_t *tbsData, size_t len,
                  uint8_t **signedData, size_t *signedDataLen)
    {

        /* create the ToBeSignedData (6.3.6) data structure */
        this->tbsData->headerInfo.psid = psid; /* just use the psid only for now */
        SignedDataPayload *payload = &this->tbsData->payload;
        /* unsecured data */
        payload->data->content.type = Ieee1609Dot2ContentUnsecuredData;
        payload->data->protocolVersion = 0x03;
        payload->data->content.UNSECUREDDATA.length = len;
        payload->data->content.UNSECUREDDATA.octets = (uint8_t *)buf_alloc(len);
        /* copy the data into unsecured buffer */
        for(int i = 0; i < len; i++)
        {
            payload->data->content.UNSECUREDDATA.octets[i] = tbsData[i];
        }

        /* the complete flow is something like this */
        // /* get the cert for this psid */
        cert = certMgrPtr->operator[](psid);
        if (cert != nullptr)
        {
            /* sign the data */
            sig = cert->SignData(tbsData, len, ecdsaNistP256Signature);
        }
        encode();
        *signedDataLen = enc->get(signedData);
    }


    void Ieee1609Data::sign(int psid, const uint8_t *buf, size_t len,
                  uint8_t **signedData, size_t *signedDataLen,
                  Ieee1609Certs *certs)
    {
        int ret = 0;
        /* for signing, get the encoded certiificate */
        uint8_t *hashBuf = nullptr;
        size_t hashBufLen = 0;;
        uint8_t *hash = nullptr;
        uint8_t *tbsBuf = nullptr;
        size_t tbsLen = 0;

        LOG_INFO("Ieee1609Data::sign", MODULE);
        /* create the ToBeSignedData (6.3.6) data structure */
        //tbsData = (ToBeSignedData *) buf_realloc(tbsData, sizeof(ToBeSignedData));
        data->content.type = Ieee1609Dot2ContentSignedData;
        tbsData->headerInfo.psid = psid; /* just use the psid only for now */
        SignedDataPayload *payload = &tbsData->payload;
        /* unsecured data */
        payload->data->content.type = Ieee1609Dot2ContentUnsecuredData;
        payload->data->protocolVersion = 0x03;
        payload->data->content.UNSECUREDDATA.length = len;
        payload->data->content.UNSECUREDDATA.octets = (uint8_t *)buf_alloc(len);
        /* create a local copy of the certificate */
        this->certs = certs;
        /* copy the data into unsecured buffer */
        for(int i = 0; i < len; i++)
        {
            payload->data->content.UNSECUREDDATA.octets[i] = buf[i];
        }
        if (certs != nullptr)
        {
            tbsLen = 0;

           /* get the hash the data */
            ret = certs->Hash256(buf, len, &hash);
            /* failure to calculate the hash */
            if(ret == 0)
            {
                LOG_ERR("Ieee1609Data::sign::cert->Hash256 tbsData::hash", MODULE);
                goto done;
            }

            tbsLen += SHA256_DIGEST_LENGTH;
            tbsBuf = nullptr;
            tbsBuf = (uint8_t *)buf_realloc(tbsBuf, tbsLen);
            memcpy(tbsBuf,hash,tbsLen);
            free(hash);
            hash = nullptr;

            /* get the encoded buffer of the signer */
            hashBufLen = certs->encode_signer(&hashBuf);
            /* get the hash of the  certificate buffer */
            ret = certs->Hash256(hashBuf, hashBufLen, &hash);
            /* failure to calculate the hash */
            if(ret == 0)
            {
                LOG_ERR("Ieee1609Data::sign::cert->Hash256 cert::hash", MODULE);
                goto done;
            }

            tbsLen += SHA256_DIGEST_LENGTH;
            tbsBuf = (uint8_t *)buf_realloc(tbsBuf, tbsLen);
            /*hash(tbsData) || hash(signer)*/
            memcpy(&tbsBuf[SHA256_DIGEST_LENGTH], hash, SHA256_DIGEST_LENGTH);
            free(hash);
            hash = nullptr;
            /* calculate the hash of hash(tbsData) || hash(signer) */
            ret = certs->Hash256(tbsBuf, tbsLen, &hash);
            /* failure to calculate the hash */
            if(ret == 0)
            {
                LOG_ERR("Ieee1609Data::sign::cert->Hash256 cert::hash", MODULE);
                goto done;
            }
            /* sign the data */
            sig = certs->SignData(hash, SHA256_DIGEST_LENGTH,ecdsaNistP256Signature);
            if(signature == nullptr)
            signature = (Signature *)buf_alloc(sizeof(Signature));
            /* get the signature from sig */
            certs->SigToSignature(sig, std::ref(*signature));
        }
        encode();
        /* get the encoded buffer */
        *signedDataLen = enc->get(signedData);
        done:
            if(hash)
                free (hash);
            if(tbsBuf)
                free(tbsBuf);
        LOG_INFO("Ieee1609Data::sign Exit", MODULE);
    }


    /* encode tobesigned data */
    int Ieee1609Data::encode_tbsdata(bool cont)
    {
        if(cont == false)
            enc->clear();
        return enc->ToBesignedData_(std::ref(*tbsData));
    }
    /* we are always signing with a  cert */
    int Ieee1609Data::encode_signeridentifier(bool cont)
    {
        /* if only signer identifier need to be encoded */
        if (cont == false)
            enc->clear();
        return enc->SignerIdentifier_(std::ref(*certs), SignerIdentifierTypeCert);
    }

    int Ieee1609Data::encode_signature(bool cont)
    {
        if(cont == false)
            enc->clear();
        return enc->Signature_(std::ref(*signature));
    }


    /*encode signed data */
    int Ieee1609Data::encode_signeddata(bool cont)
    {
        if (cont == false)
            enc->clear();
        enc->HashAlgo(HashAlgorithmTypeSha256);
        enc->ToBesignedData_(std::ref(*tbsData));
        /* encode the signer */
        encode_signeridentifier(true);
        encode_signature();
        return 0;
    }


    void Ieee1609Data::encode_content(bool cont)
    {
        if(cont == false)
            enc->clear();
        /* encode signed data content type */
        enc->ContentType_(data->content.type);
        switch(data->content.type)
        {
            case Ieee1609Dot2ContentSignedData:
                encode_signeddata(true);
                break;
            default:
                LOG_ERR("content type not supported ", MODULE);
                break;
        }
    }


    int Ieee1609Data::encode(uint8_t **buf)
    {
        /* encode and return the length and buffer */
        encode();
        return enc->get(buf);
    }

    void Ieee1609Data::encode()
    {
        /* clear everything */
        enc->clear();
        enc->OctetsFixed(&data->protocolVersion, 1);
        encode_content();
        // enc->HashAlgo(HashAlgorithmTypeSha256);
        // enc->ToBesignedData_(std::ref(*tbsData));
        // /* since signer is the certificate, we need to pass the object to the certificate */
        // enc->SignerIdentifier_(std::ref(*cert), SignerIdentifierTypeCert); 
        // enc->Signature_(signature);
    }

    void Ieee1609Data::print_encoded(const char *file)
    {
        enc->clear();
        encode();
        uint8_t *_buf=nullptr;
        size_t _buflen = 0;
        _buflen = enc->get(&_buf);
        print_data(file, _buf, _buflen);
        return;
    }

    void Ieee1609Data::print_decoded(const char* file)
    {
        //std::ofstream os(file, std::ios::out| std::ios::binary);
        std::ostream os(std::cout.rdbuf());
        //os.rdbuf(std::cout.rdbuf());
        // std::ofstream os(std::cout);
        // using os = std::cout;
        //typedef std::cout os;
        os << " Protocol version: " << std::hex << data->protocolVersion << std::endl;
        // std::cout << " Protocol version: " << std::hex << data->protocolVersion << std::endl;
        os << "content " << std::setw(100) << std::endl;
        os << std::setw(50) << " Content choice " << data->content.type << std::endl;
        if(data->content.type == Ieee1609Dot2ContentSignedData)
        {
            os << " signed data " << std::endl;
            os << " hash algo " << data->content.content.signedData.hashAlgorithm << std::endl;
            os << "payload option " << tbsData->payload.mask << std::endl;
            if(tbsData->payload.mask == SDP_OPTION_DATA_MASK)
            {
                os << std::setw(50) << "signed data payload " << std::endl; 
                Ieee1609Dot2Data *data_ = tbsData->payload.data;
                os << "protocol version " << data_->protocolVersion << std::endl;
                os << "content choice " << data_->content.type << std::endl;
                if(data_->content.type == Ieee1609Dot2ContentUnsecuredData)
                {
                    os << " unsecured data " << std::endl;
                    os << "data length " << data_->content.content.unsecuredData.length << std::endl;
                    for (int i = 0; i < data_->content.content.unsecuredData.length; i++)
                    {
                        os << data_->content.content.unsecuredData.octets[i] << ":";
                        if (i != 0 && i %16==0)
                            os << std::endl;
                    }
                }

                os << "Header info " << std::endl;
                os << " psid  " << tbsData->headerInfo.psid << std::endl;
            }
        }
        // os.close();
        return;
    }



    /* decode the data */
    int Ieee1609Data::decode(const uint8_t * buf, size_t len)
    {
        dec->clear();
        dec->set(buf, len);
        decode_content();
        return 0;
    }

    int Ieee1609Data::decode_content()
    {
        int ret = 0;
        try
        {
            dec->Ieee1609Dot2Data_(std::ref(*data));
            decode_signeridentifier();
            if(signer.type == SignerIdentifierTypeCert)
            {
                /* decode the sequence of certs */
                certs->decode(dec);
            }
        }
        catch(const Exception& e)
        {
            std::cerr << e.what() << '\n';
        }
        
        return 0;
    }
    int Ieee1609Data::decode_signeridentifier()
    {
        dec->SignerIdentifier_(std::ref(signer));
        /* just copy the hashedid of the signer */
        /* we will find if we have this certificate or not */
        if(signer.type == SignerIdentifierTypeDigest)
        {
            dec->OctetsFixed((uint8_t *)signer.digest.x, sizeof(signer.digest));
        }
        return 0;
    }
    int Ieee1609Data::decode_tbsdata()
    {
        dec->ToBesignedData_(std::ref(data->content.content.signedData.toBeSignedData));
        return 0;
    }
    int Ieee1609Data::decode_signeddata()
    {
        //dec->SignedDataPayload_()
        return 0;
    }
    int Ieee1609Data::decode_signature()
    {
        return 0;
    }

























}//namespace ctp 
