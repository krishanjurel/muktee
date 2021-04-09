#ifndef __IEEE_1609DOT2CERT_HPP__
#define __IEEE_1609DOT2CERT_HPP__
#include <iostream>
#include "ieee1609dot2common.hpp"
#include "ieee1609dot2.hpp"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"
#include <openssl/bn.h>
#include <map>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <string>

#define MODULE 4

void print_data(const char* file, const uint8_t *buf, size_t len);

namespace ctp
{
    class Ieee1609Encode; /* forward declaration of encode class */
    class Ieee1609Decode;
    class Ieee1609Certs;


    /* cert class */
    class Ieee1609Cert
    {
        // std::vector<CertificateBase *> certs;
        // std::map<int, ctp::Ieee1609Cert*> certsPsidMap;
        // std::map<std::string, ctp::Ieee1609Cert*> certsHashIdMap;


        /*next pointer*/
        Ieee1609Cert *next;

        /* encode/decode objects*/
        std::shared_ptr<Ieee1609Encode> pEncObj;
        std::shared_ptr<Ieee1609Decode> pDecObj;

        const EC_GROUP *ecGroup;
        EC_KEY *ecKey;
        uint8_t keyType;

        CertificateBase *base;
        IssuerIdentifier *issuer;
        ToBeSignedCertificate *tbs;
        VerificationKeyIndicator *vki;
        Signature *signature;
        SequenceOfPsidSsp *psidSsp;
        //SequenceOfCertificate *seqOfCert;
        /* hash id 8 of this certificate */
        HashedId8 hashid8;
        int public_key_get(point_conversion_form_t conv = POINT_CONVERSION_COMPRESSED);
        int private_key_get();
        int _sign(const uint8_t *buf, size_t len, SignatureType type);
        /* encode the certificate */

        int EncodeCertBase(bool cont = true); /* encode certificate base */
        int sign(); /* sign the certificate, this is valid only for self-signed */
        int sign(const uint8_t *buf, size_t len, SignatureType type=ecdsaNistP256Signature);
        const Signature *signEx(const uint8_t *buf, size_t len, SignatureType type = ecdsaNistP256Signature);

        public:

            void create(int nid = NID_X9_62_prime256v1);

            //void encode();
            //void decode();

            explicit Ieee1609Cert();
            /* no copy constructure */
            Ieee1609Cert(const Ieee1609Cert&) = delete;
            /* no copy assignment */
            const Ieee1609Cert& operator=(const Ieee1609Cert&) = delete;
            /* no move constructor */
            Ieee1609Cert(const Ieee1609Cert&&) = delete;
            ~Ieee1609Cert(){};
            /* returns the certificate for the given psid */
            Ieee1609Cert* operator[](int psid);
            //int sign (SignatureType type = ecdsaNistP256Signature);
             const ECDSA_SIG* SignData(const uint8_t *buf, size_t len, SignatureType type);
             int SigToSignature(const ECDSA_SIG* sig, Signature& signature);
             /* and then the hashed data */
             int Hash256(const uint8_t* tbHash, size_t len, uint8_t **hash);

            /* \fn encode(uint8_t **buf)
                    encodes the certificate.

                    returns 0: error, else
                            length of the encoded buffer 
            */
           /* cert encoder */
            int encode(uint8_t **buf);
            int encode(const uint8_t* buf, size_t len) = delete;
            int encode(std::shared_ptr<Ieee1609Encode> enc);
            /* encode to be signed data of the certificate */
            int EncodeToBeSigned(bool cont=true);

            /* cert decoder */
            int decode(const uint8_t* buf, size_t len);
            int decode(std::shared_ptr<Ieee1609Decode> ptr);
            int DecodeToBeSigned(bool cont = true); /* decode to be sined */
            
            void set(Ieee1609Cert *cert)
            {
                this->next = cert;
            }
            const SequenceOfPsidSsp& psid_get() const;

            /* print to stdout or store in a file */
            int print_encoded(const std::string filename);
            int print_decoded(const std::string filename);


    };

    class Ieee1609Encode:public std::enable_shared_from_this<Ieee1609Encode>
    {
        uint8_t *encBuf; /*encoded buffer */
        size_t encLen;   /* encoded length */

        using sharedPtr = std::shared_ptr<Ieee1609Encode>;

        public:
            sharedPtr getPtr()
            {
                return shared_from_this();
            }
            Ieee1609Encode():encBuf(nullptr),encLen(0){};
            ~Ieee1609Encode()
            {
                std::cout << " encode destructor " << std::endl;
                delete encBuf;
                encBuf = nullptr;
                encLen = 0;
            }
            // /*FIXME, define a lenght enocding function */
            // int Length(const uint8_t *length, int len);
            // {
            //     uint8_t numBytes = len/128;
            //     if(numBytes)
            //     {
            //         numBytes += 1;
            //         numByets = ASN1_LENGTH_ENCODING_MASK
            //     }
            // }
            /* encode fixed length octets, i.e, no need for length encoding */
            int OctetsFixed(const uint8_t *octets, size_t len);
            /* encode psid */
            int psid_(int psid, int bytes = 1);
            /* encode octets */
            int Octets_(const uint8_t* octets, size_t len);
            /* encode certificate identifier */
            int CertId(const CertificateId& id);
            /* encode crl series */
            int CrlSeries(const uint16_t series);
            /* encode hashid3 */
            int HashId3(const uint8_t* hash, size_t len);
            /* encode the signature */
            int Sign(const Signature& signature);
            /* encode validity period */
            int VP(const ValidityPeriod& validityPeriod);
            /* encode verfication key indicator */
            int Vki(const VerificationKeyIndicator& vki);
            int SequenceOfPsid_(const SequenceOfPsidSsp& psids);
            int IssuerIdentifier_(const IssuerIdentifier& issuer);
            int Length(size_t bytes);
            int Length(const uint8_t *values, size_t bytes);


           /*encoding of signed data, 6.3.4 */
            int SignedDataPayload_(const Ieee1609Dot2Data& data);
            int HashAlgo(HashAlgorithmType type);
            int HeaderInfo_(const HeaderInfo& header);
            int ToBesignedData_(const ToBeSignedData& tbsData);
            int SignerIdentifier_(Ieee1609Cert& signer, SignerIdentifierType type);
            int SignerIdentifier_(Ieee1609Certs& signer, SignerIdentifierType type);
            int Signature_(const Signature& signature);
            int ContentType_(const Ieee1609Dot2ContentType type);
            // int SequenceOfCerts_(const SequenceOfCertificate& certs);
            /* int encoded buffer get */
            int get(uint8_t **buf);
            /* clear the encoded buuffer */
            int clear();
    };


    class Ieee1609Decode:public std::enable_shared_from_this<Ieee1609Decode>
    {
        uint8_t *buf; /*encoded buffer */
        size_t len;   /* encoded length */
        size_t offset; /* buffer offset */
        typedef std::shared_ptr<Ieee1609Decode> SharedPtr;
        public:

            SharedPtr GetPtr()
            {
                return shared_from_this();
            }

            Ieee1609Decode():buf(nullptr),len(0){};
            ~Ieee1609Decode()
            {
                std::cout << "Ieee1609Decode::~Ieee1609Decode" << std::endl;
                delete buf;
                len = 0;
            }
            /* decode fixed length octets, i.e, no need for length encoding */
            int OctetsFixed(uint8_t *octets, size_t len_)
            {
                std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
                std::ostream os(&log_);
                os << " Ieee1609Decode::OctetsFixed enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();
                if (len_+offset > this->len)
                {
                    os << " Ieee1609Decode::OctetsFixed not enough buffer " <<  len << " offset " << offset << std::endl;
                    LOG_ERR(log_.str(), MODULE);
                    os.clear();
                    return 0;
                }

                while(len_--)
                {
                    *octets++ = buf[offset++];
                }

                os << " Ieee1609Decode::OctetsFixed exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();
                return offset;
            }
            /* decode psid */
            int psid_(int *psid, int bytes = 1)
            {
                return 0;
            }
            /* encode octets */
            int Octets_(uint8_t* octets, size_t len)
            {
                return OctetsFixed(octets, len);
            }

            /* encode certificate identifier */
            // done
            // int CertId(CertificateId& id)
            // {
            //     return 0;
            // }
            /* encode crl series */
            // int CrlSeries(uint16_t *series);
            // {
            //     return 0;
            // }
            /* encode hashid3 */
            // int HashId3(uint8_t* hash, size_t len)
            // {
            //     return 0;
            // }
            /* encode the signature */
            int Sign(Signature& signature)
            {
                return 0;
            }
            /* encode validity period */
            int VP(ValidityPeriod& vp)
            {
                
                std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
                std::ostream os(&log_);
                os << " Ieee1609Decode::VP enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();

                /* read 4 bytes of uint32 in big endian format */
                uint8_t *buf_ = (uint8_t *)&vp.start;
                size_t len_ = 4;
                while(len_)
                {
                    len_ --;
                    buf_[len_] = buf[offset++];
                }
                std::cout << "VP start " << vp.start << std::endl;
                /* get the choice of duration */
                vp.duration.type = (DurationType)(buf[offset++] & ASN1_COER_CHOICE_MASK);
                std::cout << "duration type " << vp.duration.type << std::endl;
                /* read remaining two bytes of the duration */
                vp.duration.duration = (buf[offset++] << 8);
                vp.duration.duration |= (buf[offset++]);
                os << " Ieee1609Decode::VP exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();

                return 0;
            }
            /* encode verfication key indicator,6.4.35  */
            /* FIXME, break it into sub modules */
            int Vki(VerificationKeyIndicator& vki)
            {
                std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
                std::ostream os(&log_);
                os << " Ieee1609Decode::Vki enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();

                /* read the choice, 6.4.35 */
                vki.type = (VerificationKeyIndicatorType)(buf[offset++] & ASN1_COER_CHOICE_MASK);
                switch(vki.type)
                {
                    case VerificationKeyIndicatorTypeKey:
                        /* decode public verfiification key, 6.4.36 */
                        vki.indicator.verificationKey.type = (PublicVerificationKeyType)(buf[offset++] & ASN1_COER_CHOICE_MASK);
                        switch(vki.indicator.verificationKey.type)
                        {
                            case PublicVerificationKeyTypEecdsaNistP256S:
                            {
                                /* decode the curve point 6.3.23*/
                                EccP256CurvPoint *point = &vki.indicator.verificationKey.key.ecdsaNistP256;
                                /* get the choice type */
                                point->type = (EccP256CurvPointType)(buf[offset++] & ASN1_COER_CHOICE_MASK);
                                char *_buff = point->point.octets.x;
                                size_t _len = 0;
                                switch(point->type)
                                {
                                    case EccP256CurvPointTypeXOnly:
                                    case EccP256CurvPointTypeCompressedy0:
                                    case EccP256CurvPointTypeCompressedy1:
                                        _len = 32;
                                        break;
                                    case EccP256CurvPointTypeUncompressed:
                                        _len = 64;
                                        break;
                                    case EccP256CurvPointTypeFill:
                                        _len = 0;
                                        break;
                                    default:
                                        std::cout << "Ieee1609Decode::Vki:: point type not supported " << point->type << std::endl;
                                        throw Exception("Ieee1609Decode::Vki:: point type not supported ");

                                }
                                /* handle the available buffer size */
                                if(_len+offset > len)
                                {
                                    std::cout << "Ieee1609Decode::Vki:: point type not enough length " << _len << "offset " << offset << "total " << len << std::endl;
                                    throw Exception("Ieee1609Decode::Vki:: point type not enough length ");
                                }

                                while(_len--)
                                {
                                    *_buff++ = buf[offset++];
                                }
                            }
                            break;
                            default:
                                std::cout << "Ieee1609Decode::Vki:: verfication public key type not supported " << vki.indicator.verificationKey.type << std::endl;
                                throw Exception("Ieee1609Decode::Vki:: verfication public key type not supported ");
                        }
                    break;
                    default:
                        std::cout << "Ieee1609Decode::Vki:: verfication key type not supported " << vki.type << std::endl;
                        throw Exception("Ieee1609Decode::Vki:: verfication key type not supported ");
                }

                os << " Ieee1609Decode::Vki exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();

                return offset;
            }
            int SequenceOfPsid_(SequenceOfPsidSsp& psids)
            {
                std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
                std::ostream os(&log_);
                os << " Ieee1609Decode::SequenceOfPsid_ enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();

                /* get the number of items in the sequence */
                psids.quantity= 0;
                Length((uint8_t *)&psids.quantity, 4);
                psids.psidSsp = (PsidSsp*)buf_alloc(psids.quantity * sizeof(PsidSsp));
                for(int i = 0; i < psids.quantity; i++)
                {
                    PsidSsp *ssp = psids.psidSsp + i;
                    uint8_t *buf_ = (uint8_t *)&ssp->psid;
                    /* get the optinal map of the first ssp */
                    ssp->optionalMask = buf[offset++];
                    /* get the variable length bytes */
                    int intBytes = buf[offset++];
                    for(int j = intBytes; j > 0; j--)
                    {
                        buf_[j-1] = buf[offset++];
                    }
                    /*FIXME, throw away the data, not using for the time being */
                    if (ssp->optionalMask)
                    {
                        /* get the length of the bytes, assuming it is less than 127 */
                        int len_ = (int)buf[offset++];
                        
                        /* just increment the offset by length */
                        offset += len_;
                    }
                }
                os << " Ieee1609Decode::SequenceOfPsid_ exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();
                return offset;
            }
            int IssuerIdentifier_(IssuerIdentifier& issuer)
            {
                std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
                std::ostream os(&log_);
                os << " Ieee1609Decode::IssuerIdentifier_ enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();

                /* get the choice */
                int c = (int)buf[offset];
                std::cout << "the value at offset " << offset << " is " << std::hex << std::to_string(c) << std::endl;
                issuer.type = (IssuerIdentifierType)(buf[offset++] & ASN1_COER_CHOICE_MASK);



                switch(issuer.type)
                {
                    case IssuerIdentifierTypeHashId:
                    {
                        std::cout << "is this hash " << std::endl;
                        char *buf_ = issuer.issuer.hashId.x;
                        /* copy fixed size eight bytes */
                        for (int i = 0; i < 8; i++)
                        {
                            *buf_++ = buf[offset++];
                        }
                    }
                    break;
                    case IssuerIdentifierTypeSelf:
                        /* there is only one type of hash algo, so just skip it */
                        offset++;
                    break;
                    default:
                        os << "Ieee1609Decode::IssuerIdentifier_ unsuuported issuer type " << issuer.type;
                        LOG_ERR(log_.str(), MODULE);
                        throw new Exception(log_.str());
                }
                os << " Ieee1609Decode::IssuerIdentifier_ exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();

                return 0;
            }
            /* sequence of routines only encodes the number of components */
            int Length(uint8_t *value, size_t bytes)
            {
                uint8_t lengthEncoding=1;
                std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
                std::ostream os(&log_);
                os << " Ieee1609Decode::Length enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();

                /* read first byte of the integer encoding */
                lengthEncoding = buf[offset];
                if(buf[offset] & ASN1_LENGTH_ENCODING_MASK)
                {
                    /* number of bytes in the length */
                    lengthEncoding = buf[offset++] & ASN1_LENGTH_ENCODING_MASK;
                    if(lengthEncoding > bytes)
                    {
                        throw new Exception("the supplied buffer not long enough");
                    }
                }else{
                    /* only 1 bytes */
                    lengthEncoding = 1;
                }
                /* copy the bytes into the given buffer */
                while(lengthEncoding)
                {
                    lengthEncoding--;
                    value[lengthEncoding] = buf[offset++];
                }
                os << " Ieee1609Decode::Length exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();
                return offset;
            }

            int ContentType_(Ieee1609Dot2ContentType& type)
            {
                std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
                std::ostream os(&log_);
                os << " Ieee1609Decode::ContentType_ enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();
                type =  (Ieee1609Dot2ContentType)(buf[offset++] & ASN1_COER_CHOICE_MASK);

                os << " Ieee1609Decode::ContentType_ exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();
                return offset;
            }
            

            /* encode certificate identifier */
            int CertId(CertificateId& id);
            // /* encode crl series */
            int CrlSeries(uint16_t& series);
            // /* encode hashid3 */
            int HashId3(uint8_t* hash, size_t len);
            /* encode the signature */
            int Signature_(Signature& signature);
            /* decode signdata payload */
            int SignedDataPayload_(Ieee1609Dot2Data& data);
            /* to be signed data */
            int ToBesignedData_(ToBeSignedData& tbsData);
            /* two versions of decoding 1609Dot2data */
            int SignedData(Ieee1609Dot2Data& data);
            int Ieee1609Dot2Data_(Ieee1609Dot2Data& data);
            int SignedDataPayload1(SignedDataPayload& payload);
            int HeaderInfo_(HeaderInfo& header);
            int SignerIdentifier_(SignerIdentifier& signer);
            // /* encode validity period */
            // int ValidityPeriod(const validityPeriod& validityPeriod);
            // /* encode verfication key indicator */
            // int Vki(const VerificationKeyIndicator& vki);

            /* initialize the decoding engine buffers with the incoming data */
            void set(const uint8_t *buf, size_t len);
            void clear()
            {
                delete buf;
                buf = nullptr;
                len  = 0;
            }
    };



    /* sequence of certs */
    class Ieee1609Certs
    {
        int quantity;
        Ieee1609Cert *cert;
        std::shared_ptr<Ieee1609Encode> enc;
        std::shared_ptr<Ieee1609Decode> dec;
        SignerIdentifier signerIdentifier;

        public:
            /*constructor */
            /* self-signed signature */
            explicit Ieee1609Certs()
            {
                quantity = 0; 
                cert = new Ieee1609Cert();
                enc = std::shared_ptr<Ieee1609Encode>(new Ieee1609Encode(), [](Ieee1609Encode *p){ delete p;});
                dec = std::shared_ptr<Ieee1609Decode>(new Ieee1609Decode, [](Ieee1609Decode *p){delete p;});
            }

            void create(int nid = NID_X9_62_prime256v1)
            {
                try
                {
                    cert->create(nid);
                    quantity++;
                }catch( std::exception& e){
                    LOG_ERR("Ieee1609Certs::Ieee1609Certs()::create()", MODULE);
                    std::cout << " exception " << e.what() << std::endl;
                    delete cert;
                }
            }


            /* encoded file */
            explicit Ieee1609Certs(std::string& file)
            {
                /* default */
                quantity = 0;
                cert = new Ieee1609Cert();
            }
            /* encoded buffer */
            explicit Ieee1609Certs(const uint8_t *buffer)
            {
                quantity = 0;
                cert = new Ieee1609Cert();
            }
            ~Ieee1609Certs()
            {
                enc = nullptr;
                dec = nullptr;
                delete cert;
            }

            const Ieee1609Cert *get() const
            {
                return cert;
            }

            /* encoded message of the signer, 
                used to create a Signature of the data packet 
            */
            int encode_signer(uint8_t **buf)
            {
                return cert->encode(buf);
            }

            int encode(uint8_t **buf){

                size_t len = 0;
                try{
                    /* encode the sequence of certs */
                    enc->clear();
                    /* only 1 byte is needed to encode the number seuqnce */
                    enc->Length((uint8_t *)&quantity, 1);
                    cert->encode(enc);
                    len = enc->get(buf);
                }catch(Exception& e)
                {
                    LOG_ERR(e.what(), MODULE);
                    len = 0;

                }
                return len;
            }

            /* decode the buffer */
            int decode(const uint8_t *buf, size_t len)
            {
                int ret = 1;
                try
                {
                    dec->clear();
                    dec->set(buf, len);
                    dec->Length((uint8_t*)&quantity, 4);
                    /* decode the certificate with the given decoder */
                    cert->decode(dec);
                }catch(Exception& e)
                {
                    LOG_ERR(e.what(), MODULE);
                    ret = 0;

                }
                return ret;
            }
            int decode (std::shared_ptr<Ieee1609Decode> ptr)
            {
                /* clear the exisiting pointer */
                dec.reset();
                dec = ptr->GetPtr();
                try
                {
                    // dec->SignerIdentifier_(std::ref(signerIdentifier));
                    /* maximmum 4 bytes */
                    dec->Length((uint8_t *)&quantity, 4);
                    for(int i =0; i < quantity; i++)
                    {
                        Ieee1609Cert *pcert = new Ieee1609Cert();
                        /* passed the decode buffer to the cert */
                        pcert->decode(dec);
                    }

                }catch(Exception& e)
                {
                    std::cout << "Exception " << e.what() << std::endl;

                }
                return 0;                

            }

            int Hash256(const uint8_t* tbHash, size_t len, uint8_t **hash)
            {
                return cert->Hash256(tbHash, len, hash);
            }

            const ECDSA_SIG* SignData(const uint8_t *buf, size_t len, SignatureType type)
            {
                return cert->SignData(buf, len, type);
            }
            int SigToSignature(const ECDSA_SIG* sig, Signature& signature)
            {
                return cert->SigToSignature(sig, signature);
            }

            void print()
            {
                uint8_t *buf = nullptr;
                size_t len = enc->get(&buf);
                print_data("certs.txt", buf, len);
            }
    };


    /* certificate manager, contains the list of all the 
       certificates in the system
    */
    class CertMgr
    {
        std::map<int, Ieee1609Cert*> psidMap;
        std::map<HashedId8, Ieee1609Cert*> hashIdMap;


    };




} /* namespace ctp */

#endif // __IEEE_1609DOT2CERT_HPP__