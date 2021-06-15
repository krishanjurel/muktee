#ifndef __DOT2CERT_HPP__
#define __DOT2CERT_HPP__
#include <iostream>
#include "dot2common.hpp"
#include <openssl/sha.h>
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
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include "tp_util.hpp"
#include <condition_variable>


void print_data(const char* file, const uint8_t *buf, size_t len);

namespace ctp
{
    class Ieee1609Encode; /* forward declaration of encode class */
    class Ieee1609Decode;
    class Ieee1609Certs;
    class Ieee1609Cert;
    class CertMgr;

    /* useful short notations */
    using SHARED_CERT = std::shared_ptr<Ieee1609Cert>;
    using SHARED_CERTS = std::shared_ptr<Ieee1609Certs>;
    using PTR_CERT = Ieee1609Cert *;
    using PTR_CERTS = Ieee1609Certs *;
    using SHARED_ENC = std::shared_ptr<Ieee1609Encode>;
    using SHARED_DEC = std::shared_ptr<Ieee1609Decode>;
    using PTR_ENC = Ieee1609Encode *;
    using PTR_DEC = Ieee1609Decode *;

    using SHARED_CERTMGR = std::shared_ptr<CertMgr>;
    using PTR_CERTMGR = CertMgr *;




    /* cert class */
    class Ieee1609Cert: public mem_mgr
    {
        // std::vector<CertificateBase *> certs;
        // std::map<int, ctp::Ieee1609Cert*> certsPsidMap;

        // std::map<std::string, ctp::Ieee1609Cert*> certsHashIdMap;


        /*next pointer*/
        Ieee1609Cert *next;

        /* encode/decode objects*/
        SHARED_ENC pEncObj;
        SHARED_DEC pDecObj;

        const EC_GROUP *ecGroup;
        EC_KEY *ecKey;
        uint8_t keyType;

        CertificateBase *base;
        IssuerIdentifier *issuer;
        ToBeSignedCertificate *tbs;
        VerificationKeyIndicator *vki;
        Signature *signature;
        SequenceOfPsidSsp *seqOfPsidSsp;
        //SequenceOfCertificate *seqOfCert;
        /* hash id 8 of this certificate */
        HashedId8 hashid8;
        int public_key_get(point_conversion_form_t conv = POINT_CONVERSION_COMPRESSED);
        int private_key_get();
        int private_key_set(const uint8_t *keyBuf, size_t keyBufLen);
        int _sign(const uint8_t *buf, size_t len, SignatureType type);
        /* encode the certificate */

        int EncodeCertBase(bool cont = true); /* encode certificate base */
        int sign(); /* sign the certificate, this is valid only for self-signed */
        int sign(const uint8_t *buf, size_t len, SignatureType type=ecdsaNistP256Signature);
        const Signature *signEx(const uint8_t *buf, size_t len, SignatureType type = ecdsaNistP256Signature);
        /*FIXME! cache the encoded cert */
        // uint8_t *encodedBuf;
        // size_t encodeBufLen;

        const int MODULE=MODULE_CERT;



        public:

            void create(int nid = NID_X9_62_prime256v1);
            void create(int nid, const std::vector<int> psids);


            explicit Ieee1609Cert();
            /* no copy constructure */
            Ieee1609Cert(const Ieee1609Cert&) = delete;
            /* no copy assignment */
            const Ieee1609Cert& operator=(const Ieee1609Cert&) = delete;
            /* no move constructor */
            Ieee1609Cert(const Ieee1609Cert&&) = delete;
            ~Ieee1609Cert()
            {
                std::cout << "Ieee1609Cert::~Ieee1609Cert()"<< std::endl;
                pEncObj.reset();
                pDecObj.reset();
                pEncObj = nullptr;
                pDecObj = nullptr;
                if(seqOfPsidSsp && seqOfPsidSsp->psidSsp)
                {
                    std::cout << "Ieee1609Cert::~Ieee1609Cert()::buf_free(seqOfPsidSsp->psidSsp)"<< std::endl;
                    buf_free(seqOfPsidSsp->psidSsp);
                }
                buf_free(base);
                if(ecKey)
                    EC_KEY_free(ecKey);

                std::cout << "Ieee1609Cert::~Ieee1609Cert() exit"<< std::endl;
            }

            const ECDSA_SIG* SignData(const uint8_t *buf, size_t len, SignatureType type);
            /* verify the signature of the certificate */
            int verify(const uint8_t *dgst, size_t len);
            /* verify a signature signed this cert */
            int verify(const uint8_t *dgst, size_t dgst_len, const Signature& signature);

            int SigToSignature(const ECDSA_SIG* sig, Signature& signature);
            /* and then the hashed data */
            int Hash256(const uint8_t* tbHash, size_t len, uint8_t **hash);
            /*haeder info consistency check */
            int ConsistencyCheck(const HeaderInfo& header);

            /* \fn encode(uint8_t **buf)
                    encodes the certificate.

                    returns 0: error, else
                            length of the encoded buffer 
            */
           /* cert encoder */
            int encode(uint8_t **buf);
            int encode(const uint8_t* buf, size_t len) = delete;
            int encode(SHARED_ENC enc);
            /* encode to be signed data of the certificate */
            int EncodeToBeSigned(bool cont=true);

            /* cert decoder */
            int decode(const uint8_t* buf, size_t len);
            int decode(std::shared_ptr<Ieee1609Decode> ptr);
            /* cert signer from file */
            int decode(std::string certFile, std::string keyFile);

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

    /* sequence of certs*/
    class Ieee1609Certs : public mem_mgr
    {
        int quantity;
        /* list of certificates under this certs */
        std::vector<SHARED_CERT> certs;
        SHARED_ENC enc;
        SHARED_DEC dec;
        SignerIdentifier signerIdentifier;
        const int MODULE=MODULE_CERTS;

        public:
            /*constructor */
            /* self-signed signature */
            explicit Ieee1609Certs();
            /* encoded file */
            explicit Ieee1609Certs(std::string& file);
            /* encoded buffer */
            explicit Ieee1609Certs(const uint8_t *buffer);
            ~Ieee1609Certs();
            const Ieee1609Cert *get() const;
            /* create variants */
            void create(int nid = NID_X9_62_prime256v1);
            void create(int nid, std::vector<int> psids);
            void create(std::vector<int> psids);


            /* encoded message of the signer, 
                used to create a Signature of the data packet 
            */
            int encode_signer(uint8_t **buf);
            int encode(uint8_t **buf);
            /* decode the buffer */
            int decode(const uint8_t *buf, size_t len);
            int decode (std::shared_ptr<Ieee1609Decode> ptr);
            int Hash256(const uint8_t* tbHash, size_t len, uint8_t **hash);
            int verify(const uint8_t *dgst, size_t dgst_len, const Signature& signature);
            int verify(const uint8_t *dgst, size_t dgst_len);
            const ECDSA_SIG* SignData(const uint8_t *buf, size_t len, SignatureType type);
            int SigToSignature(const ECDSA_SIG* sig, Signature& signature);
            int ConsistencyCheck(const HeaderInfo& header);
            const std::vector<SHARED_CERT>& CertList(){ return certs;};
            void CertAdd(SHARED_CERT cert){
                /* increase the quantity */
                quantity++;
                certs.push_back(cert);
                return;
            }
            void print();
    };

    /* encoode/decode */
    class Ieee1609Encode:public std::enable_shared_from_this<Ieee1609Encode>,public mem_mgr
    {
        using sharedPtr = std::shared_ptr<Ieee1609Encode>;
        uint8_t *encBuf; /*encoded buffer */
        size_t encLen;   /* encoded length */

        const int MODULE = MODULE_ENC;


        public:
            sharedPtr getPtr()
            {
                return shared_from_this();
            }
            Ieee1609Encode():encBuf(nullptr),encLen(0){};
            ~Ieee1609Encode()
            {
                std::cout << " Ieee1609Encode::~Ieee1609Encode " << std::endl;
                if(encBuf)
                    buf_free(encBuf);
                encBuf = nullptr;
                encLen = 0;
            }
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
            int SequenceOf(size_t quantity);
            int SequenceOfPsid_(const SequenceOfPsidSsp& psids);
            int IssuerIdentifier_(const IssuerIdentifier& issuer);
            int Length(size_t bytes);
            int Length(const uint8_t *values, size_t bytes);
            /* There are instances where only the number of bytes to store a number, i.e. sequence-of, and 
                There are instances where a certain length has to be encoded. the length encoding is done 
                by Length method.
            */
            size_t NumBytes(size_t number);


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


    class Ieee1609Decode:public std::enable_shared_from_this<Ieee1609Decode>,public mem_mgr
    {
        uint8_t *buf; /*encoded buffer */
        size_t len;   /* encoded length */
        size_t offset; /* buffer offset */
        const int MODULE = MODULE_DEC;

        public:
            SHARED_DEC GetPtr()
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
                std::stringbuf log_(std::ios_base::out);
                std::ostream os(&log_);
                os << " Ieee1609Decode::OctetsFixed enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
                if (len_+offset > this->len)
                {
                    os << " Ieee1609Decode::OctetsFixed not enough buffer " <<  len << " offset " << offset << std::endl;
                    LOG_ERR(log_.str(), MODULE);
                    throw Exception(log_.str());
                    return 0;
                }

                while(len_--)
                {
                    *octets++ = buf[offset++];
                }

                os << " Ieee1609Decode::OctetsFixed exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
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
                log_.str("");

                /* read 4 bytes of uint32 in big endian format */
                uint8_t *buf_ = (uint8_t *)&vp.start;
                size_t len_ = 4;
                while(len_)
                {
                    len_ --;
                    buf_[len_] = buf[offset++];
                }
                os << " Ieee1609Decode::VP start " << vp.start << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
                /* get the choice of duration */
                vp.duration.type = (DurationType)(buf[offset++] & ASN1_COER_CHOICE_MASK_CLR);
                os << " Ieee1609Decode::VP " << " duration type " << vp.duration.type << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
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
                std::stringstream log_(std::ios_base::out);
                log_ << " Ieee1609Decode::Vki enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");

                /* read the choice, 6.4.35 */
                vki.type = (VerificationKeyIndicatorType)(buf[offset++] & ASN1_COER_CHOICE_MASK_CLR);
                switch(vki.type)
                {
                    case VerificationKeyIndicatorTypeKey:
                        /* decode public verfiification key, 6.4.36 */
                        vki.indicator.verificationKey.type = (PublicVerificationKeyType)(buf[offset++] & ASN1_COER_CHOICE_MASK_CLR);
                        switch(vki.indicator.verificationKey.type)
                        {
                            case PublicVerificationKeyTypEecdsaNistP256S:
                            {
                                /* decode the curve point 6.3.23*/
                                EccP256CurvPoint *point = &vki.indicator.verificationKey.key.ecdsaNistP256;
                                /* get the choice type */
                                point->type = (EccP256CurvPointType)(buf[offset++] & ASN1_COER_CHOICE_MASK_CLR);
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
                                        log_ << "Ieee1609Decode::Vki:: point type not supported " << point->type << std::endl;
                                        LOG_ERR(log_.str(), MODULE);
                                        throw Exception(log_.str());

                                }
                                /* handle the available buffer size */
                                if(_len+offset > len)
                                {
                                    log_ << "Ieee1609Decode::Vki:: point type not enough length " << _len << "offset " << offset << "total " << len << std::endl;
                                    LOG_ERR(log_.str(), MODULE);
                                    throw Exception(log_.str());
                                }

                                while(_len--)
                                {
                                    *_buff++ = buf[offset++];
                                }
                            }
                            break;
                            default:
                                log_ << "Ieee1609Decode::Vki:: verfication public key type not supported " << vki.indicator.verificationKey.type << std::endl;
                                LOG_ERR(log_.str(), MODULE);
                                throw Exception(log_.str());
                        }
                    break;
                    default:
                        log_ << "Ieee1609Decode::Vki:: verfication key type not supported " << vki.type << std::endl;
                        LOG_ERR(log_.str(), MODULE);
                        throw Exception(log_.str());
                }

                log_ << " Ieee1609Decode::Vki exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                return offset;
            }
            /* decode the sequence of quantity, it returns the number of iterations in quantity
             */
            int SequenceOf(uint8_t *quantity, size_t bufLen)
            {
                std::stringstream log_;
                log_ << "Ieee1609Decode::SequenceOf enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
                /* first get the length of iterations */
                size_t iterations;
                size_t bytes = Length((uint8_t *)&iterations, sizeof(size_t));
                if( bytes > bufLen)
                {
                    throw Exception("Ieee1609Decode::SequenceOf quantity buffer is not enough");
                }
                log_ << "Ieee1609Decode::SequenceOf length bytes " <<  bytes << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
                /* copy the quantity bytes */
                while(bytes)
                {
                    quantity[--bytes] = buf[offset++];
                }
                log_ << "Ieee1609Decode::SequenceOf exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
                return offset;
            }
            int SequenceOfPsid_(SequenceOfPsidSsp& psids)
            {
                std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
                std::ostream os(&log_);
                os << " Ieee1609Decode::SequenceOfPsid_ enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");

                /* get the number of items in the sequence */
                psids.quantity= 0;
                SequenceOf((uint8_t *)&psids.quantity, sizeof(psids.quantity));
                os << " Ieee1609Decode::SequenceOfPsid_ psids.quantity " <<  psids.quantity << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");


                psids.psidSsp = (PsidSsp*)buf_alloc(psids.quantity * sizeof(PsidSsp));
                for(int i = 0; i < psids.quantity; i++)
                {
                    PsidSsp *ssp = psids.psidSsp + i;
                    uint8_t *buf_ = (uint8_t *)&ssp->psid;
                    /* get the optinal map of the first ssp */
                    ssp->optionalMask = buf[offset++];
                    /* get the variable length bytes */
                    int intBytes = buf[offset++];
                    os << "Ieee1609Decode::SequenceOfPsid_ optional mask / number of bytes " << std::to_string(ssp->optionalMask) << " " << intBytes << std::endl;
                    log_info(log_.str(), MODULE);
                    log_.str("");
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
                os << "Ieee1609Decode::IssuerIdentifier_ enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");

                /* get the choice */
                int c = (int)buf[offset];
                os << "Ieee1609Decode::IssuerIdentifier_ the value at offset " << offset << " is " << std::hex << std::to_string(c) << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
                issuer.type = (IssuerIdentifierType)(buf[offset++] & ASN1_COER_CHOICE_MASK_CLR);
                switch(issuer.type)
                {
                    case IssuerIdentifierTypeHashId:
                    {
                        os << "Ieee1609Decode::IssuerIdentifier_ is hash " << std::endl;
                        log_info(log_.str(), MODULE);
                        log_.str("");
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
                        issuer.issuer.algo = (HashAlgorithmType)buf[offset++];
                        
                    break;
                    default:
                        os << "Ieee1609Decode::IssuerIdentifier_ unsuuported issuer type " << issuer.type;
                        LOG_ERR(log_.str(), MODULE);
                        throw Exception(log_.str());
                }
                os << " Ieee1609Decode::IssuerIdentifier_ exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();

                return 0;
            }
            /* only copies the integer encoded and returns number of bytes integer occupies */
            int Length(uint8_t *value, size_t bytes)
            {
                int numBytes = 0;
                uint8_t lengthEncoding=1;
                std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
                std::ostream os(&log_);
                os << " Ieee1609Decode::Length enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
                /* read first byte of the integer encoding */
                lengthEncoding = buf[offset];
                if(buf[offset] & ASN1_LENGTH_ENCODING_MASK)
                {
                    /* number of bytes in the length */
                    lengthEncoding = (buf[offset++] & ~ASN1_LENGTH_ENCODING_MASK);
                }else{
                    /* only 1 bytes */
                    lengthEncoding = 1;
                }
                if(lengthEncoding > bytes)
                {
                    throw Exception("the supplied buffer not long enough");
                }
                numBytes = lengthEncoding;
                /* copy the bytes into the given buffer */
                while(lengthEncoding)
                {
                    lengthEncoding--;
                    value[lengthEncoding] = buf[offset++];
                }
                os << " Ieee1609Decode::Length exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();
                return numBytes;
            }

            int ContentType_(Ieee1609Dot2ContentType& type)
            {
                std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
                std::ostream os(&log_);
                os << " Ieee1609Decode::ContentType_ enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();
                type =  (Ieee1609Dot2ContentType)(buf[offset++] & ASN1_COER_CHOICE_MASK_CLR);

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

    struct HashedId8Cmp
    {
        bool operator()(const HashedId8& lhs, const HashedId8& rhs)
        {
            return std::string(lhs.x, sizeof(HashedId8)).compare(std::string(rhs.x, sizeof(HashedId8)));
        }
    };


    /* certificate manager, creates, maintaines , updates the certificats in the system
    */
    class CertMgr: public std::enable_shared_from_this<CertMgr>, public mem_mgr
    {
        const int MODULE=MODULE_CERTMGR;
        // std::map<int, std::shared_ptr<Ieee1609Cert>> psidMap;
        std::map<HashedId8, SHARED_CERT, HashedId8Cmp> hashIdMap;
        int _stop;
        static int _initDone;
        static SHARED_CERTMGR pCertMgr;
        std::shared_ptr<tp_cfg> cfg;

        /* list of certificates*/
        std::vector<SHARED_CERT> signerList;
        std::vector<SHARED_CERT> caList;

        std::thread validThread; /* thread checking the validity of the certs */
        std::thread remoteThread; /* thread communicating with remote host */
        std::thread localThread; /* thread to create and load the local certs */

        int certReady;
        std::mutex hashdMapMutex;
        // std::condtional_variable cv;
        std::condition_variable cv;

        // /* only one instance of the certificate manager at all costs */
        // explicit CertMgr():mem_mgr(),_stop(0)
        // {
        //     std::stringstream log_(std::ios_base::out);
        //     log_ << "CertMgr::CertMgr() enter" << std::endl;
        //     log_dbg(log_.str(), MODULE);
        //     try
        //     {
        //         /* create instances of cert and data manager */
        //         certs = SHARED_CERTS(new Ieee1609Certs(),[this](const PTR_CERTS p){log_dbg(std::string("CertMgr::CertMgr delete CertMgr::certs \n"),this->MODULE);delete p;});
        //     }catch(Exception& e)
        //     {
        //         log_.str("");
        //         log_ << " CertMgr::CertMgr() " << e.what() << std::endl;
        //         LOG_ERR(log_.str(), MODULE);
        //     }
        //  }
        // CertMgr(const CertMgr& ) = delete;
        // CertMgr(const CertMgr&& ) = delete;


        public:
            /* only one instance of the certificate manager at all costs */
            explicit CertMgr():mem_mgr(),_stop(0)
            {
                std::stringstream log_(std::ios_base::out);
                log_ << "CertMgr::CertMgr() enter" << std::endl;
                log_dbg(log_.str(), MODULE);
                // try
                // {
                //     /* create instances of cert and data manager */
                //     certs = SHARED_CERTS(new Ieee1609Certs(),[this](const PTR_CERTS p){log_dbg(std::string("CertMgr::CertMgr delete CertMgr::certs \n"),this->MODULE);delete p;});
                // }catch(Exception& e)
                // {
                //     log_.str("");
                //     log_ << " CertMgr::CertMgr() " << e.what() << std::endl;
                //     LOG_ERR(log_.str(), MODULE);
                // }
                certReady = 0;
                cfg = std::shared_ptr<tp_cfg>(nullptr);
                signerList.clear();
            }
            CertMgr(const CertMgr& ) = delete;
            CertMgr(const CertMgr&& ) = delete;

            CertMgr& operator=(const CertMgr& ) = delete;
            CertMgr& operator=(const CertMgr&& ) = delete;

            ~CertMgr()
            {
                log_dbg("CertMgr::~CertMgr\n", MODULE);
                signerList.clear();
                _initDone = 0;
                pCertMgr = nullptr;
                cfg = nullptr;
            }
            /* get the certificate for the sepcified psid */
            SHARED_CERT operator[](const int psid)
            {
                SHARED_CERT _cert = nullptr;
                std::unique_lock<std::mutex> lck(hashdMapMutex);
                cv.wait(lck, [this](){ return certReady == 1;});
                for (SHARED_CERT cert : signerList)
                {
                    const SequenceOfPsidSsp& psids = cert->psid_get();
                    for(int i =0; i < psids.quantity; i++)
                    {
                        PsidSsp *psidSsp = psids.psidSsp;
                        if(psid == psidSsp->psid)
                        {
                            _cert = cert;
                            break;
                        }
                    }
                }
                return _cert;
            }
            /* get the certificate for the specified hashId */
            SHARED_CERT operator[](HashedId8 hashId)
            {
                std::unique_lock<std::mutex> lck(hashdMapMutex);
                cv.wait(lck, [this](){ return certReady == 1;});
                return signerList[0];
            }

            void start(std::shared_ptr<tp_cfg> tpcfg)
            {
                cfg = std::shared_ptr<tp_cfg>(tpcfg);
                remoteThread = std::thread(&CertMgr::cert_mgr_remote_handler, this);
                validThread = std::thread(&CertMgr::cert_mgr_valid_handler, this);
                localThread = std::thread(&CertMgr::cert_mgr_local_handler, this);
                hashIdMap.clear();
            }

            void stop()
            {
                _stop = 1;
                /* wait for threads to end */
                remoteThread.join();
                validThread.join();
                localThread.join();
                 _initDone = 0;
            }

            SHARED_CERTMGR get_instance()
            {
                // return shared_from_this();
                return SHARED_CERTMGR(this);
            }

            /* initialized the cert manager */
            static SHARED_CERTMGR init()
            {
                if(_initDone == 0)
                {
                    _initDone = 1;
                    pCertMgr = SHARED_CERTMGR(new CertMgr(), [](PTR_CERTMGR ptr){ std::cout << "CertMgr::Init delete CertMgr \n";delete ptr;});
                }
                // std::cout << "CertMgr::init " << pCertMgr.use_count() << std::endl;
                return pCertMgr;
            }
            /* cert manager handler */
            void cert_mgr_valid_handler()
            {
                log_dbg(std::string("CertMgr::cert_mgr_valid_handler enter\n"), MODULE);
                while(!_stop)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                }
                log_dbg(std::string("CertMgr::cert_mgr_valid_handler exit\n"), MODULE);

            }
            void cert_mgr_remote_handler()
            {
                log_dbg(std::string("CertMgr::cert_mgr_remote_handler enter\n"), MODULE);
                while(!_stop)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                }
                log_dbg(std::string("CertMgr::cert_mgr_remote_handler exit\n"), MODULE);

            }

            void cert_mgr_local_handler()
            {
                std::vector<std::string> files;

                SHARED_CERT cert = nullptr;
                {
                    std::lock_guard<std::mutex> lck(hashdMapMutex);
                    int fd;
                    dirent *dent;
                    log_dbg(std::string("CertMgr::cert_mgr_local_handler enter\n"), MODULE);
                    /* open the certs directory */
                    DIR *dir = opendir(cfg->certcfg.path1);
                    if(dir != nullptr)
                    {
                        while((dent = readdir(dir)) != nullptr)
                        {
                            files.emplace_back(dent->d_name, dent->d_reclen);
                        }
                    }

                    for(auto& file: files)
                    {
                        int ret = 0;
                        uint8_t *certbuf_ = nullptr;
                        size_t buflen_ = 0;
                        file  = cfg->certcfg.path1 + file;
                        file_read(file.c_str(), &certbuf_, &buflen_);
                        if(buflen_ == 0 ) continue;
                        SHARED_CERT cert = std::make_shared<Ieee1609Cert>();
                        ret = cert->decode(certbuf_, &buflen_);
                        if(ret)
                        {
                            certList.push_back(cert);
                        }
                    }
                    if(certsList.size() == 0)
                    {
                        cert = std::make_shared<ctp::Ieee1609Cert>();
                        std::string _file = cfg->certcfg.path1;
                        try
                        {
                            if(cfg && cfg->psids.size())
                                cert->create(cfg->psids);
                            else
                                cert->create();
                            
                            /* store it */
                            certList.push_back(cert);

                            for(auto& cert: certList)
                            {
                                /* since I am creating this, store it */
                                uint8_t *_buf = 0;
                                size_t _buflen = certs->encode(&_buf);

                                if(_buflen)
                                {
                                    _file += "signer/cert.file";
                                    file_write(_file, _buf, _buflen);
                                    
                                }
                            }
                        }catch(ctp::Exception& e)
                        {
                            std::stringstream log_(std::ios_base::out);
                            log_ << "CertMgr::cert_mgr_local_handler() " << e.what() << std::endl;
                            LOG_ERR(log_.str(), MODULE);
                        }
                    }
                }

                /* create the list of certificates */
                for(auto _certs:certsList)
                {
                    for(auto _cert: _certs->CertList())
                    {
                        signerList.push_back(_cert);
                    }
                }
                certReady = 1;
                cv.notify_all();

                while(!_stop)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                }
                log_dbg(std::string("CertMgr::cert_mgr_local_handler exit\n"), MODULE);
            }
    };













} /* namespace ctp */

#endif // __IEEE_1609DOT2CERT_HPP__