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

#define MODULE 2

void print_data(const char* file, const uint8_t *buf, size_t len);

namespace ctp
{
    class Ieee1609Encode; /* forward declaration of encode class */


    /* cert class */
    class Ieee1609Cert
    {
        // std::vector<CertificateBase *> certs;
        // std::map<int, ctp::Ieee1609Cert*> certsPsidMap;
        // std::map<std::string, ctp::Ieee1609Cert*> certsHashIdMap;


        /*next pointer*/
        Ieee1609Cert *next;

        /* encode/decode objects*/
        Ieee1609Encode *pEncObj;

        const EC_GROUP *ecGroup;
        EC_KEY *ecKey;
        uint8_t keyType;

        CertificateBase *base;
        IssuerIdentifier *issuer;
        ToBeSignedCertificate *tbs;
        VerificationKeyIndicator *vki;
        Signature *signature;
        SequenceOfPsidSsp *psidSsp;
        SequenceOfCertificate *seqOfCert;
        int public_key_get(point_conversion_form_t conv = POINT_CONVERSION_UNCOMPRESSED);
        int private_key_get();
        int _sign(const uint8_t *buf, size_t len, SignatureType type);
        /* encode the certificate */

        int EncodeCertBase(bool cont = true); /* encode certificate base */
        int sign(const uint8_t *buf, size_t len, SignatureType type=ecdsaNistP256Signature);
        const Signature *signEx(const uint8_t *buf, size_t len, SignatureType type = ecdsaNistP256Signature);

        public:
            void create();

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

            int encode(uint8_t **buf);
            /* encode to be signed data of the certificate */
            int EncodeToBeSigned(bool cont=true);

            void set(Ieee1609Cert *cert)
            {
                this->next = cert;
            }
            const SequenceOfPsidSsp& psid_get() const;

            /* print to stdout or store in a file */
            int print();


    };

    class Ieee1609Encode
    {
        uint8_t *encBuf; /*encoded buffer */
        size_t encLen;   /* encoded length */
        public:
            Ieee1609Encode():encBuf(nullptr),encLen(0){};
            ~Ieee1609Encode()
            {
                std::cout << " encode destructor " << std::endl;
                delete encBuf;
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
            int SequenceOfPsid_(const SequenceOfPsidSsp& psids);
            int IssuerIdentifier_(const IssuerIdentifier& issuer);
            int SequenceOf(const uint8_t *values, size_t bytes);


            /*6.3.3*/
            int SignedDataPayload_(const Ieee1609Dot2Data& data);
            /*encoding of signed data, 6.3.4 */
            int HashAlgo(HashAlgorithmType type);
            int HeaderInfo_(const HeaderInfo& header);
            int ToBesignedData_(const ToBeSignedData& tbsData);
            int SignerIdentifier_(Ieee1609Cert& signer, SignerIdentifierType type);
            int Signature_(const Signature& signature);
            int Ieee1609Dot2ContentType_(const Ieee1609Dot2ContentType type);
            int SequenceOfCerts_(const SequenceOfCertificate& certs);
            /* int encoded buffer get */
            int get(uint8_t **buf);
            /* clear the encoded buuffer */
            int clear();
    };


    class decode
    {
        uint8_t *buf; /*encoded buffer */
        size_t len;   /* encoded length */
        public:
            decode():buf(nullptr),len(0){};
            ~decode()
            {
                delete buf;
                len = 0;
            }
            /* encode certificate identifier */
            int CertId(const CertificateId& id);
            /* encode crl series */
            int CrlSeries(const uint16_t series);
            /* encode hashid3 */
            int HashId3(const uint8_t* hash, size_t len);
            /* encode the signature */
            int Signature(const Signature& signature);
            /* encode validity period */
            int ValidityPeriod(const validityPeriod& validityPeriod);
            /* encode verfication key indicator */
            int Vki(const VerificationKeyIndicator& vki);
    };



    /* sequence of certs */
    class Ieee1609Certs
    {
        int num;
        Ieee1609Cert *cert;
        Ieee1609Encode *enc;

        public:
            /*constructor */
            /* self-signed signature */
            explicit Ieee1609Certs(){
                num = 0;
                cert = new Ieee1609Cert();
                enc = new Ieee1609Encode();
                /* create a self-signed certificate */
                try {
                    cert->create();
                    num++;
                }catch( std::exception& e){
                    LOG_ERR("Ieee1609Certs::Ieee1609Certs()::create()", MODULE);
                    std::cout << " exception " << e.what() << std::endl;
                    delete cert;
                    delete enc;
                }
            }
            /* encoded file */
            explicit Ieee1609Certs(std::string& file)
            {
                /* default */
                num = 0;
                cert = new Ieee1609Cert();
            }
            /* encoded buffer */
            explicit Ieee1609Certs(const uint8_t *buffer)
            {
                num = 0;
                cert = new Ieee1609Cert();
            }
            ~Ieee1609Certs()
            {
                delete cert;
            }

            const Ieee1609Cert *get() const
            {
                return cert;
            }

            int encode(){
                uint8_t *buf = nullptr;
                /* encode the sequence of certs */
                enc->clear();
                /* only 1 byte is needed to encode the number seuqnce */
                enc->SequenceOf((uint8_t *)&num, 1);
                /* encode the actual certificate */
                size_t len = cert->encode(&buf);
                if (len > 0)
                    enc->OctetsFixed(buf, len);
                return len;
            }

            void print()
            {
                uint8_t *buf = nullptr;
                size_t len = enc->get(&buf);
                print_data("cert.txt", buf, len);
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