#ifndef __DOT2COMMON_HPP__
#define __DOT2COMMON_HPP__
#include <iostream>
#include <vector>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <sys/time.h>


/* common structures with c++ linkage */
namespace ctp
{

/* define modules */
    enum
    {
        MODULE_TP = 0,
        MODULE_CERT,
        MODULE_CERTS,
        MODULE_CERTMGR,
        MODULE_DATA,
        MODULE_ENC,
        MODULE_DEC,
        MODULE_MEM,
        MODULE_CFG,
        MODULE_USER     /* test programs use from here */
    };

    enum {
        PSID_BSM = 0x20,
        /* use this to test the unspported psid */
        PSID_FAIL=0xAABB
    };

    struct _cert_cfg
    {
        int nid;
        char *path1;
        char *path2;
    };

    struct _remote_host
    {
        /* ip address */
        std::string ip;
        /* port number */
        int port;
    };


    /* distribution center */
    struct _dc
    {
        /* certis distribution center */
        _remote_host certs;
        _remote_host ctls;
        _remote_host crls;
    };


    /* trusted platform configuration */
    struct tp_cfg
    {
        /* supported psids */
        std::vector<int> psids;
        std::vector<std::string> curves; /* supported curves */
        /* identifier of the system, use mac address for now */
        std::string id;
        _dc  dc;    /* distribution center */
        _remote_host ra; /* registration authority */
        _remote_host dcm; /* device config manager */
        _cert_cfg certcfg;
        tp_cfg(const char *filename);
        ~tp_cfg()
        {
            psids.clear();
            curves.clear();
            std::cout << "tp_cfg::~tp_cfg() " << std::endl;
        }
        void tp_cert_cfg(const char *filename);

        const int MODULE=MODULE_CFG;

    };


    /* clients will create an instance of this class and register with the TP.
       These clients will be notified whenever a packet of specified psids
       is processed by the  TP
    */
    class tp_client
    {
        public:
            virtual void callback(void *data, size_t len) = 0;

    };

    struct client_msg
    {
        void *buf;
        size_t len;
        client_msg(void *buf_, size_t len_):buf(buf_), len(len_){};
        ~client_msg(){std::cout << " client_msg::~client_msg" << std::endl; free(buf);}
    };


    struct psid_tp_client
    {
        int psid;
        std::vector<std::shared_ptr<tp_client>> clients;
        psid_tp_client(int _psid):psid(_psid){
            clients.clear();
        }
        ~psid_tp_client()
        {
            std::cout << " psid_tp_client::~psid_tp_client() " << std::endl;
            clients.clear();
        }
    };

    class Exception:public std::exception
    {
        std::string *msg;
        public:
            Exception(std::string _msg):msg(new std::string(_msg)){};
            const char* what() const noexcept
            {
                return msg->c_str();
            }

            ~Exception()
            {
                std::cout << "Exception::~Exception() " << std::endl;
                delete msg;
            }
    };

    /* used for allocation/deallocation */
    class mem_mgr
    {
        const size_t alloc_multiple = 512;
        /* allocated memory*/
        size_t allocated_;
        /* used memory */
        size_t used_;
        /* allocated address */
        void *addr_;
        public:
            mem_mgr():allocated_(0), used_(0), addr_(0){};
            void* buf_alloc(size_t s)
            {
                try
                {
                    addr_ = calloc(s,1);
                    allocated_ = s;
                    used_ = s;
                }catch (std::bad_alloc& e){
                    throw Exception(e.what());
                }
                return addr_;
            }
            /* only alloc if addr_ != addr or s >= allocated_ */
            void *buf_realloc(void *addr, size_t s)
            {
                int factor_ = 0;
                used_ = s;

                if (addr == addr_ && s < allocated_)
                {
                    return addr_;
                }
                factor_ = s/alloc_multiple;
                s = factor_*alloc_multiple;
                s += alloc_multiple;

                try
                {   
                    addr_ = realloc(addr, s);
                    allocated_ = s;
                }catch(std::bad_alloc& e)
                {
                    throw Exception(e.what());
                }
                return addr_;
            }
            void buf_free(void *addr)
            {
                if(addr_ == addr)
                    addr_ = nullptr;
                free (addr);
            }
    };
   
    
    typedef enum
    {
        LOG_LVL_ERR,
        LOG_LVL_WARN, 
        LOG_LVL_DBG,
        LOG_LVL_INFO
    }LogLvl;

    static struct _Loglevel
    {
       const char* lvl;
    }LogLevel[] = {
        {" Err "},
        {" Warn "},
        {" Dbg "},
        {" info "}
    };

    class log_mgr
    {

        std::mutex mLock;
        std::condition_variable cv;
        std::vector<std::string> queues[2];
        int index = 0;
        static LogLvl logLvl;
        // std::thread _thread;s

        /* thread */
        void operator()()
        {
            std::unique_lock<std::mutex> lk(mLock);
            cv.wait(lk, [](){return 0;});
        }

        log_mgr()
        {
            /* clear both queues */
            queues[0].clear();
            queues[1].clear();
            index = 0;
            logLvl = LOG_LVL_INFO;
        }

        public:

            static void log_level(LogLvl lvl_)
            {
                logLvl = lvl_;

            }

            static void log(LogLvl lvl, int mod,const std::string &msg)
            {
                /* log only the messages with high severity */
                struct timeval _timeval;
                gettimeofday(&_timeval, nullptr);
                if (lvl <= logLvl)
                    std::cout << LogLevel[(int)lvl].lvl << " : " << mod << " : " << std::dec << _timeval.tv_sec << "."<< _timeval.tv_usec << " "<< msg; 
            }

            static void log(LogLvl lvl, std::string& mod,const std::string &msg)
            {
                struct timeval _timeval;
                gettimeofday(&_timeval, nullptr);
                /* log only the messages with high severity */
                if (lvl <= logLvl)
                    std::cout << LogLevel[(int)lvl].lvl << " : " << mod << " : " << _timeval.tv_sec <<"."<<_timeval.tv_usec << " "<< msg; 
            }

            static void init()
            {
                static log_mgr *logmgr = nullptr;
                if(logmgr == nullptr)
                {
                    logmgr = new log_mgr();
                    std::thread _thread = std::thread(&log_mgr::operator(), logmgr);
                    _thread.detach();
                }
            }
    };

#define LOG_ERR(msg, mod) ctp::log_mgr::log(ctp::LOG_LVL_ERR,mod,msg)
#define LOG_DBG(msg, mod) ctp::log_mgr::log(ctp::LOG_LVL_DBG,mod,msg)
#define LOG_INFO(msg, mod) ctp::log_mgr::log(ctp::LOG_LVL_INFO,mod,msg)
#define LOG_WARN(msg, mod) ctp::log_mgr::log(ctp::LOG_LVL_WARN,mod,msg)
#define log_info(msg, mod) LOG_INFO(msg, mod)
#define log_dbg(msg, mod) LOG_DBG(msg, mod)


} //namespace ctp



#ifdef __cpluplus
extern "C"
{
#endif
/* 
    All data type is represented in upper camel case, with no underscores.
    All variables are declared in lower camel case, with no underscores.

    The Data Type and variable names are kept, as much as possible, as described in IEEE 1609.2-2016 spec, unless the name is of generic type.

*/

/* general definitions */
/* a variable length octet string */

typedef struct 
{
    uint8_t length;
    uint8_t *octets;
}OctetString;


#define ASN1_COER_CHOICE_MASK_CLR  (uint8_t)(~0x80)
#define ASN1_COER_CHOICE_MASK_SET  (uint8_t)(0x80)

#define ASN1_LENGTH_ENCODING_MASK (uint8_t)(0x80)
#define ASN1_BITS_PER_BYTE  8




/*6.3.25 */
typedef struct {char x[3];}HashedId3;
/* 6.3.26 */
typedef struct {char x[8];}HashedId8;
/* 6.3.27 */
typedef struct {char x[10];}HashedId10;

/*6.3.8*/
typedef struct {char x[32];}HashedData32;

/*6.3.5 */
typedef enum
{
    HashAlgorithmTypeSha256
}HashAlgorithmType;


/* 6.3.23 */
typedef enum 
{
    EccP256CurvPointTypeXOnly,
    EccP256CurvPointTypeFill,
    EccP256CurvPointTypeCompressedy0,
    EccP256CurvPointTypeCompressedy1,
    EccP256CurvPointTypeUncompressed,
    EccP256CurvPointTypeMax,
}EccP256CurvPointType;


typedef struct 
{
    EccP256CurvPointType type;
    union 
    {
        HashedData32 octets;
        struct {
            HashedData32 x;
            HashedData32 y;
        }uncompressed;
#define  uncompressedx   uncompressed.x 
#define  uncompressedy   uncompressed.y
    }point;
}EccP256CurvPoint;

/*6.3.29*/
struct EcdsaP256Signature
{
    EccP256CurvPoint r;
    HashedData32 s;
};
typedef struct EcdsaP256Signature EcdsaP256Signature;

/*6.3.28 */
typedef enum 
{
    ecdsaNistP256Signature,
    ecdsaBrainpoolP256r1Signature,
}SignatureType;

struct Signature
{
    SignatureType type;
    union
    { 
        EcdsaP256Signature ecdsaP256Signature;
        EcdsaP256Signature ecdsaBrainpoolP256r1Signature;
    }signature;
};
typedef struct Signature Signature;


/* certificate definitions */


typedef enum {
    CertTypeExplicit,
    CertTypeImplicit
}CertType;



/* certifiicate issuer */
/* 6.4.7 */

typedef enum
{
    IssuerIdentifierTypeHashId,
    IssuerIdentifierTypeSelf,
}IssuerIdentifierType;

struct IssuerIdentifier
{
    IssuerIdentifierType type;
    union 
    {
        HashedId8 hashId;
        HashAlgorithmType algo;
    }issuer;
};
typedef struct IssuerIdentifier IssuerIdentifier;

/* 6.4.13 */
typedef struct 
{
    uint8_t length;
    char *name;
}HostName;

/* 6.4.16 */
typedef enum{
    DurationTypeMicroSeconds,
    DurationTypeMilliSeconds,
    DurationTypeSeconds,
    DurationTypeMinutes,
    DurationTypeSixtyHours,
    DurationTypeYears
}DurationType;

typedef struct 
{
    DurationType type;
    uint16_t duration;
}Duration;


/* 6.4.14 */
struct validityPeriod
{
    time_t start;
    Duration duration;
};
typedef struct validityPeriod ValidityPeriod;

/*6.4.10 */
typedef struct linkageValue{uint8_t x[9];}LinkageValue;
struct linkageData
{
    uint16_t iCert;
    LinkageValue linkageValue;
};
typedef struct linkageData LinkageData;

/* 6.4.9 */
typedef enum
{
    CertificateIdTypeLinkageData,
    CertificateIdTypeName,
    CertificateIdTypeBinaryId,
    CertificateIdTypeNone
}CertificateIdType;

union certificateId
{
    LinkageData linkageData;
    HostName hostName;
    OctetString binaryId;
};
typedef union certificateId CertId;


typedef struct {
    CertificateIdType type;
    CertId id;
}CertificateId;




/* 6..4.36 */
typedef enum
{
    PublicVerificationKeyTypEecdsaNistP256S,
    PublicVerificationKeyTypeEcdsaBrainpoolP256r1
}PublicVerificationKeyType;



typedef struct 
{
    PublicVerificationKeyType type;
    union {
        EccP256CurvPoint ecdsaNistP256;
        EccP256CurvPoint ecdsaBrainpoolP256r1;
    }key;
}PublicVerificationKey;

/*6.4.35 */
typedef enum
{
    VerificationKeyIndicatorTypeKey, /* key , */
    VerificationKeyIndicatorTypeRecValue /* reconstruction value */
}VerificationKeyIndicatorType;

typedef struct 
{
    VerificationKeyIndicatorType type;
    union
    {
        PublicVerificationKey verificationKey;
        EccP256CurvPoint recValue;
    }indicator;
}VerificationKeyIndicator;


/*6.4.28 */
struct PsidSsp
{
    uint8_t optionalMask;
    int psid;
    OctetString ssp;
};
typedef struct PsidSsp PsidSsp;

struct SequenceOfPsidSsp
{
    int quantity;
    PsidSsp *psidSsp;
};
typedef struct SequenceOfPsidSsp SequenceOfPsidSsp;

#define TBS_OPTIONAL(_x_) TbsOptional ## _x_


// #define TbsOptionalMaskRegion   (1<<(7-TBS_OPTIONAL(Region)))
// #define TbsOptionalMaskAssuranceL   (1<<(7-TBS_OPTIONAL(Region)))
// #define TbsOptionalMaskRegion   (1<<(7-TBS_OPTIONAL(Region)))
// #define TbsOptionalMaskRegion   (1<<(7-TBS_OPTIONAL(Region)))
// #define TbsOptionalMaskRegion   (1<<(7-TBS_OPTIONAL(Region)))


typedef enum
{
    TBS_OPTIONAL(Region),
    TBS_OPTIONAL(AssuranceLevel),
    TBS_OPTIONAL(AppPerm),
    TBS_OPTIONAL(CertIssuePerm),
    TBS_OPTIONAL(CertReqPerm),
    TBS_OPTIONAL(CanReqRoll),
    TBS_OPTIONAL(EncKey)
}TbsOptionalComponnets;


#define TBS_OPTIONAL_MASK(_x_) TbsOptionalMask ## _x_
#define OPTIONAL_MASK_SHIFT_BIT 6
#define TBS_OPTIONAL_MASK_(_x_) (1<<(6-TBS_OPTIONAL(_x_)))

typedef enum
{
    TBS_OPTIONAL_MASK(Region) = TBS_OPTIONAL_MASK_(Region),
    TBS_OPTIONAL_MASK(AssuranceLevel) = TBS_OPTIONAL_MASK_(AssuranceLevel),
    TBS_OPTIONAL_MASK(AppPerm) = TBS_OPTIONAL_MASK_(AppPerm),
    TBS_OPTIONAL_MASK(CertIssuePerm) = TBS_OPTIONAL_MASK_(CertIssuePerm),
    TBS_OPTIONAL_MASK(CertReqPerm) = TBS_OPTIONAL_MASK_(CertReqPerm),
    TBS_OPTIONAL_MASK(CanReqRoll) = TBS_OPTIONAL_MASK_(CanReqRoll),
    TBS_OPTIONAL_MASK(EncKey) = TBS_OPTIONAL_MASK_(EncKey),
    TBS_OPTIONAL_MASK(All) = (3<<6)
}TbsOptionalComponnetsMask;




/* 6.4.8 */
struct ToBeSignedCertificate
{
    uint8_t optionsComps;
    CertificateId id;
    HashedId3 cracaId;
    uint16_t crlSeries;
    Duration duration;
    ValidityPeriod validityPeriod;
    SequenceOfPsidSsp appPermisions;
    VerificationKeyIndicator verifyKeyIndicator;
};
typedef struct ToBeSignedCertificate ToBeSignedCertificate;


/* 6.4.3*/
struct certificateBase
{
    uint8_t options; /* FIXME, there is only one option */
    uint8_t   version;
    CertType   certType;
    IssuerIdentifier issuer;
    ToBeSignedCertificate toBeSignedCertificate;
    Signature signature;
};
typedef struct certificateBase CertificateBase;


/*6.4.2, not used*/
// struct SequenceOfCertificate
// {
//     int length;     /* number of certs */
//     CertificateBase *certs; /* take a hit of 4 bytes */
// };
// typedef struct SequenceOfCertificate SequenceOfCertificate;


/* 6.3.24 */
typedef enum 
{
    SignerIdentifierTypeDigest,
    SignerIdentifierTypeCert,
    SignerIdentifierTypeSelf
}SignerIdentifierType;

struct SignerIdentifier
{
    SignerIdentifierType type;
    HashedId8 digest; /* either certs or just hashed id */
    /* sequence of certs are represented by the class Ieee1609Certs(Ieee1609Cert.hpp)*/
    // union
    // {
    //     HashedId8 digest;
    //     SequenceOfCertificate certificate;
    // }signer;
};
typedef struct SignerIdentifier SignerIdentifier;

/* data content related definitions */


/* contains SPDU  data structures and definitions */ 

/* 
    All data type is represented in upper camel case, with no underscores.
    All variables are declared in lower camel case, with no underscores.

    The Data Type and variable names are kept, as much as possible, as described in IEEE 1609.2-2016 spec, unless the name is of generic type.

*/

struct Ieee1609Dot2Data; /* forward declaration */
typedef struct Ieee1609Dot2Data Ieee1609Dot2Data;

/* 6.3.9 */
#define HEADER_INFO_OPTION(_option) HeaderInfoOption ## _option
#define HEADER_INFO_OPTION_MASK(_option) HeaderInfoOptionMask ## _option
#define HEADER_INFO_OPTION_MASK_VAL(_option) (1<<(OPTIONAL_MASK_SHIFT_BIT-HEADER_INFO_OPTION(_option)))

typedef enum
{
    /* Note: dont change the order */
    HEADER_INFO_OPTION(GenTime),
    HEADER_INFO_OPTION(ExTime),
    HEADER_INFO_OPTION(GenLoc),
    HEADER_INFO_OPTION(P2pcdLearnReq),
    HEADER_INFO_OPTION(MissingCrlId),
    HEADER_INFO_OPTION(EncKey),
}HeaderInfoOptions;

typedef enum
{
    HEADER_INFO_OPTION_MASK_NONE = 0,
    HEADER_INFO_OPTION_MASK(GenTime) = HEADER_INFO_OPTION_MASK_VAL(GenTime),
    HEADER_INFO_OPTION_MASK(ExTime) = HEADER_INFO_OPTION_MASK_VAL(ExTime),
    HEADER_INFO_OPTION_MASK(GenLoc) = HEADER_INFO_OPTION_MASK_VAL(GenLoc),
    HEADER_INFO_OPTION_MASK(P2pcdLearnReq) = HEADER_INFO_OPTION_MASK_VAL(P2pcdLearnReq),
    HEADER_INFO_OPTION_MASK(MissingCrlId) = HEADER_INFO_OPTION_MASK_VAL(MissingCrlId),
    HEADER_INFO_OPTION_MASK(EncKey) = HEADER_INFO_OPTION_MASK_VAL(EncKey)
}HeaderInfoOptionMask;

struct HeaderInfo
{
    HeaderInfoOptionMask options;
    int psid;
    uint64_t genTime;
    uint64_t expTime;
};
typedef struct HeaderInfo HeaderInfo;

/* 6.3.7 */
//SDP=>signed data payload
typedef enum
{
    SDP_OPTION_DATA  = 0,
    SDP_OPTION_EXT_DATA_HASH,
    SDP_OPTION_ALL
}SignedDataPayloadOptions;


typedef enum
{
    SDP_OPTION_DATA_MASK = (1<<(OPTIONAL_MASK_SHIFT_BIT-SDP_OPTION_DATA)),
    SDP_OPTION_EXT_DATA_HASH_MASK = (1<<(OPTIONAL_MASK_SHIFT_BIT-SDP_OPTION_EXT_DATA_HASH)),
    SDP_OPTION_ALL_MASK = (3<<OPTIONAL_MASK_SHIFT_BIT)
}SignedDataPayloadOptionsMask;


struct SignedDataPayload
{
    /* this is the data has to be sent */
    SignedDataPayloadOptionsMask mask;
    Ieee1609Dot2Data *data;
    HashedData32 *extDataHash;
};
typedef struct SignedDataPayload SignedDataPayload;

/*6.3.6 */
struct ToBeSignedData
{
    SignedDataPayload payload;
    HeaderInfo headerInfo;
    
};
typedef struct ToBeSignedData ToBeSignedData;


/*6.3.4 */
typedef struct SignedData
{
    HashAlgorithmType hashAlgorithm;
    ToBeSignedData toBeSignedData;
    SignerIdentifier signer;
    Signature signature;
}SignedData;

/* 6.3.3 */
typedef enum
{
    Ieee1609Dot2ContentUnsecuredData,
    Ieee1609Dot2ContentSignedData,
    Ieee1609Dot2ContentEncrData,
    Ieee1609Dot2ContentSignedCertReq,
}Ieee1609Dot2ContentType;


struct ieee1609Dot2Content
{
    Ieee1609Dot2ContentType type;
    union 
    {
        OctetString unsecuredData;
        SignedData signedData;
        /* TBD: add the types of encrypted data and signed cert request */   
    }content;
#define SIGNEDDATA  content.signedData
#define UNSECUREDDATA content.unsecuredData

};
typedef struct ieee1609Dot2Content Ieee1609Dot2Content;

/* 6.3.2 */
struct Ieee1609Dot2Data
{
    uint8_t protocolVersion;
    Ieee1609Dot2Content content;
};
//typedef struct ieee1609Dot2Data Ieee1609Dot2Data;

#ifdef _cplusplus
}
#endif

#endif //__IEEE_1609DOT2COMMON_HPP__
