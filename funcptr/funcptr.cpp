
#include <iostream>
#include <memory>
#include <vector>
#include <functional>

class message_handler
{
	public:
		virtual void callback() = 0;
        virtual void callback_(void *data, int length) = 0;
};


struct v2x_msg_hdr
{
	int psid; 	/*!< provider service identifier */
	int ssp;  	/*!< service specific permisisons */
};

struct v2x_msg_data
{
	void *data;			/*!<  pointer to incoming data */
	int length;			/*!< length of the data */
};



class bsm_msg : public message_handler
{
	private:
		v2x_msg_hdr hdr;	/*!< bsm msh header */
		void *data;			/*!< pointer to bsm message */
		int length;			/*!< length of the data */

	/*! \fn callback
		This function is a callback
	**/
	public:
	
		bsm_msg()
		{
			hdr={1,2};
			data = static_cast<void *>(new int(256));
			length = 256;
		}
	
		void callback() {
			std::cout << "bsm_msg::callback() called\n";
            std::cout << "id:ssp " << hdr.psid <<  ":" << hdr.ssp << std::endl;
		}

        void callback_(void *data, int length) {
            int *_data = static_cast<int *>(data);
            std::string _indata(std::to_string(*_data));
            std::cout << "incoming data and length is " << _indata << " " << length <<std::endl;
		}

        void test_ptr(int **data, int *length)
        {
            /* get the current pointer and values from here */
            int *data_ = *data;
            std::cout << "the current pointer and value is " << std::hex << data_ << " " << *data_ << std::endl;
            int *temp = new int[512];
            *temp = 512;
            std::cout << "the new  pointer and value is " << std::hex << temp << " " << *temp << std::endl;
            free(*data);
            *data = temp;
            return;
        }

};


class srm_msg : public message_handler
{
	private:
		v2x_msg_hdr hdr;	/*!< bsm msh header */
		void *data;			/*!< pointer to bsm message */
		int length;			/*!< length of the data */

	/*! \fn callback
		This function is a callback
	**/
	public:
	
		srm_msg()
		{
			hdr={3,4};
			data = static_cast<void *>(new int(256));
			length = 256;
		}
	
		void callback() {
			std::cout << "srm::callback() called\n";
            std::cout << "id:ssp " << hdr.psid <<  ":" << hdr.ssp << std::endl;
		}


        void callback_(void *data, int length) {
            int *_data = static_cast<int *>(data);
            std::string _indata(std::to_string(*_data));
            std::cout << "incoming data and length is " << _indata << " " << length <<std::endl;
		}
};


class v2x
{
	std::vector<message_handler *> handlers;
    std::function<void (void *, int)> pfn;
   
    void *data;
    int length;
	
	public:
		v2x() {handlers.clear();}
		void add_handler(message_handler *handler)
		{
			return handlers.push_back(handler);
		}
		void call_handlers()
		{
            int i = 1000;
			for (auto handler:handlers)
			{
                using std::placeholders::_1;
                using std::placeholders::_2;
                pfn = std::bind(&message_handler::callback_, handler, _1, _2);
                data = static_cast<void *>(new int (i));
                ++ i;
                pfn(data, i);
                //handler->callback_(data, i);
			}
		}
};

int main()
{
	v2x *pV2X = new v2x();
    int *temp = new int(1024);
    *temp = 1024;
    int length = 1024;
	bsm_msg *pBsm = new bsm_msg();
	srm_msg *pSrm = new srm_msg();

    std::cout << "from main, ptr and value " << std::hex << temp << " " << *temp << std::endl;
    pBsm->test_ptr(&temp,&length);
    std::cout << "in main, ptr and value " << std::hex << temp << " " << *temp << std::endl;

    free (temp);



	
	pV2X->add_handler(pBsm);
	pV2X->add_handler(pSrm);
	
	pV2X->call_handlers();
	return 0;
	
}
