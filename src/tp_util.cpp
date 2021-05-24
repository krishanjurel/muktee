#include "tp_util.hpp"

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
    struct tm epoch = {0};
    epoch.tm_sec = 0;
    epoch.tm_min=0;
    epoch.tm_hour = 0;
    epoch.tm_mday=1;
    epoch.tm_mon = 0;
    epoch.tm_year = 2004;
    epoch.tm_isdst = 0;
    
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


// void* buf_alloc(size_t s)
// {
//     void *addr_ = calloc(s,1);
//     return addr_;
// }
// /* only alloc if addr_ != addr or s >= allocated_ */
// void *buf_realloc(void *addr, size_t s)
// {
//     void *addr_ = realloc(addr, s);
//     return addr_;
// }
// void buf_free(void *addr)
// {
//     free (addr);
// }





#ifdef __cplusplus
}
#endif

void print_data(const char* file, const uint8_t *buf, size_t len)
{
    size_t i = 0, j = 0;
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

