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
    epoch.tm_mday=0;
    epoch.tm_mon = 1;
    epoch.tm_year = (2004-1900);
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

int file_read(const char *file, uint8_t **buf, size_t *len)
{
    const size_t minBufSize = 256;
    const size_t readStep = 256;
    size_t read_;  /* how much read */
    // std::cout << "file_read " << file << std::endl;
    int fd  = open(file, O_RDONLY, S_IRUSR | S_IWUSR | S_IXUSR);
    if(fd == -1)
    {
        perror("file_read");
        *buf = nullptr;
        *len = 0;
        return fd;
    }

    uint8_t *buf_ = (uint8_t *)calloc(minBufSize, sizeof(char));
    *len = 0;
    do
    {
        read_ = read(fd, buf_ + *len, readStep);
        if(read_ == -1)
        {
            perror("file_read");
            *len = 0;
            break;
        }
        /* increment the count */
        *len += read_;

        if(read_ >= readStep)
        {
            buf_ = (uint8_t *)realloc(buf_, *len + minBufSize);
            /* error in allocating the buffer */
            if(buf_ == nullptr)
            {
                free(buf_);
                *len = 0;
                read_ = 0;
                buf_ = nullptr;
                break;
            }
        }
    }while(read_);

    if(*len == 0 && buf_ != nullptr)
    {
        free(buf_);
    }
    *buf = buf_;
    close(fd);
    return *len;
}

/* FIXME, take care of the errors */
int file_write(const char *file, const uint8_t *buf, size_t len)
{
    const char *cwd = get_current_dir_name();
    // std::cout << "file_write cwd " << cwd << std::endl;
    // std::cout << "file_write " << file << std::endl;
    int fd  = open(file, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IXUSR);
    if(fd == -1)
    {
        perror("file_write");
        // std::cout << "file_write error opening" << file << std::endl;
        return fd;
    }
    size_t wrote = write(fd, buf, len);
    close(fd);
    return wrote;
}

int file_path_create(std::string path)
{
    int comps = 0;
    std::string _path(path);
    /* get the current working directory */
    const char *cwd = get_current_dir_name();
    // std::cout << "file_path_create cwd " << cwd << std::endl;
    /* parse the string based on the forward slash, and ignore . and first slash */
    if(path.front() == '.')
    {
        path.erase(0,1);
        _path = std::string(cwd);
        _path.append(path);
    }

    /* the next character has to be /  or nothing */
    if(path.front() != '/')
    {
        comps = -1;
        free((void*)cwd);
        return comps;
    }

    size_t n = 0;
    size_t pos = 0;
    struct stat sb;
    while((n=_path.find('/')) != std::string::npos)
    {
        /* if it is the first character */
        if(n == 0)
            n++;
        std::string _temp = _path.substr(pos, n);
        // std::cout << " path component# " << (comps + 1) << " " << _temp << std::endl;
        if(stat(_temp.c_str(), &sb) != -1)
        {
            /* goto the current directory */
            chdir(_temp.c_str());
            if(comps) n++;
            /* remove the current substring from the _path */
            _path.erase(_path.begin(), _path.begin() + n);
            comps++;
            continue;
        }
        comps++;

        /* create create the directory */
        if(mkdir(_temp.c_str(), S_IRUSR | S_IWUSR | S_IXUSR) == -1)
        {
            perror(_temp.c_str());
            comps = -1;
            break;
        }

        /* goto the current directory */
        (void)chdir(_temp.c_str());
        if(comps) n++;
        /* remove the current substring from the _path */
        _path.erase(_path.begin(), _path.begin() + n);
    }

    // std::cout << "remainin path " << _path << std::endl;
    /* take care of the last component */
    if(comps != -1 && _path.size() != 0)
    {
        if(stat(_path.c_str(), &sb) == -1)
        {
            comps ++;
            /* create create the directory */
            if(mkdir(_path.c_str(), S_IRUSR | S_IWUSR | S_IXUSR) == -1)
            {
                perror(_path.c_str());
                comps = -1;
            }
        }
    }
    /* go back to the original directory */
    chdir(cwd);
    free((void *)cwd);
    return comps;
}

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
    os << std::hex;
    for(i=0; i < len; i++)
    {
        int c = (int)(buf[i]);
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

