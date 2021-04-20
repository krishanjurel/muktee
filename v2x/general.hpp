/* file to implement general function of memory, logging etc */

#include <string>
#include <memory>

template< class T>
struct custom_allocator
{
    using ptr = T*;
    using type = T;
    using value_type = T;
    size_t MAX_SIZE;

    public:

        template <class U> constexpr custom_allocator (const custom_allocator <U>&) noexcept {}

        custom_allocator() = default;
        // {
        //     std::cout << "custom_allocator" << std::endl;
        // }=default;
        ~custom_allocator(){
            std::cout << "~custom_allocator" << std::endl;
        };

        ptr address (T& x)
        {
            ptr addr = &x;
            std::cout << "address " << std::hex << addr << std::endl;
            return addr;
        }

        ptr allocate(size_t n, const void* hint =0)
        {
            size_t bytes = n * sizeof(T);
            std::cout << "allocator:: allocate " << bytes << " bytes " << std::endl;
            ptr ret =  (ptr)(::operator new (bytes));
            std::cout << std::hex << ret << std::endl;
            return ret;
        }
        void deallocate(T* p, std::size_t n)
        {
            std::cout << "allocator:: deallocate " << p << std::endl;
            ::operator delete((void *)p);
        }

        void construct (ptr p, const T& val)
        {
            std::cout << "allocator:: construct addr " << std::hex << std::showbase << p << std::endl;
            std::cout << "allocator:: construct val " << std::hex << std::showbase << val << std::endl;
            if (p != nullptr)
            {
                *p = std::move(val);
            }
        }

        void destroy(ptr p)
        {
            std::cout << "allocator:: destroy " << std::endl;
            p->~T();
        }

        size_t max_size()
        {
            return 1024;
        }
        bool operator== (const custom_allocator& a)
        {
            return true;
        }
        bool operator != (const custom_allocator& a)
        {
            return false;
        }


};



template <class T>
struct Mallocator
{
  typedef T value_type;
 
  Mallocator () = default;
  template <class U> constexpr Mallocator (const Mallocator <U>&) noexcept {}
 
  [[nodiscard]] T* allocate(std::size_t n) {
    if (n > std::numeric_limits<std::size_t>::max() / sizeof(T))
      throw std::bad_alloc();
 
    if (auto p = static_cast<T*>(std::malloc(n*sizeof(T)))) {
      report(p, n);
      return p;
    }
 
    throw std::bad_alloc();
  }
 
  void deallocate(T* p, std::size_t n) noexcept {
    report(p, n, 0);
    std::free(p);
  }
 
private:
  void report(T* p, std::size_t n, bool alloc = true) const {
    std::cout << (alloc ? "Alloc: " : "Dealloc: ") << sizeof(T)*n
      << " bytes at " << std::hex << std::showbase
      << reinterpret_cast<void*>(p) << std::dec << '\n';
  }
};
 
template <class T, class U>
bool operator==(const Mallocator <T>&, const Mallocator <U>&) { return true; }
template <class T, class U>
bool operator!=(const Mallocator <T>&, const Mallocator <U>&) { return false; }





template<typename CharT=char, typename Traits=std::char_traits<CharT>, class Allocator=custom_allocator<char>>
class mystring_stream:public std::basic_stringstream<CharT, Traits, Allocator>
{
  /* pointer to private raw string device */
  std::basic_stringbuf<CharT, Traits, Allocator> *pRdbuf;

  public:
    mystring_stream():std::basic_stringstream<char,std::char_traits<char>, custom_allocator<char>>(){
      std::cout << "mystring_stream::mystring" << std::endl;
      /* create a pointer to the rDbuf */
      pRdbuf = new  std::basic_stringbuf<CharT, Traits, Allocator>();
    }
    void clear()
    {
      delete pRdbuf;
      pRdbuf = new  std::basic_stringbuf<CharT, Traits, Allocator>();
    }

    std::basic_stringbuf<CharT, Traits, Allocator>* rdbuf() const
    {
      return pRdbuf;
    }
};


template <typename T>
class mytype
{
  T value;

  public:
    mytype(T& valu_):value(valu_){

      std::cout << "mytype::mytype(T& valu_) " << std::endl;
    }
    ~mytype()
    {
      std::cout << "mytype::~mytype() " << std::endl;
    }

    const T& Value() const
    {
      return value;
    }
};


/* specific type */
template<typename T>
class myderivedtype: public mytype<T>
{
    public:
      myderivedtype(T& b):mytype<T>(b){
        std::cout << "myderivedtype:: myspecifictype(T &b) " << std::endl;
      }

      ~myderivedtype(){
        std::cout << "myderivedtype:: ~myspecifictype(T &b) " << std::endl;
      };

      // void print()
      // {
      //   std::cout << "myderivedtype::print " <<  value << std::endl;
      // }
};



template<>
class myderivedtype<double>: public mytype<double>
{
    public:
      myderivedtype(double& b):mytype<double>(b){
        std::cout << "myderivedtype:: myspecifictype(double &b) " << std::endl;
      }

      ~myderivedtype(){
        std::cout << "myderivedtype:: ~myspecifictype(double &b) " << std::endl;
      };

      // void print()
      // {
      //   std::cout << "myderivedtype::print " <<  value << std::endl;
      // }
};


















