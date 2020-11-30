#include <iostream>
#include <list>
#include <functional>
#include <thread>
#include <chrono>


class base
{
    public:
    base() {};
    virtual void callback() =0;
};

using pfn = std::function<void()>;
typedef void (*hello)(int, int);

class A
{
    /* all the clients */
    std::list<pfn> clients;
    std::thread m_thread;
    public:
    A(){clients.clear();}
    void register_clients(const pfn& _pfn)
    {
        clients.push_back(_pfn);
    }

    void register_clients(base& obj)
    {
        std::function<void()> _pfn = std::bind(&base::callback, &obj);
        clients.push_back(_pfn);
    }

    void start()
    {
        m_thread = std::thread(&A::operator(), this);
        m_thread.detach();
    }

    void operator()()
    {
        for( auto& client: clients)
        {
            /* call the client */
            client();
        }
        std::cout << std::endl;

        return;
    }
};

class B: public base
{
    std::string name;
    public:
        explicit B(std::string _name):base(),name(_name){};
        void callback()
        {
            std::cout << name;
        }
};


void pointer_to_function_test()
{
    std::cout << "Hi its me static standalone function" << std::endl;
}

void pointer_to_function_test1()
{
    std::cout << "Hi its me static standalone function1" << std::endl;
}

void pointer_to_function_test2()
{
    std::cout << "Hi its me static standalone function2" << std::endl;
}




int main()
{
    A *a = new A();
    base *b1 = new B("Hello");
    base *b2 = new B(" World");
    base *b3 = new B("!");
    //pfn pPfn=std::bind(&B::callback, b1);
    //pfn pPfn2 = std::bind(&B::callback, b2);
    //a->register_clients(pointer_to_function_test);
    //a->register_clients(pointer_to_function_test1);
    //a->register_clients(pointer_to_function_test2);
    a->register_clients(*b1);
    a->register_clients(*b2);
    a->register_clients(*b3);

    a->start();
    std::this_thread::sleep_for(std::chrono::seconds(10));
}
