#include "include.h"
#include <thread>
#include <chrono>
#include <random>




namespace v2x
{
    bool eventCompare(const ptrEE a, const ptrEE b)
    {
        return a->operator<(b);
    }


    double rand_num(double start, double end)
    {
        int diff = int(end-start);
        //srand(rand());
        int rnd = rand() % diff + start;

    //    std::cout << "random number " << rnd << std::endl;

        return double(rnd);
    }

};


 std::shared_ptr<v2x::fcw> fcw_init()
{
    std::thread m_thread;
    std::shared_ptr<v2x::fcw> fcw(new v2x::fcw());
    fcw->init();
    fcw->start();
    //m_thread.join();
    //std::this_thread::sleep_for(std::chrono::seconds(1));
    return fcw;
}
