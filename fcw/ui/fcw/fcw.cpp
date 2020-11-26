#include "include.h"
#include <thread>
#include <chrono>
#include <random>


namespace v2x
{
void collision_thread(std::shared_ptr<v2x::fcw> obj)
{
    /* call the overloaded function call operator */
    //v2x::fcw *pObj = obj.get();
    std::cout << "coliision thread has started" <<std::endl;
    obj->operator()(0);
    return;
}

double rand_num(double start, double end)
{
    int diff = int(end-start);
    srand(rand());
    int rnd = rand() % diff + start;

    std::cout << "random number " << rnd << std::endl;

    return double(rnd);
}

};


 std::shared_ptr<v2x::fcw> fcw_init()
{
    std::thread m_thread;
    std::shared_ptr<v2x::fcw> fcw(new v2x::fcw());
    fcw->init();
    m_thread = fcw->start(fcw);
    //m_thread.join();
    //std::this_thread::sleep_for(std::chrono::seconds(1));
    return fcw;
}
