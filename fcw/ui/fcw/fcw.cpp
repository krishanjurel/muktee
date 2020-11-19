#include "include.h"

namespace v2x
{
void collision_thread(std::shared_ptr<v2x::fcw> obj)
{
    /* call the overloaded function call operator */
    v2x::fcw *pObj = obj.get();
    pObj->operator()(0);
    return;
}
};


 std::shared_ptr<v2x::fcw> fcw_init()
{
    std::shared_ptr<v2x::fcw> fcw(new v2x::fcw());
    fcw->init();
    fcw->start(fcw);  
    return fcw;
}
