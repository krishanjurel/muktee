#include "fcw.hpp"
#include <memory>

namespace v2x
{
class fcw
{
    MinPQ<Event> pq; /* priority queue */
    double t;  /* simulation clock time */
    ee ees[MAX_V2X_EE]; /* this is others */
    ee e; /* this is us */

    public:
        fcw() {
        }







        int init(){
            return 0;
        }
        int start()
        {
            return 0;
        }

        void newAdd(ee _ee)
        {
            double dt = e.timeToCollide(_ee);
            std::shared_ptr<Event> event (new Event(dt,e, _ee),[](Event *p){delete p;});
            pq.insert(event);
        }


















};




}; /* namespace v2x */