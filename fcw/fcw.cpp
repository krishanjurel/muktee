#include "fcw.hpp"
#include <memory>
#include <thread>
#include <random>
#include <chrono>
#include <condition_variable>

namespace v2x
{
class fcw; /* forward declaration */
static void collision_thread(std::shared_ptr<fcw> obj);
#if 0
static std::default_random_engine gen;
static std::uniform_real_distribution<> pos_dist(-15.0, 15.0);
static std::uniform_real_distribution<> spd_dist(-15.0, 15.0);
#endif
const static double MAX_TIME_DELTA=500;
const static double MIN_TIME_DELTA=100;

class fcw
{
    MinPQ<Event> *pq; /* priority queue */
    double t;  /* simulation clock time */
    ee ees[MAX_V2X_EE]; /* this is others */
    ee e; /* this is us */
    std::thread _thread;
    Event *event;
    
    public:
        fcw() {
            pq = new MinPQ<Event>();
            ee_spd spd{2.0,5.0,0.0};
            ee_pos pos{2.0, 5.0, 0.0};
            std::cout << spd;
            pos << std::cout;
            for (int i = 0; i < MAX_V2X_EE; i++)
            {
                //ees[i].setSpeed(spd);
                //ees[i].setPosition(pos);
                ees[i].init();
                ees[i].setId(i+1);
            }

            //e.setSpeed(spd);
            //e.setPosition(pos);
            e.init();
            e.setId(0);
        }


        int init(){
            return 0;
        }
        std::thread start(std::shared_ptr<fcw> obj)
        {
            std::cout << "thread start" << std::endl;
            std::thread _thread(collision_thread, obj);
            return _thread;
        }

        void add(ee _ee)
        {
            double dt = e.timeToCollide(_ee);
            std::cout << "add ee id " << _ee.getId() << std::endl;
            event = new Event(dt, e, _ee);
            //std::shared_ptr<Event> event (new Event(dt,e, _ee),[](Event *p){delete p;});
            std::cout << "add_ ee id " << _ee.getId() << std::endl;
            //pq->insert(std::shared_ptr<Event>(new Event(dt,e, _ee),[](Event *p){delete p;}));
            pq->insert(event);
        }


        /* function call operator overloaded */
        int operator()(int i)
        {
            int count = 0; 
            std::condition_variable cv;
            std::mutex mtx;
            //std::shared_ptr<Event> evt;
            Event *evt;
            double dt = MAX_TIME_DELTA;
            int sz;
            
            while(true)
            {
                sz = pq->size();
                std::unique_lock<std::mutex> lck(mtx);
                cv.wait_for(lck, std::chrono::milliseconds(int(dt)));
                if (sz)
                {
                    dt = evt->timeToEvent();
                }
                if (dt > MAX_TIME_DELTA)
                    dt = MAX_TIME_DELTA;
                if (dt <= MIN_TIME_DELTA)
                    dt = MIN_TIME_DELTA;
                e.move(dt);
                e.draw();
                count = 0;
                while(count < sz)
                {
                    /* this will be our next event */
                    evt = pq->min();
                    ee b = evt->eeGetB();
                    b.move(dt);
                    b.draw();
                    ++count;
                }
                count = 0;
                while(count < MAX_V2X_EE)
                {
                    std::cout << "count " << count << std::endl;
                    add (ees[count]);
                    ++count;
                }
            }



            #if 0
            while(count++ < 10)
            {
                double pos_x = pos_dist(gen);
                double pos_y = pos_dist(gen);
                double spd_x = spd_dist(gen);
                double spd_y = spd_dist(gen);
                std::cout << "write stream " ;
                std::cout << pos_dist(gen) << std::endl;
                std::cout << "position " << std::fixed << pos_x << ":" << pos_y << std::endl;
                std::cout << "speed " << std::fixed << spd_x << ":" << spd_y << std::endl;
                std::this_thread::sleep_for<int, std::milli>(std::chrono::duration<int, std::milli>(1000));
            }
            #endif
            return 0;
        }

};

static void collision_thread(std::shared_ptr<fcw> obj)
{
    /* call the overloaded function call operator */
    fcw *pObj = obj.get();
    pObj->operator()(0);

}

}; /* namespace v2x */



int main()
{
    std::shared_ptr<v2x::fcw> fcw(new v2x::fcw());
    std::thread fcwThread;

    fcw->init();
    fcwThread = fcw->start(fcw);
   // int i = fcw->operator()(0);
    fcwThread.join();
    return 0;
}