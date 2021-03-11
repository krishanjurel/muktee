#ifndef __FCW_HPP__
#define __FCW_HPP__
#include <iostream>
#include <math.h>
#include <memory>
#include <random>
#include <cassert>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <time.h>
#include <cstdlib>
#include <algorithm>

namespace v2x
{

//using pow=std::pow;

const int MAX_V2X_EE = 50;
const int MAX_PQ_SIZE=5;
const double X_LOW_LIMIT=20.0;
const double Y_LOW_LIMIT=20.0;

const double X_HIGH_LIMIT=500.0;
const double Y_HIGH_LIMIT=500.0;
static std::default_random_engine gen;
static std::uniform_real_distribution<> pos_dist(X_LOW_LIMIT, X_HIGH_LIMIT);
static std::uniform_real_distribution<> spd_dist(-20.0, 20.0);
double rand_num(double start, double end);




enum ee_color {
    green,
    yellow,
    red
};

/* define a entity with dimentions and weight */
struct ee_spd
{
    /* speed along the x axis, and y axis, z axis (even though we are not flying yet) */
    double x, y, z;
    ee_spd():x(0.0),y(0.0),z(0.0){}
    ee_spd(double x_, double y_, double z_):x(x_),y(y_), z(z_){}
    ee_spd(const ee_spd& that):x(that.x),y(that.y),z(that.z){};

    ee_spd& operator=(const ee_spd &that)
    {
        this->x = that.x;
        this->y = that.y;
        this->z = that.z;
        return *this;
    }
    friend void operator<<(std::ostream& os, const ee_spd& spd)
    {
        os << "speed x/y/z " << spd.x << "/" << spd.y << "/" << spd.z << std::endl;
    }
};
struct ee_pos
{
    /* current position */
    double x, y, z;
    ee_pos():x(0.0),y(0.0),z(0.0){}
    ee_pos(double x_, double y_, double z_):x(x_),y(y_), z(z_){}
    ee_pos(const ee_pos& that):x(that.x),y(that.y),z(that.z){};

    ee_pos& operator=(const ee_pos &that)
    {
        this->x = that.x;
        this->y = that.y;
        this->z = that.z;
        return *this;
    }

    void operator<< (std::ostream& os)
    {
        os << "pos lat/long/alt " << x << "/" << y << "/" << z << std::endl;
    }
};


struct ee
{
    private:
        double mass;
        /* speed and position */
        ee_spd spd;
        ee_pos pos;
        double length, width;
        double distance;
        const double INIFINITY = 100000.0;
        int id;
        bool tracked; /* being tracked or not */
        double dt;

    public:
        ee():mass(0.0),length(300.0), width(400.0){
            distance = 0;
            dt = 0;
            id = 0;
            tracked = false;
        }
        /* copy constructor */
        ee(const ee &that){
            mass = that.mass;
            spd = that.spd;
            pos = that.pos;
            length = that.length;
            width = that.width;
            dt=that.dt;
            id = that.id;
            tracked = that.tracked;
            distance = that.distance;
        }

        /* move constructor */
        ee(const ee&& that){
            mass = that.mass;
            spd = that.spd;
            pos = that.pos;
            length = that.length;
            width = that.width;
            dt=that.dt;
            id = that.id;
            tracked = that.tracked;
            distance = that.distance;
        }

        ~ee()
        {
//            std::cout << id << "is destroyed " << std::endl;
        }

        void setSpeed(ee_spd& spd)
        {
            this->spd = spd;
        }

        void setPosition(ee_pos& pos)
        {
            this->pos = pos;
        }

        double radius()
        {
            return 20.0;//sqrt(pow(length, 2) + pow (width, 2));
        }


        double timeToCollide(ee& that)
        {
            if(operator==(that))
            {
                dt = INFINITY;
                that.dt = dt;
                std::cout << "fourth check " << std::endl;
                return INIFINITY;
            }



            double dx = that.pos.x - pos.x;
            double dy = that.pos.y - pos.y;
            double dvx = that.spd.x - spd.x;
            double dvy = that.spd.y -  spd.y;

            double dvdr = dx * dvx +  dy * dvy;


            double dvdv  = pow(dvx, 2) + pow(dvy, 2);
            double drdr = pow(dx, 2) + pow(dy, 2);
            distance = drdr;
            that.distance = distance;

            double sigma = radius() + that.radius();
            double d = pow(dvdr, 2) - (dvdv * (drdr -  pow(sigma, 2)));
            if ( d < 0.0) 
            {
////                std::cout << "third check " << std::endl;

////                std::cout << "this " << std::endl;
////                std::cout << spd;
////                pos << std::cout;

////                std::cout << "that " << std::endl;
////                std::cout << that.spd;
////                that.pos << std::cout;
//                   std::cout << " third distance " << id << " that " << that.id << " " << d << std::endl;

                that.dt = INFINITY;;
                return that.dt;
            }

            /* if the average speed is zero,
             *  in our case it can happen, since we are using random numbers.
             *  Handle gracefully and claim never meet.
            */
            if(dvx == dvy && dvx == 0)
            {
////                std::cout << "second check " << std::endl;
////                std::cout << "this " << std::endl;
////                std::cout << spd;
////                pos << std::cout;

////                std::cout << "that " << std::endl;
////                std::cout << that.spd;
////                that.pos << std::cout;

//                std::cout << " second speed " << id << " that " << that.id << " " << dvx << std::endl;

                that.dt = INFINITY;;
                return that.dt;
            }

            if(dvdr > 0)
            {
////                std::cout << "first check " << std::endl;

////                std::cout << "this " << std::endl;
////                std::cout << spd;
////                pos << std::cout;

////                std::cout << "that " << std::endl;
////                std::cout << that.spd;
////                that.pos << std::cout;
//                std::cout << " dvdr this  " << id << " that " << that.id << " " << dvdr << std::endl;

                that.dt = INFINITY;;
                return that.dt;
            }



            dt =  -(dvdr + sqrt(d))/dvdv;
            that.dt = dt;

//            std::cout << "this " << std::endl;
//            std::cout << spd;
//            pos << std::cout;

//            std::cout << "that " << std::endl;
//            std::cout << that.spd;
//            that.pos << std::cout;

//            std::cout << "timetohit " << id << " and " << that.id << " is "  << that.dt << std::endl;
            return dt;
        }
        double distanceGet() { return distance;}
        double timeToEvent(){return dt;}
        double timeToHitTheVertWall() {return 0.0;}
        double timeToHitTheHorizWall() {return 0.0;}

        double bounceOff(ee &that) { return that.dt;}

        double bounceOffVertWall() {return 0.0;}
        double bounceOffHorizWall() {return 0.0;}

        bool operator==(ee &that)
        {
            return this->id == that.id;
        }

        ee& operator=(const ee& that)
        {
            mass = that.mass;
            spd = that.spd;
            pos = that.pos;
            length = that.length;
            width = that.width;
            id=that.id;
            tracked = that.tracked;
            distance = that.distance;
            dt = that.dt;
            return *this;
        }

        void init()
        {
            pos.x = rand_num(X_LOW_LIMIT, X_HIGH_LIMIT);
            pos.y = rand_num(Y_LOW_LIMIT,Y_HIGH_LIMIT);
            spd.x = rand_num(-50,50);
            spd.y = rand_num(-20,20);

        }

        int getId() const { return id;}
        void setId(int id){ 
            this->id = id;
            }
        /* move this element, by the time*/
        void move(double dt_)
        {
            pos.x = pos.x + spd.x * dt_/1000;
            pos.y = pos.y + spd.y * dt_/1000;
            pos.z = pos.z + spd.z * dt_/1000;

            
            if (pos.x <= X_LOW_LIMIT || 
                pos.x >= X_HIGH_LIMIT || 
                pos.y <= Y_LOW_LIMIT || 
                pos.y >= Y_HIGH_LIMIT)
                {
                    init();
                }
        }

        bool trackedGet(){ return tracked;}
        void trackedSet(bool tracked) { this->tracked = tracked;}
        ee_spd& speedGet() { return spd;}
        ee_pos& posGet() { return pos;}


        bool operator<(const ee* that) const
        {
//            std::cout << "compare " << id <<":"<< dt << "<" <<that->id <<":"<< that->dt << std::endl;
            return dt < that->dt;
        }



        /* return the time to collision to that end entity */
        double timeToEvent() const
        {
            return dt;
        }
};

using sharedEE = std::shared_ptr<ee>;
typedef ee* ptrEE;


bool eventCompare(const ptrEE a, const ptrEE b);


/* create a priority queue that contains the items in the
    order of collision event (time). The next collision is at the top
*/

 
//template <typename T>
class MinPQ
{
    int firstEl, lastEl;
    int N;
    std::vector<ptrEE> events;

    void sort()
    {
        std::sort(events.begin(), events.end(),eventCompare);
    }

    public:
        MinPQ() 
        { 
            firstEl = 0;
            lastEl = 0;
            events.clear();
            events.reserve(MAX_PQ_SIZE);
            N = 0;
        }



        void insert(const ptrEE ky_)
        {
            bool _insert = false;

            /* if its not colliding, dont put into priority queue */
            if(ky_->timeToEvent() == INFINITY)
            {
                return;
            }



            if(events.size() < MAX_PQ_SIZE)
            {
                _insert = true;

            }else
            {
                /* grab the last element */
                ptrEE last = events[N-1];
                if (eventCompare(ky_, last) == true)
                {
                    //std::cout << "remove the last one " << std::endl;
                    --N;
                    ptrEE temp = events[N];
                    temp->trackedSet(false);
                    events.pop_back();
                    _insert = true;
                }
            }

            if(_insert == true)
            {
                ky_->trackedSet(true);
                events.push_back(ky_);
                ++N;
                sort();
            }
            return;

        }


        bool isEmpty() { return firstEl==N;}
        ptrEE max() { return events[N-1];}
        ptrEE min() { return events[firstEl];}
        int size() { return N;}
        void clear() { /* clear the list */
            events.clear();
            N = 0;
        }

        //const std::vector<ptrEE>& get() { return events;}


        void print()
        {
//            for (unsigned long long i = 0; i < events.size(); i ++)
//            {
//               ptrEE temp = events[i];
//                std::cout << "PQ id:timetocollision " << temp->getId() << ":" << temp->timeToEvent() << std::endl;
//            }
        }
};


const static double MAX_TIME_DELTA=500;
const static double MIN_TIME_DELTA=50;

class fcw;
void collision_thread(std::shared_ptr<fcw> obj);


class fcw
{
    MinPQ *pq;
    ptrEE ees[MAX_V2X_EE]; /* this is others */
    ptrEE e; /* this is me */
    std::thread _thread;
    std::mutex _mtex;
    
    public:
        fcw() {
            pq = new MinPQ();
            for (int i = 0; i < MAX_V2X_EE; i++)
            {
                ees[i] = new ee();
                ees[i]->setId(i+1);
                ees[i]->init();
            }
            e = new ee();
            e->setId(0);
            e->init();
        }


        int init(){
            return 0;
        }

        void start()
        {
            std::cout << "thread start" << std::endl;
            _thread = std::thread(&fcw::operator(), this);
            _thread.detach();
            return;
        }

        void add(ptrEE _ee)
        {
            pq->insert(_ee);
        }

        std::vector<ee>& eesGet(std::vector<ee>& eeVector)
        {
            std::lock_guard<std::mutex> lck(_mtex);
            {
                eeVector.clear();
                /* get the list of priority queue */
//                const std::vector<ee>& pqList = pq->get();
//                const std::vector<ptrEE>& pqList = pq->get();
//                for (auto&& ee_ : pqList)
//                {
//                    int id = ee_->getId();
//                    ees[id-1]->trackedSet(true);
//                }
                for (int i = 0; i < MAX_V2X_EE; i++)
                {
                    eeVector.push_back(std::ref(*ees[i]));
                }
                /* also push the current object */
                eeVector.push_back(std::ref(*e));
            }
            return eeVector;
        }


        /* function call operator overloaded */
        int operator()()
        {
            int count = 0; 
            std::condition_variable cv;
            std::mutex mtx;
            //Event *evt;
            double dt = MIN_TIME_DELTA;
            //ee tempEE;
            /* loop forever */
            while(true)
            {
                std::unique_lock<std::mutex> lck(mtx);
                cv.wait_for(lck, std::chrono::milliseconds(int(dt)));
                /* update the positions */
                std::lock_guard<std::mutex> lck_(_mtex);
                {

                    if (dt > MAX_TIME_DELTA)
                        dt = MAX_TIME_DELTA;
                    if (dt <= MIN_TIME_DELTA)
                        dt = MIN_TIME_DELTA;

                    e->move(dt);
                    count = 0;
                    while(count < MAX_V2X_EE)
                    {
                        ees[count]->trackedSet(false);
                        ees[count]->move(dt);
                        e->timeToCollide(std::ref(*ees[count]));
                        ++count;
                    }
                    count = 0;
                    pq->clear();
                    {
                        while(count < MAX_V2X_EE)
                        {
                            add (ees[count]);
                            ++count;
                        }
                    }
                    pq->print();
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
} /* end of namespace v2x */
#endif // __FCW_HPP__
