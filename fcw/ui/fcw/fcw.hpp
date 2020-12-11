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

const int MAX_V2X_EE = 10;
const int MAX_PQ_SIZE=MAX_V2X_EE;
const double X_LOW_LIMIT=100.0;
const double Y_LOW_LIMIT = 30.0;

const double X_HIGH_LIMIT=900.0;
const double Y_HIGH_LIMIT=400.0;
static std::default_random_engine gen;
static std::uniform_real_distribution<> pos_dist(X_LOW_LIMIT, X_HIGH_LIMIT);
static std::uniform_real_distribution<> spd_dist(2, 15.0);
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
    //ee_spd():x(0.0),y(0.0),z(0.0){}
    //ee_spd(double x_, double y_, doub)
    ee_spd& operator=(const ee_spd &that)
    {
        this->x = that.x;
        this->y = that.y;
        this->z = that.z;
        return *this;
    }
    friend std::ostream& operator<<(std::ostream& os, const ee_spd& spd) 
    {
        return os << "speed x/y/z " << spd.x << "/" << spd.y << "/" << spd.z << std::endl;
    }
};
struct ee_pos
{
    /* current position */
    double x, y, z;
    //ee_pos():lat(0.0),lng(0.0),alt(0.0){}
    ee_pos& operator=(const ee_pos &that)
    {
        this->x = that.x;
        this->y = that.y;
        this->z = that.z;
        return *this;
    }
    std::ostream& operator<< (std::ostream& os)
    {
        return os << "pos lat/long/alt " << x << "/" << y << "/" << z << std::endl;
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
        const double INIFINITY = 1000000.0;
        int id;
        ee_color color; /* green,yellow,red*/
        double dt;

    public:
        ee():mass(0.0),length(300.0), width(400.0){ }
        /* copy constructor */
        ee(const ee &that){
            mass = that.mass;
            spd = that.spd;
            pos = that.pos;
            length = that.length;
            width = that.width;
            dt=that.dt;
            id = that.id;
            color = green;
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
            return sqrt(pow(length, 2) + pow (width, 2));
        }
        double radius (ee &that)
        {
            return sqrt(pow(that.length, 2) +  pow(that.width, 2));
        }


        double timeToCollide(ee& that)
        {
            if(*this == that) return INIFINITY;

            pos << std::cout;
            that.pos << std::cout;

            double dx = that.pos.x - pos.x;
            double dy = that.pos.y - pos.y;
            double dvx = that.spd.x - spd.x;
            double dvy = that.spd.y -  spd.y;

            double dvdr = dx * dvx +  dy * dvy;
            if(dvdr > 0) 
            {
                dt=INIFINITY;
                return dt;
            }

            double dvdv  = pow(dvx, 2) + pow(dvy, 2);
            double drdr = pow(dx, 2) + pow(dy, 2);
            double sigma = radius() + that.radius();
            double d = (dvdr * dvdr) - dvdv * (drdr -  pow(sigma, 2));
            if ( d < 0.0) 
            {
                dt = INFINITY;
                return dt;
            }

            dt =  -(dvdr + sqrt(d))/dvdv;
            return dt;
        }
        double timeToEvent(){return dt;}
        double timeToHitTheVertWall() {return 0.0;}
        double timeToHitTheHorizWall() {return 0.0;}

        double bounceOff(ee &that) { return 0.0;}

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
            return *this;
        }

        void init()
        {
            std::cout << "Init position and speed " << std::endl;
            pos.x = rand_num(X_LOW_LIMIT, Y_HIGH_LIMIT);
            pos.y = rand_num(Y_LOW_LIMIT,Y_HIGH_LIMIT);
            spd.x = rand_num(50,150);
            spd.y = rand_num(50,150);
        }

        int getId(){ return id;}
        void setId(int id){ 
            this->id = id;
            //std::cout << " the id " << this->id << ":" << id << std::endl; 
            }
        /* move this element, by the time*/
        void move(double dt)
        {
            std::cout << "moving ee " << id << std::endl;
            pos.x = pos.x + spd.x * dt/1000;
            pos.y = pos.y + spd.y * dt/1000;
            pos.z = pos.z + spd.z * dt/1000;

            this->dt -= dt;
            
            if (pos.x <= X_LOW_LIMIT || 
                pos.x >= X_HIGH_LIMIT || 
                pos.y <= Y_LOW_LIMIT || 
                pos.y >= Y_HIGH_LIMIT)
                {
                    init();
                }
        }
        void draw()
        {
            /*draw the ball*/
            //std::cout << "draw id: " << id << " pos " << pos.x << "/" << pos.y << "/" << pos.z;
            //std::cout << " spd " << spd.x << "/" << spd.y << "/" << spd.z << std::endl;
        }

        ee_color colorGet(){ return color;}
        ee_spd& speedGet() { return spd;}
        ee_pos& posGet() { return pos;}


        bool operator<(const ee& that)
        {
            return dt < that.dt;
        }
};

using sharedEE = std::shared_ptr<ee>;

/* collision event between two end entities*/
class Event
{
    
    double t; /* time to the collision */
    sharedEE a, b;     /* the two ee thats going to collide */
    int countA, countB; /* number of collisions for these two ees */

    public:
        Event():t(0.0),a(),b(){};
        Event(double t_, sharedEE a_, sharedEE b_)
        {
            t = t_;
            a = a_;
            b = b_;
        }

        ~Event(){
            std::cout << "event " << b->getId() << " is destroyed " << std::endl;
        }

        int compareTo(Event& that) {
            //std::cout << "t:that" << t << ":" << that.t << std::endl;
            int ret = 0;
            if (t > that.t) ret = 1;
            else if (t < that.t) ret = -1;
            else ret = 0;
            return ret;
        }
        bool isValid() { return true;}
        double timeToEvent(){return t;}
        ee& eeGetA() {return *a.get();};
        ee& eeGetB() { return *b.get();}
};


template<typename T>
struct customLess
{
    bool operator() (T a, T b)
    {
        return a < b;
    }
};




/* create a priority queue that contains the items in the
    order of collision event (time). The next collision is at the top
*/
 
template <typename T>
class MinPQ 
{
    int firstEl, lastEl;
    int N;
    std::vector<T> events;

    void sort()
    {
        customLess<T> eventCompare;
        std::sort(events.begin(), events.end(), eventCompare);
        return ;
    }

    public:
        MinPQ() 
        { 
            firstEl = 0;
            lastEl = 0;
            events.clear();
            N = 0;
        }
        MinPQ(T key_[], int N_)
        {
            firstEl = 0;
            lastEl = 0;
            events.clear();
            N = 0;
        }

        //void insert(std::shared_ptr<T> ky_)
        void insert(T& ky_)
        {
            bool _insert = false;
            //T atlast = events.back();

            if(events.size() <= MAX_PQ_SIZE)
            {
                _insert = true;
            }


            if(events.size() >= MAX_PQ_SIZE)
            {
                --N;
                events.pop_back();
                _insert = true;
            }

            if(_insert == true)
            {
                ++N;
                events.push_back(ky_);
                sort();
            }
            return;

        }
        T delMin() 
        {
            T temp;
            if(firstEl != N)
            {
                
                temp = events[firstEl];
                firstEl ++;
            }else{
                firstEl = 0;
                N = 0;;
            }
            return temp;
            
        }

        T delMax()
        {
            T temp;
            if (N != 0)
            {
                temp = events[--N];
            }else{
                firstEl = 0;
                N = 0;
            }
            return temp;
        }


        bool isEmpty() { return firstEl==N;}
        T max() { return events[N-1];}
        T min() { return events[firstEl];}
        int size() { return N;}


        #if 0
        void print()
        {
            std::cout << "priority queue elemnets " <<std::endl;
            for (int i = 0; i < N; i ++)
            {
                std::cout << "id:col " << key[i]->eeGetB().getId() <<":"<< key[i]->timeToEvent() << std::endl;

            }
        }
        #endif

};


const static double MAX_TIME_DELTA=500;
const static double MIN_TIME_DELTA=100;

class fcw;
void collision_thread(std::shared_ptr<fcw> obj);


class fcw
{
    MinPQ<ee> *pq; /* priority queue */
    double t;  /* simulation clock time */
    ee ees[MAX_V2X_EE]; /* this is others */
    ee e; /* this is us */
    std::thread _thread;
    std::mutex _mtex;
    //Event *event;
    
    public:
        fcw() {
            pq = new MinPQ<ee>();
            for (int i = 0; i < MAX_V2X_EE; i++)
            {
                ees[i].init();
                ees[i].setId(i+1);
            }
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
            _thread.detach();
            return _thread;
        }

        void add(ee& _ee)
        {
            double dt = e.timeToCollide(_ee);
            std::cout << "time to collide:id1:id2 " << dt << ":" <<  e.getId() << ":" << _ee.getId() <<  std::endl;
            pq->insert(_ee);
        }

        std::vector<ee>& eesGet(std::vector<ee>& eeVector) 
        {
            std::lock_guard<std::mutex> lck(_mtex);
            {
                for (int i = 0; i < MAX_V2X_EE; i++)
                {
                    eeVector.push_back(ees[i]);
                }
                /* also push the current object */
                eeVector.push_back(e);
            }
            return eeVector;
        }


        /* function call operator overloaded */
        int operator()(int i)
        {
            int count = 0; 
            std::condition_variable cv;
            std::mutex mtx;
            //Event *evt;
            double dt = MAX_TIME_DELTA;
            int sz;
            int testCount = 0;
            //ee tempEE;
            
            while(Count++ < 5)
            {
                sz = pq->size();
                ee tempEE = pq->delMin();
                std::unique_lock<std::mutex> lck(mtx);
                cv.wait_for(lck, std::chrono::milliseconds(int(dt)));
                if (sz)
                {
                    dt = tempEE.timeToEvent();
                }
                if (dt > MAX_TIME_DELTA)
                    dt = MAX_TIME_DELTA;
                if (dt <= MIN_TIME_DELTA)
                    dt = MIN_TIME_DELTA;
                e.move(dt);
                e.draw();
                count = 0;
                std::cout << "number of elements " << sz << std::endl;
                while(count < sz)
                {

                    
                    ees[count].move(dt);
                    ees[count].draw();
                    ++count;
                }
                count = 0;
                while(count < MAX_V2X_EE)
                {
                    /* update the positions */
                    std::lock_guard<std::mutex> lck(_mtex);
                    {
                        std::cout << "count " << count << std::endl;
                        add (ees[count]);
                        ++count;
                    }
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
