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

namespace v2x
{

const int MAX_V2X_EE = 10;
const int MAX_PQ_SIZE=MAX_V2X_EE;
const double X_LOW_LIMIT=100.0;
const double Y_LOW_LIMIT = 100.0;

const double X_HIGH_LIMIT=1000.0;
const double Y_HIGH_LIMIT=1000.0;
static std::default_random_engine gen;
static std::uniform_real_distribution<> pos_dist(X_LOW_LIMIT, X_HIGH_LIMIT);
static std::uniform_real_distribution<> spd_dist(2, 15.0);




/* define a entity with dimentions and weight */
struct ee_spd
{
    /* speed along the x axis, and y axis, z axis (even though we are not flying yet) */
    double x, y, z;
    //ee_spd():x(0.0),y(0.0),z(0.0){}
    //ee_spd(double x_, double y_, doub)
    ee_spd& operator=(ee_spd &that)
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
    ee_pos& operator=(ee_pos &that)
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
        const double INIFINITY = double(100000.0);
        int id;
        int color; /* green,yellow,red*/
        double dt;

    public:
        ee():mass(0.0),length(300.0), width(400.0){ }
        /* copy constructor */
        ee(ee &that){
            mass = that.mass;
            spd = that.spd;
            pos = that.pos;
            length = that.length;
            width = that.width;
            dt=that.dt;
            id = that.id;
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

            //pos << std::cout;
            //that.pos << std::cout;

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
            double sigma = radius() + radius(that);
            double d = (dvdr * dvdr) - dvdv * (drdr -  pow(sigma, 2));
            if ( d < 0.0) 
            {
                dt = INFINITY;
                return dt;
            }
            dt =  -(dvdr + sqrt(d))/dvdv;
            return dt;
        }
        double timeToHitTheVertWall() {return 0.0;}
        double timeToHitTheHorizWall() {return 0.0;}

        double bounceOff(ee &that) { return 0.0;}
        double bounceOffVertWall() {return 0.0;}
        double bounceOffHorizWall() {return 0.0;}
        bool operator==(ee &that)
        {
            return this->id == that.id;
        }

        ee& operator=(ee& that)
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
            pos.x = pos_dist(gen);
            pos.y = pos_dist(gen);
            spd.x = spd_dist(gen);
            spd.y = spd_dist(gen);
        }

        int getId(){ return id;}
        void setId(int id){ 
            this->id = id;
            //std::cout << " the id " << this->id << ":" << id << std::endl; 
            }
        /* move this element, by the time*/
        void move(double dt)
        {
            pos.x = pos.x + spd.x * dt/1000;
            pos.y = pos.y + spd.y * dt/1000;
            pos.z = pos.z + spd.z * dt/1000;
            if(this->dt <= dt)
            {
                std::cout << "collision occured " << id << std::endl;
            }
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
};

/* collision event between two end entities*/
class Event
{
    double t; /* time to the collision */
    ee a, b;     /* the two ee thats going to collide */
    int countA, countB; /* number of collisions for these two ees */

    public:
        Event():t(0.0),a(),b(){};
        Event(double t_, ee a_, ee b_)
        {
            t = t_;
            a = a_;
            b = b_;
        }

        ~Event(){
            std::cout << "event " << b.getId() << " is destroyed " << std::endl;
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
        ee& eeGetA() {return a;};
        ee& eeGetB() { return b;}
};




/* create a priority queue that contains the items in the
    order of collision event (time). The next collision is at the top
*/
 
template <typename T>
class MinPQ 
{
    typedef std::shared_ptr<Event> sharedT;
    sharedT key[MAX_PQ_SIZE];
    int N;
    


    void exch(int k1, int k2)
    {
        //std::cout << "exch k1:k2 " << k1 <<":" << k2 << std::endl;
        assert((k1 >= 1) && (k2 >= 1));
        sharedT temp = sharedT(key[k2-1]);
        key[k2-1] = sharedT(key[k1-1]);
        key[k1-1] = sharedT(temp);
    }

    void swim(int k)
    {
        /* the indexing is zero index based, while tree is 1 index-based*/
        k += 1;
        //std::cout << "swimming " << k << std::endl;
        while(k > 1 && greater(k/2, k)==true)
        {
            exch(k, k/2);
            k = k/2;
        }
    }
    void sink(int k)
    {
        /* the indexing is zero index based, while tree is 1 index-based*/
        k += 1;
        //std::cout << "sinking " << k << std::endl;
        while(2*k <= N)
        {
            int j = 2*k;
            if (j < N && greater(j+1, j)==false) j++;
            if(greater(k, j) == false) break;
            exch(k, j);
            k = j;
        }
    }

    bool greater (int k1, int k2)
    {
        bool _greater = false;
        /* the tree is based on 1 index, but array is 0 indexed */
        assert(((k1 >= 1) && (k2 >= 1)));
        k1 -= 1;
        k2 -= 1;
        int ret = key[k1]->compareTo(*key[k2]);
        if(ret >= 1)  _greater = true;
        return _greater;
    }

    public:
        MinPQ() 
        { 
            N = 0;
            for (int i=0; i < N; i++)
                key[i] = nullptr;
        }
        MinPQ(T key_[], int N_)
        {
            N = 0;
            for (int i=0; i < N_; i++)
            {
                key[N++] = key_[i];
                swim(i);
            }
        }

        //void insert(std::shared_ptr<T> ky_)
        void insert(sharedT ky_)
        {
            bool _insert = false;
            sharedT key_ = sharedT(ky_);
            //std::cout << "use count " << key_.use_count() << ":" << std::endl;
            if (N  < MAX_PQ_SIZE )
            {
                _insert = true;
            }
            if(_insert == false && 
                N >= MAX_PQ_SIZE)
            {
                std::cout << "delete max " << N << std::endl;
                delMax();
                _insert = true;
          
            }

            if(_insert == true)
            {
                this->key[N] = key_;
                swim(N);
                N++;
            }
            return;

        }
        sharedT delMin() 
        {
            sharedT key_ = nullptr;
            int k = 1;
            if(isEmpty() == false)
            {
                key_ = key[0];
                {
                    exch(k, N);
                    N--;
                    sink(0);
                }
                key[N] = nullptr;
            }
            return key_;
        }

        sharedT delMax()
        {
            sharedT key_ = nullptr; 
            if(isEmpty() == false)
            {
                std::cout << "delete " << N << std::endl;
                key_ = key[--N];
                key[N] = nullptr;
            }
            return key_;
        }


        bool isEmpty() { return N == 0;}
        sharedT max() { return key[N-1];}
        sharedT min() { return key[0];}
        int size() { return N;}

        void print()
        {
            std::cout << "priority queue elemnets " <<std::endl;
            for (int i = 0; i < N; i ++)
            {
                std::cout << "id:col " << key[i]->eeGetB().getId() <<":"<< key[i]->timeToEvent() << std::endl;

            }
        }

};


const static double MAX_TIME_DELTA=500;
const static double MIN_TIME_DELTA=100;

class fcw;
void collision_thread(std::shared_ptr<fcw> obj);


class fcw
{
    MinPQ<Event> *pq; /* priority queue */
    double t;  /* simulation clock time */
    ee ees[MAX_V2X_EE]; /* this is others */
    ee e; /* this is us */
    std::thread _thread;
    //Event *event;
    
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

        MinPQ<Event> *pqGet() {
            return pq;
        }
        void add(ee _ee)
        {
            _ee.init();
            double dt = e.timeToCollide(_ee);
            std::cout << "time to collide:id1:id2 " << dt << ":" <<  e.getId() << ":" << _ee.getId() <<  std::endl;
            //event = new Event(dt, e, _ee);
            std::shared_ptr<Event> event (new Event(dt,e, _ee),[](Event *p){delete p;});
            //std::cout << "event: " <<std::hex << event << " id: "<< _ee.getId() << std::endl;
            //pq->insert(std::shared_ptr<Event>(new Event(dt,e, _ee),[](Event *p){delete p;}));
            pq->insert(event);
        }


        /* function call operator overloaded */
        int operator()(int i)
        {
            int count = 0; 
            std::condition_variable cv;
            std::mutex mtx;
            std::shared_ptr<Event> evt;
            //Event *evt;
            double dt = MAX_TIME_DELTA;
            int sz;
            
            while(true)
            {
                sz = pq->size();
                evt = pq->delMin();
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
                std::cout << "number of elements " << sz << std::endl;
                while(evt != nullptr)
                {
                    ee b = evt->eeGetB();
                    b.move(dt);
                    b.draw();
                    /* this will be our next event */
                    evt = pq->delMin();
                    ++count;
                }
                count = 0;
                while(count < MAX_V2X_EE)
                {
                    std::cout << "count " << count << std::endl;
                    add (ees[count]);
                    ++count;
                }
                pq->print();
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
