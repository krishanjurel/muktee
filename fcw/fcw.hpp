#ifndef __FCW_HPP__
#define __FCW_HPP__
#include <iostream>
#include <math.h>
#include <memory>
#include <random>

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
static std::uniform_real_distribution<> spd_dist(-15.0, 15.0);




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
        this->z = that.z;
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
        const double INIFINITY = double(-1.0);
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


        void setSpeed(ee_spd &spd)
        {
            this->spd = spd;
        }

        void setPosition(ee_pos &pos)
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
            std::cout << "that id is " << that.id << std::endl;
            if(*this == that) return INIFINITY;
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

        ee& operator=(ee &that)
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
            std::cout << " the id " << this->id << ":" << id << std::endl; 
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
            std::cout << "id: " << id << " pos " << pos.x << "/" << pos.y << "/" << pos.z;
            std::cout << " spd " << spd.x << "/" << spd.y << "/" << spd.z << std::endl;
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

        int compareTo(Event that) {
            int ret = 0;
            if (that.t < t) ret = -1;
            else if (that.t > t) ret = 1;
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
    typedef Event* sharedT;
    sharedT key[MAX_PQ_SIZE];
    int N;
    


    void exch(int k1, int k2)
    {
        sharedT temp = sharedT(key[k2]);
        key[k2] = sharedT(key[k1]);
        key[k1] = sharedT(temp);
    }

    void swim(int k)
    {
        while(k > 1 && greater(k/2, k))
        {
            exch(k, k/2);
            k = k/2;
        }
    }
    void sink(int k)
    {
        while(2*k <= N)
        {
            int j = 2*k;
            if (j < N && greater(j, j+1)) j++;
            if(!greater(k, j)) break;
            exch(k, j);
            k = j;
        }
    }

    bool greater (int k1, int k2)
    {
        bool _greater = false;
        int ret = key[k1]->compareTo(*key[k2]);
        if(ret > 1)  _greater = true;
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
        void insert(T *ky_)
        {
            bool _insert = false;
            sharedT key_ = sharedT(ky_);
            //std::cout << "use count " << key_.use_count() << ":" << std::endl;
            if (N  < MAX_PQ_SIZE )
            {
                _insert = true;
            }
            if(_insert == false && 
                N >= MAX_PQ_SIZE && 
                key[N]->compareTo(*key_) > 1)
            {
                std::cout << "delete max " << N << std::endl;
                delMax();
                _insert = true;
          
            }

            if(_insert == true)
            {
                std::cout << "insert " << N << std::endl;
                this->key[N] = key_;
                swim(N++);
            }
            return;

        }
        T delMin() 
        {
            sharedT key_ = key[0];
            exch(0, N--);
            sink(0);
            key[N+1] = nullptr;
            return key_;
        }

        T delMax()
        {
            sharedT key_ = key[N--];
            std::cout << "delete " << N << std::endl;
            key[N+1] = nullptr;
            //return *(key_.get());
            return *key_;
        }


        bool isEmpty() { return N == 0;}
        sharedT max() { return key[N];}
        sharedT min() { return key[0];}
        int size() { return N;}
};

} /* end of namespace v2x */
#endif // __FCW_HPP__
