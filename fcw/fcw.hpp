#ifndef __FCW_HPP__
#define __FCW_HPP__
#include <iostream>
#include <math.h>
#include <memory>

namespace v2x
{

const int MAX_V2X_EE = 10;

/* define a entity with dimentions and weight */
struct ee_spd
{
    /* speed along the x axis, and y axis, z axis (even though we are not flying yet) */
    double x, y, z;
    ee_spd():x(0.0),y(0.0),z(0.0){}
    ee_spd& operator=(ee_spd &that)
    {
        this->x = that.x;
        this->y = that.y;
        this->z = that.z;
        return *this;
    }
};
struct ee_pos
{
    /* current position */
    double lat, lng, alt;
    ee_pos():lat(0.0),lng(0.0),alt(0.0){}
    ee_pos& operator=(ee_pos &that)
    {
        this->alt = that.alt;
        this->lng = that.lng;
        this->alt = that.alt;
        return *this;
    }
};

struct ee
{
    private:
        double mass;            key[N--] = nullptr;

        /* speed and position */
        ee_spd spd;
        ee_pos pos;
        double length, width;
        const double INIFINITY = double(-1.0);
        int id;

    public:
        ee():mass(0.0),length(300.0), width(400.0){ }
        /* copy constructor */
        ee(ee &that){
            mass = that.mass;
            spd = that.spd;
            pos = that.pos;
            length = that.length;
            width = that.width;
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


        double timeToCollide(ee &that)
        {
            if(*this == that) return INIFINITY;
            double dx = that.pos.lat - pos.lat;
            double dy = that.pos.lng - pos.lng;
            double dvx = that.spd.x - spd.x;
            double dvy = that.spd.y -  spd.y;

            double dvdr = dx * dvx +  dy * dvy;
            if(dvdr > 0) return INIFINITY;

            double dvdv  = pow(dvx, 2) + pow(dvy, 2);
            double drdr = pow(dx, 2) + pow(dy, 2);
            double sigma = radius() + radius(that);
            double d = (dvdr * dvdr) - dvdv * (drdr -  pow(sigma, 2));
            if ( d < 0.0) return INIFINITY;
            return -(dvdr + sqrt(d))/dvdv;
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
            return *this;
        }

        int getId(){ return id;}


};

/* collision event between two end entities*/
class Event
{
    double t; /* time to the collision */
    ee a, b;     /* the two ee thats going to collide */
    int countA, countB; /* number of collisions for these two ees */

    public:
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
};




/* create a priority queue that contains the items in the
    order of collision event (time). The next collision is at the top
*/
 
template <typename T>
class MinPQ 
{
    const int MAX_PQ_SIZE=5;
    std::shared_ptr<T> key[MAX_PQ_SIZE];
    int N;


    void exch(int k1, int k2)
    {
        T temp = key[k2];
        key[k2] = key[k1];
        key[k1] = temp;
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
        int ret = key[k1]->compareTo(key[k2]);
        if(ret > 1)  _greater = true;
        return _greater;
    }

    public:
        MinPQ() 
        { 
            N = 0;
            for (int i=0; i < N; i++)
                Key[i] = nullptr;
        }
        MinPQ(T[] key_, int N_)
        {
            N = 0;
            for (int i=0; i < N_; i++)
            {
                key[N++] = key_[i];
                swim(i);
            }
        }

        void insert(std::shared_ptr<T> key)
        {
            bool _insert = false;
            if (N  < MAX_PQ_SIZE )
            {
                _insert = true;
            }
            if(_insert == false && 
                N >= MAX_PQ_SIZE && 
                greater(key, key[N]))
            {
                delMax();
                _insert = true;
            }

            if(_insert == true)
            {
                this->key[N] = key;
                swim(N++);
            }
            return;

        }
        T delMin() 
        {
            T key_ = key[0];
            exch(0, N--);
            sink(0);
            key[N+1] = nullptr;
            return key_;
        }

        T delMax()
        {
            T key_ = key[N--];
            key[N+1] = nullptr;
            return key_;
        }


        bool isEmpty() { return N == 0;}
        T max() { return key[N];}
        T min() { return key[0];}
        int size() { return N;}
};

} /* end of namespace v2x */
#endif // __FCW_HPP__
