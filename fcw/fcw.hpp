#ifndef __FCW_HPP__
#define __FCW_HPP__
#include <iostream>

/* define a entity with dimentions and weight */
struct ee_spd
{
    /* speed along the x axis, and y axis, z axis (even though we are not flying yet) */
    double x, y, z;
    ee_spd():x(0.0),y(0.0),z(0.0){}
};
struct ee_pos
{
    /* current position */
    double lat, lng, alt;
    ee_pos():lat(0.0),lng(0.0),alt(0.0){}
};



struct ee
{
    private:
        double mass;
        /* speed and position */
        ee_spd spd;
        ee_pos pos;
        double ht, wdth;

    public:
     ee();
     double timeToCollide(ee &that);
     double timeToHitTheVertWall();
     double timeToHitTheHorizWall();

    double bounceOff(ee &that);
    double bounceOffVertWall();
    double bounceOffHorizWall();
};







#endif // __FCW_HPP__
