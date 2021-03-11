#include "widget.h"

#include <QApplication>
#include <QFrame>
#include <QRect>
#include <chrono>
#include <thread>
#include "include.h"
static std::thread m_thread;



static int test();

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    Widget w;
    return a.exec();

//    return test();
}




void test_collision()
{
    v2x::ee *ee1 = new v2x::ee();
    v2x::ee_spd spd1(-1,-1, 0);
    v2x::ee_pos pos1(448.9,162.9, 0);
    ee1->setId(0);
    ee1->setSpeed(spd1);
    ee1->setPosition(pos1);


    v2x::ee *ee2 = new v2x::ee();
    v2x::ee_spd spd2(2, -1, 0);
    v2x::ee_pos pos2(433.2,167.9, 0);
    ee2->setId(1);
    ee2->setSpeed(spd2);
    ee2->setPosition(pos2);


    double dt = ee1->timeToCollide(std::ref(*ee2));
    std::cout << " time to collidie " << dt << std::endl;
    delete ee1;
    delete ee2;
}



static int test()
{
    test_collision();
    return 0;
}



