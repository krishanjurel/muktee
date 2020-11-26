#include "widget.h"
#include "ui_widget.h"
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <random>
#include <cstring>
#include <string>
#include <iostream>
#include <cstdlib>
#include <time.h>
#include "include.h"
#include <vector>


static std::default_random_engine gen;
static std::uniform_real_distribution<> x_pos_dist(100,900);
static std::uniform_real_distribution<> y_pos_dist(30, 400);

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
}

Widget::~Widget()
{
    delete ui;
}

void Widget::operator()()
{
    std::mutex mtx;
    std::condition_variable cv;
    double dt = 100;
    QPushButton *m_button, *m_button1;
    int x, y; 

    v2x::MinPQ<v2x::Event> *pq;
    std::shared_ptr<v2x::fcw> fcw;
    using sharedEE = std::shared_ptr<v2x::ee>;

    std::vector<QPushButton*> buttons;
    std::vector<sharedEE>  ees;

    fcw = fcw_init();
    

    Widget *w = new Widget();
    w->setFixedSize(1000,500);

    int count = 1;
    std::string name("button");
    setUpdatesEnabled(true);
    name += std::to_string(count);
    buttons.clear();
    m_button = new QPushButton(name.c_str(), w);
    m_button1 = new QPushButton(name.c_str(), w);
    buttons.push_back(m_button);
    buttons.push_back(m_button1);
    
    while (count < 10)
    {
        /*get the updated priority queue*/
        // pq = fcw->pqGet();
        buttons.clear();

        std::unique_lock<std::mutex> lck(mtx);
        cv.wait_for(lck, std::chrono::milliseconds(int(dt)));
        ees = fcw->eesGet();
        std::vector<sharedEE>::iterator it;
        for(it = ees.begin(); it != ees.end(); ++it)
        {
            sharedEE _ee = *it;
            std::cout << "endpoint id " << _ee->getId() << std::endl;
            _ee->posGet() << std::cout;
        }



        w->repaint();
        w->show();
    }
    w->show();
    return;
}
