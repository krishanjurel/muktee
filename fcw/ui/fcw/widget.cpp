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
    double dt = 1000;
    QPushButton *m_button, *m_button1;
    int x, y; 

    v2x::MinPQ<v2x::Event> *pq;
    std::shared_ptr<v2x::fcw> fcw;
    std::vector<v2x::ee*> ees;

    std::vector<QPushButton*> buttons;

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
    
    while (true)
    {
        /*get the updated priority queue*/
       // pq = fcw->pqGet();
        buttons.clear();

        std::unique_lock<std::mutex> lck(mtx);
        cv.wait_for(lck, std::chrono::milliseconds(int(dt)));
        m_button->setText(name.c_str());
        m_button->windowTitleChanged(name.c_str());
        srand(time(NULL));
        x = rand()% 9 + 1; // between 1 and 9 */
        y = rand()% 40 + 3; //3->40
        x *= 100; /* scale it by 100, 100->900 */
        y *= 10; /* scale it by 10, 30 and 400 */
        m_button->setGeometry(x,y, 80, 30);
        //m_button->updateGeometry();

       // m_button1->updateGeometry();
        x = rand()% 9 + 1; // between 1 and 9 */
        y = rand()% 40 + 3; //3->40
        x *= 100; /* scale it by 100, 100->900 */
        y *= 10; /* scale it by 10, 30 and 400 */
        m_button1->setText(name.c_str());
        m_button1->windowTitleChanged(name.c_str());
        m_button1->setGeometry(x,y,80, 30);


        name += std::to_string(count);

        std::cout << "new name is " << name << std::endl;
        count++;
        w->repaint();
        w->show();
    }
    w->show();
    return;
}
