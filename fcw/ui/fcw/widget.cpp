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
#include <QPushButton>
#include <QTime>
#include <QPainter>

#define PAINT



static std::default_random_engine gen;
static std::uniform_real_distribution<> x_pos_dist(100,900);
static std::uniform_real_distribution<> y_pos_dist(30, 400);

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    timer = new QTimer();
    timer->setInterval(100); /* every 500 milliseconds */
    trackedColor.setRgb(127,0,127);
    targetColor.setRgb(255,127,0);

    setFixedSize(500,500);

    setBackgroundRole(QPalette::Base);
#ifndef PAINT
    for(int i = 0; i < v2x::MAX_V2X_EE+1; i++)
    {
        QPushButton *m_button = new QPushButton(std::to_string(i).c_str(), this);
        m_button->resize(20,20);
        m_button->setAutoFillBackground(true);
        m_buttons.push_back(m_button);
    }
#endif
    /* connect the timeout signal to move EE slot */
    connect(timer, &QTimer::timeout, this, &Widget::moveEE);
    /* start the timer */
    timer->start();
    fcw = new v2x::fcw();
    /* start the process */
    fcw->start();
    ees.clear();



    show();

}

void Widget::moveEE()
{
#ifndef PAINT
//    /* get the list of end-entities from the fcw */
    ees = fcw->eesGet(std::ref(ees));
    int id;
    bool tracked = false;

    for(auto&& ee: ees)
    {
        id = ee.getId();
        tracked = ee.trackedGet();
        v2x::ee_pos pos = ee.posGet();

        QColor color(QColor::Spec::Rgb);
        color.setRgb(0,255, 0);

        if(tracked)
        {
            color.setRgb(255, 0, 0);
        }
        if(id == 0)
        {
            color.setRgb(0,0,255);
        }

        QPalette pal;
        pal.setColor(QPalette::Normal, QPalette::Button, color);
        m_buttons[id]->setPalette(pal);
        m_buttons[id]->move(pos.x, pos.y);
    }
    ees.clear();
#endif
    update();
}

Widget::~Widget()
{
    delete ui;
    m_buttons.clear();
}

/* draw items */
void Widget::drawItems(QPainter& p)
{
    ees = fcw->eesGet(std::ref(ees));
    int id;
    bool tracked = false;

    for(auto&& ee: ees)
    {
        id = ee.getId();
        tracked = ee.trackedGet();
        v2x::ee_pos pos = ee.posGet();

        QColor color(QColor::Spec::Rgb);
        p.setBrush(QColor(0,255,0));

        if(tracked)
        {
            p.setBrush(trackedColor);
        }
        if(id == 0)
        {
            p.setBrush(targetColor);
        }
        int x = pos.x;
        int y = pos.y;
        QRect rect(0,0,20,20);

        p.save();
        rect.moveCenter(QPoint(x, y));
        p.drawEllipse(rect);
        p.restore();
    }
    ees.clear();
}


void Widget::paintEvent(QPaintEvent *event)
{
#ifdef PAINT
    QWidget::paintEvent(event);

    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    p.setPen(Qt::NoPen);

    drawItems(p);
#endif
}

