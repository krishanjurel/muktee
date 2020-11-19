#include "widget.h"

#include <QApplication>
#include <QFrame>
#include <QRect>
#include <chrono>
#include <thread>
#include "include.h"
static std::thread m_thread;


static void thread_handlr(Widget *w)
{
    w->operator()();
}



static std::thread thread_handler(QApplication *a)
{
   Widget w;
   w.setFixedSize(1000,500);
#if 0
   QFrame *qframe = new QFrame(&w);
   qframe->setFrameShape(QFrame::Shape::Box);
   //qframe->setFixedSize(500, 200);
   qframe->setGeometry (500,250, 500, 250);
   //QRect qrect(100,100,500,500);
   //qframe->setFrameRect(qrect);
   QPushButton *m_button = new QPushButton("Hello World", qframe);
   m_button->setGeometry(10,10, 80, 30);
   m_button = new QPushButton("Hello World 3",qframe);
   m_button->setGeometry(10,40, 80, 30);
   m_button = new QPushButton("Hello World 4",qframe);
   m_button->setGeometry(10,70, 80, 30);
   w.show();
 #endif
   std::thread _thread(thread_handlr, &w);
   a->exec();
   return _thread;
}

int main(int argc, char *argv[])
{
    int count = 0;
    QApplication a(argc, argv);
    std::thread _thread;
    //std::thread m_thread(thread_handler, &a);
    //m_thread.join();
    _thread = thread_handler(&a);
    
    //Widget w;
    //w.setFixedSize(1000,500);
    //QPushButton *m_button = new QPushButton("Hello World", &w);
    //w.show();
    //_thread.join();
    return 0;//a.exec();
}


