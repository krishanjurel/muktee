#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QPushButton>
#include <QTimer>
#include <QPainter>
#include "include.h"



QT_BEGIN_NAMESPACE
namespace Ui { class Widget; }
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QWidget *parent = nullptr);
    ~Widget();

    std::vector<QPushButton *> m_buttons;
    void drawItems(QPainter& p);


public slots:
        /* on timeout, move the end-entity*/
        void moveEE();
        void paintEvent(QPaintEvent *event) override;
public:
//    /*get the priority queue */
//    void operator()();
private:
    Ui::Widget *ui;
    QTimer *timer;
    std::vector<v2x::ee> ees;
    v2x::fcw *fcw;
    QColor targetColor;
    QColor trackedColor;

};
#endif // WIDGET_H
