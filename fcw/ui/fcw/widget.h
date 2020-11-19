#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QPushButton>


QT_BEGIN_NAMESPACE
namespace Ui { class Widget; }
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QWidget *parent = nullptr);
    ~Widget();
    QPushButton *m_button;



public:
    /*get the priority queue */
    void operator()();
private:
    Ui::Widget *ui;
};
#endif // WIDGET_H
