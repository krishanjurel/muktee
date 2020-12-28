#include <opencv2/core.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/highgui.hpp>
#include <vector>
#include <iostream>
#include <math.h>

using namespace cv;


/*draw a rect and return that as roi of the target image */
/* declare two global points, top and bottom */
Point gTop, gBottom;
bool gValidMouseEvent = false;

/* create a function that returns a ROI of the rectangle specified
 by top and bottom points
*/ 
void roiImage(std::string filename, Mat& image, Point from, Point to)
{
    /*store the roi into the given filename */
    std::cout << "image size is " << image.size() << std::endl;
     imwrite(filename, image(Range(from.y, to.y), Range(from.x, to.x)));
     return;
}  


// function to capture mouse events and trigger roiImage */
void mouseEvent(int action, int x, int y, int flags, void *userdata)
{
  // Action to be taken when left mouse button is pressed
  if( action == EVENT_LBUTTONDOWN )
  {
    gTop = Point(x,y);
    // std::cout << "top " << gTop << std::endl;
  }
  // Action to be taken when left mouse button is released
  else if( action == EVENT_LBUTTONUP)
  {
    gBottom = Point(x,y);
    Mat *image = static_cast<Mat *>(userdata);
    std::string filename = "cropped-";
    filename += std::to_string(gBottom.x) + "x" + std::to_string(gBottom.y);
    // std::cout << "bottom " << gBottom << std::endl;
    /* save the part of the image between top and bottom pooints */
    roiImage("cropped.jpg", std::ref(*image), gTop, gBottom);
    rectangle(*image, Rect(gTop, gBottom), Scalar(255,0,0), 2, LINE_AA);
  }
}

int main()
{
    Mat image = imread("sample.jpg");
    if(!image.empty())
    {
        namedWindow("Window");
        std::cout << "read image size " << image.size() << std::endl;
        // highgui function called when mouse events occur
        /* pass image as a user data */
        setMouseCallback("Window",mouseEvent, &image);

        Mat dup = image.clone();

        while()
        {
            int key = (int)(waitKey(100)& 0xff);
            imshow("Window", image);




        };
    }
    std::cout << "Submission program ended" << std::endl;

    return 0;
}



























