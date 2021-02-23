#include <opencv2/core.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/photo.hpp>
#include <opencv2/videoio.hpp>
#include <vector>
#include <iostream>
#include <math.h>

using namespace cv;


/*draw a rect and return that as roi of the target image */
/* declare two global points, top and bottom */
Point gFrom, gTo;
bool gValidMouseEvent = false;

/* rearrange points point where from is always smaller than  to */
void pointRearrange(Point& from, Point& to)
{
    int temp;
    /* take care of y */
    if(from.y > to.y)
    {
      temp = to.y;
      to.y = from.y;
      from.y = temp;
    }

    if(from.x > to.x)
    {
      temp = to.x;
      to.x = from.x;
      from.x = temp;
    }  
}

/* create a function that returns a ROI of the rectangle specified
 by top and bottom points
*/ 
void roiImage(std::string filename, Mat& image, Point from, Point to)
{
    /*store the roi into the given filename */
    pointRearrange(from, to);
    //std::cout << "image size is " << image.size() << std::endl;
    imwrite(filename, image(Range(from.y, to.y), Range(from.x, to.x)));
    return;
}  


// function to capture mouse events and trigger roiImage */
void mouseEvent(int action, int x, int y, int flags, void *userdata)
{
  // Action to be taken when left mouse button is pressed
  if( action == EVENT_LBUTTONDOWN )
  {
      gValidMouseEvent = false;
      gFrom = Point(x,y);
    // std::cout << "top " << gFrom << std::endl;
  }
  // Action to be taken when left mouse button is released
  else if( action == EVENT_LBUTTONUP)
  {
    gTo = Point(x,y);
    // Mat *image = static_cast<Mat *>(userdata);
    // std::string filename = "cropped-";
    // filename += std::to_string(gTo.x) + "x" + std::to_string(gTo.y);
    // filename += ".jpg";
    // Mat dup = (*image).clone();
    // // std::cout << "bottom " << gTo << std::endl;
    // /* save the part of the image between top and bottom pooints */
    // roiImage(filename, std::ref(*image), gFrom, gTo);
    // rectangle(dup, Rect(gFrom, gTo), Scalar(255,0,0), 2, LINE_AA);
    // imshow("Window", dup);
    gValidMouseEvent = true;
  }
}


int main()
{
    VideoCapture cap("./greenscreen-asteroid.mp4");
    namedWindow("Window");
    Mat frame, dup;
    
    while(cap.isOpened() == true)
    {
        cap >> frame;
        if(frame.empty() != true)
        {
            dup = frame.clone();
            setMouseCallback("Window",mouseEvent, &dup);
            if(gValidMouseEvent == true)
            {
                rectangle(dup, Rect(gFrom, gTo), Scalar(255,0,0), 2, LINE_AA);
            }
            //Mat dup = image.clone();
            imshow("Window", dup);
            /* for 30 fps, the wait should be 1000/30=30*/
            waitKey(30);
        }else
        {
            break;
        }
    }
    destroyAllWindows();
    std::cout << "Submission program ended" << std::endl;

    return 0;
}



























