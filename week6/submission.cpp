#include <opencv2/core.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/photo.hpp>
#include <vector>
#include <iostream>
#include <math.h>

using namespace cv;


/* create a kernel, such that the selected point contributes nothing in the final outcome*/
Mat blemishKernel(int size)
{
  Mat kernel = Mat::zeros(size, size, CV_32FC1);
  /* set the central pixel to zero */
  for (int rows; rows < size ; rows++)
  {
    kernel.at<uint8_t>(size-1/2, size-1/2) = 0;
  }

  kernel = kernel/(size * size);
  return kernel;
}

/* copy a ROI of given kernel size around the point */
Mat roiImage(Mat& image, Point point, int kernel)
{
    /* for now assuming that blemish is not at the edges */
    return image(Range(point.y-kernel, point.y+kernel), Range(point.x-kernel, point.x+kernel));
}  


// function to capture mouse events and trigger roiImage */
void mouseEvent(int action, int x, int y, int flags, void *userdata)
{
  Point point;
  int roiSize = 7;
  // Action to be taken when left mouse button is pressed
  if( action == EVENT_LBUTTONDOWN )
  {
    point = Point(x,y);
    // std::cout << "top " << gFrom << std::endl;
  }
  // Action to be taken when left mouse button is released
  else if( action == EVENT_LBUTTONUP)
  {
    point = Point(x,y);
    Mat *image = static_cast<Mat *>(userdata);
    /* save the part of the image between top and bottom pooints */
    // Mat roi = roiImage(std::ref(*image), point, roiSize);
    Mat imageRef = std::ref(*image);

    Mat roi = Mat::zeros(image->size(), CV_8U);
    /* creata a mask patch */
    roi(Range(point.y-roiSize, point.y+roiSize), Range(point.x-roiSize, point.x+roiSize)) = Scalar::all(255);

    inpaint(imageRef, roi, imageRef,5, INPAINT_TELEA);
    // /* get the kernel of size 3 */
    // Mat kernel = blemishKernel(5);
    // std::cout << kernel.size() << std::endl;
    // std::cout << kernel << std::endl;

    // Mat temp;
    // roi.convertTo(temp, CV_32FC3);
    // filter2D(temp, temp, CV_32F, kernel);//, borderType=BORDER_REFLECT_101);
    // //boxFilter(roi, temp, CV_32F, Size(5,5));
    // temp.convertTo(temp, CV_8UC3);
    // temp.copyTo(imageRef(Range(point.y-roiSize, point.y+roiSize), Range(point.x-roiSize, point.x+roiSize)));
    imshow("Window", imageRef);
  }
}

int main()
{
    Mat image = imread("blemish.png");
    if(!image.empty())
    {
        namedWindow("Window");
        // namedWindow("Roi");
        // //std::cout << "read image size " << image.size() << std::endl;
        // highgui function called when mouse events occur
        /* pass image as a user data */
        setMouseCallback("Window",mouseEvent, &image);

        //Mat dup = image.clone();
        imshow("Window", image);
        waitKey(0);
        destroyAllWindows();
    }
    std::cout << "Submission program ended" << std::endl;

    return 0;
}



























