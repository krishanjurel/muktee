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
static Point gFrom, gTo;
static bool gValidMouseEvent = false;
static int gColorFactor = 10;
static int gMaxColorValue = 20;

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



// function to capture mouse events and trigger roiImage */
void mouseEvent(int action, int x, int y, int flags, void *userdata)
{
  // Action to be taken when left mouse button is pressed
  if( action == EVENT_LBUTTONDOWN )
  {
      gValidMouseEvent = false;
      gFrom = Point(x,y);
  }
  // Action to be taken when left mouse button is released
  else if( action == EVENT_LBUTTONUP)
  {
    gTo = Point(x,y);
    gValidMouseEvent = true;
  }
}
/* the method to perform Chorma key */
int chormakey(Mat &frontImage, Mat &backImage)
{
    Mat channels[3];
    split(frontImage, channels);
    static double prevColorThresholdvalue = 0.0;
    
    Mat backChannels[3];
    split(backImage, backChannels);

    Mat cloneImage = frontImage.clone();

    /* smoothen the edges */
    GaussianBlur(cloneImage, frontImage, Size(5,5), 1);

    Mat colorMask = Mat(frontImage, Rect(gFrom, gTo));
    /* get the value of the green channel, default set to 120 */
    double colorThresholdValue = 125.0;
    if(gValidMouseEvent == true)
    {
      colorThresholdValue =  mean(colorMask)(1);
      colorThresholdValue *= gColorFactor;
      colorThresholdValue /= gMaxColorValue;
    }

    if(colorThresholdValue != prevColorThresholdvalue)
    {
      prevColorThresholdvalue = colorThresholdValue;
      //std::cout << "new threshold value " << colorThresholdValue << std::endl;
    }

    Mat maskG;
    /* get the mask of asteroid */
    threshold(channels[1], maskG, colorThresholdValue, 255, THRESH_BINARY_INV);
    /*FIXME, the hack to remove the edge in the final chormatized image */
    Mat temp;
    Mat kernel = getStructuringElement(MORPH_RECT, Size(3,3));
    morphologyEx(maskG,temp,MORPH_DILATE, kernel,Point(-1,-1), 5);
    morphologyEx(temp,maskG, MORPH_ERODE, kernel,Point(-1,-1), 10);
	
	
	  /* get the asteroids only */
   	bitwise_and(channels[0], maskG, channels[0]);
   	bitwise_and(channels[1], maskG, channels[1]);
   	bitwise_and(channels[2], maskG, channels[2]);

	  /* get the mask of green screen */
	  bitwise_not(maskG, maskG);   

   	bitwise_and(backChannels[0], maskG, backChannels[0]); 
   	bitwise_and(backChannels[1], maskG, backChannels[1]); 
  	bitwise_and(backChannels[2], maskG, backChannels[2]);

	  /* get the remaining floavors in the asteroid of Blue and red channels */
  	bitwise_or(backChannels[0], channels[0], backChannels[0]);
	  bitwise_or(backChannels[1], channels[1], backChannels[1]);
	  bitwise_or(backChannels[2], channels[2], backChannels[2]);
	  merge(backChannels, 3, frontImage);
   	return 0;
}

void TrackbarChangeHandler(int value, void *userdata)
{
	/* get the color factor */
	gColorFactor = value;
}



int main()
{
    VideoCapture cap("./greenscreen-asteroid.mp4");
    namedWindow("Window");
    namedWindow("Green Patch");
    Mat frame, dup;
    Mat backgroundImage = imread("./background.jpg", IMREAD_COLOR);

    /*get the frame height and width to resize the image */
    double width, height;

    width = cap.get(CAP_PROP_FRAME_WIDTH);
    height = cap.get(CAP_PROP_FRAME_HEIGHT);
    Mat backImage;
    resize(backgroundImage, backImage, Size_<double>(width, height));
	  createTrackbar( "tolerance slider","Green Patch",&gColorFactor, gMaxColorValue, TrackbarChangeHandler, nullptr );

    
    while(cap.isOpened() == true && backgroundImage.empty() == false)
    {
        cap >> frame;
        if(frame.empty() != true)
        {
            dup = frame.clone();
            chormakey(dup, backImage);
            setMouseCallback("Green Patch",mouseEvent, &frame);
            if(gValidMouseEvent == true)
            {
                pointRearrange(gFrom, gTo);
                rectangle(frame, Rect(gFrom, gTo), Scalar(255,0,0), 2, LINE_AA);
            }
            //Mat dup = image.clone();
            imshow("Window", dup);
            imshow("Green Patch", frame);
            /* for 30 fps, the wait should be 1000/30=~30*/
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



























