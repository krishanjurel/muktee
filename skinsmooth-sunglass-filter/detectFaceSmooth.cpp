/*
 Copyright 2017 BIG VISION LLC ALL RIGHTS RESERVED

 This program is distributed WITHOUT ANY WARRANTY to the
 Plus and Premium membership students of the online course
 titled "Computer Visionfor Faces" by Satya Mallick for
 personal non-commercial use.

 Sharing this code is strictly prohibited without written
 permission from Big Vision LLC.

 For licensing and other inquiries, please email
 spmallick@bigvisionllc.com

 */

#include "opencv2/objdetect.hpp"
#include "opencv2/videoio.hpp"
#include "opencv2/highgui.hpp"
#include "opencv2/imgproc.hpp"
#include "opencv2/photo.hpp"

#include <iostream>
#include <stdio.h>

using namespace std;
using namespace cv;

/*
    takes the face image and returns the skin
*/
void SkinDetection(Mat &image, Mat &skin, const char* window)
{
    /* first thing first, convert the image image into YCrCb format */
    Mat yuv;
    Mat imageClone = image.clone();
    cvtColor(image, yuv, COLOR_BGR2YCrCb);

    int sw = image.cols;
    int sh = image.rows;
    Mat mask, maskPlusBorder;

    const int NUM_SKIN_POINTS = 6;
    Point2d skinPoints[NUM_SKIN_POINTS];
    skinPoints[0] = Point2d(sw*0.5, sh*0.15); /* get the forehead, middle and 15% from top */
    skinPoints[1] = Point2d(sw*0.3, sh*0.15); /* take two on both sides of the cernter point */
    skinPoints[2] = Point2d(sw*0.7, sh*0.15); 
    skinPoints[3] = Point2d(sw*0.5, sh*0.5); /* get the middle of the nose, photo is front facing */
    skinPoints[4] = Point2d(sw*0.3, sh*0.5); /* left cheek */
    skinPoints[5] = Point2d(sw*0.7, sh*0.5);  /* right cheek */

    /* for face detection lets vary the brightness as much as possible, but Cr and Cb not so much */
    const int LOWER_Y = 75;
    const int UPPER_Y = 80;
    const int LOWER_cr = 15;
    const int UPPER_cr = 18;
    const int LOWER_cb = 15;
    const int UPPER_cb = 20;

    Scalar lowerDiff = Scalar(LOWER_Y, LOWER_cr, LOWER_cb);
    Scalar upperDiff = Scalar(UPPER_Y, UPPER_cr, UPPER_cb);


    
    const int CONNECTED_COMPONENTS = 4;
    const int flags = CONNECTED_COMPONENTS | FLOODFILL_FIXED_RANGE | FLOODFILL_MASK_ONLY;

    maskPlusBorder = Mat::zeros(sh+2, sw+2, CV_8UC1);
    mask = maskPlusBorder(Rect(1,1,sw, sh));

    for(int i = 0; i < NUM_SKIN_POINTS; i++)
    {
        // cv::circle(image, skinPoints[i], 4, Scalar(255,0,0), 4,FILLED);
        floodFill(yuv, maskPlusBorder, skinPoints[i], Scalar(),NULL, lowerDiff, upperDiff, flags);
    }
    mask.copyTo(skin);
    return;
}

/* skin is the single channel mask, 1-skin, 0:otherwise*/
void SmoothSkin(Mat& image, Mat skinMask)
{
    Mat imageClone = image.clone();

    /*get rid of the non-skin from the image */
    
    
    /* generrously smooth the skin, just use the box fliter */
//   medianBlur(imageClone, imageClone, 5);
//   medianBlur(imageClone, imageClone, 5);
    blur(imageClone, imageClone, Size(3,3));
    blur(imageClone, imageClone, Size(3,3));
    blur(imageClone, imageClone, Size(3,3));
    blur(imageClone, imageClone, Size(3,3));

    Mat skin;
    imageClone.copyTo(skin, skinMask);


    /* now just get an image that has only the non-skin */
    Mat nonSkin;
    image.copyTo(nonSkin, 1-skinMask);

    image.setTo(Scalar(0,0,0));

    /* now add nonSkin image into the softened skin */
    add(skin, nonSkin, image);
    return;
}

void EyeMarker(Mat& image, Mat& glasses, Mat& effect)
{
    /* get the face mappings */
    int sw = image.cols;
    int sh = image.rows;
    Mat effectClone = Mat::zeros(image.size(), CV_8UC3);
    /* lets get the eye region, a face has eyes */
    Point2d topLeftEye(sw*0.10, sh*0.25);
    Point2d btmRightEye(sw*0.90, sh*0.55);
    // rectangle(image, Rect(topLeftEye, btmRightEye), Scalar(0,255, 0), 2, LINE_AA);
    Mat eyes = image(Rect(topLeftEye, btmRightEye));
    Mat resizedGlass;
    cv::resize(glasses,resizedGlass, eyes.size());

    /* check is effect is provoided */
    if(effect.empty() == false)
    {
        effectClone = effect.clone();
    }
    /* resize the effect */
    Mat resizedEffect_;
    cv::resize(effectClone,resizedEffect_, eyes.size());
    cvtColor(resizedEffect_, resizedEffect_, COLOR_BGR2GRAY);

    Mat resizedEffectChannels[] = {resizedEffect_, resizedEffect_, resizedEffect_};
    Mat resizedEffect;
    merge(resizedEffectChannels, 3, resizedEffect);



    /* check glasses ke channels */
    std::vector<Mat> glassesChannels;
    split(resizedGlass, glassesChannels);
    Mat glassBGRChannels[3]={glassesChannels[0], glassesChannels[1], glassesChannels[2]};
    Mat glassMask_[3]  = {glassesChannels[3],glassesChannels[3],glassesChannels[3]};

    Mat glassBGR;
    merge(glassBGRChannels, 3, glassBGR);
    Mat glassMask;
    cv::merge(glassMask_, 3, glassMask);
    glassMask /= 255;

    std::vector<Mat> eyesChannels;
    split(eyes, eyesChannels);

    Mat maskedEyeChannels[3];
    Mat unmaskedEyeChannels[3];
    Mat maskedEye;
    Mat unmaskedEye;

    for(int i = 0; i < eyesChannels.size(); i++)
    {
        multiply(eyesChannels[i], 1-glassMask_[i], maskedEyeChannels[i]);
        multiply(eyesChannels[i], glassMask_[i]/255, unmaskedEyeChannels[i]);
    }
   
    merge(maskedEyeChannels, 3, maskedEye);
    merge(unmaskedEyeChannels, 3, unmaskedEye);


    /*multiply glass with glass mask */
    Mat unmaskedGlass;
    multiply(glassBGR, glassMask, unmaskedGlass);

    Mat unmaskedEffect;
    multiply(resizedEffect, glassMask, unmaskedEffect);

    Mat unmaskedEyeGlass;

    addWeighted(unmaskedEye, 0.2, unmaskedGlass, 0.8, 0,unmaskedEyeGlass);
    Mat unmaskedEyeGlassEffect;
    addWeighted(unmaskedEffect, 0.2, unmaskedEyeGlass, 0.8,0, unmaskedEyeGlassEffect);


    // imshow("unmaskedEye", unmaskedEye);
    // imshow("maskedGlass", maskedGlass);
    add(maskedEye,unmaskedEyeGlassEffect, eyes);
    // imshow("maskedEyeGlass", maskedEyeGlass);
}

int main( int argc, const char** argv )
{
    int smileNeighborsMax = 100;
    int neighbors = 8;
    CascadeClassifier faceCascade;
    String faceCascadePath = "../data/models/haarcascade_frontalface_default.xml";
    
    //-- 1. Load the cascades
    if( !faceCascade.load( faceCascadePath ) ){ printf("--(!)Error loading face cascade\n"); return -1; };
    std::vector<Rect> faces;

    
    //  if(argc < 2)
    //  {
    //          std::cout << "error please provide full or relative path of the image " << std::endl;
    //          exit(EXIT_SUCCESS);

    //  }

    std::string filename = "../data/images/face.jpg";
    std::string glassfile = "../data/images/sunglass.png";
    std::string effectfile = "../data/images/effect.jpg";

    Mat img = imread(filename, IMREAD_COLOR);
    Mat effect = imread(effectfile, IMREAD_COLOR);
    Mat glasses = imread(glassfile, IMREAD_UNCHANGED);
    if(img.empty() ||  
      effect.empty() ||
      glasses.empty())
      {
          std::cout << "please provide valid files of face, sunglasses and effect " << std::endl;
          exit(EXIT_FAILURE);
      }

    Mat frameGray, frameClone, frame;
    frame =img.clone();
    cvtColor(frame, frameGray, COLOR_BGR2GRAY);
    faceCascade.detectMultiScale( frameGray, faces, 1.1, neighbors);
    if(faces.size() == 0)
    {
        std::cout << "error no faces detected " << filename << " can not be read " << std::endl;
        exit(EXIT_SUCCESS);
    }

    std::string finalWindow("Final");
    std::string origWindow("Original");
    std::string effectWindow("Effect");
    namedWindow(finalWindow, WINDOW_NORMAL);
    namedWindow(origWindow, WINDOW_NORMAL);
    namedWindow(effectWindow, WINDOW_NORMAL);

    std::cout << "number of faces " << faces.size() << std::endl;


    for(auto& face_: faces)
    {
        Mat skin, smoothFace;
        Mat face = frame(face_);
        SkinDetection(face, skin, finalWindow.c_str());
        SmoothSkin(face, skin);
        EyeMarker(face, glasses, effect);
        // imshow("face", face);
        // cv::rectangle(frame, Rect(Point(face_.x, face_.y), Size(face_.width, face_.height)),Scalar(255, 0, 0), 2, LINE_AA);
    }

    imshow(finalWindow, frame);
    imshow(origWindow,img);
    imshow(effectWindow, effect);
    waitKey(0);
    destroyAllWindows();
    exit(EXIT_SUCCESS);
}