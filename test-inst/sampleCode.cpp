#include <opencv2/opencv.hpp>

using namespace cv;

int main(void) {
	
	// Read image in GrayScale mode
	Mat image = imread("boy.jpg",IMREAD_COLOR);
	Mat grayimage=imread("boy.jpg",IMREAD_GRAYSCALE);

	namedWindow("mywindow",WINDOW_AUTOSIZE);
	

	// Save grayscale image
	//imwrite("boyGray.jpg",image);
	imshow("mywindow", image);
	imshow("grayimage ", grayimage);

	waitKey(0);
	destroyAllWindows();

	return 0;
}
