#!/bin/bash

# this line will ensure the users enters the credentials if needed 
# for the rest of the installation to succeed

sudo apt -y update

curr_dir=$(pwd)

install_packages()
{
    filename=$1;
    echo "installing packages from $filename"
    while IFS= read -r line;
    do
        echo "installing packages $line"
        sudo apt -y install $line;
    done < "$filename"
}

filename="$(pwd)/pkglist/pkglist1";
install_packages $filename
cd /usr/include/linux;
sudo ln -s -f ../libv4l1-videodev.h videodev.h;
cd $curr_dir;
# install the remaining packages */
filename="$(pwd)/pkglist/pkglist2";
install_packages $filename


opencv_home_dir=$OpenCV_Home_DIR

if [ "$opencv_home_Dir" = "" ]
    then
        mkdir -p $HOME/installation/OpenCV
        opencv_home_dir="$HOME/installation/OpenCV"
fi        

cmake -D CMAKE_BUILD_TYPE=RELEASE \
-D CMAKE_INSTALL_PREFIX=$opencv_home_dir \
-D INSTALL_C_EXAMPLES=ON \
-D WITH_TBB=ON \
-D WITH_V4L=ON \
-D WITH_OPENGL=ON \
-D OPENCV_EXTRA_MODULES_PATH=../../opencv_contrib/modules \
-D BUILD_EXAMPLES=ON ..

make -j4
make install

echo "OpenCV installed in: $opencv_home_dir"






