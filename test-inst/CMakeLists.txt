# SPECIFY THE MINIMUM VERSION OF CMAKE REQUIRED
cmake_minimum_required(VERSION 2.8.12)


# SPECIFY YOUR PROJECT NAME
PROJECT(sampleCode)


# Enable C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)




### Uncomment the line below and specify the path to OpenCV directory i.e. the path to the OpenCVConfig.cmake file. Check the examples given below.
###SET PATH TO OPENCV CMAKE CONFIG FILES

SET(OpenCV_DIR /home/krishan/installation/opencv/lib/cmake/opencv4)

################### OpenCV_DIR Examples  #####################
#
### MACOS : /Users/<Username>/installation/OpenCV/lib/cmake/opencv4
### UBUNTU : /usr/local/share/OpenCV/
#
##############################################################




# MAKE SURE OPENCV IS INSTALLED CORRECTLY
find_package( OpenCV REQUIRED )


# INCLUDE OPENCV DIRECTORIES
include_directories( ${OpenCV_INCLUDE_DIRS})


# MACRO TO COMPILE CPP FILES
# Do Not Edit
MACRO(add_example name)
  ADD_EXECUTABLE(${name} ${name}.cpp)
  TARGET_LINK_LIBRARIES(${name} ${OpenCV_LIBS} )
ENDMACRO()


# COMPILE CPP FILES USING THIS LINE
######## EDIT THE FILE NAMES ########
add_example(sampleCode)
#add_example(sampleCode2) and so on