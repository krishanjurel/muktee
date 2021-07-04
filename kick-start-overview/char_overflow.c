#include <stdio.h>
#include <stdlib.h>
#include <math.h>



int main()
{
    unsigned char char1 = 245;
    unsigned char result = char1 + 10;
    printf("Good operation, value(expected) %d(%d)\n", result, 255);
    result = char1 + 20;
    printf("Good operation, value(expected) %d(%d)\n", result, 265);
    return 0;
}