#include <stdio.h>
#include <stdlib.h>
#include <math.h>





int main()
{
    char array[256]; /* allocate an array of 256 bytes */
    char *ptr1 = &array[0]; /* ptr1 points to the start of the memory */
    char *ptr2 = &array[10]; /* ptr2 starts at the 10th byte of the big array */

    /* lets initialize the arrays to zero, so we know what we are writing */
    memset(&array[0], 0, 256);
    /* so the good case */
    sprintf(ptr1, "%s","Hi There");
    sprintf(ptr2, "%s","Hello There, how are you");

    printf("good ptr1: %s\n", ptr1); 
    printf("ptr2: %s\n", ptr2);

    /* the bad case */
    sprintf(ptr1,"%s","Hi there , how are you, am I bothering you??");

    printf("bad ptr1: %s\n", ptr1); 
    printf("ptr2: %s\n", ptr2);



    return 0;
}