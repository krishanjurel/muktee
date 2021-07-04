/* program to read the user input from the keyboard */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>


/* function to read from the file.
   filename: name of the file that contains the input numbers, 
   num1, num2: are the pointers to the numbers.
*/
void read_from_file(const char *filename, unsigned int *num1, unsigned int *num2)
{
    FILE *fp = NULL;
    unsigned int numbers[]={0,0};
    unsigned int nums = 0;
    fopen_s(&fp, filename, "rb");
    unsigned int _bytenum = 0;
    unsigned int temp = 0;
    unsigned char _bytes[3] = {0,0,0};
    unsigned char *pbytes = &_bytes[0];
    while(feof(fp) == 0)
    {
        char c = fgetc(fp);
        
        if(c != (char)(13) &&
            c != (char)(10) && 
            c != (char)(32))
        {
            *pbytes++ = c;
            temp = temp * 10 + atoi(_bytes);
            _bytenum ++;
            pbytes = &_bytes[0];
            continue;
        }
        /* the next number is only valid if there is a valid byte read from the file */
        if (_bytenum != 0)
        {
            numbers[nums++] = temp;
        }
        _bytenum = 0;
        temp = 0;
        /* we just want to read two numbers */
        if(nums == 2)
            break; /* break the loop */
    }
    *num1 = numbers[0];
    *num2 = numbers[1];
    fclose(fp);
}




int main(int argc, const char *argv[])
{
    /* these are two numbers that the user is adding */
    unsigned int num1, num2;
    num1 = 0;
    num2 = 0;
    if(argc == 2)
    {
        read_from_file(argv[1], &num1, &num2);
    }else
    {
        scanf_s("%d %d", &num1, &num2);
    }
    printf("the two numbers are %u and %u\n", num1, num2);
    unsigned int sum = num1+num2;
    printf("the sum of two numbers is %u\n", sum);
    
    return 0;
}