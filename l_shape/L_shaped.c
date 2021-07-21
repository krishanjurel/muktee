#include <stdio.h>
#include <stdlib.h>


/* calculate the number of ones 
int valid_segment_lenght(int **g, int i, int j, int k, int l)
{


}










int segment_length(int **g, int i, int j, int k, int l)
{
    /* segment lenght of (i,j) to (k,l) */

    /* this lenght is the sum of (i, k) and (j, l) */
    return abs(i-k) + abs(j-l) + 1;
}


int num_l_shapes(int **g, int rows, int cols)
{
    
    int start; /* start for row or col */
    int end;    /* end for current row or col */
    /* check along the row */
    int num = 0;
    for(int row=0; row < rows; row++)
    {
        for(int col = 0; col < cols; col++)
        {
            for(int row_=0; row_ < rows; row_++)
            {
                for (int col_ = 0; col_ < cols; col_++)
                {

                }
            }


            



        }

    }











}







