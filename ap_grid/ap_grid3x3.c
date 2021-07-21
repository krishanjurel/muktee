#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>


int max_progressions(int grid[3][3])
{
    int maxnum = 0;
    int tempmax = 0;

    /* with the logic, the sum of other two items along the row and coln has to be even.
       with that, just consider 4 cases, the middle row and col and diagonal
    */
     /* with the above information */
     int potentialValues[4]={0,0,0,0};
     /* middle row */
     if((grid[1][0] + grid[1][2]) % 2 == 0)
     {
         potentialValues[0] = (grid[1][0] + grid[1][2])/2;
     }

     /* middle columns */
     if((grid[0][1] + grid[2][1]) % 2 == 0)
     {
         potentialValues[1] = (grid[0][1] + grid[2][1])/2;
     }

     /* top to bottom diagnal */
     if((grid[0][0] + grid[2][2]) % 2 == 0)
     {
         potentialValues[2] = (grid[0][0] + grid[2][2])/2;
     }

     /* bottom to top diagnal */
     if((grid[2][0] + grid[0][2]) % 2 == 0)
     {
         potentialValues[3] = (grid[2][0] + grid[0][2])/2;
     }



    
    for(int i=0; i < 4; i++)
    {
        grid[1][1] = potentialValues[i];
        tempmax = 0;
        
        for(int row=0; row<3; row++)
        {
            if(grid[row][2] - grid[row][1] == grid[row][1] - grid[row][0])
            {
                tempmax +=1;
            }
        }

        for(int col=0; col<3; col++)
        {
            if(grid[2][col] - grid[1][col] == grid[1][col] - grid[0][col])
            {
                tempmax += 1;
            }
        }

        /* manually use the diagonals */
        if(grid[1][1] - grid[0][0] == grid[2][2] - grid[1][1])
        {
            tempmax += 1;
        }
        if(grid[1][1] - grid[2][0] == grid[0][2] - grid[1][1])
        {
            tempmax += 1;
        }
        // printf("max num %d\n", tempmax);
        if(tempmax >= maxnum)
            maxnum = tempmax;
    }
    return maxnum;
}


#define MAX_MEM pow(10, 9)
#define MAX_TESTs (MAX_MEM/9)

int main(int argc, char *argv[1])
{
    int T;
    int offset = 0;
    int g[3][3];
    char *line = NULL;
    size_t sz = 0;

    if(argc < 2)
    {
        printf("Usage ./test.o <input-file-name>");
        exit(EXIT_FAILURE);
    }

    FILE *fp = fopen(argv[1], "r");

    if(fp == NULL)
    {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    size_t sz_ = getline(&line, &sz, fp);
    if(sz_ == -1)
    {
        perror("getline error ");
        exit(EXIT_FAILURE);
    }
    sscanf(line, "%d", &T);
    for(int i = 0; i < T; i++)
    {
        sz_ = getline(&line, &sz, fp);
        if(sz_ == -1)
        {
            break;
        }
        sscanf(line, "%d %d %d", &g[0][0], &g[0][1],&g[0][2]);
        free(line);
        line = NULL;
        sz = 0;

        sz_ = getline(&line, &sz, fp);
        if(sz_ == -1)
        {
            break;
        }
        sscanf(line, "%d %d", &g[1][0],&g[1][2]);
        free(line);
        line = NULL;
        sz = 0;
       
        sz_ = getline(&line, &sz, fp);
        if(sz_ == -1)
        {
            break;
        }
        sscanf(line, "%d %d %d", &g[2][0], &g[2][1],&g[2][2]);
        free(line);
        line = NULL;
        sz = 0;

        printf("Case #%d: %d\n", i+1, max_progressions(g));

    }
    return 0;
}


















