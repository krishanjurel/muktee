#include <stdio.h>
#include <stdlib.h>
#include <math.h>




int64_t adjust_consecutive_cells(int **g, int **visitMap, int row, int col, int R, int C)
{
    int cellAbove = (row > 0)? 1 : 0;
    int cellLeft = (col > 0)?1:0;
    int cellRight  = (col < C-1)?1:0;
    int cellBelow = (row < R-1)?1:0;
    int64_t cellsAdded = 0;
    int64_t diff = 0;
    int64_t r_, c_;


    if(cellAbove)
    {
        // int rowAbove = row-1;
        diff = abs(g[row][col]-g[row-1][col]); 
        if(diff > 1)
        {
            cellsAdded += (diff-1);
            g[row-1][col] = (diff-1);
            // visitMap[row-1][col] = 1;
        }
    }

    if(cellBelow)
    {
        // int rowBelow = row+1;
        diff = abs(g[row][col]-g[row+1][col]); 
        if(diff > 1)
        {
            cellsAdded += (diff-1);
            g[row+1][col] = (diff-1);
            // visitMap[row+1][col] = 1;
        }
    }

    if(cellLeft)
    {
        // int colLeft = col-1;
        diff = abs(g[row][col]-g[row][col-1]); 
        if(diff > 1)
        {
            cellsAdded += (diff-1);
            g[row][col-1] = (diff-1);
            // visitMap[row][col-1] = 1;
        }
    }

    if(cellRight)
    {
        // int colRight = col+1;
        diff = abs(g[row][col]-g[row][col+1]);
        if(diff > 1)
        {
            cellsAdded += (diff-1);
            g[row][col+1] = (diff-1);
            // visitMap[row][col+1] = 1;

        }
    }
    return cellsAdded;
}


int64_t make_safe_rabbit_house(int32_t **g, int R, int C)
{
    int32_t cellHt, cellMaxHt;
    int64_t diff = 0;
    int32_t r_, c_, rmax_, cmax_;

    int32_t **visitMap = (int32_t **)calloc(R, sizeof(int32_t *));
    for(c_ = 0; c_ < R ; c_++)
    {
        visitMap[c_] = (int *)calloc(C, sizeof(int32_t));
    }


    /* as described in the analysis, find the cell with highest height(H), and update its neigbhours
       with the H-1 height unless they already has the height H
    */

   for(int rr_ = 0; rr_ < R; rr_++)
   {
       for (int cc_ = 0; cc_ < C; cc_++)
       {

            cellMaxHt = 0;
            cellHt = 0;
            rmax_ = -1;
            cmax_ = -1;
            /* find the cell with max entries */
            for(r_=0; r_ < R; r_++)
            {
                for(c_ = 0; c_ < C; c_++)
                {
                    /* get the highest, unvisited cell */
                    if(visitMap[r_][c_] == 0) 
                    { 
                        if(rmax_ == -1)
                        {
                            rmax_ = r_;
                            cmax_ = c_;
                        }
                        cellHt = g[r_][c_];
                    }
                    if(cellHt > cellMaxHt)
                    {
                        cellMaxHt = cellHt;
                        rmax_ = r_;
                        cmax_ = c_;
                    }
                }
            }
            if(rmax_ == -1 || cmax_ == -1)
            {
                rmax_ = 0;
                cmax_ = 0;
            }

            if(visitMap[rmax_][cmax_] == 0)
            {
                // printf("the cell will max height is %d %d and height %d\n", rmax_, cmax_, cellMaxHt);
                /* update the visit map */
                visitMap[rmax_][cmax_] = 1;

                /* update the cells around the identified cell */
                diff += adjust_consecutive_cells(g, visitMap, rmax_, cmax_, R, C);
            }
       }
   }
   for(c_ = 0; c_ < R ; c_++)
   {
        free(visitMap[c_]);
   }
   free(visitMap);
    return diff;
}

int main(int argc, char *argv[])
{
    int32_t **g;
    int T, R, C;
    FILE *fp = freopen(argv[1], "r", stdin);
    if(fp == NULL) exit(EXIT_FAILURE);

    /* get the test cases */
    (void)(scanf("%d", &T));
    for(int i = 0; i < T; i++)
    {
        scanf("%d %d", &R, &C);
        g = (int **) calloc(R, sizeof(int32_t *));
        for(int ii=0; ii < R; ii++)
        {
            g[ii] = (int *)calloc(C, sizeof(int32_t));
        }

        int offset = 0;
        

        /* read all the input values */
        for(int R_ = 0; R_ < R; R_++)
        {
            for(int C_ = 0; C_ < C; C_++)
            {
                scanf("%d", &g[R_][C_]);
            }
        }

        // printf("record #%d\n", (i+1));


        // for(int R_ = 0; R_ < R; R_++)
        // {
        //     for(int C_ = 0; C_ < C; C_++)
        //     {
        //         printf("%d ", g[R_][C_]);
        //     }
        //     printf("\n");
        // }
        // printf("\n");

        /* go thru all the rows and columns */
        // int totalCellsAdded = 0;
        // for(int R_ = 0; R_ < R; R_++)
        // {
        //     for(int C_ = 0; C_ < C; C_++)
        //     {
        //         totalCellsAdded += adjust_consecutive_cells(g, R_, C_, R, C);
        //     }
        // }
        
        printf("Case #%d: %ld\n", (i+1), make_safe_rabbit_house(g, R, C));

        
        for(int ii=0; ii < R; ii++)
        {
            free(g[ii]);
        }
        free(g);
    }
}



