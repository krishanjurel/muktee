#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int max_operations(char *str, int score)
{
    int strlen_=strlen(str);
    int score_ = 0;
    int maxops = 0;
    for(int i=0; i < strlen_/2; i++)
    {
        if(str[i] != str[strlen_-i-1]){
            score_ ++;
        }
    }

    if(score_ == score)
        maxops = 0;
    
    if(score > score_) 
    {
        maxops = score - score_;
    }
    else {
        maxops = score_ - score;
    }
    return maxops;
}




int main(int argc, char *argv[])
{
    int T, N, B;
    char *str;
    // printf("number of arguments %d\n", argc);
    // for(int ii = 0; ii < argc; ii++)
    // {
    //     printf("arg #%d is %s\n", ii+1, argv[ii]);

    // }
    FILE *fp = freopen(argv[1], "r", stdin);
    scanf("%d", &T);
    
    for(int i = 0; i < T; i++)
    {
        scanf("%d %d", &N, &B);
        str = (char *)calloc(N+1, 1);
        scanf("%s", str);
        // printf("#%d %d %d %s\n", T, N, B, str);
        printf("Case #%d: %d\n", (i+1), max_operations(str, B));
        free(str);

    }
    return 0;
}



