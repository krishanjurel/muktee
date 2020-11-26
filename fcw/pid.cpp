#include <iostream>
#include <string>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

using namespace std;

int iGlobalVar=10;
int main()
{
    string sId;
    int iStackVar = 20;
    int timestamp = time(nullptr);

    pid_t pid = fork();
    if (pid == 0)
    {
        std::cout << "child process is created " << timestamp << std::endl;
        int iChildPid = getpid();
        iStackVar ++;
        iGlobalVar ++ ;

        cout << " the child pid is " << iChildPid << std::endl;
        sleep (10);
        timestamp = time(nullptr);
        std::cout << "child process is exited " << timestamp << std::endl;
        exit(10);
    }else {
        std::cout << "parent process is created " << timestamp << std::endl;
        int iParentPid = getpid();
        iStackVar ++;
        iGlobalVar ++ ;

        cout << " the parent pid is " << iParentPid << std::endl;
        int childExitStatus;
        pid_t ws = waitpid(0, &childExitStatus, WSTOPPED);
        std::cout << " the child exit status " << WEXITSTATUS(childExitStatus) << std::endl;
        timestamp = time(nullptr);
        std::cout << "parent process is exited " << timestamp << std::endl;
        exit(0);
    }
    return 0;
}