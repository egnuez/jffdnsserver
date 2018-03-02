
#include <stdio.h>
#include <signal.h>

int main(){
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGHUP);
    sigprocmask(SIG_BLOCK, &set, NULL);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
}
