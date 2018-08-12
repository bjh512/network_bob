#include <stdio.h>      
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h> 
#include <string.h> 
#include <arpa/inet.h>
#include <pthread.h>

void *threadRoutine1(void *arg){
    for(int i=0; i<100;i++){
        callInThread(100);
        printf("1\n");
    }
}

void *threadRoutine2(void *arg){
    for(int i=0; i<100;i++){
        callInThread(200);
        printf("2\n");
    }
}

int main (int argc, const char * argv[]) {
    pthread_t threadID1,threadID2;
    int status;

    pthread_create(&threadID1,NULL,threadRoutine1,NULL);
    pthread_create(&threadID2,NULL,threadRoutine2,NULL);

    pthread_join(threadID1,(void **)&status);
    pthread_join(threadID2,(void **)&status);
}