#include "mq_include.h"
int main(int argc, char* argv[])// args[1] = number of Clients
{    
	int numOfClients = 2;
	if(!argv[1])
	{
		numOfClients = 0;
		printf("NO CLIENTS... bye bye\n");
		exit(1);
	}
	
	numOfClients = atoi(argv[1]);
    if(numOfClients > MAX_NUM_OF_CLIENTS)
    {
    	printf("[EXIT] Number of Clients exceeded MAX_NUM_OF_CLIENTS\nbye bye...\n");
    	exit(1);
    }

    pid_t wpid, rpid[2];
	/* create writer process */
	wpid = fork();
	if (wpid == 0) //Server(encrypter)
	{
		char *argv[] = {"./server.out",0};
		execv("./server.out",argv);
		
	}
	
	sleep(2);
	/* Create reader process */
   	for(int i = 1; i <= numOfClients; i++)
    	{
		rpid[i] = fork();
		if(rpid[i] == 0) //Client(decrypter)
		{
			char* buff;
			sprintf(buff,"%d",i);
			char *argv[] = {"./client.out",buff,0};
			execv("./client.out", argv);
		}
    } 
   
	// Do nothing, only parent process should get here
	pause();

    return 0;
}
