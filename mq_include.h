#include <stdlib.h>	
#include <stdio.h>
#include <unistd.h>
#include <string.h>
# include "mta_crypt.h"
# include "mta_rand.h"
# include <ctype.h>
#include <mqueue.h>
#include <errno.h>
#include <pthread.h>

typedef int BOOL;
#define TRUE 1
#define FALSE 0


#define MQ_MAX_SIZE         10
#define MQ_MAX_MSG_SIZE     100	//Some big value(in bytes)
#define MQ_SERVER          "/server_mq"
#define MAX_NUM_OF_CLIENTS     10
#define ORIGINAL_PASS_LENGTH  8
#define KEY_LENGTH 	    1
#define MQ_CLIENT       "/mq_ "
#define STR_MQ_LENGTH 6
#define ERROR_OUT -1
#define MAX_SIZE_MQ_NAME 11 // "/mq_ "+0-99999
#define MAX_ENCRYPTED_PASSWORD_LENGTH 1024

typedef enum{
	IDLE, //client keeps guessing passwords
	CONNECT_REQUEST,   //client request to connect
	CLOSE_REQUEST, //client sends to server
	PRINTABLE_PASSWORD, //client sends to the server
	CONNECTION_SUCCEED_RESPOND, //server respond
	CONNECTION_FAILED_RESPOND, //server respond
	DUPLICATE_ID_RESPOND, //server respond
	SERVER_INFO_NEW_PASSWORD, //client succeed

} MESSAGE_TYPE;

/* Data that will be passed from the Writer to the reader
should hold the actual application data */ 
typedef struct message{
	MESSAGE_TYPE type;
	int clientNumber;
	int iterationNumber;
	char mq_name[6]; //mq_*
	char decrypted_pass[ORIGINAL_PASS_LENGTH]; //decrypted password
	int encryptedPasswordLength; 
	char encrypted_pass[];
}MSG_T;


//Server:
void broadcastNewPasswordsToAllClients(char* encryptedPassword,int encryptedPasswordLength,  int* clientsIDArray);
void addClientToIDArray(int clientID, int* clientsIDArray);
void deleteClientFromArray(int clientID, int* clientsIDArray);
BOOL checkIfClientExist(int clientID, int* clientsIDArray);
void FreeServer(MSG_T* msg, char* OriginalPass, char* OriginalKey, char* PassFromClient, char* encryptedPassword);
void randPasswordAndKeyServer(char* OriginalPass, char* OriginalKey);

//Client:
void freeClient(MSG_T* msg, char* clientKey, char* ClientPasswordGuess, char* passwordFromServer);
void randKeyClient(char* key);
BOOL checkIfPrintableGuess(char* password);
void UpdateMQClientBeforeSent(MSG_T* msg, int clientID, int IterationNumber, char* localMqName);
int countDigit(int number);
