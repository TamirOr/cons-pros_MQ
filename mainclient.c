#include "mq_include.h"


void main(int argc, char* argv[])//args[1]= '-n'; args[2]=limit of rounds
{
	mqd_t mqServer = 0;
	int globalRoundAllowed;
	if(argv[2])
	{
		globalRoundAllowed=atoi(argv[2]);
	}

	MSG_T* msg = (MSG_T*)(malloc(sizeof(char) * MQ_MAX_MSG_SIZE)); // Allocate big size in advance
    mqServer = mq_open(MQ_SERVER, O_WRONLY ); //open the main queue
	char* clientKey=malloc(sizeof(char)*KEY_LENGTH+1);
	char* ClientPasswordGuess=malloc(sizeof(char)*ORIGINAL_PASS_LENGTH+1);
	char* passwordFromServer = NULL;
	int clientID = atoi(argv[1]);
	char localMqName[MAX_SIZE_MQ_NAME];
	localMqName[countDigit(clientID)] = '\0';
	unsigned int unEncryptedPasswordSize=ORIGINAL_PASS_LENGTH;
	int iterationNumber = 0;
	//Client MQ:
	strcpy(localMqName,MQ_CLIENT);
	sprintf(localMqName+4,"%s",argv[1]);
	((MSG_T*)msg)->clientNumber = clientID;
	struct mq_attr mqAttr = {0};
	mqAttr.mq_maxmsg = MQ_MAX_SIZE;
	mqAttr.mq_msgsize = MQ_MAX_MSG_SIZE;
	mq_unlink(localMqName);
	mqd_t mqDecryptor = mq_open(localMqName,O_CREAT | O_NONBLOCK , S_IRWXU | S_IRWXG | O_RDWR, &mqAttr); //open private queue "/mq_*CLIENT NUMBER*"  
	msg->type = CONNECT_REQUEST; //connect to server	
	memcpy(((MSG_T*)msg)->mq_name, localMqName,5);
	msg->mq_name[countDigit(clientID)] = '\0';
	printf("[CLIENT #%d]\t[INFO]  Sending connect request on %s\n",clientID,MQ_SERVER );
	mq_send(mqServer, (char*)msg, MQ_MAX_MSG_SIZE, 0); 
	int roundNumber = 1;
	while(TRUE)
	{
		sleep(0.5);
		if((argv[2])&&(roundNumber>globalRoundAllowed))
		{
			((MSG_T*)msg)->type = CLOSE_REQUEST;
			mq_send(mqServer,(char*)msg,MQ_MAX_MSG_SIZE,0);
			mq_close(mqDecryptor);
			mq_unlink(localMqName);
    	 	printf("[MAX_ROUNDs] connection closed \n");
    	 	exit(0);
		}
		
		mq_receive(mqDecryptor,(char*)msg,MQ_MAX_MSG_SIZE,NULL);
		switch (msg->type)
		{
		case DUPLICATE_ID_RESPOND:
			printf("[DUPLICATE_KEY] connection request FAILED\n");
			freeClient(msg, clientKey, ClientPasswordGuess, passwordFromServer);
			exit(1);
			break;

		case CONNECTION_FAILED_RESPOND:
			printf("[MAX NUMBER OF CLIENTS] connection request FAILED\n");
			freeClient(msg, clientKey, ClientPasswordGuess, passwordFromServer);
			exit(1);
			break;

		case CONNECTION_SUCCEED_RESPOND:
			iterationNumber = 0;
			printf("[CLIENT #%d]\t[CONNECTION]  Connected to server\n", clientID);

		case SERVER_INFO_NEW_PASSWORD:
			printf("[CLIENT #%d]\t[INFO]  Recieved new encrypted password %s\n", clientID, ((MSG_T*)msg)->encrypted_pass);

		case IDLE:
			((MSG_T*)msg)->type = IDLE;
			//finding random characters for key
			randKeyClient(clientKey);
			iterationNumber++;
			MTA_CRYPT_RET_STATUS returnValue = MTA_CRYPT_RET_OK;
			do
			{
				MTA_CRYPT_RET_STATUS returnValue = MTA_decrypt(clientKey, KEY_LENGTH, ((MSG_T*)msg)->encrypted_pass, ((MSG_T*)msg)->encryptedPasswordLength, ((MSG_T*)msg)->decrypted_pass, &unEncryptedPasswordSize);
			} while (returnValue != MTA_CRYPT_RET_OK);

			if (checkIfPrintableGuess(msg->decrypted_pass))
			{
				roundNumber++;
				UpdateMQClientBeforeSent(msg, clientID, iterationNumber, localMqName);
				mq_send(mqServer, (char*)msg, MQ_MAX_MSG_SIZE, 0);
				((MSG_T*)msg)->type = IDLE;
				printf("[CLIENT #%d]\t[INFO]  After Decryption %s, Key guessed %s, sending to server after %d iterations\n", clientID, ((MSG_T*)msg)->decrypted_pass, clientKey, iterationNumber);
				iterationNumber = 0;
			}
		}
	}
	freeClient(msg, clientKey, ClientPasswordGuess, passwordFromServer);
}

void UpdateMQClientBeforeSent(MSG_T* msg, int clientID, int IterationNumber, char* localMqName)
{
	msg->type = PRINTABLE_PASSWORD;
	msg->clientNumber = clientID;
	msg->iterationNumber = IterationNumber;
	msg->decrypted_pass[ORIGINAL_PASS_LENGTH] = '\0';
	strcpy(msg->mq_name, localMqName);
}

void randKeyClient(char* clientKey)
{
	int indexRandKey;
	for (indexRandKey = 0; indexRandKey < (ORIGINAL_PASS_LENGTH / 8); indexRandKey++)
	{
		clientKey[indexRandKey] = MTA_get_rand_char();
	}

	clientKey[indexRandKey] = '\0';
}

void freeClient(MSG_T* msg, char* clientKey, char* ClientPasswordGuess, char* passwordFromServer)
{
	free(msg);
	free(clientKey);
	free(ClientPasswordGuess);
	free(passwordFromServer);
}

BOOL checkIfPrintableGuess(char* password)
{
	int i;
	for (i = 0; i < ORIGINAL_PASS_LENGTH; i++)
	{
		if (!isprint(password[i]))
		{
			return FALSE;
		}
	}
	return TRUE;
}

int countDigit(int number)
{
	int numOfDigit = 0;
	while (numOfDigit > 9)
	{
		numOfDigit %= 10;
		numOfDigit++;
	}
	return 5+numOfDigit;
}
