#include "mq_include.h"


void main()
{	//local parms:
	int clientsIDArray[MAX_NUM_OF_CLIENTS] = {0}; //array for the clients ID	
	char* OriginalPass = malloc(sizeof(char)*ORIGINAL_PASS_LENGTH+1);
	char* OriginalKey = malloc(sizeof(char)*KEY_LENGTH+1);
	char* PassFromClient = malloc(sizeof(char)*ORIGINAL_PASS_LENGTH+1);
	unsigned int encryptedPasswordLength=0;
	char* encryptedPassword=(char*)calloc(MAX_ENCRYPTED_PASSWORD_LENGTH, sizeof(char));
	int clientID;
	char localClientMQName[STR_MQ_LENGTH];
	int clientsCounter = 0;
	
	//set priority and policy
	int res = ERROR_OUT;
	struct sched_param max_prio = {sched_get_priority_max(SCHED_FIFO)};
	res = pthread_setschedparam(pthread_self(),SCHED_FIFO,&max_prio);
	if(res == ERROR_OUT)
	{
		printf("[ERROR]\tSet schedule\n");
	}
	
	//open server message queue
	struct mq_attr mqAttr = {0};
	mqAttr.mq_maxmsg = MQ_MAX_SIZE;
	mqAttr.mq_msgsize = MQ_MAX_MSG_SIZE;
	mq_unlink(MQ_SERVER);
	mqd_t mq_fileDescriptor_SERVER = mq_open(MQ_SERVER, O_CREAT, S_IRWXU | S_IRWXG | O_RDONLY, &mqAttr); //main queue who gets messages from the decryptors
	MSG_T* msg = malloc(MQ_MAX_MSG_SIZE);
	
	
	//finding random characters for the password to encrypt
	randPasswordAndKeyServer(OriginalPass, OriginalKey);
	
	MTA_CRYPT_RET_STATUS returnValue = MTA_CRYPT_RET_OK;
	do
	{
		MTA_CRYPT_RET_STATUS returnValue = MTA_encrypt(OriginalKey, (ORIGINAL_PASS_LENGTH/8), OriginalPass, ORIGINAL_PASS_LENGTH, encryptedPassword, (unsigned int*)&encryptedPasswordLength);
			
	}while(returnValue != MTA_CRYPT_RET_OK);

	while(TRUE)
	{
		mq_receive(mq_fileDescriptor_SERVER, (char*)msg, MQ_MAX_MSG_SIZE, NULL); //pull a message from the main queue. mq_recieve is blocking if queue is empty
		clientID = ((MSG_T*)msg)->clientNumber; //client ID of the current message in the queue
		strcpy(localClientMQName,((MSG_T*)msg)->mq_name); //mq name of the current message in the queue
		switch (msg->type)
		{
		case CONNECT_REQUEST:
			if (clientsCounter == MAX_NUM_OF_CLIENTS)  //check if descryptorCounter reached the maximum
			{
				((MSG_T*)msg)->type = CONNECTION_FAILED_RESPOND;
				printf("[SERVER]\t[ERROR]  Server queue is FULL\n");
			}
			else if (checkIfClientExist(clientID, clientsIDArray))
			{
				printf("[SERVER]\t[ERROR]  DUPLICATE ID for client #%d Connection FAILED\n", clientID);
				((MSG_T*)msg)->type = DUPLICATE_ID_RESPOND;
				memcpy(((MSG_T*)msg)->encrypted_pass, encryptedPassword, encryptedPasswordLength);
				((MSG_T*)msg)->encryptedPasswordLength = encryptedPasswordLength;
			}
			else
			{
				printf("[SERVER]\t[INFO]  Recieved connection request from decryptor id %d queue name %s\n", clientID, ((MSG_T*)msg)->mq_name);
				addClientToIDArray(clientID, clientsIDArray);
				clientsCounter++;
				((MSG_T*)msg)->type = CONNECTION_SUCCEED_RESPOND;
				memcpy(((MSG_T*)msg)->encrypted_pass, encryptedPassword, encryptedPasswordLength);
				((MSG_T*)msg)->encryptedPasswordLength = encryptedPasswordLength;
			}

			mqd_t mqClient = mq_open(localClientMQName, O_WRONLY); //send the answer to the descryptor in his private queue
			mq_send(mqClient, (char*)msg, MQ_MAX_MSG_SIZE, 0);
			mq_close(mqClient);
			break;
	
		case PRINTABLE_PASSWORD:
			if (strncmp(((MSG_T*)msg)->decrypted_pass, OriginalPass, ORIGINAL_PASS_LENGTH) == 0)
			{
				printf("[SERVER]\t[OK]  password decrypted successfully by client #%d after %d iteratioans,recieved password is %s\n", clientID, ((MSG_T*)msg)->iterationNumber, ((MSG_T*)msg)->decrypted_pass);
				randPasswordAndKeyServer(OriginalPass, OriginalKey);
				MTA_CRYPT_RET_STATUS returnValue = MTA_CRYPT_RET_OK;
				do
				{
					MTA_CRYPT_RET_STATUS returnValue = MTA_encrypt(OriginalKey, (ORIGINAL_PASS_LENGTH / 8), OriginalPass, ORIGINAL_PASS_LENGTH, encryptedPassword, (unsigned int*)&encryptedPasswordLength);

				} while (returnValue != MTA_CRYPT_RET_OK);

				broadcastNewPasswordsToAllClients(encryptedPassword, encryptedPasswordLength, clientsIDArray);
			}
			else
			{
				printf("[SERVER]\t[ERROR]  wrong password recieved from client #%d: recieved password: %s, should be %s\n", clientID, ((MSG_T*)msg)->decrypted_pass, OriginalPass);
			}
			break;
		
		case CLOSE_REQUEST:
			deleteClientFromArray(clientID, clientsIDArray); //remove client number from array of ID
			clientsCounter--;
			printf("[SERVER]\t[INFO] Client #%d - Connection Closed\n", clientID);
			break;
		
		}
	}
	FreeServer(msg,OriginalPass, OriginalKey, PassFromClient, encryptedPassword);
}

void broadcastNewPasswordsToAllClients(char* newPassword, int passwordLength, int* clientsIDArray)
{
	int i;
	struct timespec abs_timeout;
	clock_gettime(CLOCK_REALTIME, &abs_timeout);
	abs_timeout.tv_sec += 2;
	char localMQName[STR_MQ_LENGTH];
	strcpy(localMQName,MQ_CLIENT);
	mqd_t tempDescriptor;
	MSG_T* localMsg = malloc(sizeof(char) * MQ_MAX_MSG_SIZE);
	for(i=0;i<MAX_NUM_OF_CLIENTS;i++)
	{
		if(clientsIDArray[i])//if !=0 so client exist
		{
			sprintf(localMQName + 4 , "%d",clientsIDArray[i]);
			tempDescriptor = mq_open(localMQName,O_WRONLY);
			((MSG_T*)localMsg)->type = SERVER_INFO_NEW_PASSWORD;
			memcpy(((MSG_T*)localMsg)->encrypted_pass,newPassword,passwordLength);
			((MSG_T*)localMsg)->encryptedPasswordLength = passwordLength;
			int ret = mq_timedsend(tempDescriptor,(char*) localMsg,MQ_MAX_MSG_SIZE,0,&abs_timeout);
			if(ret == ERROR_OUT)
			{
				deleteClientFromArray(clientsIDArray[i],clientsIDArray);
				mq_close(tempDescriptor);
				mq_unlink(localMQName);
			}
			mq_close(tempDescriptor);		
		}
	}	

	free(localMsg);
}



void addClientToIDArray(int clientID, int* clientsIDArray)
{
	int i;
	for(i = 0;i<MAX_NUM_OF_CLIENTS;i++)
	{
		if(clientsIDArray[i] == 0)
		{
			clientsIDArray[i] = clientID;
			break;
		}
	}	
}

void deleteClientFromArray(int clientID, int* clientsIDArray)
{
	int i;
	for(i = 0;i<MAX_NUM_OF_CLIENTS;i++)
	{
		if(clientsIDArray[i] == clientID)
		{
			clientsIDArray[i] = 0;
			break;
		}
	}	
}

BOOL checkIfClientExist(int clientID, int* clientsIDArray)
{
	int i;
	for(i=0;i<MAX_NUM_OF_CLIENTS;i++)
	{
		if(clientsIDArray[i] == clientID)
		{
			return TRUE;					
		}	
	}
	return FALSE;
}

void FreeServer(MSG_T* msg, char* OriginalPass, char* OriginalKey, char* PassFromClient, char* encryptedPassword)
{
	free(msg);
	free(OriginalPass);
	free(OriginalKey);
	free(PassFromClient);
	free(encryptedPassword);
}

void randPasswordAndKeyServer(char* OriginalPass, char* OriginalKey)
{
	int indexRandPass;
	int indexRandKey;
	char printableChar;
	for (indexRandPass = 0; indexRandPass < ORIGINAL_PASS_LENGTH; indexRandPass++)
	{
		printableChar = MTA_get_rand_char();
		while (!isprint(printableChar))
		{
			printableChar = MTA_get_rand_char();
		}
		OriginalPass[indexRandPass] = printableChar;
	}

	OriginalPass[indexRandPass] = '\0';
	//finding random characters for key

	for (indexRandKey = 0; indexRandKey < (ORIGINAL_PASS_LENGTH / 8); indexRandKey++)
	{
		OriginalKey[indexRandKey] = MTA_get_rand_char();
	}

	OriginalKey[indexRandKey] = '\0';
}










