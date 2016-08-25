
/* RC4 - Tom D */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <errno.h>
//#include <unistd.h>

#include "funcs.h"


int welcomeSocket, newSocket;
struct sockaddr_in serverAddr;
struct sockaddr_storage serverStorage;
socklen_t addr_size;
pthread_t rThread;
unsigned char key[10];


int sendFile(unsigned char * fileLoc, unsigned char * key, int socketAddr) {
    unsigned char iv[6];                  // 6 byte IV
    unsigned char ivkey[16];              // 16 byte iv+key for KSA
    unsigned char s[256];                 // s holds internal state
    unsigned int i,j;
    i = j = 0;

    unsigned int messageLen = openMessage(fileLoc); printf("messageLen: %d\n\n", messageLen);
    unsigned char message[messageLen];
    unsigned char encrypted[messageLen];
    unsigned char decrypted[messageLen];
    unsigned char ivEncrypted[messageLen + 6];

    ivkeyCreate(iv, key, ivkey); printf("IV KEY: %sEND\n\n", ivkey);
    readMessage(message, messageLen, fileLoc);
    printf("Message: %s\n", messageLen, message);

    ksa(s, ivkey, 16, i, j); //printf("ONE %d, %d\n", s[0],s[1]);
    encrypt(s, message, encrypted, decrypted, i, j);
    addIV(iv, encrypted, ivEncrypted, messageLen);

    send(socketAddr, ivEncrypted, messageLen+6, 0);
    printf("\n\nEncrypted message sent: %s\n", ivEncrypted);

    ksa(s, ivkey, 16, i, j); //printf("\nTWO %d, %d\n", s[0],s[1]);
    decrypt(s, message, encrypted, decrypted, i, j);    //*/
}


int sendMessage(unsigned char * key, int socketAddr) {
    int check = 0;
    while(1) {
        if(check == 0)
            check = 1;
        else if (check == 1) {
            char messageText[250];
            printf("\nMessage > ");
            fgets(messageText, 250, stdin);
            /*printf("messageBUFFER: %s", messageBuffer);
            scanf("%[^\n]%*c", messageBuffer);
            printf("\nMessageBuffer2: %s", messageBuffer);
            printf("HERETWO");
            unsigned char messageText[256];
            printf("HEREONE");
            strncpy(messageText, messageBuffer, 256);
            printf("\nMessage Text: %sEND\n", messageText); //*/

            if (messageText == 'quit') {
                printf("\n\nQuitting...");
                exit(0);
            }

            unsigned char iv[6];                  // 6 byte IV
            unsigned char ivkey[16];              // 16 byte iv+key for KSA
            unsigned char s[256];                 // s holds internal state
            unsigned int i, j;
            i = j = 0;

            unsigned int messageLen = 250;        //sizeof(messageText);
            //printf("\n\nmessageLen: %d\n\n", messageLen);
            unsigned char message[messageLen];
            unsigned char encrypted[messageLen];
            unsigned char decrypted[messageLen];
            unsigned char ivEncrypted[messageLen + 6];
            memset(ivEncrypted, '\0', 256);

            ivkeyCreate(iv, key, ivkey);

            /*printf("IV KEY: ");
            for (int k = 0; k < 16; k++) {
                printf("%.2x ", ivkey[k]);
            } //*/
            //printf("Encrypted Message: ");

            ksa(s, ivkey, 16, i, j); //printf("ONE %d, %d\n", s[0],s[1]);
            encrypt(s, messageText, encrypted, decrypted, i, j);
            addIV(iv, encrypted, ivEncrypted, messageLen);

            /*unsigned char sendBuffer[256];
            strcpy(sendBuffer, ivEncrypted);*/

            /*printf("\n\nTo Send: ");
            for (int i = 0; i < 256; i++)
                printf("%.2x ", ivEncrypted[i]); //*/

            send(socketAddr, ivEncrypted, 256, 0);

            /*printf("\n\nDecrypted: ");
            ksa(s, ivkey, 16, i, j);
            decrypt(s, messageLen, encrypted, decrypted, i, j); //*/
        }
    }
}


void decryptPrint(char * buffer) {

    unsigned char ivkey[16];              // 16 byte iv+key for KSA
    unsigned char s[256];                 // s holds internal state
    unsigned int i,j;
    i = j = 0;

    for(int i = 0; i < 6; i++) {
        ivkey[i] = buffer[i];
    }
    for(int j = 0; j < 10; j++) {
        ivkey[j+6] = key[j];
    }
    /*unsigned char * messageText[256];
    strncpy(messageText, buffer, 256); //*/

    int messageLen =  250;  //sizeof(messageText); //printf("\n\nmessageLen: %d\n\n", messageLen);
    //unsigned char message[messageLen];
    unsigned char encrypted[messageLen];
    unsigned char decrypted[messageLen];

    for(int k = 0; k < messageLen; k++) {
        encrypted[k] = buffer[k+6];
    }
    /*printf("IV Key: ");
    for(int k = 0; k < 16; k++)
        printf("%.2x ", ivkey); //*/
    printf("\n\nReceived: ");
    ksa(s, ivkey, 16, i ,j);
    decrypt(s, messageLen, encrypted, decrypted, i, j);
    printf("\n\n");
}


void receiveMessage(int socketAddr) {
    char buffer[256];
    //memset(buffer, 0, 256);
    while(1) {
        if(recvfrom(socketAddr, buffer, 256, 0, NULL, NULL) < 0) {
            printf("\nError receieving data\n");
            exit(1);
        }
        else {
            /*printf("\nRecieved: ");
            for(int i = 0; i < 256; i++)
                printf("%.2x ", buffer[i]); //*/
            decryptPrint(buffer);
        }
    }
}


int serverSetup(void) {
    int optval = 1;

    //Create socket. internet, streamtype, 0=tcp
    welcomeSocket = socket(PF_INET, SOCK_STREAM, 0);
    setsockopt(welcomeSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    // configure server address struct
    serverAddr.sin_family = AF_INET;                                // internet
    serverAddr.sin_port = htons(9696);                              // port number
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");            // on localhost
    memset(serverAddr.sin_zero, '\0', sizeof(serverAddr.sin_zero));  // set padding to null bytes

    //bind address struct to socket
    bind(welcomeSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

    //listen on the socket, max five connections
    if(listen(welcomeSocket,5)==0)
        printf("Waiting for connections...\n");
    else {
        printf("Error listening\n");
        exit(0);
    }

    // accepting call creates a new socket for communicating
    addr_size = sizeof(serverStorage);
    newSocket = accept(welcomeSocket, (struct sockaddr *) &serverStorage, &addr_size);
    setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    printf("Connection accepted on socket address %d\n", newSocket);

    //send(newSocket, "Connected to RC4\n", 18, 0);
    return newSocket;
}


int clientSetup(void) {
    char serverIp[256];
    printf("\nWhats the IP of the server? > ");
    fgets(serverIp, sizeof(serverIp), stdin);
    scanf("%s", serverIp);
    int optval = 1;

    //Create socket. internet, streamtype, 0=tcp
    newSocket = socket(PF_INET, SOCK_STREAM, 0);
    setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (welcomeSocket < 0) {
        printf("Error creating socket\n");
        exit(1);
    }
    // configure server address struct
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;                                    // internet
    serverAddr.sin_port = htons(9696);                                  // port number
    serverAddr.sin_addr.s_addr = inet_addr(serverIp);                   // on localhost
    // connect to server
    if (connect(newSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
        printf("Error connect(): %i: %s \n", errno, strerror(errno));
        exit(1);
    }
    else {
        printf("\nConnected to the server");
    }

    return newSocket;
}


int main(void) {
    int option, socketAddr;
    char charOption[3];
    char lineBuffer[256];
    srand((unsigned int)time(NULL));

    printf("\n~ ~ ~ ~ ~ RC4 Encrypted File Transfer/Chat v1.04 ~ ~ ~ ~ ~\n\n");
    printf("Type your RC4 symmetric key > ");

    fgets(lineBuffer, sizeof(lineBuffer), stdin);
    strncpy(key, lineBuffer, 10);
    memset(lineBuffer, 0, 256);
    fflush(stdin); //*/

    printf("\nDo you want to run as server (1) or client (2)? > ");
    scanf("%s", charOption);
    option = atoi(charOption);

    while (1) {
        if (option == 1) {
            socketAddr = serverSetup();
            break;
        }
        if (option == 2) {
            socketAddr = clientSetup();
            break;
        } else {
            printf("\nIncorrect Option\n");
            //exit(0);
        }
    }

    if( pthread_create(&rThread, NULL, receiveMessage, (void *)socketAddr) ) {
        printf("\nError: thread can't create");
        exit(1);
    } //*/

    printf("\nDo you want to send files (1) or message from the command line (2)? > ");
    scanf("%s", charOption);
    option = atoi(charOption);

    while(1) {
        if (option == 1) {
            printf("Whats the files path? > ");
            scanf("%s", lineBuffer);
            unsigned char *fileLoc = malloc(strlen(lineBuffer));
            strncpy(fileLoc, lineBuffer, strlen(lineBuffer));
            printf("\nFile location: %sEND\n", fileLoc); //*/

            sendFile(fileLoc, key, socketAddr);
            break;
        }
        if (option == 2) {
            sendMessage(key, socketAddr);
            break;
        } else {
            printf("Invalid Option");
        }
    }

    //close(socketAddr);
    return 0;
}



