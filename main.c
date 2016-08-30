﻿
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
#include <unistd.h>
//#include <unistd.h>

#include "funcs.h"


int welcomeSocket, newSocket;
struct sockaddr_in serverAddr;
struct sockaddr_storage serverStorage;
socklen_t addr_size;
pthread_t rThread;
unsigned char key[10];


void sendMessage(unsigned char * key, int socketAddr, int option) {
    int count = 0;

    while(1) {
        char messageText[250];
        if(option == 0) {
            memset(messageText, '\0', 250);
            //printf("\nMessage > ");
            fgets(messageText, 250, stdin);
        }
        else if (option == 1) {
            messageText[0] = 'a';
        }

        unsigned char iv[6];                  // 6 byte IV
        unsigned char ivkey[16];              // 16 byte iv+key for KSA
        unsigned char s[256];                 // s holds internal state
        unsigned int i, j;
        i = j = 0;

        unsigned int messageLen = strlen(messageText);        //sizeof(messageText);
        unsigned char encrypted[messageLen];
        unsigned char decrypted[messageLen];
        unsigned char ivEncrypted[messageLen + 7];

        ivkeyCreate(iv, key, ivkey);

        ksa(s, ivkey, 16, i, j); //printf("ONE %d, %d\n", s[0],s[1]);
        encryptMine(s, messageText, encrypted, decrypted, i, j, messageLen);
        addIV(iv, encrypted, ivEncrypted, messageLen);

        send(socketAddr, ivEncrypted, (messageLen+7), 0);
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

    int messageLen =  buffer[6];
    unsigned char encrypted[messageLen];
    unsigned char decrypted[messageLen];

    for(int k = 0; k < messageLen; k++) {
        encrypted[k] = buffer[k+7];
    }

    printf("> ");
    ksa(s, ivkey, 16, i ,j);
    decrypt(s, messageLen, encrypted, decrypted, i, j);
}


void receiveMessage(int socketAddr) {
    char buffer[256];
    while(1) {
        if(recvfrom(socketAddr, buffer, 256, 0, NULL, NULL) < 0) {
            printf("\nError receiving data\n");
            exit(1);
        }
        else {
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
        printf("\nWaiting for connections...\n");
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
        printf("Connected to the server\n");
    }

    return newSocket;
}


int main(void) {
    int option, socketAddr;
    char charOption[3];
    char lineBuffer[256];
    srand((unsigned int)time(NULL));

    printf("\n~ ~ ~ ~ ~ RC4 Encrypted File Transfer/Chat v1.05 ~ ~ ~ ~ ~\n\n");
    printf("Type your RC4 symmetric key > ");

    fgets(lineBuffer, sizeof(lineBuffer), stdin);
    strncpy(key, lineBuffer, 10);
    memset(lineBuffer, 0, 256);
    fflush(stdin); //*/

    printf("Do you want to run as server (1) or client (2)? > ");
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

    atexit(shutdown(socketAddr, 'MT-Safe'));
    if( pthread_create(&rThread, NULL, receiveMessage, (void *)socketAddr) ) {
        printf("\nError: thread can't create");
        exit(1);
    } //*/

    printf("\nDo you want to send files (1), message from the command line (2) or simulate WEP traffic (3)? > ");
    scanf("%s", charOption);
    option = atoi(charOption);

    while(1) {
        if (option == 1) {
            printf("Whats the files path? > ");
            scanf("%s", lineBuffer);
            unsigned char *fileLoc = malloc(strlen(lineBuffer));
            strncpy(fileLoc, lineBuffer, strlen(lineBuffer));
            printf("\nFile location: %sEND\n", fileLoc); //*/
            printf("adding functionality...");
            //sendFile(fileLoc, key, socketAddr);
            break;
        }
        if (option == 2) {
            sendMessage(key, socketAddr, 0);
            break;
        }
        if (option == 3) {
            printf("\n\nSimulating WEP traffic. Warning: CPU intensive");
            sendMessage(key, socketAddr, 1);
        }
        else {
            printf("Invalid Option, choose again > ");
        }
    }

    //close(socketAddr);
    return 0;
}



