
/* RC4 - Tom D */

#ifndef ARCFOUR_FUNCS_H
#define ARCFOUR_FUNCS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void ivkeyCreate(unsigned char * iv, unsigned char * key, unsigned char * ivkey) {
    for(unsigned int k = 0; k < 6; k++) {
        iv[k] = rand() % 127;
    }
    for(unsigned int i = 0; i < 6; i++) {
        ivkey[i] = iv[i];
    }
    for(unsigned int j = 0; j < 10; j++) {
        ivkey[j+6] = key[j];
    }
}


unsigned int openMessage(unsigned char * fileLoc) {
    FILE * messageFile;
    //printf("\nFile location: %s\n", fileLoc);
    messageFile = fopen(fileLoc, "r");
    printf("\nFile Location OPENMESSAGE: %s\n", fileLoc);
    if(!messageFile) {
        printf("Cannot open message file");
        exit(1);
    }
    printf("\nFile opened (openMessage)\n\n");
    fseek(messageFile, 0L, SEEK_END);
    unsigned int messageLen = ftell(messageFile);
    rewind(messageFile);
    fclose(messageFile);

    return messageLen;
}


void readMessage(unsigned char * message, unsigned int messageLen, unsigned char * fileLoc) {
    FILE * messageFile;
    messageFile = fopen(fileLoc, "r");
    if(!messageFile) {
        printf("Cannot open message file");
        exit(1);
    }

    fgets(message, messageLen, messageFile);
    fclose(messageFile);
}


void ksa(unsigned char * s, unsigned char * ivkey, unsigned int keyLength, unsigned int i, unsigned int j) {
    for(i = 0; i < 256; i++) {
        s[i] = i;
    }

    for(i = j = 0; i < 256; i++) {
        j = (j + s[i] + ivkey[i % keyLength])%256;
        unsigned char temp = s[j];
        s[j] = s[i];
        s[i] = temp;
    }
    i = j = 0;
}


unsigned char prga(unsigned char * s, unsigned int i, unsigned int j) {
    i = (i + 1) % 256;
    j = (j + s[i]) % 256;
    unsigned char temp = s[j];
    s[j] = s[i];
    s[i] = temp;
    return s[(s[i] + s[j]) % 256];
}


int encrypt(unsigned char * s, unsigned char * message, unsigned char * encrypted, unsigned char * decrypted, unsigned int i, unsigned int j, unsigned int messageLen) {
    for(int k = 0; k < messageLen; k++) {
        encrypted[k] = (message[k]) ^ (prga(s,i,j));
        //printf("%.2x ", encrypted[k]);
    }
}


int decrypt(unsigned char * s, int messageLen, unsigned char * encrypted, unsigned char * decrypted, unsigned int i, unsigned int j) {
    for(int k = 0; k < messageLen; k++) {
        decrypted[k] = (encrypted[k]) ^ (prga(s,i,j));
        printf("%c", decrypted[k]);
    }
}


void addIV(unsigned char * iv, unsigned char * encrypted, unsigned char * ivEncrypted, unsigned int messageLen) {
    for(int i = 0; i < 6; i++) {
        ivEncrypted[i] = iv[i];
    }
    ivEncrypted[6] = messageLen;
    for(int j = 0; j < messageLen; j++) {
        ivEncrypted[j+7] = encrypted[j];
    }
}


/*int sendFile(unsigned char * fileLoc, unsigned char * key, int socketAddr) {
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
    decrypt(s, message, encrypted, decrypted, i, j, messaageLen);
} //*/


#endif //ARCFOUR_FUNCS_H


