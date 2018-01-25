/* 
*
*       mkillebrew@net7systems.com
*       28th June 2016
*
*       Generates random 20 character plaintext and SHA-512 ciphertext, for further saltstack automation
*
*       $ gcc -o genpwd -lcrypt -lssl -lcrypto genpwd.c
*	$ ./genpwd 
*	a;7w=;{??!AC%CG)EK-G    $6$AYcEgIkMoQasUcwY$YIfbVKe0WjtwIYORe0JtxOlDtqWgECEmDwlwgK9BcwmVQ8gyD2sbnGCRZnY22.e1u/vBvbvC73AFVWTVQ2381.
*	$ ./genpwd -n
*	xlN0pR2tV4xZ68bfjn2r    $6$C7wEGICKGMKOO1QS$hBv/JObEJuWyqRVA6KgL9kNMUjbFhyosAeRW0G.8gCIQDcLKZGj6aUG3b1fdrlNHUHMQnBBvFMJnaWtFGuBpG1
*
*
*
*/

#define _XOPEN_SOURCE
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <inttypes.h>
#include <getopt.h>


unsigned int rand_range(int min_n, int max_n)
{
	unsigned bit;
	uintptr_t lshift;
	unsigned char *buffer, *buffer2;
	buffer=malloc(1);
	buffer2=malloc(1);

	RAND_bytes(buffer, 1);
	RAND_bytes(buffer2, 1);

	lshift=(uintptr_t)buffer;

	if(!((uintptr_t)buffer2 % 3)){
		bit  = ((lshift >> 0) ^ (lshift >> 2) ^ (lshift >> 3) ^ (lshift >> 5) ) & 1;
		lshift =  (lshift >> 1) | (bit << 15);
		buffer=(unsigned char *)(uintptr_t)lshift;
	}


        return (uintptr_t)buffer % max_n + min_n;
}


int main(int argc, char *argv[]){
        time_t t;
        int i, x, alnum, opt, phash;
        char plaintext[21], salt[21]="$6$";

	alnum,phash=0;
	bzero(plaintext, 21);

	if(RAND_load_file("/dev/urandom", 32) != 32) {
		printf("Error loading /dev/urandom\n");
		return 1;
	}

	while ((opt = getopt(argc, argv, "cnah")) != -1) {
		switch (opt) {                                                                                                                                                                                                                
			case 'n':
				alnum=1;
				break;
			case 'a':
				alnum=0;
				break;
			case 'c':
				phash=1;
				break;
			case 'h':
			default:
				fprintf(stderr, "Usage: %s -a (all printable) || -n (alpha-numeric), -c (print hash)\n", argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if(alnum==0) {
        	for(i=0; i<20; i++){
                	plaintext[i]=rand_range(33,94);
        	}
	} else { 
		for(i=0; i<20; i++){
			x=rand_range(48,94);
			if(isalnum(x)){
				plaintext[i]=x;
			} else { 
				i--;
			}
		}
	}


	plaintext[20]='\0';

        printf("%s\t", plaintext);

        for(i=0; i<16; i++){
                x=rand_range(49,94);
                if(isalnum(x)){
                        salt[i+3]=x;
                } else {
                        i--;
                }
        }

	salt[19]='$';
	salt[20]='\0';

	if(phash){
        	printf("%s\n", crypt((char*) plaintext, (char*) salt));
	} else {
		printf("\n");
	}

        return 0;
}

