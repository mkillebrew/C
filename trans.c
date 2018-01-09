/* 
*
*       mkillebrew@net7systems.com
*	20th January 2015
*
*	$ ./trans3 -E -k VISIT -K ARIZONA -d PLAINTEXTTOCIPHERTEXT
*	output: LEHPTTCXPTNEITOEAXRIT
*	$ ./trans3 -D -k ARIZONA -K VISIT -d LEHPTTCXPTNEITOEAXRIT
*	output: PLAINTEXTTOCIPHERTEXT
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int cmpfunc( const void *a, const void *b) {
	return *(const char *)a - *(const char *)b;
}

char * trans_encode(int direction, char *input,char *key, char *keyu){
	int i, j, x, base;
	int k=0;
	int pos=0;
	int oindex=0;
	char *output;
	int *order;

	order=malloc(strlen(key)*sizeof(int))+1;

	for(i=0; i < strlen(key); i++){
		for(j=0; j < strlen(key); j++){
			if(keyu[i] == key[j]){
				order[i]=j;
				key[j]='0';
				break;
			}
		}
	}

	output=malloc(strlen(input)*sizeof(char))+1;
		for(i=0; i < strlen(key); i++){
			for(x=0; x < strlen(key); x++){
				if(order[x] == i){
					oindex=x;
					base=0;
					for(pos=oindex+base; pos < strlen(input); pos+=strlen(key)){
						if(direction==1) output[k]=input[pos];
						else output[pos]=input[k];
						k++;
					}
					break;
				}
			}
	}

	return output;
}


int main(int argc, char **argv){
	char *key1=NULL,*key1u=NULL;
	char *key2=NULL, *key2u=NULL;
	int direction=0,optindex;
	
	char *plaintext;
	char *cipher1;
	char *cipher2;

	while((optindex = getopt(argc, argv, "k:K:d:DE")) != -1){
		switch(optindex){
			case 'k':
				key1=malloc(strlen(optarg)*sizeof(char))+1;
				key1u=malloc(strlen(optarg)*sizeof(char))+1;
				strcpy(key1, optarg);
				strcpy(key1u, optarg);
				break;
			case 'K':
				key2=malloc(strlen(optarg)*sizeof(char))+1;
				key2u=malloc(strlen(optarg)*sizeof(char))+1;
				strcpy(key2, optarg);
				strcpy(key2u, optarg);
				break;
			case 'd':
				plaintext=malloc(strlen(optarg)*sizeof(char))+1;
				strcpy(plaintext, optarg);
				break;
			case 'D':
				direction=0;
				break;
			case 'E':
				direction=1;
				break;
			default:
				abort();
		}
	}



	cipher1=malloc(strlen(plaintext)*sizeof(char))+1;
	cipher2=malloc(strlen(plaintext)*sizeof(char))+1;
	qsort(key1, strlen(key1), 1, cmpfunc);
	qsort(key2, strlen(key2), 1, cmpfunc);

	cipher1=trans_encode(direction, plaintext,key1,key1u);
	cipher2=trans_encode(direction, cipher1,key2,key2u);
	printf("output: %s\n", cipher2);

	return 0;
}


