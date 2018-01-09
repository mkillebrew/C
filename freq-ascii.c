/* 
*
*	mkillebrew@net7systems.com
*	22nd January 2015
*
*	$ ./freq-ascii -d SOMEDISPERSEDDATAINASCII
*	I - 4
*	S - 4
*	A - 3
*	D - 3
*	E - 3
*	C - 1
*	M - 1
*	N - 1
*	O - 1
*	P - 1
*	R - 1
*	T - 1
*	========================
*	Total unique symbols: 12
*
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv){

	char *cipher;
	int optindex, j, x=0, i, count[94];
	
	while((optindex = getopt(argc, argv, "d:")) != -1){
		switch(optindex){
			case 'd':
				cipher=malloc(strlen(optarg)*sizeof(char)+1);
				strcpy(cipher, optarg);
				break;
			default:
				abort();
			}
	}

	memset(count, 0, sizeof(count));

	for(i=0; i < strlen(cipher); i++){
		count[(int)(cipher[i]-0x21)]+=1;
	}


	for(i=94; i > 0; i--){
		for(j=0; j < 94; j++){
			if(count[j] == i){ 
				printf("%c - %d\n", (char)j+0x21, count[j]);
				x++;
			}
		}
	}
		

	printf("========================\n");
	printf("Total unique symbols: %d\n\n", x);

	return 0;
	
}
