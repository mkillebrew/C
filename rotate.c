/* 
*
*       mkillebrew@net7systems.com
*       21st January 2015
*
*	Iterates over key for rotate right value, (int)char % 8
*	rotates byte by value and steps to the next char in the key, repeating
*
*	$ gcc -o rotate -lcrypto rotate.c
*
*       $ ./rotate -E -k Alice -d "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua"
*       JvY5rGsQljhuq7YCMu1jtycQbks6ArCtKzrCEGx7NzeybKOyR7pOAbBGtA5LuTa0
*	zTsQVjYtoxYCuawjEEa3BCu0V7mtezICOqxrOPY5BEs3NrSMSzJXN44BukcQjQsx
*	9jmsAbJHEIx7NvY5rAG2FrPNCxAWNi2LuhY=
*
*       $ ./rotate -D -k Alice -d "JvY5rGsQljhuq7YCMu1jtycQbks6ArCtKzrCEGx7NzeybKOyR7pOAbBGtA5LuTa0zTsQVjYtoxYCuawjEEa3BCu0V7mtezICOqxrOPY5BEs3NrSMSzJXN44BukcQjQsx9jmsAbJHEIx7NvY5rAG2FrPNCxAWNi2LuhY="
*	Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua       
*
*/

#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <unistd.h>

unsigned char circshiftl(unsigned char x, int n) {
  return (x << n) | (x >> (8 - n));
}
unsigned char circshiftr(unsigned char x, int n) {
  return (x >> n) | (x << (8 - n));
}

int main(int argc, char **argv){

	char *input, *output, *decoded, *key;
	int i, j, optindex, direction, length, padding=0;
        BIO *bmem, *bio, *b64;

	while((optindex = getopt(argc, argv, "k:K:d:DE")) != -1){
		switch(optindex){
			case 'k':
				key=malloc(strlen(optarg)+1);
				strcpy(key, optarg);
				break;
			case 'd':
				input=malloc(strlen(optarg)+1);
				output=malloc(strlen(optarg)+1);
				strcpy(input, optarg);
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


	if(direction == 1){
		j=0;
        	for(i=0; i < strlen(input); i++){
			if(j == strlen(key)) j=0;
                	output[i]=circshiftr(input[i],(int)key[j] % 8);
			j++;
        	}
		output[i]='\0';
        	b64 = BIO_new(BIO_f_base64());
        	bio = BIO_new_fp(stdout, BIO_NOCLOSE);
        	BIO_push(b64, bio);
        	BIO_write(b64, output, strlen(output));
        	BIO_flush(b64);
        	BIO_free_all(b64);
	}

	if(direction == 0){

		output=malloc(strlen(input)+1);
		decoded=malloc(strlen(input)+1);

		length=strlen(input);
		if (input[length-1] == '=' && input[length-2] == '=') padding = 2;
		else if (input[length-1] == '=') padding = 1;
                length=(int)length*0.75 - padding;


		memset(decoded, 0, strlen(input)+1);
		b64 = BIO_new(BIO_f_base64());
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
		bmem = BIO_new_mem_buf(input, strlen(input));
		bmem = BIO_push(b64, bmem);
		BIO_read(bmem, decoded, length);
		decoded[strlen(input)] = '\0';
		BIO_free_all(bmem);


		j=0;
        	for(i=0; i < length; i++){
			if(j == strlen(key)) j=0;
                	output[i]=circshiftl(decoded[i],(int)key[j] % 8);
			j++;
        	}
		output[i]='\0';

	
		printf("%s\n", output);
	}





	return 0;
}

