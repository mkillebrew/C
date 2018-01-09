/* 
*
*       mkillebrew@net7systems.com
*       21st January 2015
*
*	Iterates over key for xor value
*
*	$ gcc -o xor -lcrypto xor.c
*
*	$ ./xor -E -o 3 -k Alice -d "OMG my C is absolutely horrid, sometimes I think I just randomly assign which string length I'll use in a for loop and forget that nulls are a thing."
*	LCgGTAQaRQJMABBFIA4aDAk0GAwPHGEEBhEXKAhFQxYuAQwXDCwJGkMsYRgBCgsq
*	TCBDDzQfHUMXIAINDAgtFUkCFjIFDg1FNgQAAA1hHx0RDC8LSQ8ALwsdC0UISwUP
*	RTQfDEMML0wIQwMuHkkPCi4cSQILJUwPDBcmCR1DESkNHUMLNAAFEEUgHgxDBGEY
*	AQoLJkI=
*
*	$ ./xor -D -o 3 -k Alice -d "LCgGTAQaRQJMABBFIA4aDAk0GAwPHGEEBhEXKAhFQxYuAQwXDCwJGkMsYRgBCgsqTCBDDzQfHUMXIAINDAgtFUkCFjIFDg1FNgQAAA1hHx0RDC8LSQ8ALwsdC0UISwUPRTQfDEMML0wIQwMuHkkPCi4cSQILJUwPDBcmCR1DESkNHUMLNAAFEEUgHgxDBGEYAQoLJkI="
*	OMG my C is absolutely horrid, sometimes I think I just randomly assign which string length I'll use in a for loop and forget that nulls are a thing.
*
*
*
*/

#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <unistd.h>

int main(int argc, char **argv){

	char *input, *output, *decoded, *key;
	int i, offset, optindex, direction, length, padding=0;
        BIO *bmem, *bio, *b64;

	while((optindex = getopt(argc, argv, "o:k:K:d:DE")) != -1){
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
			case 'o':
				offset=atoi(optarg);
				break;
			default:
				abort();
		}
	}



	if(direction == 1){
        	for(i=0; i < strlen(input); i++){
			if(offset == strlen(key)) offset=0;
                	output[i]=input[i] ^ (int)key[offset];
			offset++;
        	}
		output[i]='\0';
        	b64 = BIO_new(BIO_f_base64());
        	bio = BIO_new_fp(stdout, BIO_NOCLOSE);
        	BIO_push(b64, bio);
        	BIO_write(b64, output, strlen(input));
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
		decoded[length] = '\0';
		BIO_free_all(bmem);


        	for(i=0; i < length; i++){
			if(offset == strlen(key)) offset=0;
                	output[i]=decoded[i] ^ (int)key[offset];
			offset++;
        	}
		output[i]='\0';

	
		printf("%s\n", output);
	}





	return 0;
}

