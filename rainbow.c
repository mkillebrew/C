/* 		mkillebrew@50ae.net 					*
 *  	rainbow table generation for truncated hash to IPs 		*
 *  gcc -O2 -L/usr/local/BerkeleyDB.5.1/lib/ -ldb -o rainbow rainbow.c  */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <CommonCrypto/CommonDigest.h>
#include "db.h"


#define BUFSIZE 32
#define NUMTHR 3

DB *dbp;
u_int32_t flags;
int ret;


typedef struct{
        volatile unsigned int complete1, complete2; 
	unsigned int read, write, size, capacity;
        char *data[BUFSIZE];
	pthread_mutex_t mutex;
	pthread_cond_t cond1, cond2;
} fifo;

typedef struct{
        volatile unsigned int complete1, complete2;
        unsigned int read, write, size, capacity;
        char *ip[BUFSIZE];
        char *hash[BUFSIZE];
	unsigned long int counter;
        pthread_mutex_t mutex;
        pthread_cond_t cond1, cond2;
} fifo2;


void queueadd(char *input);
void queueadd2(char *input, char *hash);
void queuedel(char *output);
void *generate();
void *comphash();
void *writeq();
void *statq();
int writeDB(char *ipval, char *hval);
int openDB();
int closeDB();

fifo *queue;
fifo2 *queue2;

int main(){
	pthread_t generatethr, compthr[NUMTHR], writethr, statthr;
	unsigned int i;

	queue=(fifo *)malloc(sizeof(fifo));
	for(i=0; i < BUFSIZE; i++) queue->data[i]=malloc(sizeof(char *)*16);

        queue2=(fifo2 *)malloc(sizeof(fifo2));
        for(i=0; i < BUFSIZE; i++) queue2->ip[i]=malloc(sizeof(char *)*16);
        for(i=0; i < BUFSIZE; i++) queue2->hash[i]=malloc(sizeof(char *)*16);

	pthread_cond_init(&queue->cond1, NULL);
	pthread_cond_init(&queue->cond2, NULL);
	pthread_mutex_init(&queue->mutex, NULL);

        pthread_cond_init(&queue2->cond1, NULL);
        pthread_cond_init(&queue2->cond2, NULL);
        pthread_mutex_init(&queue2->mutex, NULL);


	queue->complete1=0;
	queue->complete2=0;
	queue->size=0;
	queue->read=0;
	queue->write=0;
	queue->capacity=BUFSIZE;

        queue2->complete1=0;
        queue2->complete2=0;
        queue2->size=0;
        queue2->read=0;
        queue2->write=0;
        queue2->capacity=BUFSIZE;
	queue2->counter=0;

	pthread_create(&generatethr, NULL, generate, NULL);
	for(i=0; i < NUMTHR; i++) pthread_create(&compthr[i], NULL, comphash, NULL);
	pthread_create(&writethr, NULL, writeq, NULL);
	pthread_create(&statthr, NULL, statq, NULL);

	pthread_join(generatethr, NULL);
	for(i=0; i < NUMTHR; i++) pthread_join(compthr[i], NULL);
	pthread_join(writethr, NULL);
	pthread_join(statthr, NULL);

	printf("queue sizes: 1 - %d, 2 - %d\n", queue->size, queue2->size);
	free(queue);
	free(queue2);

	return 0;
}

void queueadd(char *input){
	pthread_mutex_lock(&queue->mutex);
	while(queue->size == queue->capacity) pthread_cond_wait(&queue->cond2, &queue->mutex);
	strlcpy(queue->data[queue->write], input, strlen(input)+1);
	++queue->size;
	++queue->write;
	queue->write %= queue->capacity;
	pthread_mutex_unlock(&queue->mutex);
	pthread_cond_signal(&queue->cond1);
}	

void queueadd2(char *input, char *hash){
        pthread_mutex_lock(&queue2->mutex);
        while(queue2->size == queue2->capacity) pthread_cond_wait(&queue2->cond2, &queue2->mutex);
        strlcpy(queue2->ip[queue2->write], input, strlen(input)+1);
        strlcpy(queue2->hash[queue2->write], hash, strlen(hash)+1);
        ++queue2->size;
        ++queue2->write;
        queue2->write %= queue2->capacity;
        pthread_mutex_unlock(&queue2->mutex);
        pthread_cond_signal(&queue2->cond1);
}
	
void queuedel(char *output){
	pthread_mutex_lock(&queue->mutex);
	while(queue->size == 0 && queue->complete2 == 0)  pthread_cond_wait(&queue->cond1, &queue->mutex);
	strlcpy(output, queue->data[queue->read], strlen(queue->data[queue->read])+1);
	--queue->size;
	++queue->read;
	queue->read %= queue->capacity;
	pthread_mutex_unlock(&queue->mutex);
	pthread_cond_signal(&queue->cond2);
	if(queue->complete1 == 1 && queue->size < 1) queue->complete2=1;
}

void queuedel2(char *output, char *hash){
        pthread_mutex_lock(&queue2->mutex);
        while(queue2->size == 0 && queue2->complete2 == 0)  pthread_cond_wait(&queue2->cond1, &queue2->mutex);
        strlcpy(output, queue2->ip[queue2->read], strlen(queue2->ip[queue2->read])+1);
        strlcpy(hash, queue2->hash[queue2->read], strlen(queue2->hash[queue2->read])+1);
        --queue2->size;
        ++queue2->read;
        queue2->read %= queue2->capacity;
        pthread_mutex_unlock(&queue2->mutex);
        pthread_cond_signal(&queue2->cond2);
        if(queue2->complete1 == 1 && queue2->size < 1) queue2->complete2=1;
}

	
void *generate(){

        unsigned int a=1, b=0, c=0, d=0;
	char *ipbuff;


        for(; a <= 223; a++){
        if(a==10) a++;
        if(a==127) a++;
                for(; b <= 255; b++){
                if(a==192 && b == 168) b++;
                if(a==172 && b == 16) b=32;
                        for(; c <= 255; c++){
                                for(; d <= 255; d++){

					asprintf(&ipbuff, "%i.%i.%i.%i", a, b, c, d);
					queueadd(ipbuff);
					free(ipbuff);

                                }
                                d=0;
                        }
                        c=0;
                }
                b=0;
        }

	queue->complete1=1;
	return NULL;
}

void *comphash(){
	char ip[16], *hash;
	unsigned char digest[16];

	while(queue->complete2 == 0){
		queuedel(ip);
		CC_MD5(ip, strlen(ip), digest);
		asprintf(&hash, "%02x%02x%02x", digest[0], digest[1], digest[2]);
		queueadd2(ip, hash);
		free(hash);
	}
	queue2->complete1=1;
	return NULL;
}

void *writeq() {
	char *ip, *hash;

	ip=malloc(sizeof(char)*8)+1;
	hash=malloc(sizeof(char)*16)+1;

	openDB();

	while(queue2->complete2 == 0){
		queuedel2(ip, hash);
		writeDB(ip, hash);
		queue2->counter++;
	}

	closeDB();
	return NULL;
}

void *statq() {
	unsigned int p1, p2, p3, p4, i;
	p1=p2=p3=p4=0;

	printf("\n");
	while(queue2->complete2 == 0){
		p1=queue->size;
		p3=queue2->size;
		p2=BUFSIZE-p1;	
                p4=BUFSIZE-p3;
		printf("\rqueue1: [");
		for(i=0; i < p1; i++) printf("=");
		for(i=0; i < p2; i++) printf(" ");
		printf("]");

                printf("  queue2: [");
                for(i=0; i < p3; i++) printf("=");
                for(i=0; i < p4; i++) printf(" ");
                printf("]  counter: %lu", queue2->counter);
		usleep(5000);
	}
	printf("\n");
	return NULL;
}

int openDB(){
        ret = db_create(&dbp, NULL, 0);
        if (ret != 0) {
                fprintf(stderr, "Error initializing database structure.\n");
                exit(1);
        }

        flags = DB_CREATE;
        ret = dbp->set_flags(dbp, DB_DUP);
        ret = dbp->open(dbp, NULL, "rainbow.db", NULL, DB_BTREE, flags, 0);
        if (ret != 0) {
                fprintf(stderr, "Error opening database rainbow.db\n");
                exit(1);
        };

        return ret;
}

int writeDB(char *ipval, char *hval){
        DBT key, data;
        int ret;

        memset(&key, 0, sizeof(DBT));
        memset(&data, 0, sizeof(DBT));
        key.data = hval;
        key.size = strlen(hval)+1;
        data.data = ipval;
        data.size = strlen(ipval)+1;
        ret = dbp->put(dbp, NULL, &key, &data, 0);

        return ret;
}

int closeDB(){
        if (dbp != NULL) ret = dbp->close(dbp, 0);
        return ret;
}
