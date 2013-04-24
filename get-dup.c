#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "db.h"

DB *dbp;           

int main(int argc, char *argv[]){
	DBT key, data; 
	DBC *dbcp;
	char keystr[]="aaaaaa";
	char *value = "255.255.255.255"; 
	int ret=0;


	if(argc < 2){ 
		printf("Usage: %s <hash>\n", argv[0]);
		exit(1);
	}
	else{
		strlcpy(keystr, argv[1], sizeof(keystr));
		if(strlen(keystr) != 6){
			printf("hash value is six characters, too short\n");
			exit(1);
		}
	}

	ret = db_create(&dbp, NULL, 0); 
	if (ret != 0) { 
		fprintf(stderr, "Error initializing database structure.\n");
		exit(1);
	} 
 
 
	ret = dbp->open(dbp, NULL, "rainbow.db", NULL, DB_BTREE, DB_READ_UNCOMMITTED|DB_RDONLY, 0);		
	if (ret != 0) { 
		fprintf(stderr, "Error opening database rainbow.db\n");
		exit(1);
	}

	ret = dbp->cursor(dbp, NULL, &dbcp, DB_CURSOR_BULK);
        if (ret != 0) {
                fprintf(stderr, "Error getting cursor\n");
                exit(1);
        }

 
	memset(&key, 0, sizeof(DBT)); 
	memset(&data, 0, sizeof(DBT)); 
	key.data = keystr;
	key.size = strlen(keystr)+1;
	data.data = value;
	data.ulen = strlen(value)+1;
	data.flags = 0;
	printf("hash: %s\n",(char *)key.data);
	ret=0;
        ret = dbcp->c_get(dbcp, &key, &data, DB_SET);
        if(!ret) printf("IP: %s\n",(char *)data.data);
	else printf("Not Found.\n");
	while(!ret){
		ret = dbcp->c_get(dbcp, &key, &data, DB_NEXT_DUP); 
		if(!ret) printf("IP: %s\n",(char *)data.data);
	}

	return 0;
}

