#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#define MMAP_OFFSET (0x44C00000)
#define MMAP_SIZE   (0x481AEFFF-MMAP_OFFSET)

#define GPIO_REGISTER_SIZE (4)

#define GPIO0   (0x44E07000)
#define GPIO1       (0x4804C000)
#define GPIO2       (0x481AC000)
#define GPIO3       (0x481AE000)

#define GPIO_CLEARDATAOUT (0x190)
#define GPIO_SETDATAOUT   (0x194)
#define GPIO_OE               (0x134)
#define GPIO_DATAOUT      (0x13C)
#define GPIO_DATAIN       (0x138)

int pos, w1, w2, w3;
static volatile uint32_t *map;

void wset(int dst, int npass, int dir);
void clearpack();
void pulse(int delay);

int main(int argc, char **argv){
	int i, fd;

	if(argc < 2){
		printf("Usage: %s <start position (0-99)>\n", argv[0]);
		return 1;
	}

	if((atoi(argv[1]) < 0) || (atoi(argv[1]) > 99)){
		printf("Invalid start position, must be 0-99\n");
		return 1;
	}

	pos=atoi(argv[1]);

	fd = open("/dev/mem", O_RDWR);

	if(fd == -1){
		perror("Unable to open /dev/mem");
		exit(EXIT_FAILURE);
	}

	map = mmap(NULL, MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, MMAP_OFFSET);
	if(map == MAP_FAILED) {
		close(fd);
		perror("Unable to map /dev/mem");
		exit(EXIT_FAILURE);
	}

	printf("offset: 0x%08x \nGPIO1: 0x%08x \nGPIO_OE: 0x%08x \nGPIO_DATAOUT: 0x%08x\n",MMAP_OFFSET, GPIO1, GPIO_OE, GPIO_DATAOUT);
	printf("OE addr: 0x%08x - new value: 0x%08x\n",GPIO1-MMAP_OFFSET+GPIO_OE, map[(GPIO1-MMAP_OFFSET+GPIO_OE)/4] & (~(1<<28)));
	printf("hi data addr: 0x%08x - new value: 0x%08x\n",GPIO1-MMAP_OFFSET+GPIO_DATAOUT, map[(GPIO1-MMAP_OFFSET+GPIO_DATAOUT)/4] | (1<<28));
	printf("lo data addr: 0x%08x - new value: 0x%08x\n",GPIO1-MMAP_OFFSET+GPIO_DATAOUT, map[(GPIO1-MMAP_OFFSET+GPIO_DATAOUT)/4] & (~(1<<28)));
	map[(GPIO1-MMAP_OFFSET+GPIO_OE)/4] &= ~(1<<28);
	map[(GPIO1-MMAP_OFFSET+GPIO_OE)/4] &= ~(1<<13);
	map[(GPIO1-MMAP_OFFSET+GPIO_OE)/4] &= ~(1<<12);
	clearpack();
	wset(0, 0, 0); //dial 44 on 4th pass
	wset(44, 3, 0); //dial 44 on 4th pass
	wset(18, 2, 1); //dial 18 on 3rd pass
	wset(76, 1, 0); //dial 76 on 2nd pass

	return 0;
}

void wset(int dst, int npass, int dir){
	int i, x;
	char *cdir[]={"left", "right"};

	printf("Dialing %i %s on pass %i\n", dst, cdir[dir], npass+1);
	// dir 0-L 1-R
	if(dir == 0) map[(GPIO1-MMAP_OFFSET+GPIO_DATAOUT)/4] &= ~(1<<13); 
	else map[(GPIO1-MMAP_OFFSET+GPIO_DATAOUT)/4] |= 1<<13; 

	while(dst != pos){
		if(pos > 99) pos=pos-100;
		if(pos < 0) pos=pos+100;

		for(i=64; i; i--){
			pulse(10);
		}
		if(dir == 0) pos--;
       	if(dir == 1) pos++;
	}

	for(i=npass; i; i--){
		for(x=6400; x; x--){
			pulse(10);
        }
	}
	usleep(200000);
}

void clearpack(){
	int i, x;

	printf("Clearing dial\n");
	map[(GPIO1-MMAP_OFFSET+GPIO_DATAOUT)/4] &= ~(1<<13);

	for(i=4; i; i--){
    	for(x=6400; x; x--){
			pulse(1);
    	}
    }
}

void pulse(int delay){

    map[(GPIO1-MMAP_OFFSET+GPIO_DATAOUT)/4] |= 1<<28;
    map[(GPIO1-MMAP_OFFSET+GPIO_DATAOUT)/4] |= 1<<12;
    usleep(delay);
    map[(GPIO1-MMAP_OFFSET+GPIO_DATAOUT)/4] &= ~(1<<28);
    map[(GPIO1-MMAP_OFFSET+GPIO_DATAOUT)/4] &= ~(1<<12);
}
