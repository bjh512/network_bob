#include<stdio.h>
#include<iostream>
#include<stdint.h>

using namespace std;

//2 byte input -> reverse

uint16_t my_ntohs(uint16_t n){
	uint16_t front = n & 0xFF00;
	uint16_t back = n & 0x00FF;
	uint16_t all = front>>8 | back<<8;
	
	return all;
}

uint32_t my_ntohl(uint32_t n){
	uint32_t temp1 = n & 0xFF000000;
	uint32_t temp2 = n & 0x00FF0000;
	uint32_t front = temp1>>8 | temp2<<8;

	uint32_t temp3 = n & 0x0000FF00;
	uint32_t temp4 = n & 0x000000FF;
	uint32_t back = temp3>>8 | temp4<<8;

	uint32_t all = front>>16 | back<<16;
	
	return all;
}


int main(){
	//uint8_t buf[] = {0x12, 0x34};
	uint8_t buf[] = {0x12, 0x34, 0x56, 0x78};
	//uint16_t *p = (uint16_t *)buf;
	//uint16_t port = *p;
	uint32_t *p = (uint32_t *)buf;
	uint32_t ip = *p;
	//port = my_ntohs(port);
	ip = my_ntohl(ip);
	//printf("%x\n", port);
	printf("%x\n", ip);
	return 0;
}