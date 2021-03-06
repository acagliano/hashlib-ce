
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <hashlib.h>

const char *test_data = "Hello World! How are you today? I am well, replies the world.";
const char *hex_chars = "0123456789ABCDEF";

char *int32tostr(uint32_t num);

int main(void){
	uint32_t sum24, sum32, crc32;
	size_t test_data_len;

	test_data_len = strlen(test_data);

/* calculate checksums and crc */
	sum24 = hashlib_ChecksumU24(test_data, test_data_len);
	sum32 = hashlib_ChecksumU32(test_data, test_data_len);
	crc32 = hashlib_CRC32(test_data, test_data_len);

/* output checksums to CEmu console */
	sprintf((char*)0xFB0000, "checksum24: %s\n", int32tostr(sum24));
	sprintf((char*)0xFB0000, "checksum32: %s\n", int32tostr(sum32));
	sprintf((char*)0xFB0000, "crc32: %s\n", int32tostr(crc32));

	return 0;
}

/* Utility function for converting unsigned 32 bit integers to hex strings */
char *int32tostr(uint32_t num){
	char *buf;
	uint8_t *ptr;
	int i;
	if (!(buf = malloc(9))) return 0;
	ptr = (uint8_t*)&num;
	buf = &buf[8];
	for (i=0; i<4; i++){
		*--buf = hex_chars[(*ptr)>>4];
		*--buf = hex_chars[(*ptr++)&15];
	}
	buf[8] = 0;
	return buf;
}
