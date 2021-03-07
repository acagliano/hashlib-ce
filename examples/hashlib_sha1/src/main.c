
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <hashlib.h>

const char *test_data = "Hello World! How are you today? I am well, replies the world.";
const char *hex_chars = "0123456789ABCDEF";

char *digesttostr(uint8_t *num);

int main(void){
	sha1_ctx ctx;
	uint8_t digest[20];
	size_t test_data_len;
	test_data_len = strlen(test_data);

/* calculate sha1 */
	hashlib_sha1init(&ctx);
	hashlib_sha1update(&ctx, test_data, test_data_len);
	hashlib_sha1final(&ctx, &digest);

/* output checksums to CEmu console */
	strcpy((char*)0xFB0000, digesttostr(&digest));
	*((int*)(0xFB0000+40)) = 0x0A;

	return 0;
}

/* Utility function for converting sha1 digests to hex strings */
char *digesttostr(uint8_t *num){
	char *buf;
	uint8_t *ptr;
	int i;
	if (!(buf = malloc(41))) return 0;
	ptr = (uint8_t*)&num;
	for (i=0; i<20; i++){
		buf[i*2 + 0] = hex_chars[(*ptr)>>4];
		buf[i*2 + 1] = hex_chars[(*ptr++)&15];
	}
	buf[i*2] = 0;
	return buf;
}
