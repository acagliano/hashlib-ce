//--------------------------------------
// Program Name: HASHLIB performance test
// Author: Anthony Cagliano, Adam Beckingham
// License:
// Description:
//--------------------------------------

/* Keep these headers */

#include <stdint.h>
#include <tice.h>

#include <graphx.h>
#include <fileioc.h>
#include <hashlib.h>
#include <debug.h>
/* Standard headers - it's recommended to leave them included */

/* Other available headers */

const char *hex_chars = "0123456789ABCDEF";

char *digesttostr(uint8_t *num);
char *int32tostr(uint32_t num);

int main(void){
    int elapsed, i, size, size_blk1, size_blk2;
    uint8_t *ptr;
    uint8_t sha1[SHA1_DIGEST_LEN];
    sha1_ctx sha1_context;
    uint8_t sha256[SHA256_DIGEST_LEN];
    uint32_t crc;
    ti_var_t f;
    ti_CloseAll();
    if (!(f = ti_OpenVar("DEMO", "r", TI_PPRGM_TYPE))){ //Change "DEMO" and TI_PPRGM_TYPE to test on a different variable
        dbg_sprintf(dbgout, "File IO Err");
        return 1;
    }
    size = ti_GetSize(f);
    ptr = ti_GetDataPtr(f);
    ti_Close(f);

	gfx_Begin();
    size_blk1 = size/2;
    size_blk2 = size-size_blk1;
    // Time CRC
    timer_Disable(1);
    timer_Set(1, 0);
    timer_Enable(1, TIMER_32K, TIMER_NOINT, TIMER_UP);
    crc = hashlib_CRC32(ptr, size);
    elapsed = timer_GetSafe(1, TIMER_UP);
	gfx_PrintStringXY("CRC32 time: ", 1, 11);
    gfx_PrintInt(elapsed, 0);
	gfx_PrintStringXY("CRC32: ", 1, 21);
	gfx_PrintString(int32tostr(crc));

    // Time SHA1
    timer_Disable(1);
    timer_Set(1, 0);
    timer_Enable(1, TIMER_32K, TIMER_NOINT, TIMER_UP);
    hashlib_sha1init(&sha1_context);
    hashlib_sha1update(&sha1_context, ptr, size);
    hashlib_sha1final(&sha1_context, &sha1);
    elapsed = timer_GetSafe(1, TIMER_UP);
	gfx_PrintStringXY("SHA1 time: ", 1, 41);
    gfx_PrintInt(elapsed, 0);
	gfx_PrintStringXY("SHA1: ", 1, 51);
	gfx_PrintStringXY(digesttostr(&sha1), 1, 61);
    // Time SHA256
   /* timer_Disable(1);
    timer_Set(1, 0);
    timer_Enable(1, TIMER_CPU, TIMER_0INT, TIMER_UP);
    hashlib_SHA256(ptr, size, sha256);
    elapsed = (float)timer_GetSafe(1, TIMER_UP) / 1000;
    PrintTime(elapsed);
    */
    while (!os_GetCSC());
	ti_CloseAll();
	gfx_End();
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

