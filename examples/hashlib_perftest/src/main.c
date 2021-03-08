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

uint8_t y = 0;


int main(void){
    int elapsed;
    int size, size_blk1, size_blk2;
    uint8_t *ptr;
    uint8_t sha1[SHA1_DIGEST_LEN];
    sha1_ctx sha1_context;
    uint8_t sha256[SHA256_DIGEST_LEN];
    uint8_t i;
    uint32_t crc;
    ti_var_t f;
    ti_CloseAll();
    f = ti_OpenVar("DEMO", "r", TI_PPRGM_TYPE);
    if(!f) {
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
	gfx_PrintStringXY("CRC32 time:", 1, 11);
    gfx_PrintInt(elapsed, 0);
    
    // Time SHA1
    timer_Disable(1);
    timer_Set(1, 0);
    timer_Enable(1, TIMER_32K, TIMER_NOINT, TIMER_UP);
    hashlib_sha1init(&sha1_context);
    hashlib_sha1update(&sha1_context, ptr, size);
    hashlib_sha1final(&sha1_context, &sha1);
    elapsed = timer_GetSafe(1, TIMER_UP);
	gfx_PrintStringXY("SHA1 time:", 1, 21);
    gfx_PrintInt(elapsed, 0);
    
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
