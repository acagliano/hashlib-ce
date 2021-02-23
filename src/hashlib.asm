
;------------------------------------------
include '../include/library.inc'


;------------------------------------------
library "HASHLIB", 1


;------------------------------------------
; v1 functions

export hashlib_ChecksumU24
export hashlib_ChecksumU32
export hashlib_CRC32


;------------------------------------------
;uint24_t hashlib_ChecksumU24(const uint8_t *buf, size_t len);
hashlib_ChecksumU24:
	call ti._frameset0
	ld de,(ix+6)
	or a,a
	sbc hl,hl
.loop:
	ld a,(de)
	inc de
	call ti.AddHLAndA
	ld bc,(ix+9)
	dec bc
	ld (ix+9),bc
	ld a,(ix+11)
	or a,c
	or a,b
	jr nz,.loop
	pop ix
	ret

;------------------------------------------
;uint32_t hashlib_ChecksumU32(const uint8_t *buf, size_t len);
hashlib_ChecksumU32:
	call ti._frameset0
	ld bc,(ix+6)
	or a,a
	sbc hl,hl
	ld e,l
.loop:
	ld a,(bc)
	inc bc
	push bc
	call ti._ladd_b
	ld bc,(ix+9)
	dec bc
	ld (ix+9),bc
	ld a,(ix+11)
	or a,c
	or a,b
	pop bc
	jr nz,.loop
	pop ix
	ret

;------------------------------------------
;uint32_t hashlib_CRC32(const uint8_t *buf, size_t len);
hashlib_CRC32:
	push iy
	ld hl,-10
	call ti._frameset
	ld a,0
hashlib_has_crc_table:=$-1
	or a,a
	jq nz,.already_have_table
	ld iy,hashlib_crc_table
	xor a,a
.calc_table:
	ld bc,0
	ld c,a
	inc a
	push af
	xor a,a
	ld e,8
.calc_inner:
	ld h,c
	ld l,1
	call ti._lshru
	bit 0,h
	jr z,.calc_inner_nostep2
	push de
	ld e,$ed
	ld hl,$b88320
	call ti._lxor
	push hl
	pop bc
	ld a,e
	pop de
.calc_inner_nostep2:
	dec e
	jr nz,.calc_inner
	ld (iy),bc
	ld (iy+3),a
	lea iy,iy+4
	pop af
	or a,a
	jq nz,.calc_table

	ld a,1
	ld (hashlib_has_crc_table),a

.already_have_table:
	ld hl,(ix+6)
	ld (ix-7),hl ;p
	scf
	sbc hl,hl
	ld (ix-4),hl  ;crc
	ld (ix-1),l
.crc_loop:
	ld a,(ix-4)
	ld hl,(ix-7)
	xor a,(hl)
	inc hl
	ld (ix-7),hl
	ld bc,0
	ld c,a
	ld hl,hashlib_crc_table
	add hl,bc
	ld de,(hl)
	inc hl
	inc hl
	inc hl
	ld a,(hl)
	ex hl,de
	ld e,a ;euhl = data at table index
	ld bc,(ix-3) ;bc = *((&crc)+1) which is the same as crc>>8
	xor a,a
	call ti._lxor ;euhl ^= aubc
	ld (ix-4),hl
	ld (ix-1),e
	ld hl,(ix+9)
	dec hl
	ld (ix+9),hl
	ld a,(ix+11)
	or a,l
	or a,h
	jq nz,.crc_loop
	ld hl,(ix-4)
	ld e,(ix-1)
	ld sp,ix
	pop ix
	pop iy
	ret



;void hashlib_SHA1(const uint8_t *buf, uint32_t len, uint8_t *digest);
;void hashlib_SHA256(const uint8_t *buf, uint32_t len, uint8_t *digest);


; SUPPORTING FUNCTIONS
;void sha1_init(SHA1_CTX *ctx);
;void sha1_transform(SHA1_CTX *ctx, const BYTE data[]);
;void sha1_update(SHA1_CTX *ctx, const BYTE data[], uint32_t len);
;void sha1_final(SHA1_CTX *ctx, BYTE hash[]);

;void sha256_init(SHA256_CTX *ctx);
;void sha256_transform(SHA256_CTX *ctx, const BYTE data[]);
;void sha256_update(SHA256_CTX *ctx, const BYTE data[], uint32_t len);
;void sha256_final(SHA256_CTX *ctx, BYTE hash[]);




;------------------------------------------
; library static data
hashlib_k:
	dd $428a2f98,$71374491,$b5c0fbcf,$e9b5dba5,$3956c25b,$59f111f1,$923f82a4,$ab1c5ed5
	dd $d807aa98,$12835b01,$243185be,$550c7dc3,$72be5d74,$80deb1fe,$9bdc06a7,$c19bf174
	dd $e49b69c1,$efbe4786,$0fc19dc6,$240ca1cc,$2de92c6f,$4a7484aa,$5cb0a9dc,$76f988da
	dd $983e5152,$a831c66d,$b00327c8,$bf597fc7,$c6e00bf3,$d5a79147,$06ca6351,$14292967
	dd $27b70a85,$2e1b2138,$4d2c6dfc,$53380d13,$650a7354,$766a0abb,$81c2c92e,$92722c85
	dd $a2bfe8a1,$a81a664b,$c24b8b70,$c76c51a3,$d192e819,$d6990624,$f40e3585,$106aa070
	dd $19a4c116,$1e376c08,$2748774c,$34b0bcb5,$391c0cb3,$4ed8aa4a,$5b9cca4f,$682e6ff3
	dd $748f82ee,$78a5636f,$84c87814,$8cc70208,$90befffa,$a4506ceb,$bef9a3f7,$c67178f2

;------------------------------------------
; library dynamic data
hashlib_crc_table:
	dd 256 dup 0



