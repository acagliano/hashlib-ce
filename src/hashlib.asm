
;------------------------------------------
include '../include/library.inc'


;------------------------------------------
library "HASHLIB", 1


;------------------------------------------
; v1 functions

	export hashlib_ChecksumU24
	export hashlib_ChecksumU32
	export hashlib_CRC32
	export hashlib_SHA1
	export sha1_init
	export sha1_update
	export sha1_final

;------------------------------------------
; defines

;------------------------------------------
; structures
virtual at 0
	sha1_ctx:
	.data:    rb 64
	.datalen: rb 4
	.bitlen:  rb 8
	.state:   rb 4*5
	.k:       rb 4*4
	.size:
end virtual

virtual at 0
	sha256_ctx:
	.data:    rb 64
	.datalen: rb 4
	.bitlen:  rb 8
	.state:   rb 4*8
	.size:
end virtual

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
	ld hl,-10
	call ti._frameset
	push iy
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
	pop iy
	ld sp,ix
	pop ix
	ret



;------------------------------------------
;void hashlib_SHA1(const uint8_t *buf, uint32_t len, uint8_t *digest);
hashlib_SHA1:
	ld hl,-sha1_ctx.size
	call ti._frameset
	pea ix-sha1_ctx.size
	call sha1_init
	ld hl,(ix+9)
	ex (sp),hl
	ld bc,(ix+6)
	push bc,hl
	call sha1_update
	pop bc,de
	ld hl,(ix+12)
	ex (sp),hl
	push bc
	call sha1_final
;	pop bc,bc ;not needed because we're already loading the stack pointer
	ld sp,ix
	pop ix
	ret

;------------------------------------------
;void hashlib_SHA256(const uint8_t *buf, uint32_t len, uint8_t *digest);


;------------------------------------------
; SUPPORTING FUNCTIONS

;------------------------------------------
;void sha1_init(SHA1_CTX *ctx);
sha1_init:
	pop bc,hl
	push hl,bc
	ld bc,sha1_ctx.datalen
	add hl,bc
	ex hl,de
	ld hl,sha1_default_ctx
	ld bc,sha1_default_ctx.len
	ldir
	ret


;------------------------------------------
;void sha1_transform(SHA1_CTX *ctx, const BYTE data[]);
sha1_transform:
	ld hl,-24
	call ti._frameset
	ld hl,(ix+9)
	ld iy,hashlib_temp

	ld b,16
.loop1:
	ld a,(hl)
	inc hl
	ld c,(hl)
	inc hl
	ld e,(hl)
	inc hl
	ld d,(hl)
	inc hl
	ld (iy+3),a
	ld (iy+2),c
	ld (iy+1),e
	ld (iy+0),d
	lea iy,iy+4
	djnz .loop1

	ld iy,hashlib_temp + 16*4
	ld c,80-16
.loop2:
	lea hl,iy-3*4
	lea de,iy-8*4
	call .lxor
	lea hl,iy
	lea de,iy-14*4
	call .lxor
	lea hl,iy
	lea de,iy-16*4
	call .lxor
	lea hl,iy
	call .lrl
	lea iy,iy+4
	djnz .loop2


	ld hl,(iy+sha1_ctx.state+4*0+0)
	ld e, (iy+sha1_ctx.state+4*0+3)
	ld (ix-8), hl
	ld (ix-5), e

	ld hl,(iy+sha1_ctx.state+4*1+0)
	ld e, (iy+sha1_ctx.state+4*1+3)
	ld (ix-12), hl
	ld (ix-9), e

	ld hl,(iy+sha1_ctx.state+4*2+0)
	ld e, (iy+sha1_ctx.state+4*2+3)
	ld (ix-16), hl
	ld (ix-13), e

	ld hl,(iy+sha1_ctx.state+4*3+0)
	ld e, (iy+sha1_ctx.state+4*3+3)
	ld (ix-20), hl
	ld (ix-17), e

	ld hl,(iy+sha1_ctx.state+4*4+0)
	ld e, (iy+sha1_ctx.state+4*4+3)
	ld (ix-24), hl
	ld (ix-21), e

	ld iy,(ix+6)
	ld a,20
	ld (ix-4),a
	or a,a
	sbc hl,hl
	ld (ix-3),hl
.loop3:
	ld hl,(ix-12)
	ld e, (ix-9)
	ld bc,(ix-16)
	ld a, (ix-13)
	call ti._land ; (b & c)
	ld a,e
	push af,hl
	ld hl,(ix-12)
	ld e, (ix-9)
	call ti._lnot ; ~b
	ld bc,(ix-20)
	ld a, (ix-17)
	call ti._land ; (~b & d)
	pop bc,af
	call ti._lxor ; ((b & c) ^ (~b & d))
	ld bc,(iy+sha1_ctx.k+4*0+0)
	ld a ,(iy+sha1_ctx.k+4*0+3)
	call .loop3sr1
	dec (ix-4)
	jq nz,.loop3

	ld a,20
	ld (ix-4),a
.loop4:
	call .loop4sr1
	ld bc,(iy+sha1_ctx.k+4*1+0)
	ld a ,(iy+sha1_ctx.k+4*1+3)
	call .loop3sr1
	dec (ix-4)
	jq nz,.loop4

	ld a,20
	ld (ix-4),a
.loop5:
	ld hl,(ix-12)
	ld e, (ix-9)
	ld bc,(ix-16)
	ld a, (ix-13)
	call ti._land ; (b & c)
	ld a,e
	push af,hl
	ld hl,(ix-12)
	ld e, (ix-9)
	ld bc,(ix-20)
	ld a, (ix-17)
	call ti._land ; (b & d)
	ld a,e
	push af,hl
	ld hl,(ix-16)
	ld e, (ix-13)
	ld bc,(ix-20)
	ld a, (ix-17)
	call ti._land ; (c & d)
	pop bc,af
	call ti._lxor
	pop bc,af
	call ti._lxor
	ld bc,(iy+sha1_ctx.k+4*2+0)
	ld a ,(iy+sha1_ctx.k+4*2+3)
	call .loop3sr1
	dec (ix-4)
	jq nz,.loop5

	ld a,20
	ld (ix-4),a
.loop6:
	call .loop4sr1
	ld bc,(iy+sha1_ctx.k+4*3+0)
	ld a ,(iy+sha1_ctx.k+4*3+3)
	call .loop3sr1
	dec (ix-4)
	jq nz,.loop6

	ld bc,(ix-8)
	ld a,(ix-5)
	ld hl,(iy+sha1_ctx.state+4*0+0)
	ld e, (iy+sha1_ctx.state+4*0+3)
	call ti._ladd
	ld (iy+sha1_ctx.state+4*0+0),hl
	ld (iy+sha1_ctx.state+4*0+3),e

	ld bc,(ix-12)
	ld a,(ix-9)
	ld hl,(iy+sha1_ctx.state+4*1+0)
	ld e, (iy+sha1_ctx.state+4*1+3)
	call ti._ladd
	ld (iy+sha1_ctx.state+4*1+0),hl
	ld (iy+sha1_ctx.state+4*1+3),e

	ld bc,(ix-16)
	ld a,(ix-13)
	ld hl,(iy+sha1_ctx.state+4*2+0)
	ld e, (iy+sha1_ctx.state+4*2+3)
	call ti._ladd
	ld (iy+sha1_ctx.state+4*2+0),hl
	ld (iy+sha1_ctx.state+4*2+3),e

	ld bc,(ix-20)
	ld a,(ix-17)
	ld hl,(iy+sha1_ctx.state+4*3+0)
	ld e, (iy+sha1_ctx.state+4*3+3)
	call ti._ladd
	ld (iy+sha1_ctx.state+4*3+0),hl
	ld (iy+sha1_ctx.state+4*3+3),e

	ld bc,(ix-24)
	ld a,(ix-21)
	ld hl,(iy+sha1_ctx.state+4*4+0)
	ld e, (iy+sha1_ctx.state+4*4+3)
	call ti._ladd
	ld (iy+sha1_ctx.state+4*4+0),hl
	ld (iy+sha1_ctx.state+4*4+3),e

	ld sp,ix
	pop ix
	ret

.loop4sr1:
	ld hl,(ix-12)
	ld e, (ix-9)
	ld bc,(ix-16)
	ld a, (ix-13)
	call ti._lxor ; (b ^ c)
	ld bc,(ix-20)
	ld a, (ix-17)
	jp ti._lxor ; (b ^ c ^ d)

.loop3sr1:
	call ti._ladd ; t += ctx->k[.] ; k is already loaded with the correct index before this routine
	ld a,e
	push af,hl
	ld bc,(ix-8) ; a
	ld a, (ix-5)
	ld l,5
	call ti._lshl ; a << 5
	ld e,a
	push de,hl
	ld bc,(ix-8)
	ld a, (ix-5)
	ld l,32-5
	call ti._lshru ; a >> (32-5)
	pop hl,de
	call ti._lor  ; (a << 5)|(a >> (32-5))
	pop bc,af
	call ti._ladd ; t += (a << 5)|(a >> (32-5))
	ld bc,(ix-24)
	ld e, (ix-21)
	call ti._ladd ; t += e
	push de,hl
	ld hl,hashlib_temp
	ld de,(ix-3)
	inc de
	ld (ix-3),de
	add hl,de  ;add index*4
	add hl,de
	add hl,de
	add hl,de
	ld bc,(hl)
	inc hl
	inc hl
	inc hl
	ld a,(hl)
	pop hl,de
	call ti._ladd ; t += m[i]
	push de,hl
	ld hl,(ix-20)   ; e = d
	ld e, (ix-17)
	ld (ix-24), hl
	ld (ix-21), e
	ld hl,(ix-16)   ; d = c
	ld e, (ix-13)
	ld (ix-20), hl
	ld (ix-17), e
	ld bc,(ix-12)   ; c = (b << 30)|(b >> (32-30))
	ld a, (ix-9)
	ld l,30
	call ti._lshl ; b << 30
	ld e,a
	push de,hl
	ld bc,(ix-12)
	ld a, (ix-9)
	ld l,32-30
	call ti._lshru ; b >> (32-30)
	pop hl,de
	call ti._lor  ; (b << 30)|(b >> (32-30))
	ld hl,(ix-8)   ; b = a
	ld e, (ix-5)
	ld (ix-12), hl
	ld (ix-9), e
	pop hl,de
	ld (ix-8),hl   ; a = t
	ld (ix-5),e
	ret

.lrl:
	xor a,a
	rl (hl)
	adc a,a
	inc hl
	rl (hl)
	inc hl
	rl (hl)
	inc hl
	rl (hl)
	dec hl
	dec hl
	dec hl
	or a,(hl)
	ld (hl),a
	ret

.lxor:
	ld b,4
.lxor_loop:
	ld a,(de)
	xor a,(hl)
	ld (iy+0),a
	inc de
	inc hl
	djnz .lxor_loop
	ret

;------------------------------------------
;void sha1_update(SHA1_CTX *ctx, const BYTE data[], uint32_t len);
sha1_update:
	ld hl,-3
	call ti._frameset
	ld iy,(ix+6)
	or a,a
	sbc hl,hl
	ld (ix-3),hl
.loop:
	ld de,(ix-3)
	inc de
	ld (ix-3),de
	ld hl,(ix+9)
	add hl,de
	ld a,(hl)
	ld de,(iy+sha1_ctx.datalen)
	lea hl,iy+sha1_ctx.data
	add hl,de
	inc de
	ld (iy+sha1_ctx.datalen),de
	ld (hl),a
	ld a,e
	cp a,64
	jr nz,.next
	push iy,iy
	call sha1_transform
	pop iy
	ld hl,512
	ex (sp),hl
	pea iy+sha1_ctx.bitlen
	call _add64lu
	pop iy,bc
	xor a,a
	ld (iy+sha1_ctx.datalen),a
.next:
	ld hl,(ix-3)
	ld bc,(ix+12)
	or a,a
	sbc hl,bc
	jr c,.loop

	ld sp,ix
	pop ix
	ret

;------------------------------------------
;void sha1_final(SHA1_CTX *ctx, BYTE hash[]);
sha1_final:
	ld hl,-3
	call ti._frameset
	ld iy,(ix+6)
	ld a,(iy+sha1_ctx.datalen)
	cp a,56
	jr nc,.step1
	ld a,56
	sub a,c
	db $01 ;dummify next three bytes
.step1:
	ld a,64
	sub a,c
	ld bc,(iy+sha1_ctx.datalen)
	lea hl,iy+sha1_ctx.data
	add hl,bc
	ld (hl),$80
	inc hl
	ld b,a
.loop1:
	ld (hl),0
	inc hl
	djnz .loop1
	ld a,(iy+sha1_ctx.datalen)
	cp a,56
	jq c,.step2
	push iy,iy
	call sha1_transform
	pop iy,hl
.step2:
	ld b,56
.loop2:
	ld (hl),0
	inc hl
	djnz .loop2
	ld hl,(sha1_ctx.datalen)
	add hl,hl
	add hl,hl
	add hl,hl
	push hl
	pea iy+sha1_ctx.bitlen
	call _add64lu
	pop bc,bc

	lea hl,iy+sha1_ctx.bitlen
	lea de,iy+sha1_ctx.data+63
	ld b,8
.loop3:
	ld a,(hl)
	ld (de),a
	inc hl
	dec de
	djnz .loop3

	push iy,iy
	call sha1_transform
	pop iy,bc

;reverse the endian-ness of ctx->state into output hash
	ld b,5
	lea iy,iy+sha1_ctx.state
	ld hl,(ix+9)
.loop4:
	ld a,(iy)
	ld c,(iy+1)
	ld d,(iy+2)
	ld e,(iy+3)
	lea iy,iy+4
	ld (hl),e
	inc hl
	ld (hl),d
	inc hl
	ld (hl),c
	inc hl
	ld (hl),a
	inc hl
	djnz .loop4

	ld sp,ix
	pop ix
	ret


;void sha256_init(SHA256_CTX *ctx);


;void sha256_transform(SHA256_CTX *ctx, const BYTE data[]);


;void sha256_update(SHA256_CTX *ctx, const BYTE data[], uint32_t len);


;void sha256_final(SHA256_CTX *ctx, BYTE hash[]);


;------------------------------------------
; library helper functions

;uint8_t *_zero64(uint8_t *A);
;output pointer to A = 0
_zero64:
	pop bc,hl
	push hl,bc
	push hl
	ld b,8
	xor a,a
.zeroloop:
	ld (hl),a
	inc hl
	djnz .zeroloop
	pop hl
	ret

;uint8_t *add64(uint8_t *A, uint8_t *B);
;output pointer to A = A + B
_add64:
	pop bc,hl,de
	push de,hl,bc
	push hl
	or a,a
	ld b,8
.add_loop:
	ld a,(de)
	adc a,(hl)
	ld (hl),a
	inc hl
	inc de
	djnz .add_loop
	pop hl
	ret

;uint8_t *addlu64(uint8_t *A, uint24_t B);
;output pointer to A = A + B
_add64lu:
	ld hl,-8
	call ti._frameset
	lea hl,ix-8 ;zero the temporary uint8_t*
	xor a,a
	ld b,8
.voidint_loop:
	ld (hl),a
	inc hl
	djnz .voidint_loop
	ld hl,(ix+9)
	ld (ix-8),hl ;set the temporary uint8_t* to uint24_t B
	ld hl,(ix+6)
	pea ix-8
	push hl
	call _add64
	pop bc,bc
	ld sp,ix
	pop ix
	ret

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

sha1_default_ctx:
	dl 0
	db 8 dup 0
	dd $67452301, $EFCDAB89, $98BADCFE, $10325476, $c3d2e1f0, $5a827999, $6ed9eba1, $8f1bbcdc, $ca62c1d6
.len:=$-.

;------------------------------------------
; library dynamic data
hashlib_crc_table:
	dd 256 dup 0
hashlib_temp:
	dd 80 dup 0


