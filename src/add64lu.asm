
public _add64lu
extern _add64
extern __frameset

;uint8_t *addlu64(uint8_t *A, uint24_t B);
;output pointer to A = A + B
_add64lu:
	ld hl,-8
	call __frameset
	lea hl,ix-8 ;zero the temporary uint8_t*
	xor a,a
	ld b,8
_voidint_loop:
	ld (hl),a
	inc hl
	djnz _voidint_loop
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


