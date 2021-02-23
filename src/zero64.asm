
public _zero64

;uint8_t *_zero64(uint8_t *A);
;output pointer to A = 0
_zero64:
	pop bc,hl
	push hl,bc
	push hl
	ld b,8
	xor a,a
_zeroloop:
	ld (hl),a
	inc hl
	djnz _zeroloop
	pop hl
	ret
