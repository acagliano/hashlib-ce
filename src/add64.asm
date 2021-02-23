
public _add64

;uint8_t *add64(uint8_t *A, uint8_t *B);
;output pointer to A = A + B
_add64:
	pop bc,hl,de
	push de,hl,bc
	push hl
	or a,a
	ld b,8
add_loop:
	ld a,(de)
	adc a,(hl)
	ld (hl),a
	inc hl
	inc de
	djnz add_loop
	pop hl
	ret
