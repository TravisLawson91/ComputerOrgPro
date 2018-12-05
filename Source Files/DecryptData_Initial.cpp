// DecryptData.cpp
//
// THis file uses the input data and key information to decrypt the input data
//

#include "Main.h"

//////////////////////////////////////////////////////////////////////////////////////////////////
// code to decrypt the data as specified by the project assignment
int decryptData(char *data, int dataLength)
{
	int resulti = 0;

	gdebug1 = 0;					// a couple of global variables that could be used for debugging
	gdebug2 = 0;					// also can have a breakpoint in C code

	// You can not declare any local variables in C, but should use resulti to indicate any errors
	// Set up the stack frame and assign variables in assembly if you need to do so
	// access the parameters BEFORE setting up your own stack frame
	// Also, you cannot use a lot of global variables - work with registers

	__asm {

		// I'd like to thank Diet Coke for helping me get this done, you are the true champion!
		// Crypto order BDEAC
		xor eax, eax			// clear
		xor ebx, ebx			// ""
		xor ecx, ecx			// ""
		xor edx, edx			// ""

		mov edi, data

		// Crypto order BDEAC
		START_DECRY:
		cmp ecx, dataLength
		je END

		//C. swap nibblets		
							// Lorin, unsure of how to comment. Not 100% of what's going to. Could you please comment? - Travis 11-10-18
		mov dl, byte ptr[edi]	// copy first byte of file into dl
		mov al, dl

		ROR al, 4

		mov dl, al
		mov ebx, edx
		mov byte ptr[edi], bl

		// A. swap even and odd 
			// Chinedu can you make sure the comments are correct on what your algorithm is doing? - Travis 11-10-18
		mov al, byte ptr[edi]	// copy first byte into al

		and al, 0xaa			// masking odd bytes in al
		shr al, 1				// right shift to of set bits
		mov bl, al				// copy to bl to hold

		xor eax, eax			// clearing
			
		mov al, byte ptr[edi]	// re-copy first byte into al
		and al, 0x55			// masking even bytes
		shl al, 1				// left shift to offset bits

		or al, bl				// making the final swap
		mov byte ptr[edi], al	// overwrite byte in file with freshly swapped byte


	//E. reverse bit order
	xor eax, eax			// clearing regisiter
	xor ebx, ebx			// ""
	xor edx, edx
	mov al, byte ptr[edi]  // copy the first byte of  data we want to reverse
	mov edx, 8				// set our count to 8, traversing through 8 bits
	mov ebx, 0				// regist will hold the carry flag that is rotated

	START_REVERSE_BIT_ORDER:		// start innter loop
	sal al, 1							// left shift by 1 which will set CF = 1
	rcr bl, 1							// right rotate through CF copying 1 into bl
	cmp edx, 0							// is ecx == 0? nah brah, it's not
	dec edx								// decrease that boi
	jne START_REVERSE_BIT_ORDER
	mov byte ptr[edi], bl					// overwrite byte of data in file with the reversed version
	
	//D. code swapper table
	xor edx, edx
	xor ebx, ebx			// clearing 
	xor eax, eax			// ""
	lea edx, gDecodeTable	// load address of first value in encode table
	
	mov al, byte ptr[edi]
	mov ebx, [edx + eax]		// goes to position in gEncodeTable and copies value into ebx
	mov byte ptr[edi], bl		// overwrite byte in file with value from encode table

	xor ebx, ebx		// clear register

	// B. invert middle four
	mov bl, 0x3C		// copy value we want to use to invert bits
	xor byte ptr[edi], bl		// inverting middle four bits with 0x3C  ==  0011 1100


	// XOR with key
	//	ecx is used
	//	edi is used
	//	mov esi, gNumRounds

	xor eax, eax
	cmp ecx, 0
	je NO_POP
	pop eax
	jmp POPPED
	NO_POP:
	//xor eax, eax
	xor ebx, ebx
	xor edx, edx
	mov esi, gNumRounds
	lea edx, gPasswordHash
	mov ah, [edx+esi*4]
	mov al, [edx+esi*4+1]
	// code will get the starting-index and hold in eax
	
	POPPED:
	xor edx,edx
	lea edx, gPasswordHash
	mov bh, [edx+esi*4+2]
	mov bl, [edx+esi*4+3]
	
	xor edx, edx
	lea edx, gkey
	mov dh, byte ptr[edx + eax]
	xor byte ptr[edi], dh
	
	add eax, ebx
	cmp eax, 65537
	jl INDEX_NOT_GREATER
	sub eax, 65537
	INDEX_NOT_GREATER:

	push eax

	inc ecx
	inc edi
	jmp START_DECRY
		END :
		xor ecx, ecx // reset ecx back to 0 for next round
		mov ecx, gNumRounds
		dec ecx
		cmp esi, ecx
		je  FINALLY
		jmp ROUNDS

	FINALLY:
	pop eax
	nop
	}
	
	return resulti;
} // decryptData

