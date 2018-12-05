// EncryptData.cpp
//
// This file uses the input data and key information to encrypt the input data
//

#include "Main.h"

//////////////////////////////////////////////////////////////////////////////////////////////////
// code to encrypt the data as specified by the project assignment
int encryptData(char *data, int dataLength)
{
	int resulti = 0;

	gdebug1 = 0;					// a couple of global variables that could be used for debugging
	gdebug2 = 0;					// also can have a breakpoint in C code

	// You can not declare any local variables in C, but should use resulti to indicate any errors
	// Set up the stack frame and assign variables in assembly if you need to do so
	// access the parameters BEFORE setting up your own stack frame
	// Also, you cannot use a lot of global variables - work with registers

	__asm {
		// clearing just because
		xor ebx, ebx
		xor edx, edx
		xor esi, esi
		xor eax, eax
		xor ecx, ecx

		mov edi, data			// copy data from file into edi, so bytes can be changed

		jmp TOPPER				// top of XOR Loop	
		ROUNDS:					// keep track of rounds
		xor ecx, ecx			// clearing
		xor edi, edi			// ""
		pop eax					// reset stack for next round
		mov edi, data			// reset to base address of data for next round
		inc esi					// increase round count
		
		TOPPER:					// top of whole loop
		cmp ecx, dataLength		// ecx used to keep track of how many times we've looped
		je END					// if ecx == dataLength jump to end

		cmp ecx, 0				// if first iteration, take the jump
		je NO_POP
		pop eax					// restore saved value from stack
		jmp POPPED				// forced jump becuase we had to pop value from stack
		NO_POP:					// jump made if on first iteration, we do NOT want to pop from stack

		// starting index held by eax, esi will handle rounds
		lea edx, gPasswordHash		// getting base address of pwHash
		mov ah, [edx + esi * 4]		// getting the first by of hash pwHash[0]
		mov al, [edx + esi * 4 + 1]	// getting second byte of hash pyHash[1]
		POPPED:						// jump made because we do not want to overwrite the value popped in eax
									// by executing the above code								

		// hop count held by ebx, esi will handle rounds
		xor edx, edx				// clear register; probably not needed	
		lea edx, gPasswordHash		// getting address of pwHash; probably redundant
		mov bh, [edx + esi * 4 + 2]	// getting thrid byte in hash, pwHash[2]
		mov bl, [edx + esi * 4 + 3] // getting fourth byt ein has, pwHash[3]
		//getting the values in the pwHash will change as rounds increase, esi manages round numbers

		lea edx, gkey				// get base address of gKey[]
		mov dh, byte ptr[edx + eax]	// get byte at base address + value in eax
		xor byte ptr[edi], dh		// flip bits of the first byte in our file

		add eax, ebx				// adding hop_count(ebx) to starting index(eax)
		cmp eax, 65537				// check if value in eax is less than 65537
		jl INDEX_NOT_GREATER		// make jump if less than
		sub eax, 65537				// if value in eax is greater, subtract 65537 so we don't go beyond stack
		INDEX_NOT_GREATER:
		push eax					// SAVE NEW INDEX TO STACK FOR LATER USE

		// B. invert middle four
		mov bl, 0x3C				// copy value we want to use to invert bits
		xor byte ptr[edi], bl		// inverting middle four bits with 0x3C  ==  0011 1100

		//D. code swapper table
		xor edx, edx
		xor ebx, ebx					// clearing 
		xor eax, eax					// ""
		lea edx, gEncodeTable			// load address of first value in encode table

		mov al, byte ptr[edi]
		mov ebx, [edx + eax]			// goes to position in gEncodeTable and copies value into ebx
		mov byte ptr[edi], bl			// overwrite byte in file with value from encode table

		//E. reverse bit order
		xor eax, eax						// clearing regisiter
		xor ebx, ebx						// ""
		xor edx, edx						// ""
		mov al, byte ptr[edi]				// copy the first byte of  data we want to reverse
		mov edx, 8							// set our count to 8, traversing through 8 bits
		mov ebx, 0							// regist will hold the carry flag that is rotated

		START_REVERSE_BIT_ORDER:			// start innter loop
		sal al, 1							// left shift by 1 which will set CF = 1
		rcr bl, 1							// right rotate through CF copying 1 into bl
		cmp edx, 0							// is ecx == 0? no
		dec edx								// decrease edx
		jne START_REVERSE_BIT_ORDER
		mov byte ptr[edi], bl				// overwrite byte of data in file with the reversed version

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

		//C. swap nibblets		
							// Lorin, unsure of how to comment. Not 100% of what's going to. Could you please comment? - Travis 11-10-18
		mov dl, byte ptr[edi]	// copy first byte of file into dl
		mov al, dl

		ROR al, 4
			
		mov dl, al
		mov ebx, edx
		mov byte ptr[edi], bl


		inc edi
		inc ecx
		jmp TOPPER

		END:
		xor ecx, ecx			// reset ecx back to 0 for next round
		mov ecx, gNumRounds		// store total number of rounds	
		dec ecx					// decrement ecx because we start at 0 and not 1. ie iteration 0 == round 1
		cmp esi, ecx			// if rounds == 0 we take jump to FINALLY
		je  FINALLY				// esi == 0 means to more rounds to make, to exit program
		jmp ROUNDS				// esi != 0 means we have more rounds to make.

		FINALLY:				// ending program
		pop eax					// pop to restoe esp
	}

	return resulti;
} // encryptData