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
		
		mov edi, data

		//C. swap nibblets		
							// Lorin, unsure of how to comment. Not 100% of what's going to. Could you please comment? - Travis 11-10-18
		// sub edi, dataLength		// reset edi to start of file
		xor eax, eax			// clear
		xor edx, edx			// ""
		xor ecx, ecx			// ""
		mov ecx, dataLength		// used to keep count of iterations

		START_SWAP_NIBBLETS :	// start of loop
		mov dl, byte ptr[edi]	// copy first byte of file into dl
		mov al, dl

		ROR al, 4

		mov dl, al
		mov ebx, edx
		mov byte ptr[edi], bl
		INC EDI
		dec ecx
		jne START_SWAP_NIBBLETS

		// A. swap even and odd 
							// Chinedu can you make sure the comments are correct on what your algorithm is doing? - Travis 11-10-18
		sub edi, dataLength		// reset edi to start of file
		xor eax, eax			// clear 
		xor ecx, ecx			// ""
		mov ecx, dataLength		// used to keep count of interations

		START_EO_SWAP :			// start loop
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
		inc edi					// increase to next byte
		xor eax, eax			// clear
		xor ebx, ebx			// ""
		dec ecx
		jne START_EO_SWAP		// end loop

		//E. reverse bit order
		sub edi, dataLength		// reset edi back to start of data stream
		xor eax, eax			// clearing regisiter
		xor ecx, ecx			// ""
		xor ebx, ebx			// ""
		mov al, byte ptr[edi]  // copy the first byte of  data we want to reverse
		mov ecx, 8				// set our count to 8, traversing through 8 bits
		mov ebx, 0				// regist will hold the carry flag that is rotated

		xor edx, edx							// clear register
		mov edx, dataLength						// used for counting interates since ecx is being used
		START_REVERSE_BIT_ORDER_OUTER :			// start outer loop
			START_REVERSE_BIT_ORDER_INNER:		// start innter loop
			sal al, 1							// left shift by 1 which will set CF = 1
			rcr bl, 1							// right rotate through CF copying 1 into bl
			cmp ecx, 0							// is ecx == 0? nah brah, it's not
			dec ecx								// decrease that boi
			jne START_REVERSE_BIT_ORDER_INNER
		mov byte ptr[edi], bl					// overwrite byte of data in file with the reversed version
		xor eax, eax
		xor ecx, ecx
		xor ebx, ebx
		inc edi									// increse edi to get next byte of data
		mov al, byte ptr[edi]					// copy next byte of file into al
		mov ecx, 8								// set our count to 8, traversing through 8 bits					
		mov ebx, 0								// regist will hold the carry flag that is rotated
		dec edx
		jne START_REVERSE_BIT_ORDER_OUTER		// end outer

		//D. code swapper table
		sub edi, dataLength		// reset edi back to start of data stream
		lea edx, gDecodeTable	// load address of first value in encode table
		xor ebx, ebx			// clearing 
		xor ecx, ecx			// ""
		xor eax, eax			// ""

		START_TABLE_SWAP :		//	start loop
		cmp ecx, dataLength
		je END_TABLE_SWAP
		mov al, byte ptr[edi]
		mov ebx, [edx + eax]		// goes to position in gEncodeTable and copies value into ebx
		mov byte ptr[edi], bl  // overwrite byte in file with value from encode table
		inc edi
		inc ecx
		jmp START_TABLE_SWAP
		END_TABLE_SWAP :			// end loop

		xor ecx, ecx		// clear count
		xor ebx, ebx		// clear register
		sub edi, dataLength	// reset to start of data stream
		mov bl, 0x3C		// copy value we want to use to invert bits

		INVERT_MIDDLE_FOUR :			// Start of loop
		cmp ecx, dataLength
		je END_INVERT_MIDDLE_FOUR
		xor byte ptr[edi], bl		// inverting middle four bits with 0x3C  ==  0011 1100
		inc edi
		inc ecx
		jmp INVERT_MIDDLE_FOUR
		END_INVERT_MIDDLE_FOUR :		// end loop

		// CLEAR ALL THE THINGS!!!!
		xor edx, edx
		xor eax, eax
		xor ecx, ecx
		xor ebx, ebx
		xor edx, edx

		lea edx, gptrPasswordHash	 // load addres of gPhasswordHash[0]
		movzx eax, byte ptr[edx]	 // first byte of gPH[0] stored in eax
		movzx ebx, byte ptr[edx + 1] // gph[1] stored in ebx
		shl eax, 8					 // multiply by 256
		add eax, ebx				 // adding gph[1]
		// code will get the starting-index

		// the starting index stored in eax will be the location in the keyfile
		xor edx, edx		// clearing edx 
		xor ebx, ebx		// clearing ebx
		lea edx, gkey		// copy the address of out group key into edx
		mov ebx, [edx+eax]	// copy the data of edx+eax; the equivalent of  keyfile[starting index]
		// mov gdebug1, bl		// debug purposes
		
		xor ecx, ecx		// clearing any contents that may be in ecx
		sub edi, dataLength
		DECRYPT_LOOP :		  // start decrypting	
		cmp ecx, dataLength	  // if ecx == dataLength sets ZF=1
		je END				  // if ZF=1, jump to end oter
		xor byte ptr[edi], bl // xor first byte of encrypted data
		inc edi				  // incease edi to get the next byte of data
		inc ecx
		jmp DECRYPT_LOOP	  // jump to start of loop

		END :

		nop


	}
	
	return resulti;
} // decryptData

