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
		mov ebx, [edx + eax]	// copy the data of edx+eax; the equivalent of  keyfile[starting index]
		// mov gdebug1, bl		// debug purposes


		mov edi, data		// moving encrpyted file into data

		xor ecx, ecx		// clearing any contents that may be in ecx

		ENCRYPT_LOOP :		  // start decrypting	
		cmp ecx, dataLength	  // if ecx == dataLength sets ZF=1
			je END				  // if ZF=1, jump to end oter
			xor byte ptr[edi], bl // xor first byte of encrypted data
			inc edi				  // incease edi to get the next byte of data
			inc ecx
			jmp ENCRYPT_LOOP	  // jump to start of loop

			END :


		
	}

	return resulti;
} // encryptData