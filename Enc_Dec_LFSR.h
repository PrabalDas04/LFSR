/**********************************************************************************
This file contains all the declaration of the functions used in "Enc_Dec_LFSR.c"
**********************************************************************************/

#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include<string.h>

// global varible for key size of each LFSR
#define KEY_SIZE 8

// functions declaration
char * my_calloc( int );
char XOR( char , char );
int * binary_rep(int * , int );
int rev_binary_rep( int * );
char func(char * , int , int , int );
char * Shift_Right(char * , char * , int );
char * MUX( char * , char * , char * , char * , int );
char * One_Time_Pad( char * , char * , char * , int );
char * Enc_Dec(char * ,char * ,char * ,char *, char * ,int );