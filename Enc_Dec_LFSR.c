/**********************************************************************************
This file contains all the definition of the functions used in "Enc_Dec_main.c"
**********************************************************************************/

#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include<string.h>

// global varible for key size of each LFSR
#define KEY_SIZE 8

// allocates memory and return null if memory not allocated properly
char * my_calloc( int n)                           
{
    char * buf;
    buf = (char *)calloc(sizeof(char), (n));

    if(buf == NULL)
    {
        printf("Error in memory allocation.\n");
        return NULL;
    }
    return buf;
}

char XOR( char a, char b)                           // XOR of two character
{
    if(a == '0')
    {
        if(b == '0')
            return '0';
        else
            return '1';
    }
    else
    {
        if(b == '0')
            return '1';
        else
            return '0';
    }
}

int * binary_rep(int * bin_rep, int d)              //binary representation of an integer
{
    int i;
    for( i = 0; i < 7; i++)
        bin_rep[i] = 0;
    if(d == 0)
        return bin_rep;
    
    for( i = 0; d > 0; i++)    
    {    
        bin_rep[6-i] = d % 2;    
        d = d/2;
    }    
    return bin_rep;
}


int rev_binary_rep( int * rev_bin_rep)              // binary to int representation
{
    int i, val = 0;
    for( i = 0; i < 7; i++)
        val = val + rev_bin_rep[6-i] * (int)pow( 2, i);
    return val;
}

// function : s[0]⊕s[1]⊕s[4]
char func(char * bin, int i, int j, int k)         //definition of register function
{
    int bit = 0;
    char bit_char;

    bit_char = XOR(bin[i], bin[j]);
    bit_char = XOR(bit_char,bin[k]);
    
    return bit_char;
}

//this function right shifts the seed and returns X_i's
char * Shift_Right(char * buf, char * bin, int n)  //n is length of the plain text
{
   char bin1[KEY_SIZE+1];  //initial secret seed
   int i, j;

   for(j = 0; j < n; j++)
   {
        for(i = 1; i < KEY_SIZE; i++)
            bin1[i] = bin[i-1];

        bin1[0] = func(bin,1,0,4);            // function in the LFSR register : s[0]⊕s[1]⊕s[4]
        buf[j] = bin[KEY_SIZE-1];

        for( i = 0; i < KEY_SIZE; i++)
            bin[i] = bin1[i];
   }
   return buf;
}

//MUX function acts as 2*1 multiplexer takes i/p X1, X2, X3 and o/p Y
char * MUX( char * x1, char * x2, char * x3, char * buf, int n)
{
    int i;

    for( i = 0; i < n; i++)
    {
        if(x3[i] == '0')
            buf[i] = x1[i];
        if(x3[i] == '1')
            buf[i] = x2[i];
    }
    return buf;
}

// one time pad function which xors 'y' and 'M' and stores in 'buf'
char * One_Time_Pad( char * y, char * M, char * buf, int n)
{
    int i;
    char c, d;
    for(i = 0; i < n; i++)
    {
        c = y[i];
        d = M[i];
        buf[i] = XOR(c, d);
    }
    return buf;
}

// Encryption-Decryption function which encryptes 'M' by keys 's1','s2' and 's3' and outputs 'msg_str'
char * Enc_Dec(char * s1, char * s2, char * s3, char * M, char * msg_str, int n)
{
    char * x1, * x2, * x3, * y, * buf1, * buf2, * buf3, * buf4;
    int i;
    //n : length of X_i's, buf[] is a local memory to store X_i's, Y and cipher text  
    buf1 = my_calloc( n+1 );
    buf2 = my_calloc( n+1 );
    buf3 = my_calloc( n+1 );
    buf4 = my_calloc( n+1 );

    x1 = Shift_Right( buf1, s1, n );                //value of X1
    x2 = Shift_Right( buf2, s2, n);                 // value of X2
    x3 = Shift_Right( buf3, s3, n);                 // value of X3
    y = MUX( x1, x2, x3, buf4, n );                 // value of Y
    msg_str = One_Time_Pad( y, M, msg_str, n);      // XOR of Y and M(message or ciphertext)
    return msg_str;
}