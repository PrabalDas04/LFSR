/***************************************************************************************
Title : Implementation of key recovery attack of an LFSR based encryption scheme
Author : Prabal Das
Venue : ISI, Kolkata
Duration : CrS Ist year, Feb. 2024 
****************************************************************************************/

#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include<string.h>

// global varible for key size of each LFSR
#define KEY_SIZE 8

// functions declaration
char * binary_rep(char * , int );
char * my_calloc( int );
char xor( char , char );
char func(char * , int , int , int );
char * Shift_Right(char * , char * , int );
//int * possible_first_key(int * , char * , char * , int , char *);
//int * possible_third_key(int * , char * , char * , int , char *, char * );
char * MUX( char * , char * , char * , char * , int );
char * One_Time_Pad( char * , char * , char * , int );
char * Enc_Dec(char * , char * , char * , char * , char * , int );


//binary representation of an integer
char * binary_rep(char * bin_rep, int d)
{
    int i;
    int * bin_rep1;
    bin_rep1 = (int *)calloc(sizeof(int), KEY_SIZE);
    if(d == 0)
    {
        for(i = 0; i < KEY_SIZE; i++)
            bin_rep[i] = '0';
        return bin_rep;
    }
    
    for( i = 0; d > 0; i++)    
    {    
        bin_rep1[KEY_SIZE-1-i] = d % 2;    
        d = d/2;
    }
    for(i = 0; i < KEY_SIZE; i++)
    {
        if(bin_rep1[i] == 0)
            bin_rep[i] = '0';
        else
            bin_rep[i] = '1';
    }
    free(bin_rep1);
    return bin_rep;
}

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

// xor of two character
char xor( char a, char b)
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

//definition of register function : s[0]⊕s[1]⊕s[4]
char func(char * bin, int i, int j, int k)
{
    int bit = 0;
    char bit_char;

    bit_char = xor(bin[i], bin[j]);
    bit_char = xor(bit_char,bin[k]);
    
    return bit_char;
}

//This function computes the output values from the reg. function 
//and output a string of size same as plain text size
char * Shift_Right(char * buf, char * bin, int n)  //n is length of the plain text
{
   char bin1[KEY_SIZE+1];  //initial secret seed
   int i, j;

   for(j = 0; j < n; j++)
   {
        for(i = 1; i < KEY_SIZE; i++)
             bin1[i] = bin[i-1];

        bin1[0] = func(bin,1,0,4);                  // function in the LFSR register
        buf[j] = bin[KEY_SIZE-1];

        for( i = 0; i < KEY_SIZE; i++)
            bin[i] = bin1[i];
   }
   return buf;
}

// This function takes all possible key for the first register 
// and invoke the "Shift_Right" function to get X1 and do the probability analysis
// to include in the possible first key array
// This function's output is same for second register also
int * possible_first_key(int * poss_s1, char * buf1, char * buf2, int cip_size, char cip_txt[] )
{
    int  i, count = 0, j = 0, sec1;

    for(sec1 = 1; sec1 < pow(2,KEY_SIZE); sec1++)
    {
        buf1 = binary_rep(buf1, sec1);
        buf2 = Shift_Right(buf2, buf1, cip_size);
        for(i = 0; i < cip_size; i++)
        {
            if(buf2[i] == cip_txt[i])
                count++;        // "count" variable stores the no of positions X1 and cipher text matches
        }
        //printf("%d %s %d\n",sec1,buf2,count);
        if(count >= 0.54*cip_size)
        {
            poss_s1[j] = sec1;   
            j++;
        }
        count = 0;
    }
    return poss_s1;
}

// This function is same as previous function which outputs possible third key set
// Here we can not do the same probability calculation, so we do some different calculation
int * possible_third_key(int * poss_s3, char * buf1, char * buf2, int cip_size, char cip_txt[], char * buf4)
{
    int sec3, i, j = 0, count = 0, count1 = 0;

    for(i = 0; i < cip_size; i++)
        {                           // 'buf4' contains the output of the first register for the first value 
            if(buf4[i] == '0')      // of the possible key set
                count1++;           // this variable stores the count for no of positions 'buf4' is 0
        }
    //printf("count1 = %d\n",count1);

    for(sec3 = 1; sec3 < pow(2,KEY_SIZE); sec3++)
    {
        buf1 = binary_rep(buf1, sec3);
        buf2 = Shift_Right(buf2, buf1, cip_size);

        for(i = 0; i < cip_size; i++)
        {
            if(buf4[i] == '0')
            {
                if(buf2[i] == cip_txt[i])
                    count++;
            }
        }
        //printf("%d %s %d\n",sec3,buf2,count);
        if(count >= 0.54 * count1)      //those positions where 'buf4' is 0, there we are comparing
        {                               // the cipher text and third register output for all possible keys
            poss_s3[j] = sec3;   
            j++;
        }
        count = 0;
    }
    return poss_s3;
}

// //MUX function acts as 2*1 multiplexer takes i/p X1, X2, X3 and o/p Y
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
        buf[i] = xor(c, d);
    }
    return buf;
}

// Encryption-Decryption function which encryptes 'M' by keys 's1','s2' and 's3' and outputs 'msg_str'
char * Enc_Dec(char * s1, char * s2, char * s3, char * M, char * msg_str, int n)
{
    char * x1, * x2, * x3, * y, * buf1_new, * buf2_new, * buf3_new, * buf4_new;
    int i;
    //n : length of X_i's, buf[] is a local memory to store X_i's, Y and cipher text  
    buf1_new = my_calloc( n+1 );
    buf2_new = my_calloc( n+1 );
    buf3_new = my_calloc( n+1 );
    buf4_new = my_calloc( n+1 );

    x1 = Shift_Right( buf1_new, s1, n );                //value of X1
    x2 = Shift_Right( buf2_new, s2, n);                 // value of X2
    x3 = Shift_Right( buf3_new, s3, n);                 // value of X3
    y = MUX( x1, x2, x3, buf4_new, n );                 // value of Y
    msg_str = One_Time_Pad( y, M, msg_str, n);      // XOR of Y and M(message or ciphertext)
    return msg_str;
}

// Driver code
int main()
{
    char cip_txt[] = "110100000110100001001000101000010010000100"; // encryption of the text "prabal"
    int cip_size;
    cip_size = strlen(cip_txt);

    int * poss_s1, * poss_s2, * poss_s3, * poss_s1_new, * poss_s2_new, * poss_s3_new, fix, i, j, k, sec1, sec2, sec3, len1, len2, len3;
    poss_s1 = (int *)calloc((sizeof(int)), pow(2,KEY_SIZE));
    poss_s2 = (int *)calloc((sizeof(int)), pow(2,KEY_SIZE));
    poss_s3 = (int *)calloc((sizeof(int)), pow(2,KEY_SIZE));
    poss_s1_new = (int *)calloc((sizeof(int)), pow(2,KEY_SIZE));
    poss_s2_new = (int *)calloc((sizeof(int)), pow(2,KEY_SIZE));
    poss_s3_new = (int *)calloc((sizeof(int)), pow(2,KEY_SIZE));

    char * buf1, * buf2, * buf3, * buf4, * buf5, * buf1_1, * buf3_1, * buf5_1;
    buf1 = my_calloc(KEY_SIZE);      //space for storing all possible keys in binary format for sec1
    buf2 = my_calloc(cip_size);      //space for storing all possible X_i's
    buf3 = my_calloc(KEY_SIZE);      //space for storing fix sec1 for X3
    buf4 = my_calloc(cip_size);      //space for storing X1 corresponding to fix sec1
    buf5 = my_calloc(KEY_SIZE);
    buf1_1 = my_calloc(KEY_SIZE);
    buf3_1 = my_calloc(KEY_SIZE);
    buf5_1 = my_calloc(KEY_SIZE);

    poss_s1 = possible_first_key(poss_s1, buf1, buf2, cip_size, cip_txt );
    for(k = 0; k < pow(2,KEY_SIZE); k++)
        poss_s2[k] = poss_s1[k];
    
    fix = poss_s1[0];
    buf1 = binary_rep(buf1, fix);
    buf4 = Shift_Right(buf4, buf1, cip_size);
    poss_s3 = possible_third_key(poss_s3, buf1, buf2, cip_size, cip_txt, buf4);

    i = 0;
    j = 0;
    for(k = 0; k < pow(2,KEY_SIZE); k++)
    {
        if(poss_s1[k] != 0)
        {
            poss_s1_new[i] = poss_s1[k];
            poss_s2_new[i] = poss_s2[k];
            i++;
        }
        if(poss_s3[k] != 0)
        {
            poss_s3_new[j] = poss_s3[k];
            j++;
        }  
    }
    // poss_s1_new[i] = 105;
    // poss_s2_new[i] = 216;
    // poss_s3_new[j] = 136;
    len1 = i;                 //these len's are the no of possible nonzero keys
    len2 = i;
    len3 = j;
    free(poss_s1);
    free(poss_s2);
    free(poss_s3);
    printf("Possible first secrets are : \n");
    for(k = 0; k < len1; k++)
        printf("%d ",poss_s1_new[k]);
    printf("\nPossible second secrets are : \n");
    for(k = 0; k < len2; k++)
        printf("%d ",poss_s2_new[k]);
    printf("\nPossible third secrets are : \n");
    for(k = 0; k < len3; k++)
        printf("%d ",poss_s3_new[k]);
    // FILE * out_file_ptr;
    // out_file_ptr=fopen("output_strings.txt","w");

    for(i = 0; i < len1; i++)
    {
        for(j = 0; j < len2; j++)
        {
            for(k = 0; k < len3; k++)
            {
                buf1 = binary_rep(buf1, poss_s1_new[i]);
                buf3 = binary_rep(buf3, poss_s2_new[j]);
                buf5 = binary_rep(buf5, poss_s3_new[k]);
                strcpy(buf1_1, buf1);
                strcpy(buf3_1, buf3);
                strcpy(buf5_1, buf5);
                
                buf2 = Enc_Dec(buf1_1, buf3_1, buf5_1, cip_txt, buf2, cip_size);    //buf2 is used to store the decoded binary string

                char msg[] = "111000011100101100001110001011000011101100";      //encoding of the original plaintext "prabal"
                if(strcmp(buf2, msg) == 0)
                {
                    // printf("Found : ");
                    printf("%s  %s  %s\n",buf1, buf3, buf5);      //those keys for which the correctness holds
                }
            }
        }
    }
    //fclose(out_file_ptr);
    free(poss_s1_new);
    free(poss_s2_new);
    free(poss_s3_new);
    free(buf1);
    free(buf2);
    free(buf3);
    free(buf4);
    free(buf5);
    free(buf1_1);
    free(buf3_1);
    free(buf5_1);
    return 0;
}