/***************************************************************************************
Title : Implementation of an LFSR based encryption-decryption scheme
Author : Prabal Das
Venue : ISI, Kolkata
Duration : CrS Ist year, Nov. 2023 
****************************************************************************************/

#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include<string.h>
#include "Enc_Dec_LFSR.h"

// Driver code
void main()
{
    // variables declarartion
    char * msg, * fin_cipher, * encd_msg, * msg_str_1, * msg_str_2, * cipher_text, c;
    int * bin_rep, * rev_bin_rep, i, j = 0, d, val, k = 0, choice, len_msg;
    len_msg = 1000;                                  // length of the message

    // memory allocation
    msg = my_calloc(len_msg);                       // it stores readable plaintext
    encd_msg = my_calloc(7*len_msg + 1);            // it stores the 0-1 encoding of the plaintext
    msg_str_1 = my_calloc(7*len_msg + 1);           // it stores the encryption of encd_msg
    msg_str_2 = my_calloc(7*len_msg + 1);           // it stores the decryption of cipher_text which is binary string
    cipher_text = my_calloc(7*len_msg + 1);         // it stores the user cipher text input which is binary string
    fin_cipher = my_calloc(len_msg);                // it stores the decoded version of msg-str_2
    bin_rep = (int *)calloc(sizeof(int), 7);        // binary of ascii code of plaintext 
    rev_bin_rep = (int *)calloc(sizeof(int), 7);    // ascii code of binary of encoded ciphertext
    
    // Three secret values a.k.a private keys each of 32-bits
    char sec1[] = "00011100";
    char sec2[] = "11001000";
    char sec3[] = "10111001";

    /*
    First part of the code : Takes i/p plaintext and returns 0-1 encoding of ciphertext. It first ASCII based encode the text
                            in 0-1 binary string and then encrypts it.
    Second part of the code : Takes i/p 0-1 encoding of ciphertext and returns plaintext. It first decrypts the 
                             ciphertext and then decode it to readable plaintext.
    N.B.- If you have plaintext and want to encrypt then choose first part and if you have ciphertext and
          you want to decrypt then choose second part. 
    */

   //////////////////////////// FIRST PART //////////////////////////////

    {
        printf("Enter a message to encrypt : ");
        while((c = getchar()) != '\n')                      // input of plaintext
        {
            msg[k] = c;
            d = (int)c;                                     // ascii value of plaintext character
            bin_rep = binary_rep( bin_rep, d );             // binary of ascii value
            for( i = 0; i < 7; i++)
            {
                if(bin_rep[i] == 0)
                    encd_msg[j] = '0';                      // encoded msg in binary character
                else
                    encd_msg[j] = '1';
                j++;
            }
            k++;
        }
        printf("msg : %s\n",msg);
        printf("encd_msg : %s\n",encd_msg);                 // encoded plaintext in binary character

        msg_str_1 = Enc_Dec( sec1, sec2, sec3, encd_msg, msg_str_1, j);  // returns the encoded ciphertext
        printf("cipher is : %s\n",msg_str_1);
        
    }
/*
    /////////////////////////// SECOND PART ///////////////////////////////
    {
        printf("Enter the cipher text : ");
        i = 0;
        while((c = getchar()) != '\n')                            // input of binary character cipher text
        {
            cipher_text[i] = c;
            i++;
        } 
        msg_str_2 = Enc_Dec( sec1, sec2, sec3, cipher_text, msg_str_2, i);   // return encoded plaintext

        printf("Encoded Plaintext : %s\n",msg_str_2);

        i = 0;
        j = 0;
        k = 0;
        while((c = msg_str_2[k]) != '\0')
        {
            if( c == '0')                                          // binary character to binary string
                rev_bin_rep[i] = 0;
            else
                rev_bin_rep[i] = 1;

            i++;
            if(i == 7)                                              // taking 7 binary string and represent in integer
            {
                val = rev_binary_rep( rev_bin_rep);                 // integer value of binary string
                fin_cipher[j] = (char)val;                          // ciphertext in english word, the code of ascii values
                j++;
                i = 0;
            }
            k++;
        }
        printf("Plaintext : %s\n",fin_cipher);    
    }
    */
}