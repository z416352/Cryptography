#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext, char mode);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext, char mode);

int main (void)
{
	char mode;
	char filename[30];
	double START,END,encryption_time,dencryption_time; 
	
	printf("1. ECB\n");
	printf("2. CBC\n");
	printf("3. CTR\n");
	printf("Enter which mode do you want : ");
	scanf("%c", &mode);
	
	printf("Enter filename : ");
	scanf("%s", filename);
	
	/*
	printf ("-----------test begin-----------\n") ;
	
	FILE *fp;
	fp = fopen("test.txt", "r");
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	printf("%d\n", size);
	
	unsigned char *test;
	
	fread(test, size, 1, fp);
	printf("%s ", test);
	
	fclose(fp);
	
	printf ("\n-----------test finish-----------\n") ;
	*/
	
	
	
	FILE *pf,*en,*de ;
	
	pf = fopen(filename,"r");
	fseek(pf, 0, SEEK_END);
	int fsize = ftell(pf);
	fseek(pf, 0, SEEK_SET);
	unsigned char *plaintext = (unsigned char *)malloc(fsize);
	int ret = fread(plaintext,1,fsize,pf);
	fclose(pf);
	
	//printf("original file size: %d\n",ret);
    //printf("Plaintext: \n%s\n",(char *)plaintext);
		
	
	
	//char input_key[] = "01234567890123456789012345678901";
	char input_key[] = "0123456789012345"; //128 bits
	char input_iv[] = "0123456789012345";
	
	
	printf ("Enter key (128 bits) : ");
	scanf("%s", input_key);
	printf ("Enter initial vector (128 bits) : ");
	scanf("%s", input_iv);
	
	
	
    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */

    /* A 256 bit key */
    //unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    unsigned char *key = (unsigned char *) input_key;

    /* A 128 bit IV */
    //unsigned char *iv = (unsigned char *)"0123456789012345";
    unsigned char *iv = (unsigned char *) input_iv;

    /* Message to be encrypted */
    //unsigned char *plaintext = (unsigned char *)"The quick brown fox jumps over the lazy dog";
    
	
	
    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char *ciphertext = (unsigned char *)malloc(fsize);

    /* Buffer for the decrypted text */
    unsigned char *decryptedtext = (unsigned char *)malloc(fsize);

    int decryptedtext_len, ciphertext_len;

	
	START = clock();
    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                              ciphertext, mode);
	END = clock();
	encryption_time = (END - START) / CLOCKS_PER_SEC;
	
	en = fopen("encryption.txt","w");
	fwrite(ciphertext , 1 , fsize , en );
	
    /* Do something useful with the ciphertext here */
    //printf("Ciphertext is:\n");
    //BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);


	START = clock();
    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
                                decryptedtext, mode);
	END = clock();
	dencryption_time = (END - START) / CLOCKS_PER_SEC;	
	
	en = fopen("dencryption.txt","w");
	fwrite(decryptedtext , 1 , fsize , en );

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    //printf("Decrypted text is:\n");
    //printf("%s\n", decryptedtext);

	
	printf("File size : %d MB\n",fsize/1000000);
	printf("Encryption time : %lf s\n",encryption_time);
	printf("Dencryption time : %lf s\n\n",dencryption_time);
	
	double fsizeMB = (double)fsize/1000000;;
	double en_performance = fsizeMB/encryption_time;
	double de_performance = fsizeMB/dencryption_time;
	
	printf("performance of encryption/decryption : \n");
	printf("encryption : %.2lf MB/s \n",en_performance);
	printf("dencryption : %.2lf MB/s \n",de_performance);
	
    return 0;
}


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext, char mode)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    //if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    switch(mode)
    {
    case '1':
        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
        handleErrors();
        break;
    case '2':
        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();
        break;
    case '3':
        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        handleErrors();
        break;
    default:
        printf("ERROR!");
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext, char mode)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    //if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    switch(mode)
    {
    case '1':
        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
        handleErrors();
        break;
    case '2':
        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();
        break;
    case '3':
        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        handleErrors();
        break;
    default:
        printf("ERROR!");
    }


    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
