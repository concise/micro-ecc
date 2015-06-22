#ifndef __SHA256_H__
#define __SHA256_H__

#define SHA256_BLOCK_SIZE 64
#define SHA256_OUTPUT_SIZE 32

typedef unsigned long int sha256_word_t; /* to hold 0x00000000 ~ 0xffffffff */

typedef struct {
    sha256_word_t runninghash[8];   /* intermediate hash value (H0 ~ H7)    */
    sha256_word_t totalbitlen[2];   /* bit length (l) of the input message  */
    unsigned char msgchunk[64];     /* last unprocessed message chunk       */
    unsigned char msgchunklen;      /* byte length of the unprocessed chunk */
} sha256_context_t;

void sha256_starts(void *);
void sha256_update(void *, int, const unsigned char *);
void sha256_finish(void *, unsigned char *);
void sha256       (int, const unsigned char *, unsigned char *);

#endif
