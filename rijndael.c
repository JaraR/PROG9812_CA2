/*
 * Jara Rodriguez - D22127275
 * Main Rijndael algorithms and functions that encrypt and decrypt blocks of text.
 *
 */

#include <stdlib.h>
#include "rijndael.h"

// Byte substitution table
const unsigned char s_box[256] = {
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// Inverse byte substitution table
const unsigned char inv_s_box[256] = {
  0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
  0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
  0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
  0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
  0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
  0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
  0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
  0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
  0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
  0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
  0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
  0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
  0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
  0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
  0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// Round constant
const unsigned char r_con[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

/*
 * Operations used when encrypting a block
 */

// Replaces all bytes in the block with its sub byte after an s-box lookup.
void sub_bytes(unsigned char *block) {
  for (int i = 0; i < 16; i++) {
    block[i] = s_box[block[i]];
  }
}

// Rotates the 2nd row of the block by one to the left, the 3rd row by two to the left, and the 4th row by three to the left.
void shift_rows(unsigned char *block) {
  // Row 2
  unsigned char temp = block[4];
  block[4] = block[5];
  block[5] = block[6];
  block[6] = block[7];
  block[7] = temp;

  // Row 3
  temp = block[8];
  block[8] = block[10];
  block[10] = temp;
  temp = block[9];
  block[9] = block[11];
  block[11] = temp;

  // Row 4
  temp = block[12];
  block[12] = block[15];
  block[15] = block[14];
  block[14] = block[13];
  block[13] = temp;
}

// implementation taken and adapted from https://web.archive.org/web/20100626212235/http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
// also used https://www.angelfire.com/biz7/atleast/mix_columns.pdf to understand the Mix Columns transformation and matrix multiplication
unsigned char xtime(unsigned char x)
{
	return (x & 0x80) ? ((x << 1) ^ 0x1b) : (x<<1);
}

// Modulo multiplies each column in Rijndael's Galois Field by a given matrix.
void mix_columns(unsigned char *block) {
  unsigned char a, b, c, d, e;
	
	// Processes one column of the block at a time
	for (int i = 0; i < 4; i++)
	{
		a = block[i]; b = block[i+4]; c = block[i+8]; d = block[i+12];
		e = a ^ b ^ c ^ d;
		block[i]   ^= e ^ xtime(a^b);
		block[i+4] ^= e ^ xtime(b^c);
		block[i+8] ^= e ^ xtime(c^d);
		block[i+12] ^= e ^ xtime(d^a);
	}
}

/*
 * Operations used when decrypting a block
 */

// Reverses the sub bytes step using an inverse s-box lookup and substitution.
void invert_sub_bytes(unsigned char *block) {
  for (int i = 0; i < 16; i++) {
    block[i] = inv_s_box[block[i]];
  }
}

/* Reverses the shift rows step by rotating the 2nd row of the block by one to the right, 
the 3rd row by two to the right, and the 4th row by three to the right.*/
void invert_shift_rows(unsigned char *block) {
  // Row 2
  unsigned char temp = block[7];
  block[7] = block[6];
  block[6] = block[5];
  block[5] = block[4];
  block[4] = temp;

  // Row 3
  temp = block[11];
  block[11] = block[9];
  block[9] = temp;
  temp = block[10];
  block[10] = block[8];
  block[8] = temp;

  // Row 4
  temp = block[13];
  block[13] = block[14];
  block[14] = block[15];
  block[15] = block[12];
  block[12] = temp;
}

// Reverses mix columns steps.
void invert_mix_columns(unsigned char *block) {
  unsigned char a, b, c, d, e, x, y, z;
	
	// Processes one column of the block at a time
  for (int i = 0; i < 4; i++)
	{
		a = block[i]; b = block[i+4]; c = block[i+8]; d = block[i+12];
		e = a ^ b ^ c ^ d;
		z = xtime(e);
		x = e ^ xtime(xtime(z^a^c) );
		y = e ^ xtime(xtime(z^b^d) );
		block[i]   ^= x ^ xtime(a^b);
		block[i+4] ^= y ^ xtime(b^c);
		block[i+8] ^= x ^ xtime(c^d);
		block[i+12] ^= y ^ xtime(d^a);
	}
}

/*
 * This operation is shared between encryption and decryption
 */
// Adds each byte of the block to the corresponding byte of the round key using bitwise XOR.
void add_round_key(unsigned char *block, unsigned char *round_key) {
  for (int i = 0; i < 16; i++) {
   block[i] ^= round_key[i];
  }
}

/*
 * This function expands the round key. Given an input,
 * which is a single 128-bit key, it returns a 176-byte
 * vector, containing the 11 round keys one after the other
 */
// Expands a given cipher key into 11 round keys, used in the initial round, 9 main rounds, and final round.
unsigned char (*expand_key(unsigned char *cipher_key))[16] {
  unsigned char (*round_keys)[16] = malloc(sizeof(unsigned char) * 11 * 16);
  /*
   * The imaginary shape of each round key. Each round key is contained in the 2D round_keys array.
   * The round_keys array has 11 rows and 16 columns.
   *  0,  1,  2,  3, 
   *  4,  5,  6,  7,
   *  8,  9, 10, 11,
   * 12, 13, 14, 15
   */

  // Sets the first row (round key) of the 2D round_keys array equal to the bytes in the given cipher key.
  for (int i = 0; i < 16; i++) {
   round_keys[0][i] = cipher_key[i];
  }
  
  // In each subsequent 2D row, calculates each round key.
  for (int j = 1; j < 11; j++) {
   // Each round key (2D row of round_keys) is calculated based on the first 4 bytes in the row.
   for (int k = 0; k < 4; k++) {
      /* Every byte that is in a position of a multiple of 4 (first imaginary column) is calculated by taking the 
      corresponding bytes in the last (imaginary) column of the previous round key rotated up by one, doing an s-box 
      lookup, and added (XOR) to the corresponding bytes of the previous round key's first column and a round constant.*/
      if (k == 0) {
         round_keys[j][k] = s_box[round_keys[j-1][7]] ^ round_keys[j-1][k] ^ r_con[j-1];
         round_keys[j][k+4] = s_box[round_keys[j-1][11]] ^ round_keys[j-1][k+4] ^ 0x00;
         round_keys[j][k+8] = s_box[round_keys[j-1][15]] ^ round_keys[j-1][k+8] ^ 0x00;
         round_keys[j][k+12] = s_box[round_keys[j-1][3]] ^ round_keys[j-1][k+12] ^ 0x00;
      }
      /*Every other byte is calculated by adding (XOR) the previous column's corresponding bytes with the corresponding 
      bytes of the previous round key.*/
      else {
         round_keys[j][k] = round_keys[j][k-1] ^ round_keys[j-1][k];
         round_keys[j][k+4] = round_keys[j][k+3] ^ round_keys[j-1][k+4];
         round_keys[j][k+8] = round_keys[j][k+7] ^ round_keys[j-1][k+8];
         round_keys[j][k+12] = round_keys[j][k+11] ^ round_keys[j-1][k+12];
      }
   }
  }

  return round_keys;
}

/* Main encrypt function that takes a 128-bit plaintext block and a 128-bit key, applies the Rijndael algorithm, and 
returns an encrypted ciphertext.*/
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  unsigned char *output = (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  // Sends the given key to the key expansion algorithm.
  unsigned char (*all_round_keys)[16] = expand_key(key);

  // Sets the output variable equal to the given plaintext.
  for(int i = 0; i < 16; i++) {
   output[i] = plaintext[i];
  }

  // Applies AddRoundKey step for the initial round.
  add_round_key(output, all_round_keys[0]);

  // Applies the SubBytes, ShiftRows, MixColumns, and AddRoundKey steps for the 9 main rounds.
  for (int i = 1; i < 10; i++) {
    sub_bytes(output);
    shift_rows(output);
    mix_columns(output);
    add_round_key(output, all_round_keys[i]);
  }

  // Applies the SubBytes, ShiftRows, and AddRoundKey steps for the final round.
  sub_bytes(output);
  shift_rows(output);
  add_round_key(output, all_round_keys[10]);

  free(all_round_keys);

  return output;
}

/* Main decrypt function that takes a 128-bit ciphertext block and a 128-bit key, applies the Rijndael algorithm, and 
returns an unencrypted plaintext.*/
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key) {
  unsigned char *output = (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  // Sends the given key to the key expansion algorithm.
  unsigned char (*all_round_keys)[16] = expand_key(key);

  // Sets the output variable equal to the given ciphertext.
  for(int i = 0; i < 16; i++) {
   output[i] = ciphertext[i];
  }

  // Applies the AddRoundKey, inverse ShiftRows, and inverse SubBytes steps for the initial round.
  add_round_key(output, all_round_keys[10]);
  invert_shift_rows(output);
  invert_sub_bytes(output);

  // Applies the AddRoundKey, inverse MixColumns, inverse ShiftRows, and inverse SubBytes steps for the 9 main rounds.
  for (int i = 9; i > 0; i--) {
    add_round_key(output, all_round_keys[i]);
    invert_mix_columns(output);
    invert_shift_rows(output);
    invert_sub_bytes(output);
  }

  // Applies AddRoundKey step for the final round.
  add_round_key(output, all_round_keys[0]);
  
  free(all_round_keys);
  
  return output;
}
