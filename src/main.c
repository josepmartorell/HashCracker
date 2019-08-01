/**
 * main.c
 * Given a length and SHA-1 password hash, this program will use a brute-force
 * algorithm to recover the password using hash inversions.
 * Ones you have compile the file with your IDE recompile with mpicc ->
 * Compile: mpicc -g -Wall main.c -o main
 * To test the program we will calculate the hash of a simple two-letter password
 * by executing this command line in the terminal: echo -n 'hi' | sha1sum
 * Run lamd on your host by executing this command: lamboot
 * Run: mpirun -np 4 ./main num-chars hash [valid-chars]
 * e.g: mpirun -np 4 ./main 2 c22b5f9178342609428d6f51b2c5af4c0bde6a42 alpha
 * Where:
 * num-chars is the number of characters in the password
 * hash is the SHA-1 password hash
 * valid-chars tells the program what character set to use (numeric, alpha,
 *     alphanumeric)
 */

#include <ctype.h>
#include <mpi.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha1.c"

char *numeric = "0123456789";
char *alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
char *alpha_num = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* A pointer to store the current valid character set */
int hashes = 0, pw_found = 0, rank; /** TRACE pw_found */
char *valid_chars;
/* When the password is found, we'll store it here: */
char found_pw[128] = {0};
MPI_Request sendRequest, recRequest;
int comm_sz;


 /* crack function prototype */
 bool crack(char *target, char *str, int max_length);


 /* uppercase function modifies a string to only contain uppercase characters */
 void uppercase(char *string) {
  for (int i = 0; string[i] != '\0'; i++) {
    string[i] = toupper(string[i]);
  }
 }

int main(int argc, char *argv[]) {

  if (argc < 3 || argc > 4) {
    printf("Usage: mpirun %s num-chars hash [valid-chars]\n", argv[0]);
    printf("  Options for valid-chars: numeric, alpha, alphanum\n");
    printf("  (defaults to 'alphanum')\n");
    return 0;
  }

  MPI_Init(&argc, &argv);

  int comm_sz;
  double time = MPI_Wtime();
  MPI_Comm_size(MPI_COMM_WORLD, &comm_sz);
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);


  int length = atoi(argv[1]);
  char *target = argv[2];
  char *type = argv[3];

  uppercase(target);
  if (strcmp(type, "alpha") == 0) {
    valid_chars = alpha;
  } else if (strcmp(type, "numeric") == 0) {
    valid_chars = numeric;
  } else {

    valid_chars = alpha_num;
  }

  if (strlen(argv[2]) != 40) {
    if (rank == 0) {
      printf("Hash length is NOT valid. \n");
    }
    return 1;
  }
  /* check the password length */
  if (atoi(argv[1]) <= 0) {
    if (rank == 0) {
      printf("Password must be AT LEAST one character! \n");
    }
    return 1;
}

  if (rank == 0) {
    printf("Starting parallel computing hash cracker.\n");
  }

  int count = strlen(valid_chars) / comm_sz;
  int end;
  int start = rank*count;


  if (rank == comm_sz-1) {
    end = strlen(valid_chars);
  } else {
    end = (rank*count)+count;
  }

  bool found = false;
  for (int i = start; i < end && !found; i++) {
    char str_start[2] = {valid_chars[i], 0};
    found = crack(target, str_start, length);
  }

  if (!pw_found && found ) {
    for (int i = 0; i < comm_sz; i++)
      if (i != rank)
        MPI_Send(found_pw, 100, MPI_CHAR, i, 0, MPI_COMM_WORLD);
  }

  long int hash_total = 0;
  MPI_Reduce(&hashes, &hash_total, 1, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);

  /** stop password check to finalize if found */
  MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &pw_found, MPI_STATUS_IGNORE); /** &pw_found */
  if (pw_found) /** if pw_found returns true, MPI_Recv() is triggered */
    MPI_Recv(found_pw, 100, MPI_CHAR, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

  if (rank == 0) {
    printf("Operation completed.\n");
    printf("Total time elapsed: %.2fs\n", MPI_Wtime()-time);

    if (strlen(found_pw) > 0)
      printf("Recovered password: %s\n", found_pw);
    else
      printf("FAILED to retrieve password!\n");
  }

  MPI_Finalize();

  return 0;
}


 /** crack function definition:
 * Generates passwords in order (brute-force) and checks them against a
 * specified target hash.
 * Inputs ->
 *         + target -> the hash to be compared
 *         + str -> initial string. For the first function call, this can be "".
 *         + max_length -> maximum length of the password
 */
 bool crack(char *target, char *str, int max_length) {
  char *strcp = calloc(max_length + 1, sizeof(char));
  strcpy(strcp, str);

  for (int i = 0; i < strlen(valid_chars); ++i) {
    MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &pw_found, MPI_STATUS_IGNORE); /** &pw_found */
    if (pw_found) { /** if pw_found returns true, MPI_Recv() is triggered */
      MPI_Recv(found_pw, 100, MPI_CHAR, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
      return true;
    }
    strcp[strlen(str)] = valid_chars[i];
    if (strlen(str) + 1 < max_length) {
      if (crack(target, strcp, max_length) == true) {
        return true;
      }
    } else {
      /* only when the string (str) reaches the maximum length (max_length) check the hash */
      char hash[41];
      sha1sum(hash, strcp);
      /* not to collapse the screen just show the hash every million hashes */
      if (hashes % 1000000 == 0) {
        printf("[%d|%d] %s -> %s\n", rank, hashes, strcp, hash);
      }
      hashes++;
      if (strcmp(hash, target) == 0) {
        /* We found a match! */
        strcpy(found_pw, strcp);
        for (int i = 0; i < comm_sz; i++) {
          MPI_Isend(found_pw, max_length, MPI_CHAR, i, 0, MPI_COMM_WORLD, &sendRequest);
        }
        return true;
      }
    }
  }

  free(strcp);
  return false;
 }
