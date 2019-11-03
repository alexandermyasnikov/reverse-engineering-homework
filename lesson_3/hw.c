
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define HASH_TABLE_FILE_NAME "hash_table.bin"



uint32_t login_hash(const char* str) {
  uint32_t hash = 0xFFFFFFFF;

  for (uint32_t index = 0; str[index]; ++index) {
    hash = hash ^ str[index];
    for (uint32_t step_7 = 0; step_7 < 8; ++step_7) {
      uint32_t var_38 = -(hash & 0x01);
      hash = (hash >> 1) ^ (var_38 & 0xEDB88320);
    }
  }

  hash = ~hash;
  hash = hash & 0xFF;
  return hash;
}

uint32_t password_hash(const char* str) {
  uint32_t hash = 0x00;

  for (uint32_t index = 0; str[index]; ++index) {
    hash = hash + (0x99 ^ str[index]);
  }

  hash = hash & 0xFF;
  return hash;
}



struct string_32b_t {
  char data[32];
};

int next_string_rec(struct string_32b_t* string, int left_size) {
  if (left_size == 0) {
    int size = strlen(string->data);
    if (size + 1 < sizeof(string->data)) {
      string->data[size] = 'a';
      size++;
      string->data[size] = 0;
      return next_string_rec(string, size);
    } else {
      return 0;
    }
  } else if (string->data[left_size - 1] == 'z') {
    string->data[left_size - 1] = 'a';
    return next_string_rec(string, left_size - 1);
  } else {
    string->data[left_size - 1]++;
    return 1;
  }
}



struct hash_table_k1b_t {
  uint8_t               is_founds[256];
  struct string_32b_t   passwords[256];
  int                   score;
};

void save_hash_table(struct hash_table_k1b_t* hash_table, const char* fname) {
  FILE* file = fopen(fname, "wb");
  if (!file) return;

  int k = fwrite(hash_table, sizeof(*hash_table), 1, file);
  fclose(file);
}

int load_hash_table(struct hash_table_k1b_t* hash_table, const char* fname) {
  FILE* file = fopen(fname, "rb");
  if (!file) return 0;

  int k = fread(hash_table, sizeof(*hash_table), 1, file);
  fclose(file);
}



void get_password(const char* login, struct string_32b_t* password) {
  struct hash_table_k1b_t hash_table = { {}, {}, 256 };

  load_hash_table(&hash_table, HASH_TABLE_FILE_NAME);

  uint8_t l_hash = login_hash(login);
  if (hash_table.is_founds[l_hash]) {
    *password = hash_table.passwords[l_hash];
    return;
  }

  struct string_32b_t string = { "" };
  while (next_string_rec(&string, strlen(string.data))) {
    uint8_t hash = password_hash(string.data);
    if (!hash_table.is_founds[hash]) {
      hash_table.is_founds[hash] = 1;
      hash_table.passwords[hash] = string;
      hash_table.score--;
      save_hash_table(&hash_table, HASH_TABLE_FILE_NAME);
      // printf("password: %x   %s   %d \n", password_hash(string.data), string.data, hash_table.score);

      if (hash == l_hash) {
        *password = hash_table.passwords[l_hash];
        return;
      }
    }
    if (!hash_table.score) {
      break;
    }
  }

  fprintf(stderr, "get_password: ERROR: hash not found");
}



int main(int argc, char **argv) {

  if (argc == 3 && *argv[1] == 'l') {
    const char* login = argv[2];
    struct string_32b_t password;
    get_password(login, &password);
    printf("login:    %x   %s \n", login_hash(login), login);
    printf("password: %x   %s \n", password_hash(password.data), password.data);

  } else if (argc == 4 && *argv[1] == 'h') {
    // test
    const char* login    = argv[2];
    const char* password = argv[3];
    printf("login:    %x   %s \n", login_hash(login), login);
    printf("password: %x   %s \n", password_hash(password), password);
  } else {
    printf("usage: \n");
    printf("       %s l <login> \n", argv[0]);
    printf("       %s h <login> <password> \n", argv[0]);
  }

  return 0;
}

