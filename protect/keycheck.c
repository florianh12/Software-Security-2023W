#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//returns -1 as error_code
int calc_fibonacci(int nth_fib_num) {

    if (nth_fib_num < 1)
        return -1;

    int fib_num = 1;
    int first = 0;
    int second = 1;

    for(int i = 1; i < nth_fib_num; i++) {

        fib_num = first + second;
        first = second;
        second = fib_num;
    }

    return fib_num;
}

int mult_chars(char username_char, char secret_key_char) {
    return ((int)username_char) * ((int)secret_key_char);
}

char* generate_license_key(char* username, size_t username_len) {
    char key_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    char secret_key[] = "b19dbbc8a7c7571f18155d9020901635297d10f8";
    int key_length = 10;
    
    char* license_key = (char*)malloc(key_length + 1);
    

    for (int i = 0; i < key_length; i++) {
        
        int username_char_pos = calc_fibonacci(i+2);
        int secret_key_char_pos = calc_fibonacci(i+3);
        char username_char = username[username_char_pos % username_len];
        
        char secret_key_char = secret_key[secret_key_char_pos % (int)strlen(secret_key)];


        license_key[i] =  key_alphabet[mult_chars(username_char,secret_key_char) % strlen(key_alphabet)];
        
    }

    license_key[key_length] = '\0';

    return license_key;

}


int main(int argc, char *argv[]) {
    // Check the number of command-line arguments
    if (argc != 3) {
        printf("Required Arguments: Username, License-Key\n");
        return -1;
    }


    //Different errors should be treated differently with different errorcodes -> different return values
    if (strlen(argv[1]) < 3) {
        printf("Username needs to be at least 3 Characters long!\n");
        return -2;
    }

    if (strlen(argv[2]) != 10) {
        printf("License-key needs to be 10 Characters long!\n");
        return -3;
    }

    char* calculated_license_key = generate_license_key(argv[1],strlen(argv[1]));

    if (strcmp(calculated_license_key, argv[2]) == 0) {
        printf("Username and License-key match!\n");
        free(calculated_license_key);
        return 0;
    } else {
        printf("License key doesn't match username!\n");
        printf("Generated License Key: %s\n", calculated_license_key);
        free(calculated_license_key);
        return -4;
    }
}
