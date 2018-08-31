#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char* func() {
    volatile int j =2;
    for (int i=0;i<1000;i++) {
        j++;
    }

    return "yo";
}

int main(int argc, char** argv) {


    puts("This is some normal stuff hier..\n");

    printf("Prog is %s\n", argv[0]);

    char *lol;


    if (argc > 1)
        if (strcmp(argv[1], "lol") == 0) {
            lol = malloc(sizeof(char)*2);
            lol = func();
            printf("%s\n", lol);
        }



    return 0;
}

