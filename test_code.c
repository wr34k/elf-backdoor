#include <stdio.h>
#include <stdlib.h>


char* func() {
    return "yo";
}

int main(int argc, char** argv) {


    puts("This is some normal stuff hier..\n");

    printf("Prog is %s\n", argv[0]);

    int j =2;
    for (int i=0;i<1000;i++) {
        j++;
    }


    char *lol;

    lol = malloc(sizeof(char)*2);

    lol = func();

    printf("%s\n", lol);


    return 0;
}

