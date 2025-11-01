#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define MAX_LINE_LENGTH 1024 // Maximum length for a line in the file

int removeStringFromFile(char* stringa) {
    FILE *file;
    char line[MAX_LINE_LENGTH];
    char filename[] = "/tmp/wish.sh";
    int found = 0;
    // Open the original file for reading
    file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening original file");
        return 0 ;
    }
     while (fgets(line, sizeof(line), file) != NULL) {
        if (strstr(line, stringa) != NULL) {
            found = 1;
            break; // String found, no need to read further
        }
    }

    if (found) {
       return 0;
    }


    fclose(file); // Close the file
      return 1;
}

int main() {
    setuid(geteuid());
    printf("Your wish is my command... maybe :)\n");
    const char *targetFile = "/tmp/wish.sh";
    char *removeThis[] = {"bash", "sh", "flag", "txt"};
    for(int i = 0; i<4; i++){
        if(!removeStringFromFile(removeThis[1])){
            printf("Bad String in File.\n");
            return 0;
        }
    }
    system("chmod +x /tmp/wish.sh && /tmp/wish.sh");

    return 0;
}$
