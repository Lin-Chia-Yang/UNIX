#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
void listfile(char *path, char* magic);
int main(int argc, char *argv[]) {
    char path[100];
    char magic[100];
    strcpy(path, argv[1]);
    strcpy(magic, argv[2]);
    listfile(path, magic);
    return 0;
}

void listfile(char *basepath, char *magic){
    char path[1000];
    struct dirent *dp;
    DIR *dir = opendir(basepath);

    // Unable to open directory stream
    if (!dir)
        return;

    while ((dp = readdir(dir)) != NULL)
    {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0)
        {
            // fprintf(stderr, "%s\n", dp->d_name);
            // Construct new path from our base path
            strcpy(path, basepath);
            strcat(path, "/");
            strcat(path, dp->d_name);
            if(dp->d_type==4){
                listfile(path, magic);
            }
            else{
                FILE *fp;
                char buffer[1024];
                fp = fopen(path, "r");
                fread(buffer, sizeof(char), 1024, fp);
                char *ret;
                ret = strstr(buffer, magic);
                if(ret != NULL){
                    fprintf(stderr, "%s \t %s\n", magic, path);
                    fprintf(stdout, "%s\n", path);
                    exit(0);
                }
            }
        }
    }
    closedir(dir);
}
