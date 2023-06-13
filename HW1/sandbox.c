#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <elf.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

int (*sandbox__libc_start_main)(int *(main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end));
int (*libc_open)(const char *, int, ...);
ssize_t (*libc_read)(int, void *, size_t);
ssize_t (*libc_write)(int, const void *, size_t);
int (*libc_getaddrinfo)(const char *restrict, const char *restrict, const struct addrinfo *restrict, struct addrinfo **restrict);
int (*libc_connect)(int, const struct sockaddr *, socklen_t);
int (*libc_system)(const char*);

char* sandbox_config;
char* logger_fd;

char save_word[4000000];
char node_name[1024];

char open_list[20][100];
char read_list[20][100];
char write_list[20][100];
char connect_list[20][100];
char getaddrinfo_list[20][100];
char system_list[20][100];
int open_count, read_count, write_count, connect_count, getaddrinfo_count, system_count = 0;
int errno;

int sandbox_open(const char *pathname, int flags, ...){
    va_list args;
    va_start(args, flags);
    mode_t arg1 = va_arg(args, mode_t);
    va_end(args);
    int ret;
    logger_fd = getenv("LOGGER_FD");
    int log_fd = atoi(logger_fd);
    char real_path[1024];
    char list_real_path[1024];
    realpath(pathname, real_path);
    for(int i=0;i<open_count;i++){
        realpath(open_list[i], list_real_path);
        if(strcmp(real_path, list_real_path) == 0){
            errno = EACCES;
            if(arg1 & 0777 == 0){
                dprintf(log_fd, "[logger] open(\"%s\", %d) = -1\n", real_path, flags);
            }
            else{
                dprintf(log_fd, "[logger] open(\"%s\", %d, %d) = -1\n", real_path, flags, arg1 & 0777);
            }
            return -1;
        }
    }
    if(arg1 & 0777 == 0){
        ret = libc_open(pathname, flags);
        dprintf(log_fd, "[logger] open(\"%s\", %d) = %d\n", real_path, flags, ret);
    }
    else{
        ret = libc_open(pathname, flags, arg1);
        dprintf(log_fd, "[logger] open(\"%s\", %d, %d) = %d\n", real_path, flags, arg1 & 0777, ret);
    }
    return ret;
}

ssize_t sandbox_read(int fd, void *buf, size_t count){
    pid_t pid = getpid();
    logger_fd = getenv("LOGGER_FD");
    int log_fd = atoi(logger_fd);
    char filename[30];
    sprintf(filename, "%d-%d-read.log", pid, log_fd);
    FILE *fp;
    fp = fopen(filename, "a");
    int ret;
    ret = libc_read(fd, buf, count);
    strcat(save_word, buf);
    for(int i=0; i<read_count; i++){
        if(strstr(save_word, read_list[i]) != NULL){
            errno = EIO;
            dprintf(log_fd, "[logger] read(%d, %p, %ld) = -1\n", fd, buf, count);
            close(fd);
            return -1;
        }
    }
    size_t numwrite;
    numwrite = fwrite(buf, sizeof(char), strlen(buf), fp);
    fclose(fp);
    dprintf(log_fd, "[logger] read(%d, %p, %ld) = %d\n", fd, buf, count, ret);
    return ret;
}

ssize_t sandbox_write(int fd, const void *buf, size_t count){
    pid_t pid = getpid();
    logger_fd = getenv("LOGGER_FD");
    int log_fd = atoi(logger_fd);
    char filename[30];
    sprintf(filename, "%d-%d-write.log", pid, log_fd);
    FILE *fp;
    fp = fopen(filename, "a");
    int ret;
    ret = libc_write(fd, buf, count);
    size_t numwrite;
    numwrite = fwrite(buf, sizeof(char), strlen(buf), fp);
    fclose(fp);
    dprintf(log_fd, "[logger] write(%d, %p, %ld) = %d\n", fd, buf, count, ret);
    return ret;
}

int sandbox_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    logger_fd = getenv("LOGGER_FD");
    int log_fd = atoi(logger_fd);
    int ret;
    struct sockaddr_in *ip_port = (struct sockaddr_in *)addr;
    char ip[INET_ADDRSTRLEN];
    uint16_t port;
    inet_ntop (AF_INET, &ip_port->sin_addr, ip, sizeof (ip));
    port = htons (ip_port->sin_port);
    char host_name_port[2048];
    sprintf(host_name_port, "%s:%d", node_name, port);
    for(int i=0; i<connect_count; i++){
        if(strcmp(host_name_port, connect_list[i]) == 0){
            errno = ECONNREFUSED;
            dprintf(log_fd, "[logger] connect(%d, \"%s\", %d) = -1\n", sockfd, ip, addrlen);
            return -1;
        }
    }
    ret = libc_connect(sockfd, addr, addrlen);
    // printf("-------%ld\n", strlen(addr->sa_data));
    dprintf(log_fd, "[logger] connect(%d, \"%s\", %d) = %d\n", sockfd, ip, addrlen, ret);
}

int sandbox_getaddrinfo(const char *restrict node, const char *restrict service, const struct addrinfo *restrict hints, struct addrinfo **restrict res){
    logger_fd = getenv("LOGGER_FD");
    int log_fd = atoi(logger_fd);
    int ret;
    for(int i=0; i<getaddrinfo_count; i++){
        if(strcmp(node, getaddrinfo_list[i]) == 0){
            dprintf(log_fd, "[logger] getaddrinfo(\"%s\",\"%s\",%p,%p = %d)\n", node, service, hints, res, EAI_NONAME);
            return EAI_NONAME;
        }
    }
    ret = libc_getaddrinfo(node, service, hints, res);
    strcpy(node_name, node);
    dprintf(log_fd, "[logger] getaddrinfo(\"%s\",\"%s\",%p,%p = %d)\n", node, service, hints, res, ret);
    return ret;
}

int sandbox_system(const char *command){
    logger_fd = getenv("LOGGER_FD");
    int log_fd = atoi(logger_fd);
    int ret;
    dprintf(log_fd, "[logger] system(\"%s\")\n", command);
    
    ret = libc_system(command);
    if(ret == -1){
        return ret;
    }
}

int __libc_start_main(int *(main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)) {
    char exe[1024];
    int n;
    n = readlink("/proc/self/exe", exe, sizeof(exe));
    if(n > 0 && n < sizeof(exe)){
        // printf("%s\n", exe);
    }
	int fd, sz;
	char buf[16384], *s = buf, *line, *saveptr;
	if((fd = open("/proc/self/maps", O_RDONLY)) < 0) exit(-1);
	if((sz = read(fd, buf, sizeof(buf)-1)) < 0) exit(-1);
	buf[sz] = 0;
	close(fd);
    int count = 0;
    long int block[10];
	while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) {
        s = NULL;
		if(strstr(line, exe) != NULL){
            // printf("%s\n", line);
            static char* token;
            const char deli[]="-";
            token = strtok(line, deli);
            block[count] = strtol(token, NULL, 16);
            count++;
        }
    }
    mprotect((void*)(block[3]), block[4]-block[3], PROT_READ|PROT_WRITE);
    // printf("%lx, %lx\n", block[3], block[4]-block[3]);
    
    FILE *fp;
    size_t numheader;
    Elf64_Ehdr eh;
    fp = fopen(exe, "rb");
    if(fp == NULL){
        fprintf(stderr, "failed to open the file.\n");
    }
    numheader = fread(&eh, sizeof(Elf64_Ehdr), 1, fp);
    fseek(fp, eh.e_shoff, SEEK_SET);
    size_t numsheader;
    Elf64_Shdr *sh = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr) * eh.e_shnum);
    Elf64_Shdr dynsym;
    Elf64_Shdr strtab;
    Elf64_Shdr rela;
    numsheader = fread(sh, sizeof(Elf64_Shdr), eh.e_shnum, fp);
    int check = 1;
    for(int i=0; i<numsheader; i++){
        if(sh[i].sh_type == SHT_DYNSYM){
            // printf("SHT_DYNSYM: %d\n", i);
            dynsym = sh[i];
        }
        else if(sh[i].sh_type == SHT_STRTAB && check == 1){
            // printf("SHT_STRTAB: %d\n", i);
            strtab = sh[i];
            check = 0;
        }
        else if(sh[i].sh_type == SHT_RELA){
            // printf("SHT_RELA: %d\n", i);
            rela = sh[i];
        }
    }
    // printf("dynsym: %lu\n", dynsym.sh_size);
    // printf("strtab: %lu\n", strtab.sh_size);
    // printf("rela: %lu\n", rela.sh_size);
    fseek(fp, rela.sh_offset, SEEK_SET);
    size_t numrela;
    Elf64_Rela *re = (Elf64_Rela *)malloc(rela.sh_size);
    // printf("%lu\n", rela.sh_size/sizeof(Elf64_Rela));
    numrela = fread(re, sizeof(Elf64_Rela), rela.sh_size/sizeof(Elf64_Rela), fp);

    fseek(fp, dynsym.sh_offset, SEEK_SET);
    size_t numsym;
    Elf64_Sym *sym = (Elf64_Sym *)malloc(dynsym.sh_size);
    // printf("%lu\n", dynsym.sh_size/sizeof(Elf64_Sym));
    numsym = fread(sym, sizeof(Elf64_Sym), dynsym.sh_size/sizeof(Elf64_Sym), fp);

    fseek(fp, strtab.sh_offset, SEEK_SET);
    size_t numstr;
    char *str = (char *)malloc(strtab.sh_size);
    // printf("%lu\n", strtab.sh_size);
    numstr = fread(str, 1, strtab.sh_size, fp);

    fclose(fp);
    char* func_name[6];
    unsigned long int func_got[6];
    int func_count = 0;
    for(int i=0;i<numrela;i++){
        // printf("%ld\n", ELF64_R_TYPE(re[i].r_info));
        if(ELF64_R_TYPE(re[i].r_info) == 7){ // #define R_X86_64_JUMP_SLOT = 7
            Elf64_Sym _sym = sym[ELF64_R_SYM(re[i].r_info)];
            // char *_symname = &str[_sym.st_name];
            char *symname = &str[_sym.st_name];
            // printf("%s\n", symname);
            if(strcmp(symname, "open") == 0){
                // printf("%s: ", symname);
                // printf("%lx\n", re[i].r_offset);
                func_name[func_count] = "open";
                func_got[func_count] = re[i].r_offset;
                func_count++;
            }
            else if(strcmp(symname, "read") == 0){
                // printf("%s: ", symname);
                // printf("%lx\n", re[i].r_offset);
                func_name[func_count] = "read";
                func_got[func_count] = re[i].r_offset;
                func_count++;
            }
            else if(strcmp(symname, "write") == 0){
                // printf("%s: ", symname);
                // printf("%lx\n", re[i].r_offset);
                func_name[func_count] = "write";
                func_got[func_count] = re[i].r_offset;
                func_count++;
            }
            else if(strcmp(symname, "connect") == 0){
                // printf("%s: ", symname);
                // printf("%lx\n", re[i].r_offset);
                func_name[func_count] = "connect";
                func_got[func_count] = re[i].r_offset;
                func_count++;
            }
            else if(strcmp(symname, "getaddrinfo") == 0){
                // printf("%s: ", symname);
                // printf("%lx\n", re[i].r_offset);
                func_name[func_count] = "getaddrinfo";
                func_got[func_count] = re[i].r_offset;
                func_count++;
            }
            else if(strcmp(symname, "system") == 0){
                // printf("%s: ", symname);
                // printf("%lx\n", re[i].r_offset);
                func_name[func_count] = "system";
                func_got[func_count] = re[i].r_offset;
                func_count++;
            }
        }
    }
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    sandbox__libc_start_main = dlsym(handle, "__libc_start_main");
    libc_open = dlsym(handle, "open");
    libc_read = dlsym(handle, "read");
    libc_write = dlsym(handle, "write");
    libc_connect = dlsym(handle, "connect");
    libc_getaddrinfo = dlsym(handle, "getaddrinfo");
    libc_system = dlsym(handle, "system");
    for(int i=0; i<func_count; i++){
        if(strcmp(func_name[i], "open") == 0){
            long int *c = block[0] + func_got[i];
            *c = (void*)sandbox_open;
        }
        else if(strcmp(func_name[i], "read") == 0){
            long int *c = block[0] + func_got[i];
            *c = (void*)sandbox_read;
        }
        else if(strcmp(func_name[i], "write") == 0){
            long int *c = block[0] + func_got[i];
            *c = (void*)sandbox_write;
        }
        else if(strcmp(func_name[i], "connect") == 0){
            long int *c = block[0] + func_got[i];
            *c = (void*)sandbox_connect;
        }
        else if(strcmp(func_name[i], "getaddrinfo") == 0){
            long int *c = block[0] + func_got[i];
            *c = (void*)sandbox_getaddrinfo;
        }
        else if(strcmp(func_name[i], "system") == 0){
            long int *c = block[0] + func_got[i];
            *c = (void*)sandbox_system;
        }
    }


    sandbox_config = getenv("SANDBOX_CONFIG");
    logger_fd = getenv("LOGGER_FD");

    fp = fopen(sandbox_config, "r");
    if(fp == NULL){
        fprintf(stderr, "failed to open the file.\n");
    }
    char buffer[16384];
    int open_check, read_check, write_check, connect_check, getaddrinfo_check, system_check = 0;
    while(fgets(buffer, 1024, fp)){
        if(strcmp(buffer, "\n") == 0){
            continue;
        }

        if(strstr(buffer, "END open-blacklist") != NULL){
            open_check = 0;
            continue;
        }
        else if(strstr(buffer, "END read-blacklist") != NULL){
            read_check = 0;
            continue;
        }
        else if(strstr(buffer, "END write-blacklist") != NULL){
            write_check = 0;
            continue;
        }
        else if(strstr(buffer, "END connect-blacklist") != NULL){
            connect_check = 0;
            continue;
        }
        else if(strstr(buffer, "END getaddrinfo-blacklist") != NULL){
            getaddrinfo_check = 0;
            continue;
        }
        else if(strstr(buffer, "END system-blacklist") != NULL){
            system_check = 0;
            continue;
        }

        if(open_check == 1){
            strncpy(open_list[open_count], buffer, strlen(buffer)-1);
            // printf("Add open_list:%s\n", open_list[open_count]);
            open_count++;
        }
        else if(read_check == 1){
            strncpy(read_list[read_count], buffer, strlen(buffer)-1);
            // printf("Add read_list:%s\n", read_list[read_count]);
            read_count++;
        }
        else if(write_check == 1){
            strncpy(write_list[write_count], buffer, strlen(buffer)-1);
            // printf("Add write_list:%s\n", write_list[write_count]);
            write_count++;
        }
        else if(connect_check == 1){
            strncpy(connect_list[connect_count], buffer, strlen(buffer)-1);
            // printf("Add connect_list:%s\n", connect_list[connect_count]);
            connect_count++;
        }
        else if(getaddrinfo_check == 1){
            strncpy(getaddrinfo_list[getaddrinfo_count], buffer, strlen(buffer)-1);
            // printf("Add getaddrinfo_list:%s\n", getaddrinfo_list[getaddrinfo_count]);
            getaddrinfo_count++;
        }
        else if(system_check == 1){
            strncpy(system_list[system_count], buffer, strlen(buffer)-1);
            // printf("Add system_list:%s\n", system_list[system_count]);
            system_count++;
        }

        if(strstr(buffer, "BEGIN open-blacklist") != NULL){
            open_check = 1;
            continue;
        }
        else if(strstr(buffer, "BEGIN read-blacklist") != NULL){
            read_check = 1;
            continue;
        }
        else if(strstr(buffer, "BEGIN write-blacklist") != NULL){
            write_check = 1;
            continue;
        }
        else if(strstr(buffer, "BEGIN connect-blacklist") != NULL){
            connect_check = 1;
            continue;
        }
        else if(strstr(buffer, "BEGIN getaddrinfo-blacklist") != NULL){
            getaddrinfo_check = 1;
            continue;
        }
        else if(strstr(buffer, "BEGIN system-blacklist") != NULL){
            system_check = 1;
            continue;
        }

    }
    fclose(fp);
    return sandbox__libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}