#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <capstone/capstone.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

int main(int argc, char* argv[]){
    pid_t child;
    if(argc < 2){
        fprintf(stderr, "failed to execute.\n");
        return -1;
    }
    child = fork();
    if(child < 0){
        errquit("fork");
    }

    if(child == 0){
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0){
            errquit("ptrace");
        }
        execvp(argv[1], argv+1);
        errquit("execvp");
    }
    else{
        FILE *fp;
        Elf64_Ehdr eh;
        size_t num_elf_header;
        size_t num_section_header;
        int counter = 0;
        size_t count;
        fp = fopen(argv[1], "rb");
        if(fp == NULL){
            fprintf(stderr, "failed to open the file.\n");
        }
        num_elf_header = fread(&eh, sizeof(Elf64_Ehdr), 1, fp);
        if(num_elf_header < 0){
            fprintf(stderr, "failed to read the file.\n");
        }
        fseek(fp, eh.e_shoff, SEEK_SET);
        Elf64_Shdr *sh = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr) * eh.e_shnum);
        num_section_header = fread(sh, sizeof(Elf64_Shdr), eh.e_shnum, fp);
        Elf64_Shdr text_section;
        for(int i=0; i<num_section_header; i++){
            if(sh[i].sh_type == SHT_PROGBITS && sh[i].sh_flags  == (SHF_ALLOC | SHF_EXECINSTR)){
                text_section = sh[i];
                break;
            }
        }
        fseek(fp, text_section.sh_offset, SEEK_SET);
        char buffer[1024];
        size_t text_size = text_section.sh_size;
        fread(buffer, 1, text_size, fp);
        fclose(fp);
        csh handle;
        cs_insn *insn;
        if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK){
            errquit("cs_open failed");
        }
        printf("** program '%s' loaded. entry point 0x%lx\n", argv[1], eh.e_entry);
        count = cs_disasm(handle, buffer, text_size, text_section.sh_addr, 0, &insn);
        if(count > 0){
            for(int i=0; i<count; i++){
                if(insn[i].address == eh.e_entry){
                    int n = i;
                    for(int i=n; i<n+5; i++){
                        printf("\t0x%" PRIx64 ": ", insn[i].address);
                        for(int j=0; j<insn[i].size; j++){
                            printf("%02x ", insn[i].bytes[j]);
                        }
                        for(int j=0; j<5-insn[i].size; j++){
                            printf("   ");
                        }
                        printf("\t%s\t%s\n", insn[i].mnemonic, insn[i].op_str);
                    }
                    printf("(sdb) ");
                    break;
                }
            }
        }
        else{
            printf("ERROR: Failed to disassemble given code!\n");
        }
        cs_close(&handle);
        struct block_info{
            long min;
            long max;
        }block[30];
        long block_size = 0;
        int fd, sz;
        char buf[16384], *s = buf, *line, *saveptr;
        char filename[30];
        sprintf(filename, "/proc/%d/maps", child);
        if((fd = open(filename, O_RDONLY)) < 0) exit(-1);
        if((sz = read(fd, buf, sizeof(buf)-1)) < 0) exit(-1);
        buf[sz] = 0;
        close(fd);
        int num_block = 0;
        while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) {
            s = NULL;
            if(strstr(line, " rw") != NULL){
                // printf("%s\n", line);
                static char* token;
                token = strtok(line, " ");
                token = strtok(token, "-");
                block[num_block].min = strtol(token, NULL, 16);
                token = strtok(NULL, "-");
                block[num_block].max = strtol(token, NULL, 16);
                block_size += block[num_block].max - block[num_block].min;
                num_block++;
            }
        }
        int status;
        char command[20];
        struct breakpoint{
            long long address;
            unsigned long code;
            struct user_regs_struct regs;
        }bp[10];
        int num_bp = 0;
        if(waitpid(child, &status, 0) < 0){
            errquit("waitpid");
        }
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        int hit = 0;
        int restore_bp = 0;
        long anchor_code[block_size/8];
        struct user_regs_struct anchor_regs;
        while(1){
            scanf("%s", command);
            if(strcmp(command, "si") == 0){
                counter++;
                if(counter >= count){
                    printf("** the target program terminated.\n");
                    break;
                }
                if(hit == 1){
                    if(ptrace(PTRACE_POKETEXT, child, bp[restore_bp].address, 
                        (bp[restore_bp].code & 0xffffffffffffff00) | 0xcc) != 0){
                        errquit("poketext");
                    }
                }
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, child, NULL, &regs);
                long long target = regs.rip;
                hit = 0;
                for(int i=0; i<num_bp; i++){
                    if(target == bp[i].address){
                        unsigned long code = ptrace(PTRACE_PEEKTEXT, child, bp[i].address, 0);
                        if(ptrace(PTRACE_POKETEXT, child, bp[i].address, 
                            (code & 0xffffffffffffff00) | (bp[i].code & 0xff)) != 0){
                            errquit("poketext");
                        }
                        break;
                    }
                }
                if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0){
                    errquit("ptrace");
                }
                if(waitpid(child, &status, 0) < 0){
                    errquit("wait");
                }
                ptrace(PTRACE_GETREGS, child, NULL, &regs);
                target = regs.rip;
                for(int i=0; i<num_bp; i++){
                    if(target == bp[i].address){
                        unsigned long code = ptrace(PTRACE_PEEKTEXT, child, bp[i].address, 0);
                        printf("** hit a breakpoint at 0x%llx\n", regs.rip);
                        hit = 1;
                        restore_bp = i;
                        if(ptrace(PTRACE_POKETEXT, child, bp[i].address,
                            (code & 0xffffffffffffff00) | (bp[i].code & 0xff)) != 0){
                            errquit("poketext");
                        }
                        break;
                    }
                }
                for(int i=0; i<count; i++){
                    if(target == insn[i].address){
                        counter = i;
                        break;
                    }
                }
                for(int i=counter; i<counter+5; i++){
                    if(i >= count){
                        printf("** the address is out of the range of the text segment.\n");
                        break;
                    }
                    printf("\t0x%" PRIx64 ": ", insn[i].address);
                    for(int j=0; j<insn[i].size; j++){
                        printf("%02x ", insn[i].bytes[j]);
                    }
                    for(int j=0; j<5-insn[i].size; j++){
                        printf("   ");
                    }
                    printf("\t%s\t%s\n", insn[i].mnemonic, insn[i].op_str);
                }
                printf("(sdb) ");
            }
            else if(strcmp(command, "cont") == 0){
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, child, NULL, &regs);
                long long target = regs.rip;
                unsigned long code;
                int check_cont_bp = 0;
                for(int i=0; i<num_bp; i++){
                    if(target == bp[i].address){
                        code = ptrace(PTRACE_PEEKTEXT, child, bp[i].address, 0);
                        if(ptrace(PTRACE_POKETEXT, child, bp[i].address, 
                            ((code & 0xffffffffffffff00) | (bp[i].code & 0xff))
                            ) != 0){
                            errquit("poketext");
                        }
                        code = ptrace(PTRACE_PEEKTEXT, child, bp[i].address, 0);
                        if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0){
                            errquit("ptrace");
                        }
                        if(waitpid(child, &status, 0) < 0){
                            errquit("wait");
                        }
                        if(ptrace(PTRACE_POKETEXT, child, bp[i].address, 
                            (bp[i].code & 0xffffffffffffff00) | 0xcc) != 0){
                            errquit("poketext");
                        }
                        ptrace(PTRACE_GETREGS, child, NULL, &regs);
                        target = regs.rip;
                        for(int j=0; j<num_bp; j++){
                            if(target == bp[j].address){
                                printf("** hit a breakpoint at 0x%llx\n", bp[j].address);
                                check_cont_bp = 1;
                                for(int k=0; k<count; k++){
                                    if(target == insn[k].address){
                                        counter = k;
                                        break;
                                    }
                                }
                                for(int k=counter; k<counter+5; k++){
                                    if(k >= count){
                                        printf("** the address is out of the range of the text segment.\n");
                                        break;
                                    }
                                    printf("\t0x%" PRIx64 ": ", insn[k].address);
                                    for(int l=0; l<insn[k].size; l++){
                                        printf("%02x ", insn[k].bytes[l]);
                                    }
                                    for(int l=0; l<5-insn[k].size; l++){
                                        printf("   ");
                                    }
                                    printf("\t%s\t%s\n", insn[k].mnemonic, insn[k].op_str);
                                }
                                printf("(sdb) ");
                                break;
                            }
                        }
                        break;
                    }
                }
                if(check_cont_bp == 1){
                    continue;
                }
                if(ptrace(PTRACE_CONT, child, 0, 0) < 0){
                errquit("ptrace");
                }
                if(waitpid(child, &status, 0) < 0){
                    errquit("wait");
                }
                if(WIFEXITED(status)){
                    printf("** the target program terminated.\n");
                    break;
                }

                ptrace(PTRACE_GETREGS, child, NULL, &regs);
                target = regs.rip;
                hit = 0;
                for(int i=0; i<num_bp; i++){
                    if(target-1 == bp[i].address){
                        restore_bp = i;
                        hit = 1;
                        printf("** hit a breakpoint at 0x%llx\n", bp[i].address);
                        code = ptrace(PTRACE_PEEKTEXT, child, bp[i].address, 0);
                        if(ptrace(PTRACE_POKETEXT, child, bp[i].address, 
                            (code & 0xffffffffffffff00) | (bp[i].code & 0xff)) != 0){
                            errquit("poketext");
                        }
                        regs.rip = regs.rip - 1;
                        ptrace(PTRACE_SETREGS, child, NULL, &regs);
                        ptrace(PTRACE_GETREGS, child, NULL, &regs);
                        target = regs.rip;
                        for(int i=0; i<count; i++){
                            if(target == insn[i].address){
                                counter = i;
                                break;
                            }
                        }
                        for(int i=counter; i<counter+5; i++){
                            if(i >= count){
                                printf("** the address is out of the range of the text segment.\n");
                                break;
                            }
                            printf("\t0x%" PRIx64 ": ", insn[i].address);
                            for(int j=0; j<insn[i].size; j++){
                                printf("%02x ", insn[i].bytes[j]);
                            }
                            for(int j=0; j<5-insn[i].size; j++){
                                printf("   ");
                            }
                            printf("\t%s\t%s\n", insn[i].mnemonic, insn[i].op_str);
                        }
                        printf("(sdb) ");
                        break;
                    }
                }
                if(hit == 0){
                    ptrace(PTRACE_GETREGS, child, NULL, &regs);
                    target = regs.rip;
                    printf("** the target program terminated.\n");
                    break;
                }
            }
            else if(strcmp(command, "break") == 0){
                char address[20];
                scanf("%s", address);
                long addr = (int)strtol(address, NULL, 16);
                printf("** set a breakpoint at 0x%lx.\n", addr);
                unsigned long code = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
                bp[num_bp].address = addr;
                bp[num_bp].code = code;
                num_bp++;
                if(ptrace(PTRACE_POKETEXT, child, addr, 
                    (code & 0xffffffffffffff00) | 0xcc) != 0){
                    errquit("poketext");
                }
                printf("(sdb) ");
            }
            else if(strcmp(command, "anchor") == 0){
                ptrace(PTRACE_GETREGS, child, NULL, &anchor_regs);
                int index = 0;
                for(int i=0; i<num_block; i++){
                    for(long j=block[i].min; j<block[i].max; j+=8){
                        anchor_code[index] = ptrace(PTRACE_PEEKTEXT, child, j, 0);
                        index++;
                    }
                }
                printf("** dropped an anchor\n");
                printf("(sdb) ");
            }
            else if(strcmp(command, "timetravel") == 0){
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, child, NULL, &regs);
                long long target = regs.rip;
                unsigned long code;
                ptrace(PTRACE_SETREGS, child, NULL, &anchor_regs);
                int index = 0;
                for(int i=0; i<num_block; i++){
                    for(long j=block[i].min; j<block[i].max; j+=8){
                        if(ptrace(PTRACE_POKETEXT, child, j, anchor_code[index]) < 0){
                            errquit("poketext");
                        }
                        index++;
                    }
                }
                printf("** go back to the anchor point\n");
                ptrace(PTRACE_GETREGS, child, NULL, &anchor_regs);
                target = anchor_regs.rip;
                for(int i=0; i<count; i++){
                    if(target == insn[i].address){
                        counter = i;
                        break;
                    }
                }
                for(int i=counter; i<counter+5; i++){
                    if(i >= count){
                        printf("** the address is out of the range of the text segment.\n");
                        break;
                    }
                    printf("\t0x%" PRIx64 ": ", insn[i].address);
                    for(int j=0; j<insn[i].size; j++){
                        printf("%02x ", insn[i].bytes[j]);
                    }
                    for(int j=0; j<5-insn[i].size; j++){
                        printf("   ");
                    }
                    printf("\t%s\t%s\n", insn[i].mnemonic, insn[i].op_str);
                }
                printf("(sdb) ");
            }

            for(int i=0; i<num_bp; i++){
                unsigned long code = ptrace(PTRACE_PEEKTEXT, child, bp[i].address, 0);
                if(ptrace(PTRACE_POKETEXT, child, bp[i].address, 
                        (bp[i].code & 0xffffffffffffff00) | 0xcc) != 0){
                        errquit("poketext");
                    }
            }
        }
        cs_free(insn, count);
    }
    return 0;
}