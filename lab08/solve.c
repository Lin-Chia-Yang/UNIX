#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

int main(int argc, char *argv[]) {
	pid_t child;
	if(argc < 2) {
		fprintf(stderr, "usage: %s program\n", argv[0]);
		return -1;
	}
	if((child = fork()) < 0) errquit("fork");
	if(child == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace");
		execvp(argv[1], argv+1);
		errquit("execvp");
	} else {
		int status;
        long long counter = 0LL;
        long long old_rip;
        void* magic_address;
        long data;
        short data2;
        int i = 0;
        int ret_value;
        struct user_regs_struct regs;
		if(waitpid(child, &status, 0) < 0) errquit("waitpid");
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        while(WIFSTOPPED(status)){
            counter++;
            if(counter == 3){
                ptrace(PTRACE_GETREGS, child, 0, &regs);
                magic_address = (void*)(regs.rax);
            }    
            if(counter == 4){
                ptrace(PTRACE_GETREGS, child, 0, &regs);
                old_rip = regs.rip;
            }
            if(counter == 6){
                ptrace(PTRACE_GETREGS, child, 0, &regs);
                if(regs.rax != 0){
                    ptrace(PTRACE_GETREGS, child, 0, &regs);
                    regs.rip = old_rip;
                    ptrace(PTRACE_SETREGS, child, 0, &regs);
                }
                if(i <= 511){
                    data = 0x3030303030303030;
                    ptrace(PTRACE_POKEDATA, child, magic_address, data);
                    data2 = 0x3030;
                    ptrace(PTRACE_POKEDATA, child, magic_address+8, data2);
                    counter-=2;
                }
                data = ptrace(PTRACE_PEEKDATA, child, magic_address, 0);
                // printf("\nData at address %p: %lx\n", magic_address, data);
                data2 = ptrace(PTRACE_PEEKDATA, child, magic_address+8, 0);
                // printf("\nData2 at address %p: %x\n", magic_address+8, data2);
                // printf("%d", i);
                if(i & 256) data2 = data2 | 0x0001;
                if(i & 128) data = data | 0x0100000000000000;
                if(i & 64) data = data | 0x0001000000000000;
                if(i & 32) data = data | 0x0000010000000000;
                if(i & 16) data = data | 0x0000000100000000;
                if(i & 8) data = data | 0x0000000001000000;
                if(i & 4) data = data | 0x0000000000010000;
                if(i & 2) data = data | 0x0000000000000100;
                if(i & 1) data = data | 0x0000000000000001;
                ptrace(PTRACE_POKEDATA, child, magic_address, data);
                ptrace(PTRACE_POKEDATA, child, magic_address+8, data2);
                i += 1;
            }
            ptrace(PTRACE_CONT, child, 0, 0);
            waitpid(child, &status, 0);
        }
	}
	return 0;
}
