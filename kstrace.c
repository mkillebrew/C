/*
 * gcc -lproc -o kstrace kstrace.c
 */

#include <proc/readproc.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>


int main(){
	proc_t process_info;

	get_proc_stats(getppid(), &process_info);
	if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
		kill(process_info.ppid, SIGKILL);
	} else {
		printf("hello.\n");
	}

	return 0;
}

