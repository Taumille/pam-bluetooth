#include <security/_pam_types.h>
#include <stdio.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <stdbool.h>

#define SIZE_BUFF 2048
#define MAC_ADDRESS "37:91:84:52:98:26"

PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	printf("Acct mgmt\n");
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ){
    int pipefd[2];
    char buff[SIZE_BUFF];
    
    // Create a pipe
    if (pipe(pipefd) < 0){
        perror("Error creating pipe");
        exit(EXIT_FAILURE);
    }
    int cpid = fork(); // Command pid

    if (cpid < 0){
        perror("Error creating child");
        exit(EXIT_FAILURE);
    }
    else if (cpid == 0) { // Child algorithm
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]); 
        close(pipefd[0]); 

        // Command
        execl("/bin/bluetoothctl", "bluetoothctl", "info", MAC_ADDRESS, NULL);

        perror("execl");
        exit(EXIT_FAILURE);
    }
    
    // Parent algorithm
    close(pipefd[1]); 
    int i = 0;
    short endOfPipe = false;
    while (read(pipefd[0], &buff[i], sizeof(char)) >=0 
            && !endOfPipe 
            && i<SIZE_BUFF){

        i++;
        endOfPipe = (strncmp(&buff[i-13], "Connected: ",11) == 0);
    }

    wait(NULL);
    if (!endOfPipe){return PAM_IGNORE;}
    else if (buff[i-2] == 'y' &&
        buff[i-1] == 'e' &&
        buff[i] == 's'){
        return PAM_SUCCESS;
    }

    return PAM_IGNORE;
}
