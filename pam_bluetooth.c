#include <security/_pam_types.h>
#include <stdio.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>

#define SIZE_BUFF 2048
#define CONF_PATH "/etc/security/authorized_bluetooth.conf"

int parser(char ***addrs){
    // Parse the MAC Addresses
    if (access(CONF_PATH, F_OK) != 0)
        return -1;

    char buff[SIZE_BUFF] = {0};
    int fd = open(CONF_PATH, O_RDONLY);
    char c;
    int i = 0;
    // Store all the file in the buffer
    while (read(fd, &buff[i], sizeof(char))>0 && i<SIZE_BUFF)
        i++;

    // A Mac address is FF:FF:FF:FF:FF:FF\n so 18 characters long
    int nbmacaddrs = i/18+1;
    (*addrs) = (char**)malloc(nbmacaddrs*sizeof(char));
    for (i = 0; i < nbmacaddrs; i++){
        (*addrs)[i] = (char*)malloc(18*sizeof(char));
        for (int j = 0; j < 18; j++){
            (*addrs)[i][j] = buff[i*18+j];
        }
        (*addrs)[i][17] = '\0';
    }

    return nbmacaddrs;
}

PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	printf("Acct mgmt\n");
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ){
    int pipefd[2];
    char **addrs;
    int nbmacaddrs = parser(&addrs);

    if (nbmacaddrs <= 0){
        // If no mac addresses have been recognized
        // return the function
        return PAM_IGNORE;
    }

    int cpid;
    char buff[SIZE_BUFF];
    short endOfPipe = false;
    int cursor;

    for (int i = 0; i < nbmacaddrs; i++){
        // Ensure the MAC Address is correct
        if (addrs[i][2] != ':' ||
            addrs[i][5] != ':' ||
            addrs[i][8] != ':' ||
            addrs[i][11] != ':' ||
            addrs[i][14] != ':'){continue;}


        // Create a pipe
        if (pipe(pipefd) < 0){
            perror("Error creating pipe");
            exit(EXIT_FAILURE);
        }

        cpid = fork(); // Command pid

        if (cpid < 0){
            perror("Error creating child");
            exit(EXIT_FAILURE);
        }
        else if (cpid == 0) { // Child algorithm
            dup2(pipefd[1], STDOUT_FILENO);
            close(pipefd[1]); 
            close(pipefd[0]); 

            // Command
            execl("/bin/bluetoothctl", "bluetoothctl", "info", addrs[i], NULL);

            perror("execl");
            exit(EXIT_FAILURE);
        }

        // Parent algorithm
        close(pipefd[1]); 
        cursor = 0;
        endOfPipe = false;
        while (read(pipefd[0], &buff[cursor], sizeof(char)) >=0 
                && !endOfPipe 
                && cursor<SIZE_BUFF){

            cursor++;
            endOfPipe = (strncmp(&buff[cursor-13], "Connected: ",11) == 0);
        }

        wait(NULL);
        if (!endOfPipe){return PAM_IGNORE;}
        else if (buff[cursor-2] == 'y' &&
            buff[cursor-1] == 'e' &&
            buff[cursor] == 's'){
            return PAM_SUCCESS;
        }
    }
    return PAM_IGNORE;
}
