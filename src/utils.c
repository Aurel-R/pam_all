#include <stdlib.h> 
#include <stdio.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/stat.h> 
#include <fcntl.h> 
#include <unistd.h> 
#include <syslog.h> 
#include <stdarg.h> 
#include <errno.h>

#include "config.h"

/*
 * Parse all arguments. If debug option is found 
 * in configuration file, set the verbose mode 
 */
int
_pam_parse(int argc, const char **argv)
{
        int i, ctrl = 0;

        for (i=0; i<argc; i++) {
                if (!strcmp(argv[i], "debug"))
                        ctrl |= PAM_DEBUG_ARG;
        }

        return ctrl;
}


void
log_message(int level, char *msg, ...)
{
        va_list args;

        va_start(args, msg);
        openlog(NAME, LOG_PID, LOG_AUTHPRIV);

        if (level)
                vsyslog(level, msg, args);

        closelog();
        va_end(args);
}

/* specific to the passwd structure */
void
cleanup(void **data)
{
/* ! @Todo : rewrite */
        char *xx;

        if ((xx = (char *)data)) {
                while(*xx)
                        *xx++ = '\0';
                free(*data);
        }
}

int 
passwd_callback(char *pcszBuff, int size, int rwflag, void *pPass) 
{ 
        size_t onPass = strlen((char*)pPass); 
 
        if (onPass > (size_t)size) 
                onPass = (size_t)size; 
     
        memcpy(pcszBuff, pPass, onPass); 
     
        return (int)onPass; 
} 


char 
*format_command_line(const char **command_line) 
{ 
        size_t length = 0, i=0; 
        char *formated_command = NULL;   
                 
        do { 
                length += strlen(command_line[i]) + 1; /* +1 for sapce and \'0' ending */ 
                i++; 
        } while (command_line[i] != NULL); 
 
        formated_command = calloc(length, sizeof(char)); 
        if (formated_command == NULL) 
                return NULL; 
 
        length = 0; 
        i = 0; 
 
        do { 
                strncpy(formated_command+length, command_line[i], strlen(command_line[i])); 
                length += strlen(command_line[i]) + 1; 
                formated_command[length-1] = ' '; 
                i++; 
        } while (command_line[i] != NULL); 
 
        formated_command[length] = '\0'; 
                 
        return formated_command; 
}


char 
*is_a_symlink(char *file) 
{ 
        char *link, *tmp_link; 
        int ret; 
        struct stat sb; 
 
        if (lstat(file, &sb) == -1)  
                return NULL; 
         
        link = malloc(sb.st_size + 1); 
         
        if (link == NULL) {  
                log_message(LOG_ERR, "(ERROR) %m"); 
                fprintf(stderr, "malloc: %m"); 
                return NULL;     
        } 
 
        ret = readlink(file, link, sb.st_size + 1); 
 
        if (ret < 0)  
                return NULL; 
 
        if (ret > sb.st_size) { 
                fprintf(stderr, "symlink increased in size between lstat() and readlink()\n"); 
                return NULL; 
        } 
 
        link[sb.st_size] = '\0'; 
 
        log_message(LOG_INFO, "(TT) '%s' points to '%s'", file, link);   
 
        if ((tmp_link = is_a_symlink(link)) == NULL) 
		return link; 
 
        return tmp_link; 
}

unsigned char 
*alea(size_t len, unsigned char *table) 
{ 
        FILE *fd; 
        int i = 0; 
        unsigned char carac, *random_buffer = NULL;      
        random_buffer = calloc(len + 1, sizeof(unsigned char)); 
 
        if (random_buffer == NULL) 
                return NULL; 
         
        if ((fd = fopen(RANDOM_FILE, "r")) == NULL) 
                return NULL; 
 
        if (table != NULL) { 
                do  {    
                        fread(&carac, sizeof(unsigned char), 1, fd); 
                        if ((strchr((const char *)table, carac)) != NULL) { 
                                if (carac == 0) 
                                        carac = (unsigned char)48; 
                                random_buffer[i] = carac; 
                                i++; 
                        } 
                } while (i != len);              
        }  
 
        else fread(random_buffer, sizeof(unsigned char), len, fd); 
                 
        fclose(fd); 
        return random_buffer; 
} 
 


