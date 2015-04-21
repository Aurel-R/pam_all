#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <linux/limits.h>
#include <sudo_plugin.h>

#define NAME	"shared.so"
#define FIFO_PATH	"/var/lib/shamir/"
#define __dso_public __attribute__((__visibility__("default")))

char **command;

static void
log_message(int level, const char *msg, ...)
{
	va_list args;
	
	va_start(args, msg);
	openlog(NAME, LOG_PID, LOG_AUTHPRIV);
	
	if(level)
		vsyslog(level, msg, args);
	
	closelog();
	va_end(args);
}


static int
io_open(unsigned int version, sudo_conv_t conversation,
	sudo_printf_t sudo_printf, char *const settings[],
	char *const user_info[], char *const command_info[],
	int argc, char *const argv[], char *const user_env[],
	 char *const args[])
{
	log_message(LOG_INFO, "io_open");
	int i;
	
	command = malloc((argc+1)*sizeof(char *));

	if (command == NULL) {
		log_message(LOG_ERR, "malloc error: %m");
		return false;
	}	

	for (i=0; i<argc; i++)
		command[i] = argv[i];		
		
	command[argc] = NULL;
	
     	return true;
 }
 
static void
io_close(int exit_status, int error)
{
	log_message(LOG_INFO, "io_close");
	//rm fic
}
 

__dso_public struct io_plugin shared_io = {
	SUDO_IO_PLUGIN,
    	SUDO_API_VERSION,
    	io_open,
    	io_close,
};

