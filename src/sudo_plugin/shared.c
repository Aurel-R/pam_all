#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <pwd.h>
#include <crypt.h>
#include <shadow.h>
#include <linux/limits.h>
#include <sudo_plugin.h>

#define NAME	"shared.so"
#define ignore_result(x)	(void)(x)
#define __dso_public __attribute__((__visibility__("default")))


static sudo_conv_t sudo_conv;
static sudo_printf_t sudo_log;
static FILE *input, *output;


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

	log_message(LOG_DEBUG, "debug: io_open");

/*
	int i;

	for(i=0; i<argc;  i++)
		sudo_printf(SUDO_CONV_INFO_MSG, "args arg[%d]: %s\n", i, argv[i]);
	

	for(i=0; *settings!=NULL; settings++, i++)
		sudo_printf(SUDO_CONV_INFO_MSG, "setting arg[%d]: %s\n", i, *settings);
	

	for(i=0; *user_info!=NULL; user_info++, i++)
		sudo_printf(SUDO_CONV_INFO_MSG, "user info[%d]: %s\n", i, *user_info);

	for(i=0; *command_info!=NULL; command_info++, i++)
		sudo_printf(SUDO_CONV_INFO_MSG, "command info[%d]: %s\n", i, *command_info);
*/
	int fd;
	char path[PATH_MAX];

	memset(path, '\0', sizeof(path));
 
  	if (!sudo_conv)
     		sudo_conv = conversation;
     	if (!sudo_log)
     		sudo_log = sudo_printf;
 
     	/* Open input and output files. */
   	snprintf(path, sizeof(path) - 1, "/var/tmp/sample-%u.output", (unsigned int)getpid());
     	fd = open(path, O_WRONLY|O_CREAT|O_EXCL, 0644);
     	if (fd == -1)
     		return false;
    
	output = fdopen(fd, "w");
 
     	snprintf(path, sizeof(path), "/var/tmp/sample-%u.input", (unsigned int)getpid());
     	fd = open(path, O_WRONLY|O_CREAT|O_EXCL, 0644);
     	if (fd == -1)
     		return false;
     	input = fdopen(fd, "w");
 
     	return true;
 }
 
static void
io_close(int exit_status, int error)
{
	log_message(LOG_DEBUG, "debug: io_close");
	fclose(input);
     	fclose(output);
}
 
static int
io_version(int verbose)
{
	sudo_log(SUDO_CONV_INFO_MSG, "Sample I/O plugin version %s\n", SUDO_IO_PLUGIN);
    	return true;
}
 
static int
io_log_input(const char *buf, unsigned int len)
{
	ignore_result(fwrite(buf, len, 1, input));
    	return true;
}
 
static int
io_log_output(const char *buf, unsigned int len)
{
	const char *cp, *ep;
    	bool rval = 1;
 
    	ignore_result(fwrite(buf, len, 1, output));
    	/*
    	* If we find the string "honk!" in the buffer, reject it.
     	* In practice we'd want to be able to detect the word
     	* broken across two buffers.
     	*/
    	for (cp = buf, ep = buf + len; cp < ep; cp++) {
    		if (cp + 5 < ep && memcmp(cp, "honk!", 5) == 0) {
        		rval = false;
        		break;
    		}
    	}
	return rval;
}

/*
 * Note: This plugin does not differentiate between tty and pipe I/O.
 *       It all gets logged to the same file.
 */
__dso_public struct io_plugin shared_io = {
	SUDO_IO_PLUGIN,
    	SUDO_API_VERSION,
    	io_open,
    	io_close,
    	io_version,
    	io_log_input,   /* tty input */
   	io_log_output,  /* tty output */
   	io_log_input,   /* command stdin if not tty */
    	io_log_output,  /* command stdout if not tty */
    	io_log_output   /* command stderr if not tty */
};

