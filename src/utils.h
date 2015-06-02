#ifndef H_UTILS_H
#define H_UTILS_H

/*  
 * Free and set NULL 
 */ 
#define F(x) do {	\
	if (x) { free(x), x = NULL; }	\
	} while (0)

int _pam_parse(int argc, const char **argv); 
void log_message(int level, char *msg, ...); 
int  passwd_callback(char *pcszBuff, int size, int rwflag, void *pPass); 
char *format_command_line(const char **command_line); 
char *is_a_symlink(char *file);
unsigned char *alea(size_t len, unsigned char *table);

#endif
