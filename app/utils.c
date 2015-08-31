/*
 * Copyright (C) 2015 Aurélien Rausch <aurel@aurel-r.fr>
 * 
 * This file is part of pam_all.
 *
 * pam_all is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * pam_all is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pam_all.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "utils.h"

unsigned char *alea(size_t len, unsigned char *table) 
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

int insert(FILE *fd, const char *data, int data_len, long pos)
{
	long file_size, len;
	char *buffer;
	
	fseek(fd, 0, SEEK_END);
	file_size = ftell(fd);
	len = file_size - pos;

	if ((buffer = calloc(len, sizeof(char))) == NULL)
		return 1;

	fseek(fd, pos, SEEK_SET);
	fread(buffer, sizeof(char), len, fd);
	fseek(fd, pos, SEEK_SET);
	fwrite(data, sizeof(char), data_len, fd);
	fwrite(buffer, sizeof(char), len, fd);
	
	F(buffer);
		
	return 0;
}


int passwd_callback(char *pcszBuff, int size, int rwflag, void *pPass)
{
	size_t onPass = strlen((char *)pPass);
	
	if (onPass > (size_t)size)
		onPass = (size_t)size;

	memcpy(pcszBuff, pPass, onPass);

	return (int)onPass; 
}



