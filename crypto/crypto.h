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

#ifndef H_CRYPTO_H
#define H_CRYPTO_H

#define ENTRY		0
#define NO_ENTRY	2

#define SEED_LEN	256
#define RANDOM_FILE	"/dev/urandom"

#define DIGEST_LEN	SHA256_DIGEST_LENGTH

#if defined RSA_BITS && RSA_BITS == 4096
#define SIG_LEN  512
#else
#define RSA_BITS 2048
#define SIG_LEN	 256
#endif

#define EXPONENT	0x10001 /* 65537 */


#define SSL_ERR(x) do {								 \
	if (_IS_SET(_ctrl, PAM_DEBUG_ARG))					 \
		_pam_syslog(_pamh, LOG_DEBUG, "%s", ERR_reason_error_string(x)); \
	D(("%s", ERR_error_string(x, NULL)));					 \
} while (0)

#define RSA_FREE(x) do {	\
	RSA_free(x);		\
	x = NULL;		\
} while (0)

#define BN_FREE(x) do {		\
	BN_clear_free(x);	\
	x = NULL;		\
} while (0)

#define SOFT_INIT  0
#define FULL_INIT  1

void ssl_init(void *pamh, int ctrl, int flag);
void ssl_release(void);
int verify_user_entry(struct pam_user *user);
int create_user_entry(struct pam_user *user);
char *locate_sk_path(struct pam_user *user);
char *locate_pk_path(struct pam_user *user);
int random_bytes(void *buffer, size_t n);
int digest(const void *m, size_t n, unsigned char **dst);
void digest_clean(void *m);
int sign(struct pam_user *user, unsigned char *dst, const unsigned char *m); 

#endif
