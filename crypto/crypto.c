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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include "../module/pam.h"
#include "../common/utils.h"
#include "crypto.h"

static int _ctrl;
static void *_pamh;
static int _init = 0;

void ssl_init(void *pamh, int ctrl, int flag)
{
	_pamh = pamh;
	_ctrl = ctrl;
	if (flag == FULL_INIT) {
		ERR_load_crypto_strings();
		SSL_load_error_strings();
		SSL_library_init();
		_init = 1;
	}
}

void ssl_release(void)
{
	if (_init) {
		EVP_cleanup();	
		ERR_free_strings();
		_init = 0;
	}
}

static int passwd_callback(char *buffer, int size, int rwflag, void *u)
{
	size_t len = strlen((char *)u);
	if (len <= 0)
		return 0;
	if (len > (size_t)size)
		len = (size_t)size;

	memcpy(buffer, u, len);
	return (int)len;
}

static int check_owner(struct pam_user *usr, const char *path)
{
	struct stat st;
	
	if (stat(path, &st) < 0) {
		_pam_syslog(_pamh, LOG_ERR, "file stat error: %m");
		return 0;
	}	

	if (st.st_uid != usr->pwd->pw_uid || st.st_gid != usr->pwd->pw_gid) {
		_pam_syslog(_pamh, LOG_ERR, "invalid owner of file %s", path);
		return 0;
	}

	return 1;
}

static int get_user_priv_key_aux(RSA **sk, struct pam_user *usr)
{
	FILE *fp;

	if (!check_owner(usr, usr->sk_path))
		return 0;

	if ((fp = fopen(usr->sk_path, "r")) == NULL) {
		_pam_syslog(_pamh, LOG_ERR, "failed to open %s key file: %m", 
			    usr->sk_path);
		return 0;
	}

	if (!PEM_read_RSAPrivateKey(fp, sk, passwd_callback, (void *)usr->pass)) {
		SSL_ERR(ERR_peek_last_error());
		fclose(fp);
		return 0;
	}
	
	fclose(fp);
	return 1;

}

static RSA *get_user_priv_key(struct pam_user *usr)
{
	RSA *sk;
	
	sk = RSA_new();
	if (!sk) {
		SSL_ERR(ERR_peek_last_error());
		return NULL;
	}
	
	if (!get_user_priv_key_aux(&sk, usr)) {
		RSA_FREE(sk);
		return NULL;
	}
	
	return sk;
}

static int get_user_pub_key_aux(RSA **pk, struct pam_user *usr)
{
	FILE *fp;

	if (!check_owner(usr, usr->pk_path))
		return 0;

	if ((fp = fopen(usr->pk_path, "r")) == NULL) {
		_pam_syslog(_pamh, LOG_ERR, "failed to open %s key file: %m", 
			    usr->pk_path);
		return 0;
	}

	if (!PEM_read_RSAPublicKey(fp, pk, NULL, NULL)) {
		SSL_ERR(ERR_peek_last_error());
		fclose(fp);
		return 0;
	}
	
	fclose(fp);
	return 1;
}

static RSA *get_user_pub_key(struct pam_user *usr)
{
	RSA *pk;

	pk = RSA_new();
	if (!pk) {
		SSL_ERR(ERR_peek_last_error());
		return NULL;
	}

	if (!get_user_pub_key_aux(&pk, usr)) {
		RSA_FREE(pk);
		return NULL;
	}

	return pk;
}

static RSA *get_user_key_pair(struct pam_user *usr)
{
	RSA *kp;

	kp = RSA_new();
	if (!kp) {
		SSL_ERR(ERR_peek_last_error());
		return NULL;
	}

	if (!get_user_pub_key_aux(&kp, usr) || !get_user_priv_key_aux(&kp, usr)) {
		RSA_FREE(kp);
		return NULL;
	}

	return kp;
}

int verify_user_entry(struct pam_user *user)
{
	RSA *kp;

	kp = get_user_key_pair(user);
	if (!kp) {
		_pam_syslog(_pamh, LOG_ERR, "failed to get user key pair");
		return ERR;
	}

	if (RSA_check_key(kp) < 1) {
		_pam_syslog(_pamh, LOG_ERR, "failed to check user key pair");
		SSL_ERR(ERR_peek_last_error());
		RSA_FREE(kp);
		return ERR;
	}
	
	RSA_FREE(kp);
	return SUCCESS;
}

static int seed_prng(void)
{
	if (RAND_load_file(RANDOM_FILE, SEED_LEN) != SEED_LEN || !RAND_status()) {
		_pam_syslog(_pamh, LOG_ERR, "failed to reseed from %s", 
			    RANDOM_FILE);
		return 0;
	}
	return 1;
}

static RSA *generate_RSA_key(void)
{
	RSA *kp = NULL;
	BIGNUM *e = NULL;

	if (!seed_prng())
		return NULL;
	
	if ((!(e = BN_new())) || !(kp = RSA_new()) ||
	    (!(BN_set_word(e, EXPONENT)))	   || 
	    (!(RSA_generate_key_ex(kp, RSA_BITS, e, NULL)))) {
		SSL_ERR(ERR_peek_last_error());
		if (kp) 
			RSA_FREE(kp);
	}

	if (e)
		BN_FREE(e);
	return kp;
}	

static int save_RSA_key(RSA *key_pair, struct pam_user *usr)
{
	FILE *fp;
	
	umask(0022); /* -rw-r--r-- */
	if ((fp = fopen(usr->pk_path, "w+")) == NULL) {
		_pam_syslog(_pamh, LOG_ERR, "failed to open %s key file: %m", 
			    usr->pk_path);
		return ERR;
	}

	if (!PEM_write_RSAPublicKey(fp, key_pair)) 
		goto ssl_err;

	if (fchown(fileno(fp), usr->pwd->pw_uid, usr->pwd->pw_gid) == -1) {
		_pam_syslog(_pamh, LOG_ERR, "failed to set the owner of key: %m");
		fclose(fp);
		return ERR;
	}	

	fclose(fp);
	umask(0066); /* -rw------- */
	if ((fp = fopen(usr->sk_path, "w+")) == NULL) {
		_pam_syslog(_pamh, LOG_ERR, "failed to open %s key file: %m", 
			    usr->sk_path);
		return ERR;
	}
	
	if (!PEM_write_RSAPrivateKey(fp, key_pair, EVP_des_ede3_cbc(), 
				     (unsigned char *)usr->pass, 
				     strlen(usr->pass), NULL, NULL))
		goto ssl_err;

	if (fchown(fileno(fp), usr->pwd->pw_uid, usr->pwd->pw_gid) == -1) {
		_pam_syslog(_pamh, LOG_ERR, "failed to set the owner of key: %m");
		fclose(fp);
		return ERR;
	}

	fclose(fp);
	return SUCCESS;
ssl_err:
	SSL_ERR(ERR_peek_last_error());
	fclose(fp);
	return ERR;	
}

int create_user_entry(struct pam_user *user)
{
	int status;
	RSA *kp;

	_pam_syslog(_pamh, LOG_INFO, "generate RSA key pair for user %s", 
		    user->name);
	kp = generate_RSA_key();
	if (!kp) {
		_pam_syslog(_pamh, LOG_ERR, "error during key generation");
		return ERR;
	}
	
	status = save_RSA_key(kp, user);
	if (status == ERR)
		_pam_syslog(_pamh, LOG_ERR, "error during saving the key pair");

	RSA_FREE(kp);
	return status;
}

char *locate_sk_path(struct pam_user *user)
{
	char *sk;
	if (asprintf(&sk, "%s%s", USR_DIR, user->name) < 0) {
		_pam_syslog(_pamh, LOG_CRIT, "asprintf failed");
		D(("asprintf: %m"));
		return NULL;	
	}

	return sk;
}

char *locate_pk_path(struct pam_user *user)
{
	char *pk;
	if (asprintf(&pk, "%s%s.pub", USR_DIR, user->name) < 0) {
		_pam_syslog(_pamh, LOG_CRIT, "asprintf failed");
		D(("asprintf: %m"));
		return NULL;
	}
	
	return pk;
}

int random_bytes(void *buffer, size_t n)
{
	if (!seed_prng())
		return ERR;
	
	if (!RAND_bytes((unsigned char *)buffer, n)) {
		_pam_syslog(_pamh, LOG_ERR, "failed to generate random bytes");
		SSL_ERR(ERR_peek_last_error());
		return ERR;
	}	
	
	return SUCCESS;
}	

int digest(const void *m, size_t n, unsigned char **dst)
{
	static SHA256_CTX ctx;
	static int update = 0;
	static unsigned char hash[DIGEST_LEN];

	if (!update) {
		if (!SHA256_Init(&ctx))
			goto err;
		update = 1;		
	}

	if (!SHA256_Update(&ctx, m, n)) 
		goto err;

	if (dst != NULL) {
		if (!SHA256_Final(hash, &ctx)) 
			goto err;
		*dst = hash;
		update = 0;
	}
	
	return SUCCESS;
err:
	_pam_syslog(_pamh, LOG_ERR, "hash function error");
	update = 0;
	*dst = NULL;
	return ERR;
}

void digest_clean(void *m)
{
	if (m)
		memset(m, '\0', DIGEST_LEN);	
}

int sign(struct pam_user *user, unsigned char *dst, const unsigned char *m)
{
	int status = SUCCESS;
	RSA *sk = get_user_priv_key(user);
	unsigned int len = 0;  

	if (!sk) {
		_pam_syslog(_pamh, LOG_ERR, "impossible to get private key");
		return ERR;
	}

	if (!RSA_sign(NID_sha256, m, DIGEST_LEN, dst, &len, sk) || 
	    len > SIG_LEN) {
		_pam_syslog(_pamh, LOG_ERR, "cannot sign datas");
		SSL_ERR(ERR_peek_last_error());
		status = ERR;
	}

	RSA_FREE(sk);	
	return status;
}

