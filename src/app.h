#ifndef H_APP_H
#define H_APP_H

void clean(pam_handle_t *pamh UNUSED, void *data, int error_status UNUSED);
const struct pam_user *get_data(const pam_handle_t *pamh);
int get_group(struct pam_user *user);
int create_user_entry(struct pam_user *user, const char *pub_file_name, const char *priv_file_name);
int verify_user_entry(struct pam_user *user, int flag);
EVP_PKEY *get_public_key(const struct pam_user *user);
EVP_PKEY *create_rsa_key(RSA *rsa);
char *create_encrypted_file(EVP_PKEY *public_key, char *data, unsigned char *salt);
char *create_command_file(const struct pam_user *user);
int _pam_terminate(pam_handle_t *pamh, int status);
int user_authenticate(pam_handle_t *pamh, int ctrl, struct pam_user *user);
int shamir_authenticate(int ctrl, struct pam_user *user);
int wait_reply(const struct pam_user *user, const char *command_file);

#endif
