#ifndef H_APP_H
#define H_APP_H

void clean(pam_handle_t *pamh UNUSED, void *data, int error_status UNUSED);
const struct pam_user *get_data(const pam_handle_t *pamh);
int send_data(int ctrl, pam_handle_t *pamh, void *data); 
void unlink_tmp_files(struct tempory_files *tmp_files);
int get_group(struct pam_user *user);
int create_user_entry(struct pam_user *user, const char *pub_file_name, const char *priv_file_name);
int verify_user_entry(struct pam_user *user, int flag);
EVP_PKEY *get_public_key(const struct pam_user *user);
EVP_PKEY *create_rsa_key(RSA *rsa);
int sym_encrypt(unsigned char *data, int data_len, char *file, unsigned char *key, unsigned char *iv);
char *create_AES_encrypted_file(int ctrl, char *data, unsigned char *salt);
char *create_RSA_encrypted_file(int ctrl, EVP_PKEY *public_key, char *data);
char *create_command_file(int ctrl, const struct pam_user *user, struct tempory_files **tmp_files);
int _pam_terminate(pam_handle_t *pamh, int status);
int user_authenticate(pam_handle_t *pamh, int ctrl, struct pam_user *user);
int group_authenticate(int ctrl, struct pam_user *user);
int get_signed_file(struct pam_user **user, char **file, const char *command_file);
char *verify(EVP_PKEY *public_key, const char *file);
int wait_reply(int ctrl, const struct pam_user *user, const char *command_file);

#endif
