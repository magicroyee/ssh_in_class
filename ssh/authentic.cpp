#include "authentic.h"

int verify_knownhost(ssh_session session)
{
    enum ssh_known_hosts_e state;
    unsigned char* hash = NULL;
    ssh_key srv_pubkey = NULL;
    size_t hlen;
    char buf[10];
    char* hexa;
    char* p;
    int cmp;
    int rc;

    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }

    rc = ssh_get_publickey_hash(srv_pubkey,
        SSH_PUBLICKEY_HASH_SHA1,
        &hash,
        &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return -1;
    }

    state = ssh_session_is_known_server(session);
    switch (state) {
    case SSH_KNOWN_HOSTS_OK:
        /* OK */
        printf("The server is recognized.\n");
        break;
    case SSH_KNOWN_HOSTS_CHANGED:
        printf("Host key for server changed: it is now:\n");
        ssh_print_hexa("Public key hash", hash, hlen);
        printf("For security reasons, connection will be stopped\n");
        ssh_clean_pubkey_hash(&hash);

        return -1;
    case SSH_KNOWN_HOSTS_OTHER:
        printf("The host key for this server was not found but an other"
            "type of key exists.\n");
        printf("An attacker might change the default server key to"
            "confuse your client into thinking the key does not exist\n");
        ssh_clean_pubkey_hash(&hash);

        return -1;
    case SSH_KNOWN_HOSTS_NOT_FOUND:
        printf("Could not find known host file.\n");
        printf("If you accept the host key here, the file will be"
            "automatically created.\n");

        /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */

    case SSH_KNOWN_HOSTS_UNKNOWN:
        hexa = ssh_get_hexa(hash, hlen);
        printf("The server is unknown.\n");
        printf("Public key hash: %s\n", hexa);
        printf("Do you trust the host key?(yes/no)\n");
        ssh_string_free_char(hexa);
        ssh_clean_pubkey_hash(&hash);
        p = fgets(buf, sizeof(buf), stdin);
        if (p == NULL) {
            return -1;
        }

        cmp = _strnicmp(buf, "yes", 3);
        if (cmp != 0) {
            return -1;
        }

        rc = ssh_session_update_known_hosts(session);
        if (rc < 0) {
            printf("Error %s\n", strerror(errno));
            return -1;
        }

        break;
    case SSH_KNOWN_HOSTS_ERROR:
        printf("Error %s", ssh_get_error(session));
        ssh_clean_pubkey_hash(&hash);
        return -1;
    }

    ssh_clean_pubkey_hash(&hash);
    return 0;
}

int authentic_user(ssh_session session)
{
    ssh_key pubkey, privkey;
    int rc;
    enum ssh_auth_e state;

    rc = ssh_pki_import_pubkey_file("C:\\Users\\Royee\\.ssh\\id_rsa.pub", &pubkey);
    if (rc != SSH_OK)
    {
        return -1;
    }
    state = (enum ssh_auth_e)ssh_userauth_try_publickey(session, NULL, pubkey);
    switch (state) {
    case SSH_AUTH_SUCCESS:
        printf("The user's pubkey is authentic.\n");
        rc = 0;
        break;
    case SSH_AUTH_DENIED:
        printf("The user is denied.\n");
        rc = 1;
        break;
    case SSH_AUTH_PARTIAL:
        printf("The user is partial.\n");
        rc = 1;
        break;
    case SSH_AUTH_ERROR:
        printf("Fatal Error!\n");
        rc = -1;
        break;
    case SSH_AUTH_AGAIN:
        printf("The server is busy. Please try this later.\n");
        rc = 1;
        break;
    default:
        printf("Fatal Error!\n");
        rc = -1;
    }
    ssh_key_free(pubkey);

    if (rc != SSH_OK)
    {
        return -1;
    }

    rc = ssh_pki_import_privkey_file("C:\\Users\\Royee\\.ssh\\id_rsa",
        NULL, NULL, NULL, &privkey);
    if (rc != SSH_OK)
    {
        return -1;
    }
    state = (enum ssh_auth_e)ssh_userauth_publickey(session, NULL, privkey);
    switch (state) {
    case SSH_AUTH_SUCCESS:
        printf("Connection established!\n");
        rc = 0;
        break;
    case SSH_AUTH_DENIED:
        printf("The user is denied.\n");
        rc = 1;
        break;
    case SSH_AUTH_PARTIAL:
        printf("The user is partial.\n");
        rc = 1;
        break;
    case SSH_AUTH_ERROR:
        printf("Fatal Error!\n");
        rc = -1;
        break;
    case SSH_AUTH_AGAIN:
        printf("The server is busy. Please try this later.\n");
        rc = 1;
        break;
    default:
        printf("Fatal Error!\n");
        rc = -1;
    }
    ssh_key_free(privkey);      //到这里，已与服务器建立连接

    return 0;
}