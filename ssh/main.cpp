#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include "authentic.h"

int main()
{
    ssh_session my_ssh_session;
    int rc;
    char* p;
    char buf[20];

    // Open session and set options
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
        exit(-1);
    printf("Please enter the host you want to connect(eg. 10.195.249.30):\n");
    p = gets_s(buf, sizeof(buf));
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, p);
    printf("Please enter the username you want to connect(eg. royee):\n");
    p = gets_s(buf, sizeof(buf));
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, p);

    // Connect to server
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK)
    {
        printf("Error connecting to localhost: %s\n",
            ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        exit(-1);
    }

    // Verify the server's identity
    // For the source code of verify_knownhost(), check previous example
    if (verify_knownhost(my_ssh_session) < 0)
    {
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    if (authentic_user(my_ssh_session) < 0)
    {
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }



    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);

    return 0;
}