#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include "authentic.h"

int main()
{
    ssh_session my_ssh_session;
    int rc;
    char* p;
    char buf[20];

    system("chcp 65001");

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

    
    ssh_channel channel;
    channel = ssh_channel_new(my_ssh_session);
    if (channel == NULL)
    {
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    char buffer[256];
    int nbytes;

    rc = ssh_channel_request_pty(channel);
    if (rc != SSH_OK) return rc;

    rc = ssh_channel_change_pty_size(channel, 80, 24);
    if (rc != SSH_OK) return rc;

    rc = ssh_channel_request_shell(channel);
    if (rc != SSH_OK) return rc;

    printf("...\n...\n...\n");
    while (ssh_channel_is_open(channel) &&
        !ssh_channel_is_eof(channel))
    {
        Sleep(100);
        nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);
        if (nbytes < 0)
            return SSH_ERROR;

        if (nbytes > 0)
        {
            fprintf(stdout, "%.*s", nbytes, buffer);
        }
        if (nbytes == 0)
            break;
    }


    ssh_channel_close(channel);
    ssh_channel_send_eof(channel);
    ssh_channel_free(channel);

    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);

    return 0;
}