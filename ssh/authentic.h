#pragma once

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <cstring>
#include <libssh/libssh.h>

int verify_knownhost(ssh_session session);
int authentic_user(ssh_session session);
