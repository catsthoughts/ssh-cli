#ifndef AUTH_DARWIN_H
#define AUTH_DARWIN_H

#include <CoreFoundation/CoreFoundation.h>

CFTypeRef sshcli_create_auth_context(void);
void sshcli_release_auth_context(CFTypeRef ctx);

#endif
