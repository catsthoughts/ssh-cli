#import <LocalAuthentication/LocalAuthentication.h>
#include "auth_darwin.h"

CFTypeRef sshcli_create_auth_context(void) {
    LAContext *ctx = [[LAContext alloc] init];

    // Pre-evaluate so that the user authenticates once (Touch ID / password).
    // All subsequent Keychain operations bound to this context skip prompts.
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block BOOL ok = NO;
    [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
        localizedReason:@"Authenticate to use SSH key"
                  reply:^(BOOL success, NSError *error) {
        ok = success;
        dispatch_semaphore_signal(sem);
    }];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    dispatch_release(sem);
    if (!ok) {
        return NULL;
    }
    return (CFTypeRef)ctx;
}

void sshcli_release_auth_context(CFTypeRef ctx) {
    if (ctx) CFRelease(ctx);
}
