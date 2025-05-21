#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <seccomp.h>
#include <json-c/json.h>
#include <unistd.h>
#include <errno.h>

// Path to policy file
#define POLICY_FILE "./policy.json"

// Function to apply seccomp policy from JSON
void apply_seccomp_policy() {
    FILE *file = fopen(POLICY_FILE, "r");
    if (!file) {
        perror("[libblocker] Failed to open policy.json");
        return;
    }

    fseek(file, 0, SEEK_END);
    long len = ftell(file);
    rewind(file);

    char *file_contents = malloc(len + 1);
    fread(file_contents, 1, len, file);
    file_contents[len] = '\0';
    fclose(file);

    json_object *jso = json_tokener_parse(file_contents);
    free(file_contents);

    if (!jso) {
        fprintf(stderr, "[libblocker] Failed to parse policy.json\n");
        return;
    }

    json_object *block_array;
    if (!json_object_object_get_ex(jso, "block_syscalls", &block_array)) {
        fprintf(stderr, "[libblocker] 'block_syscalls' key not found in policy.json\n");
        json_object_put(jso);
        return;
    }

    if (!json_object_is_type(block_array, json_type_array)) {
        fprintf(stderr, "[libblocker] 'block' is not an array in policy.json\n");
        json_object_put(jso);
        return;
    }

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        fprintf(stderr, "[libblocker] seccomp_init failed\n");
        json_object_put(jso);
        return;
    }

    int array_len = json_object_array_length(block_array);
    for (int i = 0; i < array_len; i++) {
        json_object *entry = json_object_array_get_idx(block_array, i);
        const char *syscall_name = json_object_get_string(entry);

        int syscall_num = seccomp_syscall_resolve_name(syscall_name);
        if (syscall_num == __NR_SCMP_ERROR) {
            fprintf(stderr, "[libblocker] Unknown syscall: %s\n", syscall_name);
            continue;
        }

        printf("[libblocker] Blocking syscall: %s\n", syscall_name);
        // Change blocking action to return EPERM error instead of killing process
        if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), syscall_num, 0) < 0) {
          fprintf(stderr, "[libblocker] Failed to add rule for: %s\n", syscall_name);
        }
    }

    if (seccomp_load(ctx) < 0) {
        fprintf(stderr, "[libblocker] Failed to load seccomp rules\n");
    }

    seccomp_release(ctx);
    json_object_put(jso);
}

// Constructor to run before main()
__attribute__((constructor)) void init() {
    printf("[libblocker] Applying seccomp policy: %s\n", POLICY_FILE);
    apply_seccomp_policy();
}
