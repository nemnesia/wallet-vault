#include <stdint.h>
#include <stddef.h>
// Internal prototype ABI. No returned allocation. Capacity >= 32768 for commands.
intptr_t vault_ios_command(const uint8_t *action, size_t action_len,
    const uint8_t *data, size_t data_len, const uint8_t *secret, size_t secret_len,
    uint8_t *output, size_t output_capacity);
int32_t vault_ios_registration_key(int32_t purpose, uint8_t *output, size_t capacity);
