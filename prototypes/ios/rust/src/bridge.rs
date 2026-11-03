use super::*;
use std::{panic::AssertUnwindSafe, slice, str};

const OUTPUT_CAPACITY: usize = 32768;

// Internal PoC ABI only. Callers own all buffers, keep them live for the call,
// provide disjoint input/output ranges, and wipe secret buffers after use.
// Output contains public metadata/ciphertext or a classified error, never DEKs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vault_ios_command(
    action: *const u8,
    action_len: usize,
    data: *const u8,
    data_len: usize,
    secret: *const u8,
    secret_len: usize,
    output: *mut u8,
    output_capacity: usize,
) -> isize {
    if action.is_null()
        || data.is_null()
        || output.is_null()
        || action_len > 32
        || data_len > OUTPUT_CAPACITY
        || !matches!(secret_len, 0 | 32)
        || (secret_len != 0 && secret.is_null())
        || output_capacity < OUTPUT_CAPACITY
    {
        return -1;
    }
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| -> R<String> {
        // SAFETY: validated lengths; validity and disjointness are caller requirements.
        let action = str::from_utf8(unsafe { slice::from_raw_parts(action, action_len) })
            .map_err(|_| "INVALID_INPUT")?;
        let data = str::from_utf8(unsafe { slice::from_raw_parts(data, data_len) })
            .map_err(|_| "INVALID_INPUT")?;
        let secret = if secret_len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(secret, secret_len) }
        };
        STATE
            .lock()
            .map_err(|_| "INTERNAL_ERROR")?
            .command(action, data, secret)
    }));
    let response = match result {
        Ok(Ok(value)) => format!("{{\"ok\":{value}}}"),
        Ok(Err(code)) => json!({"error": code}).to_string(),
        Err(_) => json!({"error": "INTERNAL_ERROR"}).to_string(),
    };
    if response.len() > output_capacity {
        return -1;
    }
    unsafe { std::ptr::copy_nonoverlapping(response.as_ptr(), output, response.len()) };
    response.len() as isize
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vault_ios_registration_key(
    purpose: i32,
    output: *mut u8,
    capacity: usize,
) -> i32 {
    if output.is_null() || capacity != 32 {
        return -1;
    }
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| -> R<()> {
        let key = STATE
            .lock()
            .map_err(|_| "INTERNAL_ERROR")?
            .registration_key(purpose)?;
        unsafe { std::ptr::copy_nonoverlapping(key.as_ptr(), output, 32) };
        Ok(())
    }));
    if matches!(result, Ok(Ok(()))) {
        0
    } else {
        unsafe { std::ptr::write_bytes(output, 0, 32) };
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_rejects_short_buffers_and_invalid_utf8_without_mutation() {
        let mut output = [0u8; OUTPUT_CAPACITY];
        unsafe {
            assert_eq!(
                vault_ios_command(
                    b"start".as_ptr(),
                    5,
                    b"{}".as_ptr(),
                    2,
                    std::ptr::null(),
                    0,
                    output.as_mut_ptr(),
                    3
                ),
                -1
            );
            let len = vault_ios_command(
                [255].as_ptr(),
                1,
                b"{}".as_ptr(),
                2,
                std::ptr::null(),
                0,
                output.as_mut_ptr(),
                output.len(),
            );
            let response: Value = serde_json::from_slice(&output[..len as usize]).unwrap();
            assert_eq!(response["error"], "INVALID_INPUT");
            let mut key = [42u8; 32];
            assert_eq!(
                vault_ios_registration_key(1, key.as_mut_ptr(), key.len()),
                -1
            );
            assert_eq!(key, [0u8; 32]);
            let len = vault_ios_command(
                b"status".as_ptr(),
                6,
                b"{}".as_ptr(),
                2,
                std::ptr::null(),
                0,
                output.as_mut_ptr(),
                output.len(),
            );
            let response: Value = serde_json::from_slice(&output[..len as usize]).unwrap();
            assert_eq!(response["ok"]["state"], "locked");
        }
    }
}
