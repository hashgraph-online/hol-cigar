//! Platform-neutral raw-pointer helpers used by the audited Windows adapter.

/// Decodes a Windows-owned, NUL-terminated UTF-16 string within an exact scan bound.
///
/// # Safety
///
/// `pointer` must either be null (which is rejected without dereferencing) or point to an
/// allocation containing at least `maximum_units` initialized `u16` values, unless a NUL value
/// occurs earlier. The allocation must remain live and immutable for the duration of this call.
pub(crate) unsafe fn bounded_utf16_to_string(
    pointer: *const u16,
    maximum_units: usize,
) -> Result<String, &'static str> {
    if pointer.is_null() || maximum_units == 0 {
        return Err("UTF-16 pointer or bound is invalid");
    }
    for index in 0..maximum_units {
        // SAFETY: the caller guarantees at least `maximum_units` initialized units unless an
        // earlier terminator is found. `index` remains strictly below that bound.
        if unsafe { *pointer.add(index) } == 0 {
            // SAFETY: the bounded scan proved that `index` initialized, non-NUL units precede the
            // terminator in the caller-owned allocation, which remains live for this call.
            let units = unsafe { std::slice::from_raw_parts(pointer, index) };
            return String::from_utf16(units).map_err(|_error| "UTF-16 string is invalid");
        }
    }
    Err("UTF-16 string exceeded its bound")
}
