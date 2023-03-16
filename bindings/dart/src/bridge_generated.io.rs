use super::*;
// Section: wire functions

#[no_mangle]
pub extern "C" fn wire_new__static_method__ACDC(
    port_: i64,
    issuer: *mut wire_uint_8_list,
    schema: *mut wire_uint_8_list,
    data: *mut wire_uint_8_list,
) {
    wire_new__static_method__ACDC_impl(port_, issuer, schema, data)
}

#[no_mangle]
pub extern "C" fn wire_encode__method__ACDC(port_: i64, that: *mut wire_ACDC) {
    wire_encode__method__ACDC_impl(port_, that)
}

#[no_mangle]
pub extern "C" fn wire_get_issuer__method__ACDC(port_: i64, that: *mut wire_ACDC) {
    wire_get_issuer__method__ACDC_impl(port_, that)
}

#[no_mangle]
pub extern "C" fn wire_get_data__method__ACDC(port_: i64, that: *mut wire_ACDC) {
    wire_get_data__method__ACDC_impl(port_, that)
}

#[no_mangle]
pub extern "C" fn wire_get_schema__method__ACDC(port_: i64, that: *mut wire_ACDC) {
    wire_get_schema__method__ACDC_impl(port_, that)
}

#[no_mangle]
pub extern "C" fn wire_parse__static_method__ACDC(port_: i64, stream: *mut wire_uint_8_list) {
    wire_parse__static_method__ACDC_impl(port_, stream)
}

// Section: allocate functions

#[no_mangle]
pub extern "C" fn new_Attestation() -> wire_Attestation {
    wire_Attestation::new_with_null_ptr()
}

#[no_mangle]
pub extern "C" fn new_box_autoadd_acdc_0() -> *mut wire_ACDC {
    support::new_leak_box_ptr(wire_ACDC::new_with_null_ptr())
}

#[no_mangle]
pub extern "C" fn new_uint_8_list_0(len: i32) -> *mut wire_uint_8_list {
    let ans = wire_uint_8_list {
        ptr: support::new_leak_vec_ptr(Default::default(), len),
        len,
    };
    support::new_leak_box_ptr(ans)
}

// Section: related functions

#[no_mangle]
pub extern "C" fn drop_opaque_Attestation(ptr: *const c_void) {
    unsafe {
        Arc::<Attestation>::decrement_strong_count(ptr as _);
    }
}

#[no_mangle]
pub extern "C" fn share_opaque_Attestation(ptr: *const c_void) -> *const c_void {
    unsafe {
        Arc::<Attestation>::increment_strong_count(ptr as _);
        ptr
    }
}

// Section: impl Wire2Api

impl Wire2Api<RustOpaque<Attestation>> for wire_Attestation {
    fn wire2api(self) -> RustOpaque<Attestation> {
        unsafe { support::opaque_from_dart(self.ptr as _) }
    }
}
impl Wire2Api<String> for *mut wire_uint_8_list {
    fn wire2api(self) -> String {
        let vec: Vec<u8> = self.wire2api();
        String::from_utf8_lossy(&vec).into_owned()
    }
}
impl Wire2Api<ACDC> for wire_ACDC {
    fn wire2api(self) -> ACDC {
        ACDC(self.field0.wire2api())
    }
}
impl Wire2Api<ACDC> for *mut wire_ACDC {
    fn wire2api(self) -> ACDC {
        let wrap = unsafe { support::box_from_leak_ptr(self) };
        Wire2Api::<ACDC>::wire2api(*wrap).into()
    }
}

impl Wire2Api<Vec<u8>> for *mut wire_uint_8_list {
    fn wire2api(self) -> Vec<u8> {
        unsafe {
            let wrap = support::box_from_leak_ptr(self);
            support::vec_from_leak_ptr(wrap.ptr, wrap.len)
        }
    }
}
// Section: wire structs

#[repr(C)]
#[derive(Clone)]
pub struct wire_Attestation {
    ptr: *const core::ffi::c_void,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_ACDC {
    field0: wire_Attestation,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_uint_8_list {
    ptr: *mut u8,
    len: i32,
}

// Section: impl NewWithNullPtr

pub trait NewWithNullPtr {
    fn new_with_null_ptr() -> Self;
}

impl<T> NewWithNullPtr for *mut T {
    fn new_with_null_ptr() -> Self {
        std::ptr::null_mut()
    }
}

impl NewWithNullPtr for wire_Attestation {
    fn new_with_null_ptr() -> Self {
        Self {
            ptr: core::ptr::null(),
        }
    }
}

impl NewWithNullPtr for wire_ACDC {
    fn new_with_null_ptr() -> Self {
        Self {
            field0: wire_Attestation::new_with_null_ptr(),
        }
    }
}

impl Default for wire_ACDC {
    fn default() -> Self {
        Self::new_with_null_ptr()
    }
}

// Section: sync execution mode utility

#[no_mangle]
pub extern "C" fn free_WireSyncReturn(ptr: support::WireSyncReturn) {
    unsafe {
        let _ = support::box_from_leak_ptr(ptr);
    };
}
