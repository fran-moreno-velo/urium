//===========================================================================//
// crate::gnumach::host                                                      //
//---------------------------------------------------------------------------//
// From gnumach                                                              //
// include/mach/time_value.h                                                 //
// include/mach/host_info.h   (VERIFICAR: flavors y campos)                  //
// include/mach/mach_host.defs                                               //
//===========================================================================//

use std::ffi::{c_char, c_int};
use std::sync::atomic::{fence, Ordering};
use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::message::mach_msg_type_number_t;
use crate::gnumach::port::mach_port_t;
use crate::gnumach::vm_types::{integer_t, long_integer_t, rpc_vm_size_t};

pub use crate::gnumach::mach_types::{host_t, host_priv_t};

//---------------------------------------------------------------------------//
// time_value.h                                                              //
//---------------------------------------------------------------------------//

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct time_value_t {
    pub seconds: long_integer_t,
    pub microseconds: integer_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct time_value64_t {
    pub seconds: i64,
    pub nanoseconds: i64,
}

pub const TIME_MICROS_MAX: integer_t = 1_000_000;
pub const TIME_NANOS_MAX: i64 = 1_000_000_000;

/// Página de tiempo que el núcleo actualiza continuamente (dispositivo "time").
#[repr(C)]
pub struct mapped_time_value_t {
    pub seconds: integer_t,
    pub microseconds: integer_t,
    pub check_seconds: integer_t,
    pub time_value: time_value64_t,
    pub check_seconds64: i64,
    pub uptime_value: time_value64_t,
    pub check_upseconds64: i64,
}

/// Lee de forma coherente la hora de una página de tiempo mapeada.
/// Algoritmo de la documentación de GNU Mach: repetir mientras seconds
/// no coincida con check_seconds64 (el núcleo puede estar escribiendo).
///
/// # Safety
/// `mtime` debe apuntar a una página de tiempo mapeada y válida.
pub unsafe fn mapped_time_read(mtime: *const mapped_time_value_t) -> time_value64_t {
    unsafe {
        loop {
            let seconds = core::ptr::read_volatile(&raw const (*mtime).time_value.seconds);
            fence(Ordering::Acquire);
            let nanoseconds = core::ptr::read_volatile(&raw const (*mtime).time_value.nanoseconds);
            fence(Ordering::Acquire);
            if seconds == core::ptr::read_volatile(&raw const (*mtime).check_seconds64) {
                return time_value64_t { seconds, nanoseconds };
            }
        }
    }
}

/// Igual que mapped_time_read, para el tiempo desde el arranque.
///
/// # Safety
/// `mtime` debe apuntar a una página de tiempo mapeada y válida.
pub unsafe fn mapped_uptime_read(mtime: *const mapped_time_value_t) -> time_value64_t {
    unsafe {
        loop {
            let seconds = core::ptr::read_volatile(&raw const (*mtime).uptime_value.seconds);
            fence(Ordering::Acquire);
            let nanoseconds = core::ptr::read_volatile(&raw const (*mtime).uptime_value.nanoseconds);
            fence(Ordering::Acquire);
            if seconds == core::ptr::read_volatile(&raw const (*mtime).check_upseconds64) {
                return time_value64_t { seconds, nanoseconds };
            }
        }
    }
}

//---------------------------------------------------------------------------//
// host_info.h  (VERIFICAR en /usr/include/mach/host_info.h)                 //
//---------------------------------------------------------------------------//

pub type host_flavor_t = c_int;
pub type host_info_t = *mut integer_t;

pub const HOST_BASIC_INFO: host_flavor_t      = 1;
pub const HOST_PROCESSOR_SLOTS: host_flavor_t = 2;
pub const HOST_SCHED_INFO: host_flavor_t      = 3;
pub const HOST_LOAD_INFO: host_flavor_t       = 4;

pub type cpu_type_t = integer_t;
pub type cpu_subtype_t = integer_t;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct host_basic_info_data_t {
    pub max_cpus: integer_t,
    pub avail_cpus: integer_t,
    pub memory_size: rpc_vm_size_t,
    pub cpu_type: cpu_type_t,
    pub cpu_subtype: cpu_subtype_t,
}
pub const HOST_BASIC_INFO_COUNT: mach_msg_type_number_t =
    (size_of::<host_basic_info_data_t>() / size_of::<integer_t>()) as mach_msg_type_number_t;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct host_sched_info_data_t {
    pub min_timeout: integer_t,
    pub min_quantum: integer_t,
}
pub const HOST_SCHED_INFO_COUNT: mach_msg_type_number_t =
    (size_of::<host_sched_info_data_t>() / size_of::<integer_t>()) as mach_msg_type_number_t;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct host_load_info_data_t {
    pub avenrun: [integer_t; 3],
    pub mach_factor: [integer_t; 3],
}
pub const HOST_LOAD_INFO_COUNT: mach_msg_type_number_t =
    (size_of::<host_load_info_data_t>() / size_of::<integer_t>()) as mach_msg_type_number_t;

pub const KERNEL_VERSION_MAX: usize = 512;
pub type kernel_version_t = [c_char; KERNEL_VERSION_MAX];

//---------------------------------------------------------------------------//
// Traps y stubs MIG (mach_host.defs)                                        //
//---------------------------------------------------------------------------//

unsafe extern "C" {
    /// Trap: devuelve una referencia NUEVA al puerto del host.
    /// Liberarla con mach_port_deallocate(mach_task_self(), host).
    pub fn mach_host_self() -> host_t;

    pub fn host_info(host: host_t, flavor: host_flavor_t, host_info_out: host_info_t,
                     host_info_cnt: *mut mach_msg_type_number_t) -> kern_return_t;

    /// `version` debe apuntar a un buffer de KERNEL_VERSION_MAX bytes.
    pub fn host_get_kernel_version(host: host_t, version: *mut c_char) -> kern_return_t;

    pub fn host_get_time(host: host_t, current_time: *mut time_value_t) -> kern_return_t;
    pub fn host_get_time64(host: host_t, current_time: *mut time_value64_t) -> kern_return_t;
    pub fn host_get_uptime64(host: host_t, uptime: *mut time_value64_t) -> kern_return_t;

    pub fn host_set_time(host_priv: host_priv_t, new_time: time_value_t) -> kern_return_t;
    pub fn host_set_time64(host_priv: host_priv_t, new_time: time_value64_t) -> kern_return_t;
    pub fn host_adjust_time64(host_priv: host_priv_t, new_adjustment: time_value64_t,
                              old_adjustment: *mut time_value64_t) -> kern_return_t;

    pub fn host_reboot(host_priv: host_priv_t, options: c_int) -> kern_return_t;

    /// glibc (<hurd.h>): puertos privilegiados del host y maestro de dispositivos.
    /// Solo funciona en procesos con privilegios (root).
    pub fn get_privileged_ports(host_priv: *mut host_priv_t,
                                device_master: *mut mach_port_t) -> kern_return_t;
}

//---------------------------------------------------------------------------//
// Envolturas seguras                                                        //
//---------------------------------------------------------------------------//

/// Hora actual con resolución de nanosegundos (RPC al núcleo).
pub fn host_time64(host: host_t) -> Result<time_value64_t, kern_return_t> {
    let mut t = time_value64_t::default();
    let err = unsafe { host_get_time64(host, &mut t) };
    if err == 0 { Ok(t) } else { Err(err) }
}

/// Tiempo desde el arranque (RPC al núcleo).
pub fn host_uptime64(host: host_t) -> Result<time_value64_t, kern_return_t> {
    let mut t = time_value64_t::default();
    let err = unsafe { host_get_uptime64(host, &mut t) };
    if err == 0 { Ok(t) } else { Err(err) }
}

pub fn host_basic_info(host: host_t) -> Result<host_basic_info_data_t, kern_return_t> {
    let mut info = host_basic_info_data_t::default();
    let mut cnt = HOST_BASIC_INFO_COUNT;
    let err = unsafe {
        host_info(host, HOST_BASIC_INFO, &mut info as *mut _ as host_info_t, &mut cnt)
    };
    if err == 0 { Ok(info) } else { Err(err) }
}

pub fn host_kernel_version(host: host_t) -> Result<String, kern_return_t> {
    let mut buf: kernel_version_t = [0; KERNEL_VERSION_MAX];
    let err = unsafe { host_get_kernel_version(host, buf.as_mut_ptr()) };
    if err != 0 { return Err(err); }
    buf[KERNEL_VERSION_MAX - 1] = 0;
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    Ok(s.to_string_lossy().into_owned())
}
