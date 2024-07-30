//TODO: implement the following functions
//
// pub fn tpa_accept_burst(sid: ::std::os::raw::c_int, burst: *mut ::std::os::raw::c_int) -> ::std::os::raw::c_int;
// pub fn tpa_sock_info_get(sid: ::std::os::raw::c_int, info: *mut tpa_sock_info) -> ::std::os::raw::c_int;
// pub fn tpa_close(sid: ::std::os::raw::c_int) -> ::std::os::raw::c_int;
// pub fn tpa_zreadv(sid: ::std::os::raw::c_int, iov: *mut ::std::os::raw::c_void, iovcnt: ::std::os::raw::c_int) -> ::std::os::raw::c_int;
// pub fn tpa_zwritev(sid: ::std::os::raw::c_int, iov: *mut ::std::os::raw::c_void, iovcnt: ::std::os::raw::c_int) -> ::std::os::raw::c_int;
//
// pub fn tpa_memsegs_get() -> *mut tpa_memseg;
// pub fn tpa_extmem_register
// pub fn tpa_extmem_unregister

use crate::ffi::tpa_event;
use std::mem::MaybeUninit;

// TCP worker related functions
pub fn tcp_init(nr_worker: i32) -> Result<(), std::io::Error> {
    match unsafe { crate::ffi::tpa_init(nr_worker) } {
        0 => Ok(()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "tpa_init failed",
        )),
    }
}

pub fn tcp_worker_init() -> Box<crate::ffi::tpa_worker> {
    match unsafe { crate::ffi::tpa_worker_init() } {
        ptr if ptr.is_null() => panic!("tpa_worker_init failed"),
        ptr => unsafe { Box::from_raw(ptr) },
    }
}

pub fn tcp_worker_run(worker: &mut Box<crate::ffi::tpa_worker>) {
    unsafe { crate::ffi::tpa_worker_run(worker.as_mut()) }
}

// TCP connection related functions
pub fn tcp_connect_to(
    server: String,
    port: u16,
    opts: Option<crate::ffi::tpa_sock_opts>,
) -> Result<i32, std::io::Error> {
    let server = std::ffi::CString::new(server).unwrap();
    match unsafe {
        crate::ffi::tpa_connect_to(
            server.as_bytes().as_ptr() as *const i8,
            port,
            opts.map_or(std::ptr::null(), |opts| &opts),
        )
    } {
        sid if sid < 0 => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "tpa_connect_to failed",
        )),
        sid => Ok(sid),
    }
}

pub fn tcp_listen_on(
    local_ip: String,
    port: u16,
    opts: Option<crate::ffi::tpa_sock_opts>,
) -> Result<i32, std::io::Error> {
    let local = std::ffi::CString::new(local_ip).unwrap();
    let ptr = if local.is_empty() {
        std::ptr::null()
    } else {
        local.as_bytes().as_ptr() as *const i8
    };

    match unsafe {
        crate::ffi::tpa_listen_on(ptr, port, opts.map_or(std::ptr::null(), |opts| &opts))
    } {
        sid if sid < 0 => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "tpa_listen_on failed",
        )),
        sid => Ok(sid),
    }
}

pub fn tcp_write(sid: i32, buf: &[u8]) -> Result<isize, std::io::Error> {
    match unsafe { crate::ffi::tpa_write(sid, buf.as_ptr() as *const std::ffi::c_void, buf.len()) }
    {
        ret if ret < 0 => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "tpa_write failed",
        )),
        ret => Ok(ret),
    }
}

// Event related functions
pub fn tcp_event_register(sid: i32, events: u32) -> Result<(), std::io::Error> {
    let mut uninit = MaybeUninit::<tpa_event>::uninit();
    let event = uninit.as_mut_ptr();
    let mut event = unsafe {
        (*event).events = events;
        uninit.assume_init()
    };

    match unsafe {
        crate::ffi::tpa_event_ctrl(sid, crate::ffi::TPA_EVENT_CTRL_ADD as i32, &mut event)
    } {
        0 => Ok(()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "tpa_event_ctrl failed",
        )),
    }
}

pub fn tcp_event_update(sid: i32, events: u32) -> Result<(), std::io::Error> {
    let mut uninit = MaybeUninit::<tpa_event>::uninit();
    let event = uninit.as_mut_ptr();
    let mut event = unsafe {
        (*event).events = events;
        uninit.assume_init()
    };
    match unsafe {
        crate::ffi::tpa_event_ctrl(sid, crate::ffi::TPA_EVENT_CTRL_MOD as i32, &mut event)
    } {
        0 => Ok(()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "tpa_event_ctrl failed",
        )),
    }
}

pub fn tcp_event_poll(
    worker: &mut Box<crate::ffi::tpa_worker>,
    events: &mut [tpa_event],
    maxevents: i32,
) -> i32 {
    assert!(events.len() as i32 >= maxevents);
    unsafe { crate::ffi::tpa_event_poll(worker.as_mut(), events.as_mut_ptr(), maxevents) }
}
