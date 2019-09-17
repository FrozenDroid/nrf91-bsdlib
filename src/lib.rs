#![feature(lang_items)]
#![feature(maybe_uninit)]
#![no_std]

#[no_mangle]
extern crate nrfxlib_sys;
#[no_mangle]
extern crate tinyrlibc;
#[macro_use]
extern crate cortex_m_rt;

use nrf91::interrupt;

use nrf91::NVIC;
use core::marker::PhantomData;
use nrfxlib_sys::ctypes::c_void;
use core::time::Duration;
use core::mem::MaybeUninit;
use core::intrinsics::transmute;
use core::ptr::{null_mut, null};

extern "C" {
    fn IPC_IRQHandler();
}

#[no_mangle]
extern "C" fn bsd_os_init() { }

#[no_mangle]
extern "C" fn bsd_os_errno_set(err: nrfxlib_sys::ctypes::c_int) {
}

#[no_mangle]
extern "C" fn bsd_irrecoverable_error_handler(error: u32) {
    cortex_m::asm::bkpt();
}

#[no_mangle]
extern "C" fn bsd_os_timedwait(context: u32, p_timeout: *mut i32) -> i32 {
    0
}

#[no_mangle]
extern "C" fn bsd_os_application_irq_clear() {
    NVIC::unpend(nrf91::interrupt::EGU1);
}

#[no_mangle]
extern "C" fn bsd_os_application_irq_set() {
    NVIC::pend(nrf91::interrupt::EGU1);
}

#[no_mangle]
extern "C" fn bsd_os_trace_irq_set() {
    NVIC::pend(nrf91::interrupt::EGU2);
}

#[no_mangle]
extern "C" fn bsd_os_trace_irq_clear() {
    NVIC::unpend(nrf91::interrupt::EGU2);
}

#[no_mangle]
extern "C" fn bsd_os_trace_put(p_buffer: *const u8, buf_len: u32) -> i32 {
    0
}

pub struct Bsdlib;

pub enum ProtocolFamily {
    None  = 0 as isize,
    Inet  = nrfxlib_sys::NRF_AF_INET  as isize,
    Inet6 = nrfxlib_sys::NRF_AF_INET6 as isize,
    Local = nrfxlib_sys::NRF_AF_LOCAL as isize,
    LTE   = nrfxlib_sys::NRF_AF_LTE   as isize,
}

pub enum ProtocolType {
    None       = 0 as isize,
    Datagram   = nrfxlib_sys::NRF_SOCK_DGRAM  as isize,
    Management = nrfxlib_sys::NRF_SOCK_MGMT   as isize,
    Stream     = nrfxlib_sys::NRF_SOCK_STREAM as isize,
}

pub enum TransportProtocol {
    None = 0 as isize,
    AT   = nrfxlib_sys::NRF_PROTO_AT   as isize,
    DFU  = nrfxlib_sys::NRF_PROTO_DFU  as isize,
    GNSS = nrfxlib_sys::NRF_PROTO_GNSS as isize,
    PDN  = nrfxlib_sys::NRF_PROTO_PDN  as isize,
}


const LC_MAX_READ_LENGTH: usize = 128;

impl Bsdlib {

    pub fn create_socket(&mut self, pf: ProtocolFamily, pt: ProtocolType, tp: TransportProtocol) -> Result<Socket, i32> {
        let ret = unsafe {
            nrfxlib_sys::nrf_socket(pf as i32, pt as i32, tp  as i32)
        };

        if ret < 0 {
            return Err(ret)
        }

        Ok(Socket { file_descriptor: ret })
    }

    pub fn resolve_hostname(&mut self, hostname: &str) -> Result<u32, i32> {
        let mut addr_info = MaybeUninit::<nrfxlib_sys::nrf_addrinfo>::zeroed();

//        let mut a: *mut nrfxlib_sys::nrf_addrinfo = &mut nrfxlib_sys::nrf_addrinfo { ai_flags: 0, ai_family: ProtocolFamily::Inet as i32, ai_socktype: ProtocolType::Stream as i32, ai_protocol: 0, ai_addrlen: 0, ai_addr: null_mut(), ai_canonname: null_mut(), ai_next: null_mut() } as *mut _;
//        let hints = nrfxlib_sys::nrf_addrinfo { ai_flags: 0, ai_family: ProtocolFamily::Inet as i32, ai_socktype: ProtocolType::Stream as i32, ai_protocol: 0, ai_addrlen: 0, ai_addr: null_mut(), ai_canonname: null_mut(), ai_next: null_mut() };

        let test = ['g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', '\0'];

        let ret = unsafe {
            nrfxlib_sys::nrf_getaddrinfo(test.as_ptr() as *const u8, null(), null(), &mut addr_info.as_mut_ptr())
        };
        if ret != 0 {
            return Err(ret)
        }

        let sock_addr: &mut nrfxlib_sys::nrf_sockaddr_in = unsafe { transmute(addr_info.read().ai_addr) };

        Ok(sock_addr.sin_addr.s_addr)
    }

}

#[derive(Debug)]
pub struct Socket {
    file_descriptor: i32,
}

impl Socket {

    pub fn send_command(&mut self, cmd: &str, buffer: &mut [u8]) -> Result<isize, ()> {
        let sent = unsafe {
            nrfxlib_sys::nrf_send(self.file_descriptor, cmd.as_ptr() as *const c_void, cmd.len(), 0)
        };

        if sent != cmd.len() as isize {
            return Err(())
        }

        let recv = unsafe {
            nrfxlib_sys::nrf_recv(self.file_descriptor, buffer.as_mut_ptr() as *mut c_void, buffer.len(), 0)
        };

        Ok(recv)
    }

    pub fn wait_for_response(&mut self, response: &str, response_buffer: &mut [u8], timeout: Option<Duration>) -> Result<isize, ()> {
        loop {
            let recv = unsafe {
                nrfxlib_sys::nrf_recv(self.file_descriptor, response_buffer.as_mut_ptr() as *mut c_void, response_buffer.len(), 0)
            };
            if recv > 0 {
                if unsafe { core::str::from_utf8_unchecked(&response_buffer[..recv as usize]) }.contains(response) {
                    return Ok(recv);
                }
            }
        }
    }

}

pub fn init(nvic: &mut NVIC) -> Result<Bsdlib, i32> {
    unsafe {
        nvic.set_priority(nrf91::interrupt::EGU1, 6);
        nvic.set_priority(nrf91::interrupt::EGU2, 6);
        NVIC::unmask(nrf91::interrupt::EGU1);
        NVIC::unmask(nrf91::interrupt::EGU2);

        let ret = nrfxlib_sys::bsd_init();

        if ret != 0 {
            return Err(ret)
        }

        Ok(Bsdlib)
    }
}

#[no_mangle]
#[interrupt]
fn IPC() {
    unsafe {
        IPC_IRQHandler();
    }
}

#[no_mangle]
#[interrupt]
fn EGU1() {
    unsafe {
        nrfxlib_sys::bsd_os_application_irq_handler();
    }
}

#[no_mangle]
#[interrupt]
fn EGU2() {
    unsafe {
        nrfxlib_sys::bsd_os_trace_irq_handler();
    }
}
