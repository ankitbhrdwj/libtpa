use libtcp::ffi::*;
use libtcp::*;
use std::mem::MaybeUninit;

unsafe fn poll_connection(worker: &mut Box<tpa_worker>) -> i32 {
    tcp_worker_run(worker);
    let max_events = 1;
    let mut uninit = [MaybeUninit::<tpa_event>::uninit(); 1];
    let mut event = uninit
        .iter_mut()
        .map(|x| x.assume_init())
        .collect::<Vec<tpa_event>>();
    tcp_event_poll(worker, &mut event, max_events)
}

unsafe fn send(mut worker: Box<tpa_worker>, sid: i32) {
    let line = String::from("hello world\n");
    tcp_event_register(sid, TPA_EVENT_IN | TPA_EVENT_OUT).expect("tcp_event_register failed");

    while poll_connection(&mut worker) == 0 {}
    tcp_write(sid, line.as_bytes()).expect("tcp_write failed");
    while poll_connection(&mut worker) == 0 {}
}

fn parse_args() -> (String, u16) {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        panic!("Usage: {} <arg1> <arg2>", args[0]);
    }
    let arg1 = args[1].parse().unwrap();
    let arg2 = args[2].parse().unwrap();
    (arg1, arg2)
}

fn main() {
    let (server_ip, port) = parse_args();

    tcp_init(1).expect("tcp_init failed");
    let worker = tcp_worker_init();
    println!(":: Connecting to {}:{}", server_ip, port);
    let sid = tcp_connect_to(server_ip, port, None).expect("tcp_connect_to failed");
    unsafe { send(worker, sid) };
}
