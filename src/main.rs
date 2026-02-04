mod cli;
mod conev; // +
mod config;
mod error;
mod log;
mod params;

mod net {
    mod addr;
    mod dns;
    mod sock;
}

mod proxy {
    mod http_connect;
    mod socks5;
    mod udp;
}

mod desync {
    mod auto_cache;
    mod engine;
    mod fake;
    mod ttl;
}

fn main() {
    println!("Hello, world!");
}
