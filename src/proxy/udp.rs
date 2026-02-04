// src/proxy/udp.rs
//
// UDP associate / UDP tunnel parts from proxy.c.
// Placeholder until we port full UDP relay logic.

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use crate::conev::{eval, poolhd};

pub fn udp_associate(_pool: &mut poolhd, _val: &mut eval) -> i32 {
    // TODO: create UDP socket + bind + reply with BND.ADDR/BND.PORT
    -1
}

pub fn on_udp_tunnel(_pool: &mut poolhd, _val: &mut eval, _et: i32) -> i32 {
    // TODO: UDP relay
    -1
}
