#![no_std]
extern crate alloc;

pub mod deserializer;
pub mod event;
pub mod hasher;
pub mod serializer;
pub mod utils;
pub mod constants;
pub mod enums;
pub mod cleaning_info;

pub type RedrResult<T> = core::result::Result<T,  alloc::boxed::Box<dyn core::error::Error>>;
