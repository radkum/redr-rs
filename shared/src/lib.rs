#![no_std]
extern crate alloc;

pub mod cleaning_info;
pub mod constants;
pub mod deserializer;
pub mod enums;
pub mod event;
pub mod hasher;
pub mod serializer;
pub mod sha_buf;

pub type RedrResult<T> = core::result::Result<T, alloc::boxed::Box<dyn core::error::Error>>;
