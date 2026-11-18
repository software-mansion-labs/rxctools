//! rxctools as a library: the protocols behind `rxc`, from usbmuxd and lockdown to the iOS 17+
//! tunnel, CoreDevice and RemotePairing. Synchronous; the API follows what `rxc` needs and may change
//! between versions. Progress lines go to stderr unless `util::QUIET` is set.

mod der;
pub mod dtx;
pub mod image;
pub mod instruments;
pub mod lockdown;
pub mod nskeyed;
pub mod p12;
pub mod remote_pairing;
pub mod screen;
pub mod services;
pub mod sign;
pub mod tunnel;
pub mod usbmux;
pub mod util;
pub mod xctest;
pub mod xpc;
