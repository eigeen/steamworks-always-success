use std::{ffi::c_void, sync::Once};

use log::{error, info};
use mhw_toolkit::game::address;
use windows::Win32::{
    Foundation::{BOOL, TRUE},
    System::{
        Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
        SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
    },
};

mod logger {
    use log::LevelFilter;
    use mhw_toolkit::logger::MHWLogger;
    use once_cell::sync::Lazy;

    static LOGGER: Lazy<MHWLogger> = Lazy::new(|| MHWLogger::new(env!("CARGO_PKG_NAME")));

    pub fn init_log() {
        log::set_logger(&*LOGGER).unwrap();
        log::set_max_level(LevelFilter::Debug);
    }
}

static MAIN_THREAD_ONCE: Once = Once::new();

// ...
// ...
// .text:0000000140666AFA 75 73                                      jnz     short loc_140666B6F ; Jump to failure process code
// .text:0000000140666AFC BA 04 00 00 00                             mov     edx, 4 ; Success code
// ...
// ...
// .text:0000000140666B6F                            ; ---------------------------------------------------------------------------
// .text:0000000140666B6F
// .text:0000000140666B6F                            loc_140666B6F:                          ; CODE XREF: sub_140665F50+BAA↑j
// .text:0000000140666B6F 41 BE FF FF FF FF                          mov     r14d, 0FFFFFFFFh ; Failure code
// ...
// ...

/// VirtualProtect RAII object
struct VirtualProtectGuard {
    old_protect: PAGE_PROTECTION_FLAGS,
    new_protect: PAGE_PROTECTION_FLAGS,
    ptr: *const c_void,
    dwsize: usize,
}

impl Drop for VirtualProtectGuard {
    fn drop(&mut self) {
        if let Err(e) = self.reset_protect() {
            error!("Failed to reset memory protection: {}", e);
        }
    }
}

impl VirtualProtectGuard {
    pub fn new(
        ptr: *const c_void,
        dwsize: usize,
        new_protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<Self, String> {
        let mut this = Self {
            old_protect: PAGE_PROTECTION_FLAGS::default(),
            new_protect,
            ptr,
            dwsize,
        };
        this.set_protect()
            .map_err(|e| format!("Failed to set memory protection: {}", e))?;

        Ok(this)
    }

    fn set_protect(&mut self) -> Result<(), String> {
        unsafe {
            VirtualProtect(
                self.ptr as *const _,
                self.dwsize,
                self.new_protect,
                &mut self.old_protect,
            )
        }
        .map_err(|e| e.to_string())
    }

    fn reset_protect(&self) -> Result<(), String> {
        unsafe {
            VirtualProtect(
                self.ptr as *const _,
                self.dwsize,
                self.old_protect,
                &mut PAGE_PROTECTION_FLAGS::default(),
            )
        }
        .map_err(|e| e.to_string())
    }
}

struct Patcher {
    pub enabled: bool,
    backup: Option<[u8; 2]>,
    patch_addr: usize,
}

impl Patcher {
    pub fn new() -> Result<Self, String> {
        let patch_addr = address::AddressRepository::get_instance()
            .lock()
            .unwrap()
            .get_address(address::steamwork::FailureJnzPatch)?;

        Ok(Self {
            enabled: false,
            backup: None,
            patch_addr,
        })
    }

    pub fn enable(&mut self) -> Result<(), String> {
        let patch_ptr = self.patch_addr as *mut u8;
        let _p_guard = VirtualProtectGuard::new(patch_ptr as *const _, 2, PAGE_EXECUTE_READWRITE)?;

        let jnz_bytes = unsafe { std::slice::from_raw_parts_mut(patch_ptr, 2) };
        if jnz_bytes[0] == 0x90 {
            // already nopped, skip
            return Ok(());
        }
        if jnz_bytes[0] != 0x75 {
            return Err(format!(
                "Expected JNZ opcode at patch address 0x{:X}, found {:X}",
                patch_ptr as usize, jnz_bytes[0]
            ));
        }

        // JNZ -> NOP
        self.backup.replace(
            jnz_bytes
                .try_into()
                .map_err(|_| "Internal: jnz slice length is not 2")?,
        );
        jnz_bytes[0] = 0x90;
        jnz_bytes[1] = 0x90;
        self.enabled = true;

        Ok(())
    }

    #[allow(dead_code)]
    pub fn disable(&mut self) -> Result<(), String> {
        unimplemented!()
    }
}

fn main_entry() -> Result<(), String> {
    logger::init_log();

    info!(
        "SteamworksAlwaysSuccess plugin version: {}",
        env!("CARGO_PKG_VERSION")
    );

    let mut patcher = Patcher::new()?;
    patcher.enable()?;

    Ok(())
}

#[no_mangle]
#[allow(non_snake_case)]
extern "system" fn DllMain(_: usize, call_reason: u32, _: usize) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            MAIN_THREAD_ONCE.call_once(|| {
                if let Err(e) = main_entry() {
                    error!("{}", e);
                }
            });
        }
        DLL_PROCESS_DETACH => (),
        _ => (),
    }
    TRUE
}
