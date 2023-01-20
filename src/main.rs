#![windows_subsystem = "windows"]

extern crate native_windows_derive as nwd;
extern crate native_windows_gui as nwg;


use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::mem;

use std::os::windows::ffi::OsStrExt;
use std::ptr::{null_mut};
use std::sync::{RwLock};


use nwd::NwgUi;
use nwg::{EventHandler, NativeUi};
use once_cell::sync::{Lazy};
use winapi::{Class, Interface};
use winapi::shared::ntdef::{LPCWSTR, LPWSTR};
use winapi::shared::stralign::uaw_wcslen;
use winapi::shared::winerror::{ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER, S_FALSE, S_OK};
use winapi::um::combaseapi::{CLSCTX_ALL, CoCreateInstance};
use winapi::um::coml2api::STGM_READ;
use winapi::um::endpointvolume::IAudioEndpointVolume;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::functiondiscoverykeys_devpkey::PKEY_Device_FriendlyName;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::mmdeviceapi;
use winapi::um::mmdeviceapi::{IMMDevice, IMMDeviceCollection, IMMDeviceEnumerator, MMDeviceEnumerator};
use winapi::um::objbase::CoInitialize;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess, OpenProcessToken};
use winapi::um::propidl::PROPVARIANT;
use winapi::um::propsys::IPropertyStore;
use winapi::um::securitybaseapi::{AdjustTokenPrivileges, GetTokenInformation};
use winapi::um::synchapi::{CreateMutexW, ReleaseMutex, WaitForSingleObject};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use winapi::um::winbase::{LookupPrivilegeValueW, lstrcmpiW, SetProcessAffinityMask, WAIT_OBJECT_0};
use winapi::um::winnt::{HANDLE, LUID, PROCESS_ALL_ACCESS, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED, SE_SYSTEMTIME_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenPrivileges};
use winapi::um::winuser::WS_EX_LAYERED;

static AUDIO_DEVICE_DICT: Lazy<RwLock<BTreeMap<String, String>>> = Lazy::new(|| { RwLock::new(BTreeMap::new()) });
static SELECTED_DEVICE_ID: Lazy<RwLock<String>> = Lazy::new(|| { RwLock::new(String::new()) });

#[derive(Default, NwgUi)]
pub struct MyApp {
    #[nwg_control]
    #[nwg_events(OnWindowClose: [MyApp::exit])]
    window: nwg::MessageWindow,

    #[nwg_resource(source_embed: Some(& nwg::EmbedResource::load(None).unwrap()), source_embed_id: 1, size: Some((32, 32)))]
    tray_icon: nwg::Icon,

    #[nwg_control(tip: Some("Audio control"), icon: Some(& data.tray_icon))]
    #[nwg_events(MousePressLeftUp: [MyApp::show_slider], MousePressRightUp: [MyApp::show_popup_menu])]
    tray: nwg::TrayNotification,

    #[nwg_control(flags: "WINDOW|POPUP", size: (200, 100), position: (nwg::Monitor::width() - 200 - 100, nwg::Monitor::height() - 100 - 100), ex_flags: WS_EX_LAYERED)]
    popup_window: nwg::Window,

    #[nwg_control(range: Some(0..100), pos: Some(50), size: (200, 100))]
    #[nwg_events(OnHorizontalScroll: [MyApp::slider_moved])]
    slider: nwg::TrackBar,

    #[nwg_control(popup: true)]
    popup_menu: nwg::Menu,

    #[nwg_control(parent: popup_menu, text: "Exit")]
    #[nwg_events(OnMenuItemSelected: [MyApp::exit])]
    popumenu_exit: nwg::MenuItem,

    #[nwg_control(parent: popup_menu, text: "AudioDg Affinity")]
    #[nwg_events(OnMenuItemSelected: [MyApp::set_audio_dg_affinity])]
    popumenu_audio_dg_affinity: nwg::MenuItem,

    #[nwg_control(parent: popup_menu, text: "Devices")]
    #[nwg_events(OnMenuHover: [MyApp::show_devices])]
    devices_list_menu: nwg::Menu,

    device_list_items: RefCell<Vec<nwg::MenuItem>>,
    device_event_handlers: RefCell<Vec<EventHandler>>,

}

// TODO: Remove this function
//<editor-fold desc="DEFAULT AUDIO ENDPOINT RETRIEVAL">
fn set_default_audio_device_volume(new_volume: usize) {
    let new_volume = new_volume as f32 / 100.0;
    let hr = unsafe { CoInitialize(null_mut()) };
    if !(hr == S_OK || hr == S_FALSE) {
        panic!("CoInitialize failed: hr = 0x{:x}", hr);
    }

    let mut enumerator: *mut IMMDeviceEnumerator = null_mut();
    let hr = unsafe {
        CoCreateInstance(
            &MMDeviceEnumerator::uuidof(),
            null_mut(),
            CLSCTX_ALL,
            &IMMDeviceEnumerator::uuidof(),
            &mut enumerator as *mut _ as *mut _,
        )
    };
    if !(hr == S_OK) {
        panic!("CoCreateInstance failed: hr = 0x{:x}", hr);
    }

    // Get the default audio endpoint
    let mut device: *mut IMMDevice = null_mut();
    let hr = unsafe {
        (*enumerator).GetDefaultAudioEndpoint(
            mmdeviceapi::eRender,
            mmdeviceapi::eConsole,
            &mut device,
        )
    };
    if !(hr == S_OK) {
        panic!("GetDefaultAudioEndpoint failed: hr = 0x{:x}", hr);
    }

    // Set the new volume level of the default audio endpoint
    let mut audio_endpoint_volume: *mut IAudioEndpointVolume = null_mut();
    let hr = unsafe { (*device).Activate(&IAudioEndpointVolume::uuidof(), CLSCTX_ALL, null_mut(), &mut audio_endpoint_volume as *mut _ as *mut _) };
    if !(hr == S_OK) {
        panic!("Activate failed: hr = 0x{:x}", hr);
    }

    let hr = unsafe { (*audio_endpoint_volume).SetMasterVolumeLevelScalar(new_volume, null_mut()) };
    if !(hr == S_OK) {
        panic!("SetMasterVolumeLevelScalar failed: hr = 0x{:x}", hr);
    }
}
//</editor-fold>

fn set_selected_audio_device_volume(device_id: &str, new_volume: usize) {
    let new_volume = new_volume as f32 / 100.0;
    let hr = unsafe { CoInitialize(null_mut()) };
    if !(hr == S_OK || hr == S_FALSE) {
        panic!("CoInitialize failed: hr = 0x{:x}", hr);
    }

    let mut enumerator: *mut IMMDeviceEnumerator = null_mut();
    let hr = unsafe {
        CoCreateInstance(
            &MMDeviceEnumerator::uuidof(),
            null_mut(),
            CLSCTX_ALL,
            &IMMDeviceEnumerator::uuidof(),
            &mut enumerator as *mut _ as *mut _,
        )
    };
    if !(hr == S_OK) {
        panic!("CoCreateInstance failed: hr = 0x{:x}", hr);
    }

    // Get device with id
    let mut device: *mut IMMDevice = null_mut();
    let device_id = OsStr::new(device_id).encode_wide().chain(Some(0).into_iter()).collect::<Vec<_>>();
    let hr = unsafe {
        (*enumerator).GetDevice(LPCWSTR::from(device_id.as_ptr()), &mut device)
    };
    if !(hr == S_OK) {
        panic!("GetDevice failed: hr = 0x{:x}", hr);
    }

    unsafe { (*enumerator).Release(); }

    // Set the new volume level of the default audio endpoint
    let mut audio_endpoint_volume: *mut IAudioEndpointVolume = null_mut();
    let hr = unsafe { (*device).Activate(&IAudioEndpointVolume::uuidof(), CLSCTX_ALL, null_mut(), &mut audio_endpoint_volume as *mut _ as *mut _) };
    if !(hr == S_OK) {
        panic!("Activate failed: hr = 0x{:x}", hr);
    }

    unsafe { (*device).Release(); }

    let hr = unsafe { (*audio_endpoint_volume).SetMasterVolumeLevelScalar(new_volume, null_mut()) };
    if !(hr == S_OK) {
        panic!("SetMasterVolumeLevelScalar failed: hr = 0x{:x}", hr);
    }

    unsafe { (*audio_endpoint_volume).Release(); }
}

// Get list of audio devices
fn get_audio_devices() -> BTreeMap<String, String> {
    let hr = unsafe { CoInitialize(null_mut()) };
    if !(hr == S_OK || hr == S_FALSE) {
        panic!("CoInitialize failed: hr = 0x{:x}", hr);
    }

    let mut enumerator: *mut IMMDeviceEnumerator = null_mut();
    let hr = unsafe {
        CoCreateInstance(
            &MMDeviceEnumerator::uuidof(),
            null_mut(),
            CLSCTX_ALL,
            &IMMDeviceEnumerator::uuidof(),
            &mut enumerator as *mut _ as *mut _,
        )
    };
    if !(hr == S_OK) {
        panic!("CoCreateInstance failed: hr = 0x{:x}", hr);
    }

    // iterate over all audio devices
    let mut devices: *mut IMMDeviceCollection = null_mut();
    let hr = unsafe {
        (*enumerator).EnumAudioEndpoints(
            mmdeviceapi::eRender,
            mmdeviceapi::DEVICE_STATE_ACTIVE,
            &mut devices,
        )
    };
    if !(hr == S_OK) {
        panic!("EnumAudioEndpoints failed: hr = 0x{:x}", hr);
    }
    unsafe { (*enumerator).Release(); }

    let mut count: u32 = 0;
    let hr = unsafe { (*devices).GetCount(&mut count) };
    if !(hr == S_OK) {
        panic!("GetCount failed: hr = 0x{:x}", hr);
    }

    let mut device_id_name_dict: BTreeMap<String, String> = BTreeMap::new();


    for i in 0..count {
        let mut device: *mut IMMDevice = null_mut();
        let hr = unsafe { (*devices).Item(i, &mut device) };
        if !(hr == S_OK) {
            panic!("Item failed: hr = 0x{:x}", hr);
        }

        let mut device_id: LPWSTR = null_mut();
        let hr = unsafe { (*device).GetId(&mut device_id) };
        if !(hr == S_OK) {
            panic!("GetId failed: hr = 0x{:x}", hr);
        }

        // Get the friendly name of the device
        let mut device_properties: *mut IPropertyStore = null_mut();
        let hr = unsafe { (*device).OpenPropertyStore(STGM_READ, &mut device_properties) };
        if !(hr == S_OK) {
            panic!("OpenPropertyStore failed: hr = 0x{:x}", hr);
        }

        let mut prop_var: PROPVARIANT = PROPVARIANT::default();
        let hr = unsafe { (*device_properties).GetValue(&PKEY_Device_FriendlyName, &mut prop_var) };
        if !(hr == S_OK) {
            panic!("GetValue failed: hr = 0x{:x}", hr);
        }

        unsafe { (*device_properties).Release(); }

        let friendly_name = unsafe { prop_var.data.pwszVal() };
        // from wchar_t to String
        let friendly_name_str = unsafe {
            String::from_utf16(std::slice::from_raw_parts(*friendly_name, uaw_wcslen(*friendly_name))).unwrap()
        };

        // from wchar_t to String
        let device_id_str = unsafe {
            String::from_utf16(std::slice::from_raw_parts(device_id, uaw_wcslen(device_id)))
                .unwrap()
        };
        unsafe { (*device).Release(); }

        device_id_name_dict.insert(device_id_str, friendly_name_str);
    }

    unsafe { (*devices).Release(); }

    return device_id_name_dict;
}

impl MyApp {
    fn exit(&self) {
        nwg::stop_thread_dispatch();
    }

    fn set_audio_dg_affinity(&self) {
        set_audiodg_affinity();
    }

    fn show_slider(&self) {
        unsafe { winapi::um::winuser::SetLayeredWindowAttributes(self.popup_window.handle.hwnd().unwrap(), 0, 210, winapi::um::winuser::LWA_ALPHA); }
        self.popup_window.set_position(nwg::Monitor::width() - 200 - 100, nwg::Monitor::height() - 100 - 100);
        self.popup_window.set_visible(true);
    }

    fn slider_moved(&self) {
        if SELECTED_DEVICE_ID.read().unwrap().is_empty() {
            set_default_audio_device_volume(self.slider.pos());
            return;
        }
        set_selected_audio_device_volume(SELECTED_DEVICE_ID.read().unwrap().as_str(), self.slider.pos());
    }

    fn show_popup_menu(&self) {
        self.popup_menu.popup(nwg::Monitor::width() - 300, nwg::Monitor::height() - 50);
    }

    fn show_devices(&self) {
        {
            let mut guard = AUDIO_DEVICE_DICT.write().unwrap();
            *guard = get_audio_devices();
        }

        self.device_list_items.borrow_mut().clear();

        let read_guard = AUDIO_DEVICE_DICT.read().unwrap();

        // unbind all handlers in device_event_handlers
        for handler in self.device_event_handlers.borrow().iter() {
            nwg::unbind_event_handler(handler);
        }
        self.device_event_handlers.borrow_mut().clear();

        for (device_id, device_name) in read_guard.iter() {
            let mut menu_item = nwg::MenuItem::default();
            let enabled_item = SELECTED_DEVICE_ID.read().unwrap().contains(device_id);
            nwg::MenuItem::builder()
                .text(&device_name)
                .parent(&self.devices_list_menu)
                .check(enabled_item)
                .build(&mut menu_item).unwrap();
            let device_id = device_id.clone();


            let handler = nwg::bind_event_handler(&self.popup_window.handle, &self.window.handle, move |evt, _evt_data, handle| {
                match evt {
                    nwg::Event::OnMenuItemSelected => {
                        if handle == menu_item.handle {
                            let mut device_id_guard = SELECTED_DEVICE_ID.write().unwrap();
                            *device_id_guard = device_id.clone();
                        }
                    }
                    _ => {}
                }
            });

            self.device_event_handlers.borrow_mut().push(handler);
            self.device_list_items.borrow_mut().push(menu_item);
        }
    }
}

fn escalate_process() {
    let h_token = unsafe {
        let h_process = GetCurrentProcess();
        let mut h_token: HANDLE = null_mut();
        if OpenProcessToken(h_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut h_token) == 0 {
            panic!("OpenProcessToken failed: {}", GetLastError());
        }
        h_token
    };

    let luid = unsafe {
        let mut luid = LUID::default();
        let wide_system_time = OsStr::new(SE_SYSTEMTIME_NAME).encode_wide().chain(Some(0)).collect::<Vec<_>>();
        if LookupPrivilegeValueW(null_mut(), wide_system_time.as_ptr(), &mut luid) == 0 {
            panic!("LookupPrivilegeValueW failed: {}", GetLastError());
        }
        luid
    };
    let debug_luid = unsafe {
        let mut luid = LUID::default();
        let wide_debug = OsStr::new(SE_DEBUG_NAME).encode_wide().chain(Some(0)).collect::<Vec<_>>();
        if LookupPrivilegeValueW(null_mut(), wide_debug.as_ptr(), &mut luid) == 0 {
            panic!("LookupPrivilegeValueW failed: {}", GetLastError());
        }
        luid
    };
    let tp_buffer: [u8; 256] = [0; 256];
    let tp = unsafe { &mut *(tp_buffer.as_ptr() as *mut TOKEN_PRIVILEGES) };
    tp.PrivilegeCount = 2;

    unsafe {
        (*tp.Privileges.as_mut_ptr().offset(0)).Luid = luid;
        (*tp.Privileges.as_mut_ptr().offset(0)).Attributes = SE_PRIVILEGE_ENABLED;
        (*tp.Privileges.as_mut_ptr().offset(1)).Luid = debug_luid;
        (*tp.Privileges.as_mut_ptr().offset(1)).Attributes = SE_PRIVILEGE_ENABLED;
    }
    if unsafe { AdjustTokenPrivileges(h_token, 0, tp, 0, null_mut(), null_mut()) } == 0 {
        panic!("AdjustTokenPrivileges failed: {}", unsafe { GetLastError() });
    }

    let mut cb = mem::size_of::<TOKEN_PRIVILEGES>() as u32;

    let mut new_tp: *mut TOKEN_PRIVILEGES = unsafe { alloc_zeroed(Layout::from_size_align(cb as usize, 8).unwrap()) as *mut TOKEN_PRIVILEGES };

    unsafe {
        if GetTokenInformation(h_token, TokenPrivileges, new_tp as *mut _, cb, &mut cb) == 0 {
            if GetLastError() == ERROR_INSUFFICIENT_BUFFER {
                dealloc(new_tp as *mut u8, Layout::from_size_align(mem::size_of::<TOKEN_PRIVILEGES>(), 8).unwrap());
                new_tp = alloc_zeroed(Layout::from_size_align(cb as usize, 8).unwrap()) as *mut TOKEN_PRIVILEGES;

                if GetTokenInformation(h_token, TokenPrivileges, new_tp as *mut _, cb as u32, &mut cb as *mut _) == 0 {
                    panic!("GetTokenInformation failed: {}", GetLastError());
                }
            }
        }
    }
    let mut found1 = false;
    let mut found2 = false;

    unsafe {
        for i in 0..(*new_tp).PrivilegeCount as isize {
            if ((*(*new_tp).Privileges.as_ptr().offset(i)).Luid.LowPart == luid.LowPart
                && (*(*new_tp).Privileges.as_ptr().offset(i)).Luid.HighPart == luid.HighPart)
                || ((*(*new_tp).Privileges.as_ptr().offset(i)).Luid.LowPart == debug_luid.LowPart
                && (*(*new_tp).Privileges.as_ptr().offset(i)).Luid.HighPart == debug_luid.HighPart) {
                if (*(*new_tp).Privileges.as_ptr().offset(i)).Attributes & SE_PRIVILEGE_ENABLED == 0 {
                    panic!("AdjustTokenPrivileges failed: {}", GetLastError());
                }
                if !found1 {
                    found1 = true;
                } else {
                    found2 = true;
                }
            }
            if found1 && found2 {
                break;
            }
        }
    }

    if !found1 || !found2 {
        panic!("AdjustTokenPrivileges failed: {}", unsafe { GetLastError() });
    }
    unsafe { dealloc(new_tp as *mut u8, Layout::from_size_align(cb as usize, 8).unwrap()) };
    unsafe { CloseHandle(h_token); }
}

fn get_process_by_name(process_name: &str) -> u32 {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        panic!("CreateToolhelp32Snapshot failed: {}", unsafe { GetLastError() });
    }
    const MAX_PATH: usize = 260;
    let mut pe32 = PROCESSENTRY32W {
        dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; MAX_PATH],
    };
    unsafe {
        if Process32FirstW(snapshot, &mut pe32) == 0 {
            panic!("Process32FirstW failed: {}", GetLastError());
        }
        let wide_process_name = OsStr::new(process_name).encode_wide().chain(Some(0)).collect::<Vec<_>>();
        while lstrcmpiW(pe32.szExeFile.as_ptr(), wide_process_name.as_ptr()) != 0 {
            if Process32NextW(snapshot, &mut pe32) == 0 {
                panic!("Process32NextW failed: {}", GetLastError());
            }
        }
    }
    unsafe { CloseHandle(snapshot); }

    return pe32.th32ProcessID;
}

fn set_audiodg_affinity() {
    let process_id = get_process_by_name("audiodg.exe");

    let process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, process_id) };

    if process_handle == null_mut() {
        panic!("OpenProcess failed: {}", unsafe { GetLastError() });
    }

    let affinity_mask = 0x1;
    unsafe { SetProcessAffinityMask(process_handle, affinity_mask); }
    unsafe { CloseHandle(process_handle); }
}

fn main() {
    let mutex_name = "audiocontrol_mutex";
    let mutex = unsafe { CreateMutexW(null_mut(), 0, OsStr::new(mutex_name).encode_wide().chain(Some(0)).collect::<Vec<_>>().as_ptr()) };
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return;
    }

    let wait_result = unsafe { WaitForSingleObject(mutex, 0) };

    if wait_result != WAIT_OBJECT_0 {
        return;
    }

    escalate_process();

    nwg::init().expect("Failed to init Native Windows GUI");
    nwg::Font::set_global_family("Segoe UI").expect("Failed to set default font");
    let _app = MyApp::build_ui(Default::default()).expect("Failed to build UI");
    nwg::dispatch_thread_events();
    unsafe { ReleaseMutex(mutex); }
    unsafe { CloseHandle(mutex); }
}
