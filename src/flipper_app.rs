use core::ffi::c_void;
use flipperzero_sys as sys;
extern crate alloc;
use super::qrcodegen::{DataTooLong, QrCode, QrCodeEcc};
use crate::bip39::{entropy_to_mnemonic, MnemonicType};
use crate::flipper_wallet_core::Wallet;
use crate::hex;
use crate::trng;
use alloc::vec::Vec;

const MAX_MNEMONIC_LEN: usize = 256;
const MAX_PASSPHRASE_LEN: usize = 64;
const MAIN_MENU_VISIBLE: usize = 4;
const SETTINGS_VISIBLE: usize = 4;
const MNEMONIC_VISIBLE: usize = 4;
const SCROLLBAR_WIDTH: i32 = 6;
// QR visual tuning
const QR_BORDER_THICKNESS: i32 = 1;
const QR_MODULE_GAP: i32 = 0;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Screen {
    MainMenu = 0,
    CreateWallet = 1,
    ImportWallet = 2,
    ViewWallets = 3,
    Settings = 4,
    ShowMnemonic = 5,
    About = 6,
    ConfirmAction = 7,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Navigation = 0,
    TextInput = 1,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ConfirmAction {
    None = 0,
    DeleteWallet = 1,
    ExportMnemonic = 2,
    ClearPassphrase = 3,
    RevealPrivate = 4,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum CryptoType {
    Bitcoin = 0,
    Ethereum = 1,
    Litecoin = 2,
    Dash = 3,
    Dogecoin = 4,
    Ripple = 5,
    Ravencoin = 6,
}

#[repr(C)]
pub struct AppState {
    // Core control
    pub exit_requested: bool,
    pub current_screen: Screen,

    // Menu state
    pub menu_index: usize,
    pub menu_scroll: usize,

    // Mnemonic storage
    pub mnemonic_buffer: [u8; MAX_MNEMONIC_LEN],
    pub mnemonic_len: usize,
    pub mnemonic_scroll: usize,

    // Wallet configuration
    pub bip39_word_count: usize,
    pub selected_crypto: usize,

    // Passphrase storage
    pub passphrase_buffer: [u8; MAX_PASSPHRASE_LEN],
    pub passphrase_len: usize,
    pub input_mode: InputMode,

    // Settings
    pub settings_index: usize,
    pub settings_scroll: usize,

    // Confirmation
    pub confirm_action: ConfirmAction,
    pub confirm_index: usize,
    // Wallet storage
    pub wallets: Vec<Wallet>,
    pub current_wallet: usize,
    // creation flags to avoid heavy work in input callback
    pub create_requested: bool,
    pub create_in_progress: bool,
    pub create_error: i32,
    // whether the create request is for generating a private key instead of mnemonic
    pub create_private_requested: bool,
    // generated private key storage (if any)
    pub private_key: [u8; 32],
    pub private_key_len: usize,
    // whether currently showing generated private key (instead of mnemonic)
    pub show_private: bool,
    // scroll offset for private key hex view (vertical)
    pub private_scroll: usize,
    // stored entropy for later derivation (0..32 bytes)
    pub entropy_buffer: [u8; 32],
    pub entropy_len: usize,
    // title scrolling state
    pub title_scroll_offset: i32,
    pub title_scroll_dir: i8,
    pub title_scroll_tick: u32,
    // mnemonic view state
    pub showing_qr: bool,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            exit_requested: false,
            current_screen: Screen::MainMenu,
            menu_index: 0,
            menu_scroll: 0,
            mnemonic_buffer: [0u8; MAX_MNEMONIC_LEN],
            mnemonic_len: 0,
            mnemonic_scroll: 0,
            bip39_word_count: 12,
            selected_crypto: 0,
            passphrase_buffer: [0u8; MAX_PASSPHRASE_LEN],
            passphrase_len: 0,
            input_mode: InputMode::Navigation,
            settings_index: 0,
            settings_scroll: 0,
            confirm_action: ConfirmAction::None,
            confirm_index: 0,
            wallets: Vec::new(),
            current_wallet: 0,
            create_requested: false,
            create_in_progress: false,
            create_error: 0,
            create_private_requested: false,
            private_key: [0u8; 32],
            private_key_len: 0,
            show_private: false,
            private_scroll: 0,
            entropy_buffer: [0u8; 32],
            entropy_len: 0,
            title_scroll_offset: 0,
            title_scroll_dir: 1,
            title_scroll_tick: 0,
            showing_qr: false,
        }
    }

    pub fn clear_mnemonic(&mut self) {
        for i in 0..self.mnemonic_buffer.len() {
            self.mnemonic_buffer[i] = 0;
        }
        self.mnemonic_len = 0;
        self.mnemonic_scroll = 0;
    }

    pub fn clear_passphrase(&mut self) {
        for i in 0..self.passphrase_buffer.len() {
            self.passphrase_buffer[i] = 0;
        }
        self.passphrase_len = 0;
    }

    pub fn clamp_menu_index(&mut self, max: usize) {
        if self.menu_index >= max {
            self.menu_index = if max > 0 { max - 1 } else { 0 };
        }
    }

    pub fn validate_scroll(&mut self, total: usize, visible: usize) {
        let max_scroll = if total > visible { total - visible } else { 0 };
        if self.menu_scroll > max_scroll {
            self.menu_scroll = max_scroll;
        }
    }
}

// ============================================================================
// MAIN APPLICATION ENTRY POINT
// ============================================================================

#[no_mangle]
pub extern "C" fn app_main() -> i32 {
    unsafe {
        // Get GUI handle
        let gui_name = b"gui\0";
        let gui = sys::furi_record_open(gui_name.as_ptr() as *const i8);
        if gui.is_null() {
            return -1;
        }

        // Create viewport
        let viewport = sys::view_port_alloc();
        if viewport.is_null() {
            sys::furi_record_close(gui_name.as_ptr() as *const i8);
            return -1;
        }

        // Create state
        let mut state = AppState::new();
        let state_ptr = &mut state as *mut AppState as *mut c_void;

        // Set callbacks
        sys::view_port_draw_callback_set(viewport, Some(draw_callback), state_ptr);
        sys::view_port_input_callback_set(viewport, Some(input_callback), state_ptr);

        // Add to GUI
        sys::gui_add_view_port(gui as *mut sys::Gui, viewport, sys::GuiLayerFullscreen);
        sys::view_port_update(viewport);

        // Main loop
        loop {
            if state.exit_requested {
                break;
            }

            // If wallet creation was requested from input callback, perform it here
            if state.create_requested && !state.create_in_progress {
                state.create_requested = false;
                state.create_in_progress = true;

                // request a redraw so UI shows "Creating..."
                sys::view_port_update(viewport);

                // Temporarily disable callbacks to avoid concurrent access while creating
                let null_ctx: *mut c_void = core::ptr::null_mut();
                sys::view_port_draw_callback_set(viewport, None, null_ctx);
                sys::view_port_input_callback_set(viewport, None, null_ctx);

                // Determine entropy bits for current selection
                let bits = match state.bip39_word_count {
                    12 => 128,
                    15 => 160,
                    18 => 192,
                    21 => 224,
                    24 => 256,
                    _ => 128,
                };

                // Perform creation (TRNG + wallet derivation) while callbacks are disabled
                if state.create_private_requested {
                    // generate 256-bit private key
                    match trng::get_entropy(256) {
                        Ok(entropy) => {
                            let copy_len = core::cmp::min(entropy.len(), state.private_key.len());
                            for i in 0..copy_len {
                                state.private_key[i] = entropy[i];
                            }
                            state.private_key_len = copy_len;
                            state.show_private = true;
                            state.create_error = 0;
                        }
                        Err(_) => {
                            state.create_error = 1;
                        }
                    }
                } else {
                    match trng::get_entropy(bits) {
                        Ok(entropy) => {
                            // save entropy bytes for later derivation
                            let copy_len =
                                core::cmp::min(entropy.len(), state.entropy_buffer.len());
                            for i in 0..copy_len {
                                state.entropy_buffer[i] = entropy[i];
                            }
                            state.entropy_len = copy_len;

                            // convert to mnemonic words (no seed/master derivation here)
                            let mtype = match bits {
                                128 => MnemonicType::Words12,
                                160 => MnemonicType::Words15,
                                192 => MnemonicType::Words18,
                                224 => MnemonicType::Words21,
                                256 => MnemonicType::Words24,
                                _ => MnemonicType::Words12,
                            };
                            match entropy_to_mnemonic(
                                &state.entropy_buffer[..state.entropy_len],
                                mtype,
                            ) {
                                Ok(words) => {
                                    // join words into single string
                                    let mut mnemonic_str = alloc::string::String::new();
                                    for (i, w) in words.iter().enumerate() {
                                        if i > 0 {
                                            mnemonic_str.push(' ');
                                        }
                                        mnemonic_str.push_str(w);
                                    }
                                    let bytes = mnemonic_str.as_bytes();
                                    let len = core::cmp::min(
                                        bytes.len(),
                                        state.mnemonic_buffer.len() - 1,
                                    );
                                    state.mnemonic_buffer[..len].copy_from_slice(&bytes[..len]);
                                    if len < state.mnemonic_buffer.len() {
                                        state.mnemonic_buffer[len] = 0;
                                    }
                                    state.mnemonic_len = words.len();
                                    state.mnemonic_scroll = 0;
                                    state.create_error = 0;
                                }
                                Err(_) => {
                                    state.create_error = 2;
                                }
                            }
                        }
                        Err(_) => {
                            state.create_error = 1;
                        }
                    }
                }

                // Re-enable callbacks
                sys::view_port_draw_callback_set(viewport, Some(draw_callback), state_ptr);
                sys::view_port_input_callback_set(viewport, Some(input_callback), state_ptr);

                state.create_in_progress = false;
                // If we just generated a private key, require confirmation before showing it
                if state.create_private_requested {
                    state.show_private = false;
                    state.confirm_action = ConfirmAction::RevealPrivate;
                    state.current_screen = Screen::ConfirmAction;
                    // clear the request flag (we've handled generation)
                    state.create_private_requested = false;
                }
            }

            // advance title scroll tick and update offset if on main menu
            state.title_scroll_tick = state.title_scroll_tick.wrapping_add(1);
            if state.current_screen == Screen::MainMenu {
                // update every few main loop iterations to slow scrolling
                if state.title_scroll_tick % 6 == 0 {
                    // approximate character width in pixels
                    let char_w: i32 = 6;
                    let title = b"Flipper Zero Crypto Wallet\0";
                    let text_pixels = (title.len() as i32) * char_w;
                    let avail = 128 - 12 - SCROLLBAR_WIDTH; // left/right margins approx
                    if text_pixels > avail {
                        let max_off = text_pixels - avail;
                        state.title_scroll_offset += state.title_scroll_dir as i32;
                        if state.title_scroll_offset < 0 {
                            state.title_scroll_offset = 0;
                            state.title_scroll_dir = 1;
                        } else if state.title_scroll_offset > max_off {
                            state.title_scroll_offset = max_off;
                            state.title_scroll_dir = -1;
                        }
                    } else {
                        state.title_scroll_offset = 0;
                    }
                }
            } else {
                // reset offset and direction when not on main menu, but keep tick running
                state.title_scroll_offset = 0;
                state.title_scroll_dir = 1;
            }

            sys::view_port_update(viewport);
            sys::furi_delay_ms(50);
        }

        // Cleanup
        sys::gui_remove_view_port(gui as *mut sys::Gui, viewport);
        sys::view_port_free(viewport);
        sys::furi_record_close(gui_name.as_ptr() as *const i8);

        0
    }
}

// ============================================================================
// DRAW CALLBACK
// ============================================================================

extern "C" fn draw_callback(canvas: *mut sys::Canvas, ctx: *mut c_void) {
    unsafe {
        if canvas.is_null() || ctx.is_null() {
            return;
        }

        let state = ctx as *const AppState;
        if state.is_null() {
            return;
        }
        let state = &*state;

        sys::canvas_clear(canvas);
        sys::canvas_set_font(canvas, sys::FontPrimary);
        sys::canvas_set_color(canvas, sys::ColorBlack);

        match state.current_screen {
            Screen::MainMenu => draw_main_menu(canvas, state),
            Screen::CreateWallet => draw_create_wallet(canvas, state),
            Screen::ImportWallet => draw_import_wallet(canvas, state),
            Screen::ViewWallets => draw_view_wallets(canvas, state),
            Screen::Settings => draw_settings(canvas, state),
            Screen::ShowMnemonic => draw_show_mnemonic(canvas, state),
            Screen::About => draw_about(canvas, state),
            Screen::ConfirmAction => draw_confirm_dialog(canvas, state),
        }
    }
}

// ============================================================================
// DRAW FUNCTIONS
// ============================================================================

unsafe fn draw_main_menu(canvas: *mut sys::Canvas, state: &AppState) {
    let title = b"Flipper Zero Crypto Wallet\0";
    let title_height = 8;
    let x_off = 4 - state.title_scroll_offset;
    sys::canvas_draw_str(canvas, x_off, title_height, title.as_ptr() as *const i8);

    sys::canvas_set_font(canvas, sys::FontSecondary);
    sys::canvas_set_color(canvas, sys::ColorBlack);

    // No title on main screen (compact list)
    let items = [
        b"Create Wallet\0",
        b"Import Wallet\0",
        b"View Wallets \0",
        b"Settings     \0",
        b"About        \0",
    ];

    let items_refs: &[&[u8]] = &items.map(|s| s.as_slice());
    draw_menu_list(
        canvas,
        state,
        items_refs,
        5,
        MAIN_MENU_VISIBLE,
        3,
        title_height + 6,
        12,
        state.menu_index,
        state.menu_scroll,
    );
}

unsafe fn draw_create_wallet(canvas: *mut sys::Canvas, state: &AppState) {
    sys::canvas_set_font(canvas, sys::FontSecondary);
    sys::canvas_set_color(canvas, sys::ColorBlack);

    let title = b"Create Flipper Wallet\0";
    let x_off: i32 = 6 - state.title_scroll_offset;
    let title_height = 8;
    sys::canvas_draw_str(canvas, x_off, title_height, title.as_ptr() as *const i8);

    // Original labels
    let orig_items = [
        b"Generate Wallet in Mnemonic Phrase\0",
        b"Generate Wallet in Privatekey     \0",
    ];
    // Compute drawing box width like draw_menu_list
    const DISPLAY_WIDTH: i32 = 128;
    let margin: i32 = 3;
    let box_width = (DISPLAY_WIDTH - margin - SCROLLBAR_WIDTH - 2).max(16) as i32;
    let char_w: i32 = 6;
    let text_padding: i32 = 12; // margin+some padding used when drawing text
    let max_chars_visible = core::cmp::max(1, (box_width - text_padding) / char_w) as usize;

    // Build temporary shifted items with simple char-level bounce scrolling using title_scroll_tick
    let mut scratch: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
    for item in &orig_items {
        let s = match core::str::from_utf8(*item) {
            Ok(t) => t.trim_end_matches(char::from(0)).trim(),
            Err(_) => "",
        };
        let slen = s.len();
        if slen <= max_chars_visible {
            let mut v = alloc::vec::Vec::from(s.as_bytes());
            v.push(0);
            scratch.push(v);
            continue;
        }
        let max_offset = slen - max_chars_visible;
        let tick = (state.title_scroll_tick / 8) as usize;
        let cycle = max_offset * 2;
        let pos = if cycle > 0 { tick % cycle } else { 0 };
        let offset = if pos > max_offset { cycle - pos } else { pos };
        let end = core::cmp::min(offset + max_chars_visible, slen);
        let substr = &s[offset..end];
        let mut v = alloc::vec::Vec::from(substr.as_bytes());
        v.push(0);
        scratch.push(v);
    }
    let mut items_refs: alloc::vec::Vec<&[u8]> = alloc::vec::Vec::new();
    for v in &scratch {
        items_refs.push(v.as_slice());
    }
    draw_menu_list(
        canvas,
        state,
        items_refs.as_slice(),
        2,
        MAIN_MENU_VISIBLE,
        margin,
        title_height + 6,
        12,
        state.menu_index,
        state.menu_scroll,
    );
}

unsafe fn draw_import_wallet(canvas: *mut sys::Canvas, state: &AppState) {
    sys::canvas_set_font(canvas, sys::FontSecondary);
    sys::canvas_set_color(canvas, sys::ColorBlack);

    let title = b"Import Flipper Wallet\0";
    let x_off: i32 = 6 - state.title_scroll_offset;
    let title_height = 8;
    sys::canvas_draw_str(canvas, x_off, title_height, title.as_ptr() as *const i8);

    let items = [
        b"Enter Mnemonic  \0",
        b"Enter Passphrase\0",
        b"Confirm Import  \0",
    ];

    let items_refs: &[&[u8]] = &items.map(|s| s.as_slice());
    draw_menu_list(
        canvas,
        state,
        items_refs,
        3,
        MAIN_MENU_VISIBLE,
        3,
        title_height + 6,
        12,
        state.menu_index,
        state.menu_scroll,
    );

    if state.passphrase_len > 0 {
        sys::canvas_set_color(canvas, sys::ColorBlack);
        sys::canvas_draw_str(canvas, 8, 70, b"Passphrase: Set\0".as_ptr() as *const i8);
    }
}

unsafe fn draw_view_wallets(canvas: *mut sys::Canvas, state: &AppState) {
    sys::canvas_set_font(canvas, sys::FontSecondary);
    sys::canvas_set_color(canvas, sys::ColorBlack);

    // List addresses from current wallet
    let title = b"View Flipper Wallets\0";
    let title_height = 8;
    if state.wallets.is_empty() {
        sys::canvas_draw_str(canvas, 8, title_height, title.as_ptr() as *const i8);
        return;
    }
    let wallet = &state.wallets[state.current_wallet];
    let total = wallet.account_count();

    // draw header title bar
    let title_box_top: i32 = 6;
    let title_box_h: i32 = title_height + 6;
    let display_w: i32 = 128;
    let header_w = (display_w - 6 - SCROLLBAR_WIDTH - 2) as usize;
    sys::canvas_set_color(canvas, sys::ColorBlack);
    sys::canvas_draw_box(canvas, 6, title_box_top, header_w, title_box_h as usize);
    sys::canvas_set_color(canvas, sys::ColorWhite);
    // header text baseline positioned inside header box
    sys::canvas_draw_str(
        canvas,
        8,
        title_box_top + (title_box_h as i32) - 4,
        b"View BTC wallet\0".as_ptr() as *const i8,
    );

    // list starts below header
    let start_y = title_box_top + 16;
    let line_h = 14i32;
    let visible = MAIN_MENU_VISIBLE; // number of visible items
    let mut scroll = state.menu_scroll;
    if state.menu_index < scroll {
        scroll = state.menu_index;
    }
    if state.menu_index >= scroll + visible {
        scroll = state.menu_index - visible + 1;
    }

    for i in 0..visible {
        if scroll + i >= total {
            break;
        }
        let idx = scroll + i;
        let y = start_y + (i as i32) * line_h;

        let box_top = y - 1;
        let box_h = (line_h + 2).max(10);
        if state.menu_index == idx {
            sys::canvas_set_color(canvas, sys::ColorBlack);
            // reserve scrollbar area on the right
            let display_w: i32 = 128;
            let content_w = (display_w - 6 - SCROLLBAR_WIDTH - 2) as usize;
            sys::canvas_draw_box(canvas, 6, box_top, content_w, box_h as usize);
            sys::canvas_set_color(canvas, sys::ColorWhite);
        } else {
            sys::canvas_set_color(canvas, sys::ColorBlack);
        }
        if let Ok(account) = wallet.get_account(idx) {
            let addr = account.address.as_str();
            sys::canvas_draw_str(canvas, 12, y + 2, addr.as_ptr() as *const i8);
        }
    }

    if total > visible {
        draw_scrollbar(canvas, scroll, visible, total, 122, start_y - 2, line_h);
    }
}

unsafe fn draw_settings(canvas: *mut sys::Canvas, state: &AppState) {
    sys::canvas_set_font(canvas, sys::FontSecondary);
    sys::canvas_set_color(canvas, sys::ColorBlack);

    let title = b"Mnemonic Phrase Settings\0";
    let title_box_top: i32 = 6;
    let title_box_h: usize = 12;

    sys::canvas_draw_str(
        canvas,
        title_box_top,
        title_box_top + 3,
        title.as_ptr() as *const i8,
    );

    let word_counts = [12usize, 15, 18, 21, 24];
    let total = 5;
    let visible = SETTINGS_VISIBLE;
    let start_y = title_box_top + title_box_h as i32;
    let line_height = 12i32;

    let mut scroll = state.settings_scroll;
    if state.settings_index < scroll {
        scroll = state.settings_index;
    }
    if state.settings_index >= scroll + visible {
        scroll = state.settings_index - visible + 1;
    }

    for i in 0..visible {
        if scroll + i >= total {
            break;
        }
        let idx = scroll + i;
        let y = start_y + (i as i32) * line_height;

        // compute box dimensions to avoid clipping on different displays
        let display_w: i32 = 128;
        let _box_w = (display_w - 4 - 6).max(16);
        let box_h = (line_height + 2).max(10);
        let box_top = y - 1;

        if state.settings_index == idx {
            sys::canvas_set_color(canvas, sys::ColorBlack);
            // reserve scrollbar area
            let content_w = (display_w - 4 - SCROLLBAR_WIDTH - 2).max(16) as usize;
            sys::canvas_draw_box(canvas, 4, box_top, content_w, box_h as usize);
            sys::canvas_set_color(canvas, sys::ColorWhite);
        } else {
            sys::canvas_set_color(canvas, sys::ColorBlack);
        }

        let checkbox = if state.bip39_word_count == word_counts[idx] {
            b"[X] \0"
        } else {
            b"[ ] \0"
        };

        let label = match word_counts[idx] {
            12 => b"12-word mnemonic\0",
            15 => b"15-word mnemonic\0",
            18 => b"18-word mnemonic\0",
            21 => b"21-word mnemonic\0",
            24 => b"24-word mnemonic\0",
            _ => b"Unknown         \0",
        };

        let text_y = box_top + (box_h as i32) - 6;
        sys::canvas_draw_str(canvas, 8, text_y, checkbox.as_ptr() as *const i8);
        sys::canvas_draw_str(canvas, 28, text_y, label.as_ptr() as *const i8);
    }
    // draw scrollbar if needed
    if total > visible {
        draw_scrollbar(
            canvas,
            scroll,
            visible,
            total,
            122,
            start_y - 2,
            line_height,
        );
    }
}

unsafe fn draw_show_mnemonic(canvas: *mut sys::Canvas, state: &AppState) {
    sys::canvas_set_font(canvas, sys::FontSecondary);
    sys::canvas_set_color(canvas, sys::ColorBlack);

    let title: &[u8] = if state.show_private {
        b"PrivateKey/QR Code\0"
    } else {
        b"Mnemonic Words/QR Code\0"
    };
    let title_height = 8;
    sys::canvas_draw_str(canvas, 8, title_height, title.as_ptr() as *const i8);

    // if creation in progress, show status
    if state.create_in_progress {
        sys::canvas_draw_str(
            canvas,
            8,
            title_height + 24,
            b"Creating...\0".as_ptr() as *const i8,
        );
        return;
    }
    if state.create_error != 0 {
        sys::canvas_draw_str(
            canvas,
            8,
            title_height + 24,
            b"Create failed\0".as_ptr() as *const i8,
        );
        return;
    }

    let mnemonic_str = match core::str::from_utf8(&state.mnemonic_buffer) {
        Ok(s) => s.trim(),
        Err(_) => "",
    };
    // If we're showing a generated private key instead of mnemonic, render that view
    if state.show_private {
        if state.private_key_len == 0 {
            sys::canvas_draw_str(
                canvas,
                8,
                title_height + 30,
                b"No private key\0".as_ptr() as *const i8,
            );
            return;
        }

        // Toggle between hex view and QR view using showing_qr
        if state.showing_qr {
            // Encode private key as hex string for QR compatibility, then encode bytes of that hex string
            let hex_str = hex::encode(&state.private_key[..state.private_key_len]);
            let data = hex_str.as_bytes();
            let ecc_order = [QrCodeEcc::Quartile, QrCodeEcc::Medium, QrCodeEcc::Low];
            let mut qr_opt: Option<QrCode> = None;
            for &ecc in ecc_order.iter() {
                match QrCode::encode_binary(data, ecc) {
                    Ok(qr) => {
                        qr_opt = Some(qr);
                        break;
                    }
                    Err(DataTooLong::DataOverCapacity(_, _)) | Err(DataTooLong::SegmentTooLong) => {
                        continue;
                    }
                }
            }

            // compute render area
            let display_w: i32 = 128;
            let display_h: i32 = 64;
            let top = if state.show_private { title_height + 18 } else { title_height + 12 };
            let bottom_margin = 4;
            let avail_w = display_w - 8;
            let avail_h = display_h - top - bottom_margin;

            if let Some(qr) = qr_opt {
                let size = qr.size() as i32;
                let gap = QR_MODULE_GAP;
                let denom = size + (size - 1) * gap;
                let maybe_cell_w = if denom > 0 { avail_w / denom } else { 0 };
                let maybe_cell_h = if denom > 0 { avail_h / denom } else { 0 };
                let cell = core::cmp::min(maybe_cell_w, maybe_cell_h);
                if cell > 0 {
                    let total_px = size * cell + (size - 1) * gap;
                    let mut qr_x = (display_w - total_px) / 2;
                    let mut qr_y = top + (avail_h - total_px) / 2;
                    if qr_x - QR_BORDER_THICKNESS < 0 {
                        qr_x = QR_BORDER_THICKNESS;
                    }
                    if qr_y - QR_BORDER_THICKNESS < 0 {
                        qr_y = QR_BORDER_THICKNESS;
                    }
                    sys::canvas_set_color(canvas, sys::ColorBlack);
                    let frame_w = core::cmp::min(
                        (total_px + QR_BORDER_THICKNESS * 2) as usize,
                        (display_w - (qr_x - QR_BORDER_THICKNESS)) as usize,
                    );
                    let frame_h = core::cmp::min(
                        (total_px + QR_BORDER_THICKNESS * 2) as usize,
                        (display_h - (qr_y - QR_BORDER_THICKNESS)) as usize,
                    );
                    sys::canvas_draw_frame(
                        canvas,
                        qr_x - QR_BORDER_THICKNESS,
                        qr_y - QR_BORDER_THICKNESS,
                        frame_w,
                        frame_h,
                    );
                    for r in 0..size {
                        for c in 0..size {
                            if qr.get_module(c, r) {
                                let x = qr_x + c * (cell + gap);
                                let y = qr_y + r * (cell + gap);
                                if x >= 0
                                    && y >= 0
                                    && (x + cell) <= display_w
                                    && (y + cell) <= display_h
                                {
                                    sys::canvas_draw_box(
                                        canvas,
                                        x,
                                        y,
                                        cell as usize,
                                        cell as usize,
                                    );
                                }
                            }
                        }
                    }
                    // hint
                    sys::canvas_draw_str(
                        canvas,
                        8,
                        qr_y + total_px + 6,
                        b"Left: Back\0".as_ptr() as *const i8,
                    );
                    return;
                }
            }

            // If we couldn't encode/render QR, show error dialog (no QR)
            let dlg_w: i32 = 120;
            let dlg_h: i32 = 44;
            let dlg_x = (128 - dlg_w) / 2;
            let dlg_y = top + (avail_h - dlg_h) / 2;
            sys::canvas_set_color(canvas, sys::ColorWhite);
            sys::canvas_draw_box(canvas, dlg_x, dlg_y, dlg_w as usize, dlg_h as usize);
            sys::canvas_set_color(canvas, sys::ColorBlack);
            {
                let long_msg = "Cannot encode private key to generate QR Code";
                let char_w: i32 = 6;
                let avail_w = dlg_w - 16; // left/right padding inside dialog
                let max_chars = core::cmp::max(1, (avail_w / char_w) as usize);
                if long_msg.len() <= max_chars {
                    sys::canvas_draw_str(
                        canvas,
                        dlg_x + 8,
                        dlg_y + 8,
                        long_msg.as_ptr() as *const i8,
                    );
                } else {
                    let max_offset = long_msg.len() - max_chars;
                    let tick = (state.title_scroll_tick / 12) as usize;
                    let cycle = max_offset * 2;
                    let pos = if cycle > 0 { tick % cycle } else { 0 };
                    let offset = if pos > max_offset { cycle - pos } else { pos };
                    let end = core::cmp::min(offset + max_chars, long_msg.len());
                    let substr = &long_msg[offset..end];
                    let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::from(substr.as_bytes());
                    buf.push(0);
                    sys::canvas_draw_str(canvas, dlg_x + 8, dlg_y + 8, buf.as_ptr() as *const i8);
                }
            }
            sys::canvas_draw_str(
                canvas,
                dlg_x + 8,
                dlg_y + 22,
                b"Copy manually instead\0".as_ptr() as *const i8,
            );
            sys::canvas_draw_str(
                canvas,
                dlg_x + 8,
                dlg_y + dlg_h - 10,
                b"Left: Back\0".as_ptr() as *const i8,
            );
            // draw frame last so border is not overwritten; draw two nested frames to ensure visibility
            sys::canvas_set_color(canvas, sys::ColorBlack);
            sys::canvas_draw_frame(canvas, dlg_x, dlg_y, dlg_w as usize, dlg_h as usize);
            // inner frame (thicken)
            if dlg_w > 4 && dlg_h > 4 {
                sys::canvas_draw_frame(canvas, dlg_x + 1, dlg_y + 1, (dlg_w - 2) as usize, (dlg_h - 2) as usize);
            }
            return;
        } else {
            // show private key hex with wrapping and vertical scrolling
            let hex_str = hex::encode(&state.private_key[..state.private_key_len]);
            let hex_bytes = hex_str.as_str().as_bytes();
            // Title spacing: 18 pixels below title for private key view
            let label_y = title_height + 18;
            sys::canvas_draw_str(canvas, 8, label_y, b"Private key:\0".as_ptr() as *const i8);
            // compute characters per line based on display width
            let display_w: i32 = 128;
            let char_w: i32 = 6;
            let left_pad: i32 = 8;
            let max_per_line = core::cmp::max(1, ((display_w - left_pad * 2) / char_w) as usize);
            let total_lines = (hex_bytes.len() + max_per_line - 1) / max_per_line;
            // available vertical space for lines: from label_y+12 to bottom (reserve 12)
            let avail_h = 64 - (label_y + 12);
            let line_h = 12i32;
            let visible_lines = core::cmp::max(1, (avail_h / line_h) as usize);
            let mut scroll = state.private_scroll;
            if scroll > total_lines.saturating_sub(visible_lines) {
                scroll = total_lines.saturating_sub(visible_lines);
            }
            // draw visible lines
            for i in 0..visible_lines {
                let line_idx = i + scroll;
                if line_idx >= total_lines {
                    break;
                }
                let start = line_idx * max_per_line;
                let take = core::cmp::min(max_per_line, hex_bytes.len().saturating_sub(start));
                let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
                buf.extend_from_slice(&hex_bytes[start..start + take]);
                buf.push(0);
                let y = label_y + 12 + (i as i32) * line_h;
                sys::canvas_draw_str(canvas, left_pad, y, buf.as_ptr() as *const i8);
            }
            // draw scrollbar if needed (on right)
            if total_lines > visible_lines {
                let track_x = display_w - 6;
                let track_top = label_y + 12;
                draw_scrollbar(canvas, scroll, visible_lines, total_lines, track_x, track_top, line_h);
            }
            return;
        }
    }
    if state.showing_qr {
        if mnemonic_str.is_empty() {
            sys::canvas_draw_str(
                canvas,
                8,
                title_height + 30,
                b"No mnemonic\0".as_ptr() as *const i8,
            );
            return;
        }

        // Attempt to encode real QR using embedded qrcodegen (ECC Q -> M -> L)
        let data = mnemonic_str.as_bytes();
        let ecc_order = [QrCodeEcc::Quartile, QrCodeEcc::Medium, QrCodeEcc::Low];
        let mut qr_opt: Option<QrCode> = None;
        for &ecc in ecc_order.iter() {
            match QrCode::encode_binary(data, ecc) {
                Ok(qr) => {
                    qr_opt = Some(qr);
                    break;
                }
                Err(DataTooLong::DataOverCapacity(_, _)) | Err(DataTooLong::SegmentTooLong) => {
                    // try next lower ECC
                    continue;
                }
            }
        }

        // compute render area (tighten margins to maximize QR area)
        let display_w: i32 = 128;
        let display_h: i32 = 64;
        let top = title_height + 12; // slightly less top padding
        let bottom_margin = 4; // reduce bottom reserved space
        let avail_w = display_w - 8;
        let avail_h = display_h - top - bottom_margin;

        // If encoding succeeded, render real QR with configurable gap/border and a left-arrow icon.
        if let Some(qr) = qr_opt {
            let size = qr.size() as i32;
            let gap = QR_MODULE_GAP;
            // total pixels = size*cell + (size-1)*gap
            let denom_w = size + (size - 1) * gap;
            let denom_h = size + (size - 1) * gap;
            let maybe_cell_w = if denom_w > 0 { avail_w / denom_w } else { 0 };
            let maybe_cell_h = if denom_h > 0 { avail_h / denom_h } else { 0 };
            let cell = core::cmp::min(maybe_cell_w, maybe_cell_h);
            if cell > 0 {
                let total_px = size * cell + (size - 1) * gap;
                let mut qr_x = (display_w - total_px) / 2;
                let mut qr_y = top + (avail_h - total_px) / 2;
                // clamp to bounds
                if qr_x - QR_BORDER_THICKNESS < 0 {
                    qr_x = QR_BORDER_THICKNESS;
                }
                if qr_y - QR_BORDER_THICKNESS < 0 {
                    qr_y = QR_BORDER_THICKNESS;
                }
                if qr_x + total_px + QR_BORDER_THICKNESS > display_w {
                    qr_x = (display_w - total_px - QR_BORDER_THICKNESS).max(QR_BORDER_THICKNESS);
                }
                if qr_y + total_px + QR_BORDER_THICKNESS > display_h - bottom_margin {
                    qr_y = (display_h - bottom_margin - total_px - QR_BORDER_THICKNESS)
                        .max(QR_BORDER_THICKNESS);
                }

                sys::canvas_set_color(canvas, sys::ColorBlack);
                let frame_w = core::cmp::min(
                    (total_px + QR_BORDER_THICKNESS * 2) as usize,
                    (display_w - (qr_x - QR_BORDER_THICKNESS)) as usize,
                );
                let frame_h = core::cmp::min(
                    (total_px + QR_BORDER_THICKNESS * 2) as usize,
                    (display_h - (qr_y - QR_BORDER_THICKNESS)) as usize,
                );
                sys::canvas_draw_frame(
                    canvas,
                    qr_x - QR_BORDER_THICKNESS,
                    qr_y - QR_BORDER_THICKNESS,
                    frame_w,
                    frame_h,
                );

                for r in 0..size {
                    for c in 0..size {
                        if qr.get_module(c, r) {
                            let x = qr_x + c * (cell + gap);
                            let y = qr_y + r * (cell + gap);
                            if x >= 0
                                && y >= 0
                                && (x + cell) <= display_w
                                && (y + cell) <= display_h
                            {
                                sys::canvas_draw_box(canvas, x, y, cell as usize, cell as usize);
                            }
                        }
                    }
                }

                // draw centered back hint below QR
                let hint_y = qr_y + total_px + 4;
                let hint_text = b"Left: Back\0";
                let hint_x = (display_w / 2) - 20;
                // small left-arrow at hint_x, then text
                let arrow_x = hint_x;
                let arrow_y = hint_y - 2;
                sys::canvas_draw_box(canvas, arrow_x, arrow_y, 3, 3);
                sys::canvas_draw_box(canvas, arrow_x - 3, arrow_y + 2, 3, 3);
                sys::canvas_draw_str(canvas, hint_x + 8, hint_y, hint_text.as_ptr() as *const i8);
                return;
            }
        }

        // If encoding failed for all ECC levels or rendering cell==0, show a friendly dialog and a small pseudo-QR preview.
        let dlg_w: i32 = 120;
        let dlg_h: i32 = 48;
        let dlg_x = (128 - dlg_w) / 2;
        let dlg_y = top - 4 + (avail_h - dlg_h) / 2;
        sys::canvas_set_color(canvas, sys::ColorWhite);
        sys::canvas_draw_box(canvas, dlg_x, dlg_y, dlg_w as usize, dlg_h as usize);
        sys::canvas_set_color(canvas, sys::ColorBlack);
        sys::canvas_draw_frame(canvas, dlg_x, dlg_y, dlg_w as usize, dlg_h as usize);
        // Short, wrapped message on left; preview on right
        sys::canvas_draw_str(
            canvas,
            dlg_x + 8,
            dlg_y + 10,
            b"QR too long for ECC=L\0".as_ptr() as *const i8,
        );
        // Scroll the long dialog message if it doesn't fit
        {
            let long_msg = "Reduce words or copy manually";
            let char_w: i32 = 6;
            let avail_w = dlg_w - 16; // left/right padding inside dialog
            let max_chars = core::cmp::max(1, (avail_w / char_w) as usize);
            if long_msg.len() <= max_chars {
                sys::canvas_draw_str(
                    canvas,
                    dlg_x + 8,
                    dlg_y + 25,
                    long_msg.as_ptr() as *const i8,
                );
            } else {
                let max_offset = long_msg.len() - max_chars;
                let tick = (state.title_scroll_tick / 8) as usize;
                let cycle = max_offset * 2;
                let pos = if cycle > 0 { tick % cycle } else { 0 };
                let offset = if pos > max_offset { cycle - pos } else { pos };
                let end = core::cmp::min(offset + max_chars, long_msg.len());
                let substr = &long_msg[offset..end];
                // prepare nul-terminated buffer
                let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::from(substr.as_bytes());
                buf.push(0);
                sys::canvas_draw_str(canvas, dlg_x + 8, dlg_y + 25, buf.as_ptr() as *const i8);
            }
        }

        // back hint below dialog (no QR preview when encoding failed)
        sys::canvas_draw_str(
            canvas,
            dlg_x + 8,
            dlg_y + dlg_h - 6,
            b"Left: Back\0".as_ptr() as *const i8,
        );
        return;
    }

    if mnemonic_str.is_empty() {
        sys::canvas_draw_str(
            canvas,
            6,
            title_height + 24,
            b"No mnemonic\0".as_ptr() as *const i8,
        );
        return;
    }

    // split words
    let mut words: [Option<&str>; 32] = [None; 32];
    let mut wcount = 0usize;
    for word in mnemonic_str.split_whitespace() {
        if wcount < 32 {
            words[wcount] = Some(word);
            wcount += 1;
        } else {
            break;
        }
    }

    let words_per_line = 2usize;
    let total_lines = (wcount + words_per_line - 1) / words_per_line;
    let visible = MNEMONIC_VISIBLE;
    let mut scroll = state.mnemonic_scroll;
    // clamp scroll to valid range
    let max_scroll = if total_lines > visible {
        total_lines - visible
    } else {
        0
    };
    if scroll > max_scroll {
        scroll = max_scroll;
    }

    let start_y = title_height + 16i32;
    let line_h = 12i32;
    for i in 0..visible {
        if scroll + i >= total_lines {
            break;
        }
        let line_index = scroll + i;
        // draw two words per line with numbering, fixed column positions
        let left_x: i32 = 6;
        let left_word_x: i32 = left_x + 18;
        let right_x: i32 = 72;
        let right_word_x: i32 = right_x + 18;
        let y = start_y + (i as i32) * line_h;

        // left word
        let left_idx = line_index * 2;
        if left_idx < wcount {
            if let Some(w) = words[left_idx] {
                // number prefix "N. "
                let s = alloc::format!("{}. ", left_idx + 1);
                let sb = s.as_bytes();
                let mut num_buf: [u8; 8] = [0u8; 8];
                let nlen = core::cmp::min(sb.len(), num_buf.len() - 1);
                num_buf[..nlen].copy_from_slice(&sb[..nlen]);
                num_buf[nlen] = 0;
                sys::canvas_draw_str(canvas, left_x, y, num_buf.as_ptr() as *const i8);

                // word buffer
                let wb = w.as_bytes();
                let mut wbuf: [u8; 48] = [0u8; 48];
                let wlen = core::cmp::min(wb.len(), wbuf.len() - 1);
                wbuf[..wlen].copy_from_slice(&wb[..wlen]);
                wbuf[wlen] = 0;
                sys::canvas_draw_str(canvas, left_word_x, y, wbuf.as_ptr() as *const i8);
            }
        }

        let right_idx = line_index * 2 + 1;
        if right_idx < wcount {
            if let Some(w) = words[right_idx] {
                let s = alloc::format!("{}. ", right_idx + 1);
                let sb = s.as_bytes();
                let mut num_buf: [u8; 8] = [0u8; 8];
                let nlen = core::cmp::min(sb.len(), num_buf.len() - 1);
                num_buf[..nlen].copy_from_slice(&sb[..nlen]);
                num_buf[nlen] = 0;
                sys::canvas_draw_str(canvas, right_x, y, num_buf.as_ptr() as *const i8);

                let wb = w.as_bytes();
                let mut wbuf: [u8; 48] = [0u8; 48];
                let wlen = core::cmp::min(wb.len(), wbuf.len() - 1);
                wbuf[..wlen].copy_from_slice(&wb[..wlen]);
                wbuf[wlen] = 0;
                sys::canvas_draw_str(canvas, right_word_x, y, wbuf.as_ptr() as *const i8);
            }
        }
    }

    if !state.wallets.is_empty() {
        if let Some(wallet) = state.wallets.get(state.current_wallet) {
            let secret_bytes = wallet.master_key.secret_key().as_bytes();
            let hex_str = hex::encode(secret_bytes);
            let hex_bytes = hex_str.as_str().as_bytes();
            let label_y = start_y + (visible as i32) * line_h + 4;
            sys::canvas_draw_str(canvas, 8, label_y, b"Priv key:\0".as_ptr() as *const i8);
            let max_per_line = 32usize;
            let mut pos = 0usize;
            for line in 0..2 {
                if pos >= hex_bytes.len() {
                    break;
                }
                let take = core::cmp::min(max_per_line, hex_bytes.len() - pos);
                // prepare buffer
                let mut buf: [u8; 64] = [0u8; 64];
                let mut j = 0usize;
                for &b in &hex_bytes[pos..pos + take] {
                    buf[j] = b;
                    j += 1;
                }
                buf[j] = 0;
                sys::canvas_draw_str(
                    canvas,
                    8,
                    label_y + ((line as i32) + 1) * line_h,
                    buf.as_ptr() as *const i8,
                );
                pos += take;
            }
            // if QR view requested, draw an encoded pseudo-QR (representing full mnemonic)
            if state.showing_qr {
                // build data: full mnemonic string
                let mnemonic = match core::str::from_utf8(&state.mnemonic_buffer) {
                    Ok(s) => s.trim(),
                    Err(_) => "",
                };
                draw_pseudo_qr(canvas, 80, 24, 2, 21, mnemonic.as_bytes());
                sys::canvas_draw_str(
                    canvas,
                    8,
                    label_y + ((2 as i32) + 2) * line_h,
                    b"Left: Back to words\0".as_ptr() as *const i8,
                );
            } else {
                sys::canvas_draw_box(canvas, 90, 24, 36, 36);
                sys::canvas_draw_str(canvas, 92, 26, b"QR\0".as_ptr() as *const i8);
            }
        }
    }
}

unsafe fn draw_pseudo_qr(
    canvas: *mut sys::Canvas,
    origin_x: i32,
    origin_y: i32,
    cell: i32,
    grid_size: usize,
    data: &[u8],
) {
    use crate::sha256::Sha256;
    // derive a hash to mix with data
    let hash = Sha256::digest(data);
    // create bitstream from hash then data
    let mut bits: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    bits.extend_from_slice(&hash);
    bits.extend_from_slice(data);
    // draw border
    let total_px = (grid_size as i32) * cell;
    sys::canvas_set_color(canvas, sys::ColorBlack);
    sys::canvas_draw_frame(
        canvas,
        origin_x - 2,
        origin_y - 2,
        (total_px + 4) as usize,
        (total_px + 4) as usize,
    );
    // fill modules
    for r in 0..grid_size {
        for c in 0..grid_size {
            let bit_index = r * grid_size + c;
            let byte_index = bit_index / 8;
            let bit_in_byte = 7 - (bit_index % 8);
            let v = if byte_index < bits.len() {
                ((bits[byte_index] >> bit_in_byte) & 1) != 0
            } else {
                false
            };
            if v {
                let x = origin_x + (c as i32) * cell;
                let y = origin_y + (r as i32) * cell;
                sys::canvas_draw_box(canvas, x, y, cell as usize, cell as usize);
            }
        }
    }
}

unsafe fn draw_about(canvas: *mut sys::Canvas, state: &AppState) {
    sys::canvas_set_font(canvas, sys::FontSecondary);
    sys::canvas_set_color(canvas, sys::ColorBlack);

    let title_height = 10;
    let x_off: i32 = 8 - state.title_scroll_offset;
    sys::canvas_draw_str(
        canvas,
        x_off,
        title_height,
        b"Flipper Zero Crypto Wallet\0".as_ptr() as *const i8,
    );
    sys::canvas_draw_str(
        canvas,
        x_off,
        title_height + 16,
        b"Version 1.0.0\0".as_ptr() as *const i8,
    );
    sys::canvas_draw_str(
        canvas,
        x_off,
        title_height + 16 * 2,
        b"Written by Blueokanna\0".as_ptr() as *const i8,
    );
    sys::canvas_draw_str(
        canvas,
        x_off,
        title_height + 16 * 3,
        b"Developed in Rust\0".as_ptr() as *const i8,
    );
}

unsafe fn draw_confirm_dialog(canvas: *mut sys::Canvas, state: &AppState) {
    sys::canvas_set_font(canvas, sys::FontSecondary);
    sys::canvas_set_color(canvas, sys::ColorBlack);

    let msg = match state.confirm_action {
        ConfirmAction::DeleteWallet => b"Delete wallet?     \0",
        ConfirmAction::ExportMnemonic => b"Export mnemonic?   \0",
        ConfirmAction::ClearPassphrase => b"Clear passphrase   \0",
        ConfirmAction::RevealPrivate => b"Reveal Private Key?\0",
        ConfirmAction::None => b"Confirm?           \0",
    };

    sys::canvas_draw_str(canvas, 8, 8, msg.as_ptr() as *const i8);
    let options = ["Yes", "No"];
    let display_w: i32 = 128;
    let spacing: i32 = 8;
    let total_w = display_w - 16;
    let box_w = (total_w - spacing) / 2;
    let box_h = 18i32;
    let box_top = 50i32;
    for (i, &label) in options.iter().enumerate() {
        let x = 8 + i as i32 * (box_w + spacing);
        // draw selection background or frame
        if state.confirm_index == i {
            sys::canvas_set_color(canvas, sys::ColorBlack);
            sys::canvas_draw_box(canvas, x, box_top, box_w as usize, box_h as usize);
            sys::canvas_set_color(canvas, sys::ColorWhite);
        } else {
            sys::canvas_set_color(canvas, sys::ColorBlack);
            sys::canvas_draw_frame(canvas, x, box_top, box_w as usize, box_h as usize);
        }
        // prepare nul-terminated label buffer
        let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::from(label.as_bytes());
        buf.push(0);
        // compute text width and center it
        let text_w = (label.len() as i32) * 6;
        let mut text_x = x + (box_w / 2) - (text_w / 2);
        if text_x < x + 2 {
            text_x = x + 2;
        }
        let half_h = box_h / 2;
        let text_y = box_top + half_h - 1;
        sys::canvas_draw_str(canvas, text_x, text_y, buf.as_ptr() as *const i8);
    }
}

// Standard scrollbar used by list draw functions
unsafe fn draw_scrollbar(
    canvas: *mut sys::Canvas,
    scroll: usize,
    visible: usize,
    total: usize,
    track_x: i32,
    track_top: i32,
    line_h: i32,
) {
    if total <= visible {
        return;
    }
    // dotted track style similar to Flipper UI
    let track_h = (visible as i32) * line_h;
    // draw dotted track
    for y in (track_top..(track_top + track_h)).step_by(3) {
        sys::canvas_set_color(canvas, sys::ColorBlack);
        sys::canvas_draw_box(canvas, track_x + 1, y, 1, 1);
    }
    // draw thumb
    let thumb_h = core::cmp::max(6, track_h * (visible as i32) / (total as i32));
    let travel = track_h - thumb_h;
    let thumb_off = if total > visible {
        (travel * (scroll as i32)) / ((total - visible) as i32)
    } else {
        0
    };
    sys::canvas_set_color(canvas, sys::ColorBlack);
    let thumb_top = track_top + 1 + thumb_off;
    sys::canvas_draw_box(canvas, track_x, thumb_top, 4, thumb_h as usize);
}

unsafe fn draw_menu_list(
    canvas: *mut sys::Canvas,
    _state: &AppState,
    items: &[&[u8]],
    count: usize,
    visible: usize,
    margin: i32,
    start_y: i32,
    line_h: i32,
    selected_index: usize,
    scroll_index: usize,
) {
    // Compute scroll so selected index stays visible (use provided indices)
    let mut scroll = scroll_index;
    if selected_index < scroll {
        scroll = selected_index;
    }
    if selected_index >= scroll + visible {
        scroll = selected_index - visible + 1;
    }

    // Layout helpers
    const DISPLAY_WIDTH: i32 = 128;
    // reserve space for scrollbar on the right
    let box_width = (DISPLAY_WIDTH - margin - SCROLLBAR_WIDTH - 2).max(16);
    let box_height = (line_h + 2).max(10);

    for i in 0..visible {
        if scroll + i >= count {
            break;
        }
        let idx = scroll + i;
        let y = start_y + (i as i32) * line_h;

        // draw selection box: top at y-1, height = line_h + 2, text drawn at y+2
        let box_top = y - 1;
        if selected_index == idx {
            sys::canvas_set_color(canvas, sys::ColorBlack);
            sys::canvas_draw_box(
                canvas,
                margin,
                box_top,
                box_width as usize,
                box_height as usize,
            );
            sys::canvas_set_color(canvas, sys::ColorWhite);
        } else {
            sys::canvas_set_color(canvas, sys::ColorBlack);
        }
        // draw text baseline inside the box (baseline is measured from top)
        let text_y = box_top + box_height as i32 - 4;
        sys::canvas_draw_str(canvas, margin + 6, text_y, items[idx].as_ptr() as *const i8);
    }
    // draw scrollbar if needed
    if count > visible {
        let track_x = DISPLAY_WIDTH - 6;
        let track_top = start_y - 2;
        draw_scrollbar(canvas, scroll, visible, count, track_x, track_top, line_h);
    }
}

extern "C" fn input_callback(event: *mut sys::InputEvent, ctx: *mut c_void) {
    unsafe {
        if event.is_null() || ctx.is_null() {
            return;
        }

        let evt = &*event;
        let state = ctx as *mut AppState;
        if state.is_null() {
            return;
        }
        let state = &mut *state;

        if evt.type_ != sys::InputTypePress {
            return;
        }

        match state.current_screen {
            Screen::MainMenu => handle_main_menu(state, evt),
            Screen::CreateWallet => handle_create_wallet(state, evt),
            Screen::ImportWallet => handle_import_wallet(state, evt),
            Screen::ViewWallets => handle_view_wallets(state, evt),
            Screen::Settings => handle_settings(state, evt),
            Screen::ShowMnemonic => handle_show_mnemonic(state, evt),
            Screen::About => handle_about(state, evt),
            Screen::ConfirmAction => handle_confirm(state, evt),
        }
    }
}

fn handle_main_menu(state: &mut AppState, evt: &sys::InputEvent) {
    match evt.key {
        sys::InputKeyUp => {
            if state.menu_index > 0 {
                state.menu_index -= 1;
            }
        }
        sys::InputKeyDown => {
            if state.menu_index < 4 {
                state.menu_index += 1;
            }
        }
        sys::InputKeyOk => match state.menu_index {
            0 => state.current_screen = Screen::CreateWallet,
            1 => {
                state.current_screen = Screen::ImportWallet;
                state.menu_index = 0;
            }
            2 => {
                state.current_screen = Screen::ViewWallets;
                state.menu_index = 0;
            }
            3 => {
                state.current_screen = Screen::Settings;
                state.settings_index = 0;
            }
            4 => state.current_screen = Screen::About,
            _ => {}
        },
        sys::InputKeyBack => state.exit_requested = true,
        _ => {}
    }
}

fn handle_create_wallet(state: &mut AppState, evt: &sys::InputEvent) {
    match evt.key {
        sys::InputKeyUp => {
            if state.menu_index > 0 {
                state.menu_index -= 1;
            }
        }
        sys::InputKeyDown => {
            if state.menu_index < 1 {
                state.menu_index += 1;
            }
        }
        sys::InputKeyOk => {
            // request creation; actual heavy crypto runs in app_main loop
            state.create_error = 0;
            if state.menu_index == 0 {
                // mnemonic generation
                state.create_private_requested = false;
                state.create_requested = true;
            } else {
                // private key generation
                state.create_private_requested = true;
                state.create_requested = true;
            }
            state.show_private = state.create_private_requested;
            state.current_screen = Screen::ShowMnemonic;
            state.menu_index = 0;
        }
        sys::InputKeyBack => {
            state.current_screen = Screen::MainMenu;
            state.menu_index = 0;
        }
        _ => {}
    }
}

fn handle_import_wallet(state: &mut AppState, evt: &sys::InputEvent) {
    match evt.key {
        sys::InputKeyUp => {
            if state.menu_index > 0 {
                state.menu_index -= 1;
            }
        }
        sys::InputKeyDown => {
            if state.menu_index < 2 {
                state.menu_index += 1;
            }
        }
        sys::InputKeyOk => match state.menu_index {
            0 => state.input_mode = InputMode::TextInput,
            1 => {}
            2 => {
                state.current_screen = Screen::ViewWallets;
                state.menu_index = 0;
            }
            _ => {}
        },
        sys::InputKeyBack => {
            state.current_screen = Screen::MainMenu;
            state.menu_index = 1;
            state.clear_mnemonic();
            state.clear_passphrase();
        }
        _ => {}
    }
}

fn handle_view_wallets(state: &mut AppState, evt: &sys::InputEvent) {
    match evt.key {
        sys::InputKeyUp => {
            if state.menu_index > 0 {
                state.menu_index -= 1;
            }
        }
        sys::InputKeyDown => {
            // clamp to number of accounts in current wallet
            if let Some(wallet) = state.wallets.get(state.current_wallet) {
                if state.menu_index + 1 < wallet.account_count() {
                    state.menu_index += 1;
                }
            }
        }
        sys::InputKeyBack => {
            state.current_screen = Screen::MainMenu;
            state.menu_index = 2;
        }
        _ => {}
    }
}

fn handle_settings(state: &mut AppState, evt: &sys::InputEvent) {
    match evt.key {
        sys::InputKeyUp => {
            if state.settings_index > 0 {
                state.settings_index -= 1;
            }
        }
        sys::InputKeyDown => {
            if state.settings_index < 4 {
                state.settings_index += 1;
            }
        }
        sys::InputKeyOk => {
            let counts = [12, 15, 18, 21, 24];
            state.bip39_word_count = counts[state.settings_index];
        }
        sys::InputKeyBack => {
            state.current_screen = Screen::MainMenu;
            state.menu_index = 3;
        }
        _ => {}
    }
}

fn handle_show_mnemonic(state: &mut AppState, evt: &sys::InputEvent) {
    match evt.key {
        sys::InputKeyBack => {
            state.current_screen = Screen::MainMenu;
            state.menu_index = 0;
            state.clear_mnemonic();
        }
        sys::InputKeyUp => {
            if state.show_private {
                if state.private_scroll > 0 {
                    state.private_scroll -= 1;
                }
            } else {
                if state.mnemonic_scroll > 0 {
                    state.mnemonic_scroll -= 1;
                }
            }
        }
        sys::InputKeyDown => {
            // only increment if not at max scroll
            if state.show_private {
                // compute total lines for private key view
                let hex_str = hex::encode(&state.private_key[..state.private_key_len]);
                let display_w: i32 = 128;
                let char_w: i32 = 6;
                let left_pad: i32 = 8;
                let max_per_line = core::cmp::max(1, ((display_w - left_pad * 2) / char_w) as usize);
                let total_lines = (hex_str.as_bytes().len() + max_per_line - 1) / max_per_line;
                let avail_h = 64 - ((8 + 12) + 12); // title_height + label_y + reserve
                let line_h = 12usize;
                let visible = core::cmp::max(1, (avail_h as usize) / line_h);
                let max_scroll = if total_lines > visible { total_lines - visible } else { 0 };
                if state.private_scroll < max_scroll {
                    state.private_scroll += 1;
                }
            } else {
                let mnemonic_str = match core::str::from_utf8(&state.mnemonic_buffer) {
                    Ok(s) => s.trim(),
                    Err(_) => "",
                };
                if !mnemonic_str.is_empty() {
                    let mut wcount = 0usize;
                    for _ in mnemonic_str.split_whitespace() {
                        wcount += 1;
                    }
                    let total_lines = (wcount + 1) / 2;
                    let visible = MNEMONIC_VISIBLE;
                    let max_scroll = if total_lines > visible {
                        total_lines - visible
                    } else {
                        0
                    };
                    if state.mnemonic_scroll < max_scroll {
                        state.mnemonic_scroll += 1;
                    }
                }
            }
        }
        sys::InputKeyRight => {
            if state.show_private {
                state.showing_qr = true;
            } else {
                // show QR of full mnemonic
                state.showing_qr = true;
            }
        }
        sys::InputKeyLeft => {
            // if QR is showing, return to words view; otherwise go back
            if state.showing_qr {
                state.showing_qr = false;
            } else {
                state.current_screen = Screen::MainMenu;
                state.menu_index = 0;
            }
        }
        _ => {}
    }
}

fn handle_about(state: &mut AppState, evt: &sys::InputEvent) {
    match evt.key {
        sys::InputKeyBack => {
            state.current_screen = Screen::MainMenu;
            state.menu_index = 4;
        }
        _ => {}
    }
}

fn handle_confirm(state: &mut AppState, evt: &sys::InputEvent) {
    match evt.key {
        // allow both up/down and left/right for compatibility, but prefer left/right for selection
        sys::InputKeyLeft => state.confirm_index = 0,
        sys::InputKeyRight => state.confirm_index = 1,
        sys::InputKeyUp => state.confirm_index = 0,
        sys::InputKeyDown => state.confirm_index = 1,
        sys::InputKeyOk => {
            if state.confirm_index == 0 {
                match state.confirm_action {
                    ConfirmAction::ClearPassphrase => state.clear_passphrase(),
                    ConfirmAction::RevealPrivate => {
                        // user confirmed revealing private key; show private view
                        state.show_private = true;
                        state.current_screen = Screen::ShowMnemonic;
                    }
                    _ => {}
                }
            }
            // If the confirm action was RevealPrivate and user confirmed, keep ShowMnemonic.
            // Otherwise return to main menu.
            if state.confirm_action != ConfirmAction::RevealPrivate || state.confirm_index != 0 {
                state.current_screen = Screen::MainMenu;
            }
            state.confirm_action = ConfirmAction::None;
        }
        sys::InputKeyBack => {
            state.current_screen = Screen::MainMenu;
            state.confirm_action = ConfirmAction::None;
        }
        _ => {}
    }
}
