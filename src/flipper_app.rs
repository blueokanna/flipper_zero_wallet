use core::ffi::c_void;
use flipperzero_sys as sys;
extern crate alloc;
use super::qrcodegen::{DataTooLong, QrCode, QrCodeEcc};
use crate::bip39::{entropy_to_mnemonic, MnemonicType};
use crate::flipper_wallet_core::Wallet;
use crate::hex;
use crate::trng;
use crate::word_list::ENGLISH_WORD_LIST;
use alloc::vec::Vec;

const MAX_MNEMONIC_LEN: usize = 256;
const MAX_PASSPHRASE_LEN: usize = 64;
const MAIN_MENU_VISIBLE: usize = 4;
const SETTINGS_VISIBLE: usize = 4;
const MNEMONIC_VISIBLE: usize = 4;
const SUGGESTION_MAX: usize = 8;
const SUGGESTION_VISIBLE: usize = 4;
// (multi-row keyboard definitions removed; using physical-key mapping CHARSET instead)

// linear charset used when no suggestions present (letters, dash, underscore, space, digits)
const CHARSET: [&str; 39] = [
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s",
    "t", "u", "v", "w", "x", "y", "z", "-", "_", " ", "0", "1", "2", "3", "4", "5", "6", "7", "8",
    "9",
];

// helper functions for previous on-screen keyboard removed
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
    SaveWallet = 5,
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
    // last saved AES password (shown once to user after saving to SD)
    pub last_saved_aes: [u8; 32],
    pub last_saved_aes_len: usize,
    pub last_saved_path: alloc::string::String,
    // Wallet storage
    pub wallets: Vec<Wallet>,
    pub current_wallet: usize,
    // Import flow state
    pub import_words: Vec<alloc::string::String>,
    pub import_word_index: usize,
    pub import_total_words: usize,
    pub selecting_word: bool,
    pub wordlist_index: usize,
    pub wordlist_scroll: usize,
    // Suggestions for text entry (prefix search over ENGLISH_WORD_LIST)
    pub suggestion_indices: [usize; SUGGESTION_MAX],
    pub suggestion_count: usize,
    pub suggestion_total: usize,
    pub suggestion_selected: usize,
    // whether we're editing the BIP39 passphrase instead of a mnemonic word
    pub editing_passphrase: bool,
    // whether to use the system keyboard/dialog for text entry (hide custom hints)
    pub use_system_keyboard: bool,
    // one-shot shift (Aa) state for keyboard (uppercase next char)
    pub shift_enabled: bool,
    // on-screen keyboard index for TextInput
    pub keyboard_index: usize,
    // index into CHARSET when no suggestions present
    pub char_index: usize,
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
    // Background save flags to avoid doing heavy work in input callback
    pub save_requested: bool,
    pub save_in_progress: bool,
    pub save_error: i32,
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
            import_words: Vec::new(),
            import_word_index: 0,
            import_total_words: 12,
            selecting_word: false,
            wordlist_index: 0,
            wordlist_scroll: 0,
            suggestion_indices: [0usize; SUGGESTION_MAX],
            suggestion_count: 0,
            suggestion_total: 0,
            suggestion_selected: 0,
            editing_passphrase: false,
            use_system_keyboard: false,
            shift_enabled: false,
            keyboard_index: 0,
            char_index: 0,
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
            save_requested: false,
            save_in_progress: false,
            save_error: 0,
            last_saved_aes: [0u8; 32],
            last_saved_aes_len: 0,
            last_saved_path: alloc::string::String::new(),
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
        let gui = sys::furi_record_open(gui_name.as_ptr() as *const u8);
        if gui.is_null() {
            return -1;
        }

        // Create viewport
        let viewport = sys::view_port_alloc();
        if viewport.is_null() {
            sys::furi_record_close(gui_name.as_ptr() as *const u8);
            return -1;
        }

        // Create state (allocate on heap to avoid stack overflow on constrained device)
        let mut state = alloc::boxed::Box::new(AppState::new());
        let state_ptr = (&mut *state) as *mut AppState as *mut c_void;

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

            // If wallet save was requested from input callback, perform it here (background)
            if state.save_requested && !state.save_in_progress {
                state.save_requested = false;
                state.save_in_progress = true;

                // request a redraw so UI can show "Saving..."
                sys::view_port_update(viewport);

                // Temporarily disable callbacks to avoid concurrent access while saving
                let null_ctx: *mut c_void = core::ptr::null_mut();
                sys::view_port_draw_callback_set(viewport, None, null_ctx);
                sys::view_port_input_callback_set(viewport, None, null_ctx);

                // Perform save: build WalletData from current state
                let mnemonic_str = match core::str::from_utf8(&state.mnemonic_buffer) {
                    Ok(s) => s.trim(),
                    Err(_) => "",
                };
                if !mnemonic_str.is_empty() {
                    let wdata = crate::storage::WalletData {
                        name: alloc::format!("wallet-{}", state.wallets.len() + 1),
                        mnemonic: alloc::string::String::from(mnemonic_str),
                        passphrase: alloc::string::String::from(
                            core::str::from_utf8(&state.passphrase_buffer[..state.passphrase_len])
                                .unwrap_or(""),
                        ),
                        word_count: state.bip39_word_count as u16,
                    };

                    // generate AES passphrase and encrypt
                    let aes_pass = crate::storage::generate_random_passphrase(10);
                    let salt = crate::trng::get_random_salt();
                    let iv = crate::trng::get_random_iv();
                    let file_bytes = crate::storage::save_wallet(&wdata, &aes_pass, &salt, &iv);

                    // build filename
                    let filename = alloc::format!("/ext/apps_data/flipperwallet/wallet_{}.dat\0", state.wallets.len() + 1);
                    // Try to persist using storage::persist_file (caller replaces with platform API)
                    let save_res = crate::storage::persist_file(&filename, &file_bytes);
                    match save_res {
                        Ok(()) => {
                            // record AES pass to show once
                            let apb = aes_pass.as_bytes();
                            let len = core::cmp::min(apb.len(), state.last_saved_aes.len());
                            for i in 0..len {
                                state.last_saved_aes[i] = apb[i];
                            }
                            state.last_saved_aes_len = len;
                            state.last_saved_path = alloc::string::String::from(
                                filename.trim_end_matches(char::from(0)),
                            );
                            // Also add wallet into in-memory list
                            if let Ok(mut wallet) = Wallet::from_mnemonic(
                                wdata.mnemonic.as_str(),
                                wdata.passphrase.as_str(),
                            ) {
                                let _ = wallet.add_account(
                                    crate::address::Cryptocurrency::Bitcoin,
                                    0,
                                    0,
                                );
                                state.wallets.push(wallet);
                                state.current_wallet = state.wallets.len().saturating_sub(1);
                            }
                            state.save_error = 0;
                            // After successful save, go to ViewWallets and show list
                            state.current_screen = Screen::ViewWallets;
                            state.menu_index = 0;
                        }
                        Err(_) => {
                            // persist failed (platform not implemented). Still add wallet to in-memory list
                            if let Ok(mut wallet) = Wallet::from_mnemonic(
                                wdata.mnemonic.as_str(),
                                wdata.passphrase.as_str(),
                            ) {
                                let _ = wallet.add_account(
                                    crate::address::Cryptocurrency::Bitcoin,
                                    0,
                                    0,
                                );
                                state.wallets.push(wallet);
                                state.current_wallet = state.wallets.len().saturating_sub(1);
                            }
                            // mark error but still navigate to ViewWallets so user can see wallet in UI
                            state.save_error = 1;
                            state.current_screen = Screen::ViewWallets;
                            state.menu_index = 0;
                        }
                    }
                } else {
                    state.save_error = 2;
                }

                // Re-enable callbacks
                sys::view_port_draw_callback_set(viewport, Some(draw_callback), state_ptr);
                sys::view_port_input_callback_set(viewport, Some(input_callback), state_ptr);

                state.save_in_progress = false;
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
        sys::furi_record_close(gui_name.as_ptr() as *const u8);

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
    sys::canvas_draw_str(canvas, x_off, title_height, title.as_ptr() as *const u8);

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
    sys::canvas_draw_str(canvas, x_off, title_height, title.as_ptr() as *const u8);

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
    sys::canvas_draw_str(canvas, x_off, title_height, title.as_ptr() as *const u8);

    if state.selecting_word {
        {
            // small stack buffer for "Select word X/Y\0"
            let mut hdr_buf: [u8; 32] = [0u8; 32];
            let prefix = b"Select word ";
            let mut pos = 0usize;
            // copy prefix
            while pos < prefix.len() && pos < hdr_buf.len() - 1 {
                hdr_buf[pos] = prefix[pos];
                pos += 1;
            }
            // write number X
            let mut n = state.import_word_index + 1;
            let mut digits: [u8; 4] = [0u8; 4];
            let mut dlen = 0usize;
            if n == 0 {
                digits[0] = b'0';
                dlen = 1;
            } else {
                while n > 0 && dlen < digits.len() {
                    digits[dlen] = b'0' + (n % 10) as u8;
                    n /= 10;
                    dlen += 1;
                }
            }
            // append digits in correct order
            for i in 0..dlen {
                if pos < hdr_buf.len() - 1 {
                    hdr_buf[pos] = digits[dlen - 1 - i];
                    pos += 1;
                }
            }
            // slash '/'
            if pos < hdr_buf.len() - 1 {
                hdr_buf[pos] = b'/';
                pos += 1;
            }
            // write total words number
            let mut m = state.import_total_words;
            let mut mdigits: [u8; 4] = [0u8; 4];
            let mut mdlen = 0usize;
            if m == 0 {
                mdigits[0] = b'0';
                mdlen = 1;
            } else {
                while m > 0 && mdlen < mdigits.len() {
                    mdigits[mdlen] = b'0' + (m % 10) as u8;
                    m /= 10;
                    mdlen += 1;
                }
            }
            for i in 0..mdlen {
                if pos < hdr_buf.len() - 1 {
                    hdr_buf[pos] = mdigits[mdlen - 1 - i];
                    pos += 1;
                }
            }
            // null-terminate
            if pos < hdr_buf.len() {
                hdr_buf[pos] = 0;
            } else {
                hdr_buf[hdr_buf.len() - 1] = 0;
            }
            sys::canvas_draw_str(canvas, 8, title_height + 6, hdr_buf.as_ptr() as *const u8);
        }

        // show already-entered words inline without heap allocation by drawing each word sequentially
        {
            let mut x = 8i32;
            let y = title_height + 18;
            for i in 0..state.import_total_words {
                if i < state.import_words.len() {
                    let w = state.import_words[i].as_str();
                    if !w.is_empty() {
                        // create small stack buffer for this word
                        let wb = w.as_bytes();
                        let mut buf: [u8; 24] = [0u8; 24];
                        let wlen = core::cmp::min(wb.len(), buf.len() - 1);
                        buf[..wlen].copy_from_slice(&wb[..wlen]);
                        buf[wlen] = 0;
                        sys::canvas_draw_str(canvas, x, y, buf.as_ptr() as *const u8);
                        // advance x by approx char width * (len + 1 space)
                        let adv = ((wlen as i32) * 6) + 6;
                        x += adv;
                        // stop if running out of horizontal space
                        if x > 120 {
                            break;
                        }
                    }
                }
            }
        }

        let total_words = ENGLISH_WORD_LIST.len();
        let visible = MAIN_MENU_VISIBLE;

        let mut scroll = state.wordlist_scroll;
        if state.wordlist_index < scroll {
            scroll = state.wordlist_index;
        }
        if state.wordlist_index >= scroll + visible {
            scroll = state.wordlist_index - visible + 1;
        }

        // draw visible items without heap-allocating the whole list (use small stack buffer per word)
        for i in 0..visible {
            let idx = scroll + i;
            if idx >= total_words {
                break;
            }
            let y = title_height + 28 + (i as i32) * 12;
            let margin = 6;
            // layout similar to draw_menu_list
            let display_w: i32 = 128;
            let box_width = (display_w - margin - SCROLLBAR_WIDTH - 2).max(16);
            let box_h = (12 + 2).max(10);
            let box_top = y - 1;

            if state.wordlist_index == idx {
                sys::canvas_set_color(canvas, sys::ColorBlack);
                sys::canvas_draw_box(canvas, margin, box_top, box_width as usize, box_h as usize);
                sys::canvas_set_color(canvas, sys::ColorWhite);
            } else {
                sys::canvas_set_color(canvas, sys::ColorBlack);
            }

            let w = ENGLISH_WORD_LIST[idx];
            let wb = w.as_bytes();
            // words are short; use a small fixed buffer to create a nul-terminated string
            let mut buf: [u8; 32] = [0u8; 32];
            let wlen = core::cmp::min(wb.len(), buf.len() - 1);
            buf[..wlen].copy_from_slice(&wb[..wlen]);
            buf[wlen] = 0;
            let text_y = box_top + box_h as i32 - 4;
            sys::canvas_draw_str(canvas, margin + 6, text_y, buf.as_ptr() as *const u8);
        }

        // draw scrollbar if needed
        if total_words > visible {
            let track_x = 128 - 6;
            let track_top = title_height + 12;
            draw_scrollbar(canvas, scroll, visible, total_words, track_x, track_top, 12);
        }

        return;
    }

    // If user is typing a word (TextInput), show input field and suggestions
    if state.input_mode == InputMode::TextInput {
        {
            let mut hdr_buf: [u8; 32] = [0u8; 32];
            let prefix = b"Enter word ";
            let mut pos = 0usize;
            while pos < prefix.len() && pos < hdr_buf.len() - 1 {
                hdr_buf[pos] = prefix[pos];
                pos += 1;
            }
            // number
            let mut n = state.import_word_index + 1;
            let mut digits: [u8; 4] = [0u8; 4];
            let mut dlen = 0usize;
            if n == 0 {
                digits[0] = b'0';
                dlen = 1;
            } else {
                while n > 0 && dlen < digits.len() {
                    digits[dlen] = b'0' + (n % 10) as u8;
                    n /= 10;
                    dlen += 1;
                }
            }
            for i in 0..dlen {
                if pos < hdr_buf.len() - 1 {
                    hdr_buf[pos] = digits[dlen - 1 - i];
                    pos += 1;
                }
            }
            // slash and total
            if pos < hdr_buf.len() - 1 {
                hdr_buf[pos] = b'/';
                pos += 1;
            }
            let mut m = state.import_total_words;
            let mut mdigits: [u8; 4] = [0u8; 4];
            let mut mdlen = 0usize;
            if m == 0 {
                mdigits[0] = b'0';
                mdlen = 1;
            } else {
                while m > 0 && mdlen < mdigits.len() {
                    mdigits[mdlen] = b'0' + (m % 10) as u8;
                    m /= 10;
                    mdlen += 1;
                }
            }
            for i in 0..mdlen {
                if pos < hdr_buf.len() - 1 {
                    hdr_buf[pos] = mdigits[mdlen - 1 - i];
                    pos += 1;
                }
            }
            if pos < hdr_buf.len() {
                hdr_buf[pos] = 0;
            } else {
                hdr_buf[hdr_buf.len() - 1] = 0;
            }
            sys::canvas_draw_str(canvas, 8, title_height + 12, hdr_buf.as_ptr() as *const u8);
        }

        // current fragment (show passphrase buffer when editing_passphrase)
        let frag = if state.editing_passphrase {
            match core::str::from_utf8(&state.passphrase_buffer[..state.passphrase_len]) {
                Ok(s) => s,
                Err(_) => "",
            }
        } else {
            if state.import_words.len() > state.import_word_index {
                state.import_words[state.import_word_index].as_str()
            } else {
                ""
            }
        };
        {
            let mut buf: [u8; 64] = [0u8; 64];
            let fb = frag.as_bytes();
            let blen = core::cmp::min(fb.len(), buf.len() - 1);
            buf[..blen].copy_from_slice(&fb[..blen]);
            buf[blen] = 0;
            sys::canvas_draw_str(canvas, 8, title_height + 12 * 2, buf.as_ptr() as *const u8);
        }

        // compute prefix suggestions locally (no heap) unless the input handler already populated state.suggestion_*
        let mut local_indices: [usize; SUGGESTION_MAX] = [0usize; SUGGESTION_MAX];
        let mut local_count: usize = 0;
        let mut total_matches: usize = 0;
        if state.editing_passphrase {
            // no suggestions when editing passphrase
            local_count = 0;
            total_matches = 0;
        } else if state.suggestion_count > 0 {
            // use state-provided suggestions (kept up-to-date by input handler)
            for i in 0..state.suggestion_count {
                if i < SUGGESTION_MAX {
                    local_indices[i] = state.suggestion_indices[i];
                }
            }
            local_count = state.suggestion_count;
            total_matches = state.suggestion_total;
        } else {
            let prefix = frag.trim();
            let pbytes = prefix.as_bytes();
            let plen = pbytes.len();
            if plen >= 2 {
                for (i, &w) in ENGLISH_WORD_LIST.iter().enumerate() {
                    let wb = w.as_bytes();
                    if wb.len() < plen {
                        continue;
                    }
                    let mut matched = true;
                    for j in 0..plen {
                        // case-insensitive ASCII compare (word list is lowercase)
                        let a = wb[j];
                        let b = pbytes[j];
                        let b_lower = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
                        if a != b_lower {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        if local_count < SUGGESTION_MAX {
                            local_indices[local_count] = i;
                            local_count += 1;
                        }
                        total_matches += 1;
                    }
                }
            }
        }

        // draw suggestion list (highlighted by state.suggestion_selected)
        // compute available vertical space for suggestions so they don't overlap the char/hints area
        let display_h: i32 = 64;
        let char_area_top: i32 = display_h - 18; // area used by Char/hints
        let suggestion_top: i32 = title_height + 30;
        let visible: usize;
        if char_area_top > suggestion_top + 4 {
            let avail = char_area_top - suggestion_top - 4;
            visible = core::cmp::min((avail / 12) as usize, SUGGESTION_VISIBLE);
        } else {
            visible = 0;
        }
        for i in 0..core::cmp::min(local_count, visible) {
            let idx = local_indices[i];
            let y = suggestion_top + (i as i32) * 12;
            let margin = 8;
            let box_top = y - 1;
            let box_h = (12 + 2).max(10);
            if state.suggestion_selected == i {
                sys::canvas_set_color(canvas, sys::ColorBlack);
                let display_w: i32 = 128;
                let box_width = (display_w - margin - SCROLLBAR_WIDTH - 2).max(16);
                sys::canvas_draw_box(canvas, margin, box_top, box_width as usize, box_h as usize);
                sys::canvas_set_color(canvas, sys::ColorWhite);
            } else {
                sys::canvas_set_color(canvas, sys::ColorBlack);
            }
            let w = ENGLISH_WORD_LIST[idx];
            let wb = w.as_bytes();
            let mut buf: [u8; 32] = [0u8; 32];
            let wlen = core::cmp::min(wb.len(), buf.len() - 1);
            buf[..wlen].copy_from_slice(&wb[..wlen]);
            buf[wlen] = 0;
            let text_y = box_top + box_h as i32 - 4;
            sys::canvas_draw_str(canvas, margin + 6, text_y, buf.as_ptr() as *const u8);
        }

        // if no room to draw suggestion rows but there are matches, show compact status line
        if visible == 0 && total_matches > 0 {
            let mut status_buf: [u8; 32] = [0u8; 32];
            let status = b"Matches: ";
            let mut pos = 0usize;
            while pos < status.len() && pos < status_buf.len() - 1 {
                status_buf[pos] = status[pos];
                pos += 1;
            }
            // append count as decimal (capped)
            let mut n = core::cmp::min(total_matches, 999);
            let mut digits: [u8; 4] = [0u8; 4];
            let mut dlen = 0usize;
            if n == 0 {
                digits[0] = b'0';
                dlen = 1;
            } else {
                while n > 0 && dlen < digits.len() {
                    digits[dlen] = b'0' + (n % 10) as u8;
                    n /= 10;
                    dlen += 1;
                }
            }
            for i in 0..dlen {
                if pos < status_buf.len() - 1 {
                    status_buf[pos] = digits[dlen - 1 - i];
                    pos += 1;
                }
            }
            status_buf[pos] = 0;
            sys::canvas_set_color(canvas, sys::ColorBlack);
            sys::canvas_draw_str(canvas, 8, suggestion_top, status_buf.as_ptr() as *const u8);
        } else if visible > 0 && total_matches > visible {
            let track_x = 128 - 6;
            let track_top = suggestion_top - 2;
            draw_scrollbar(canvas, 0, visible, total_matches, track_x, track_top, 12);
        }
        // show current selected character (when no suggestions) and simple hints for physical-key mapping (Scheme A)
        // When using the system keyboard/dialog, hide the custom character selector/hints.
        if !state.use_system_keyboard {
            let display_h: i32 = 64;
            let y = display_h - 18;
            // draw label "Char:" and selected char
            sys::canvas_set_color(canvas, sys::ColorBlack);
            sys::canvas_draw_str(canvas, 8, y, b"Char:\0".as_ptr() as *const u8);
            // selected char
            let mut cb: [u8; 8] = [0u8; 8];
            let ch = CHARSET[state.char_index];
            let chb = ch.as_bytes();
            let clen = core::cmp::min(chb.len(), cb.len() - 1);
            cb[..clen].copy_from_slice(&chb[..clen]);
            cb[clen] = 0;
            sys::canvas_draw_str(canvas, 40, y, cb.as_ptr() as *const u8);
            // hints (short)
            sys::canvas_draw_str(
                canvas,
                8,
                y + 12,
                b"Up/Down: cand/char  Left: Del\0".as_ptr() as *const u8,
            );
            sys::canvas_draw_str(
                canvas,
                8,
                y + 24,
                b"OK: Insert  Right: Accept  Back: Exit\0".as_ptr() as *const u8,
            );
        }

        return;
    }

    // default import menu
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
        sys::canvas_draw_str(canvas, 8, 70, b"Passphrase: Set\0".as_ptr() as *const u8);
    }
}

unsafe fn draw_view_wallets(canvas: *mut sys::Canvas, state: &AppState) {
    sys::canvas_set_font(canvas, sys::FontSecondary);
    sys::canvas_set_color(canvas, sys::ColorBlack);

    // List addresses from current wallet
    let title = b"View Flipper Wallets\0";
    let title_height = 8;
    sys::canvas_draw_str(canvas, 8, title_height, title.as_ptr() as *const u8);
    if state.wallets.is_empty() {
        // draw centered "No Wallet Available"
        let msg = b"No Wallet Available\0";
        let char_w: i32 = 6;
        let display_w: i32 = 128;
        let text_w = ( (msg.len()-1) as i32 ) * char_w;
        let x = (display_w - text_w) / 2;
        let y = title_height + 20;
        sys::canvas_draw_str(canvas, x, y, msg.as_ptr() as *const u8);
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
        b"View BTC wallet\0".as_ptr() as *const u8,
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
            sys::canvas_draw_str(canvas, 12, y + 2, addr.as_ptr() as *const u8);
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
        title.as_ptr() as *const u8,
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
        sys::canvas_draw_str(canvas, 8, text_y, checkbox.as_ptr() as *const u8);
        sys::canvas_draw_str(canvas, 28, text_y, label.as_ptr() as *const u8);
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
    sys::canvas_draw_str(canvas, 8, title_height, title.as_ptr() as *const u8);

    // if creation in progress, show status
    if state.create_in_progress {
        sys::canvas_draw_str(
            canvas,
            8,
            title_height + 24,
            b"Creating...\0".as_ptr() as *const u8,
        );
        return;
    }
    // If we just saved a wallet to SD and have an AES shown-once password, display it here
    if state.last_saved_aes_len > 0 {
        // show saved path and AES password (warning: shown only once)
        let mut path_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        path_buf.extend_from_slice(b"Saved: ");
        path_buf.extend_from_slice(state.last_saved_path.as_bytes());
        path_buf.push(0);
        sys::canvas_draw_str(canvas, 8, title_height + 24, path_buf.as_ptr() as *const u8);

        let mut aes_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        aes_buf.extend_from_slice(b"AES: ");
        for i in 0..state.last_saved_aes_len {
            aes_buf.push(state.last_saved_aes[i]);
        }
        aes_buf.push(0);
        sys::canvas_draw_str(canvas, 8, title_height + 36, aes_buf.as_ptr() as *const u8);
        sys::canvas_draw_str(canvas, 8, title_height + 48, b"Write down AES password (shown once)\0".as_ptr() as *const u8);
        // Note: we do not clear the stored AES here because draw callbacks are immutable;
        // it will be cleared when the user navigates away (in input handlers).
        return;
    }
    if state.create_error != 0 {
        sys::canvas_draw_str(
            canvas,
            8,
            title_height + 24,
            b"Create failed\0".as_ptr() as *const u8,
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
                b"No private key\0".as_ptr() as *const u8,
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
            let top = if state.show_private {
                title_height + 18
            } else {
                title_height + 12
            };
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
                        b"Left: Back\0".as_ptr() as *const u8,
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
                        long_msg.as_ptr() as *const u8,
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
                    sys::canvas_draw_str(canvas, dlg_x + 8, dlg_y + 8, buf.as_ptr() as *const u8);
                }
            }
            sys::canvas_draw_str(
                canvas,
                dlg_x + 8,
                dlg_y + 22,
                b"Copy manually instead\0".as_ptr() as *const u8,
            );
            sys::canvas_draw_str(
                canvas,
                dlg_x + 8,
                dlg_y + dlg_h - 10,
                b"Left: Back\0".as_ptr() as *const u8,
            );
            // draw frame last so border is not overwritten; draw two nested frames to ensure visibility
            sys::canvas_set_color(canvas, sys::ColorBlack);
            sys::canvas_draw_frame(canvas, dlg_x, dlg_y, dlg_w as usize, dlg_h as usize);
            // inner frame (thicken)
            if dlg_w > 4 && dlg_h > 4 {
                sys::canvas_draw_frame(
                    canvas,
                    dlg_x + 1,
                    dlg_y + 1,
                    (dlg_w - 2) as usize,
                    (dlg_h - 2) as usize,
                );
            }
            return;
        } else {
            // show private key hex with wrapping and vertical scrolling
            let hex_str = hex::encode(&state.private_key[..state.private_key_len]);
            let hex_bytes = hex_str.as_str().as_bytes();
            // Title spacing: 18 pixels below title for private key view
            let label_y = title_height + 18;
            sys::canvas_draw_str(canvas, 8, label_y, b"Private key:\0".as_ptr() as *const u8);
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
                sys::canvas_draw_str(canvas, left_pad, y, buf.as_ptr() as *const u8);
            }
            // draw scrollbar if needed (on right)
            if total_lines > visible_lines {
                let track_x = display_w - 6;
                let track_top = label_y + 12;
                draw_scrollbar(
                    canvas,
                    scroll,
                    visible_lines,
                    total_lines,
                    track_x,
                    track_top,
                    line_h,
                );
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
                b"No mnemonic\0".as_ptr() as *const u8,
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
                sys::canvas_draw_str(canvas, hint_x + 8, hint_y, hint_text.as_ptr() as *const u8);
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
            b"QR too long for ECC=L\0".as_ptr() as *const u8,
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
                    long_msg.as_ptr() as *const u8,
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
                sys::canvas_draw_str(canvas, dlg_x + 8, dlg_y + 25, buf.as_ptr() as *const u8);
            }
        }

        // back hint below dialog (no QR preview when encoding failed)
        sys::canvas_draw_str(
            canvas,
            dlg_x + 8,
            dlg_y + dlg_h - 6,
            b"Left: Back\0".as_ptr() as *const u8,
        );
        return;
    }

    if mnemonic_str.is_empty() {
        sys::canvas_draw_str(
            canvas,
            6,
            title_height + 24,
            b"No mnemonic\0".as_ptr() as *const u8,
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
                sys::canvas_draw_str(canvas, left_x, y, num_buf.as_ptr() as *const u8);

                // word buffer
                let wb = w.as_bytes();
                let mut wbuf: [u8; 48] = [0u8; 48];
                let wlen = core::cmp::min(wb.len(), wbuf.len() - 1);
                wbuf[..wlen].copy_from_slice(&wb[..wlen]);
                wbuf[wlen] = 0;
                sys::canvas_draw_str(canvas, left_word_x, y, wbuf.as_ptr() as *const u8);
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
                sys::canvas_draw_str(canvas, right_x, y, num_buf.as_ptr() as *const u8);

                let wb = w.as_bytes();
                let mut wbuf: [u8; 48] = [0u8; 48];
                let wlen = core::cmp::min(wb.len(), wbuf.len() - 1);
                wbuf[..wlen].copy_from_slice(&wb[..wlen]);
                wbuf[wlen] = 0;
                sys::canvas_draw_str(canvas, right_word_x, y, wbuf.as_ptr() as *const u8);
            }
        }
    }

    if !state.wallets.is_empty() {
        if let Some(wallet) = state.wallets.get(state.current_wallet) {
            let secret_bytes = wallet.master_key.secret_key().as_bytes();
            let hex_str = hex::encode(secret_bytes);
            let hex_bytes = hex_str.as_str().as_bytes();
            let label_y = start_y + (visible as i32) * line_h + 4;
            sys::canvas_draw_str(canvas, 8, label_y, b"Priv key:\0".as_ptr() as *const u8);
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
                    buf.as_ptr() as *const u8,
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
                    b"Left: Back to words\0".as_ptr() as *const u8,
                );
            } else {
                sys::canvas_draw_box(canvas, 90, 24, 36, 36);
                sys::canvas_draw_str(canvas, 92, 26, b"QR\0".as_ptr() as *const u8);
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
        b"Flipper Zero Crypto Wallet\0".as_ptr() as *const u8,
    );
    sys::canvas_draw_str(
        canvas,
        x_off,
        title_height + 16,
        b"Version 1.0.0\0".as_ptr() as *const u8,
    );
    sys::canvas_draw_str(
        canvas,
        x_off,
        title_height + 16 * 2,
        b"Written by Blueokanna\0".as_ptr() as *const u8,
    );
    sys::canvas_draw_str(
        canvas,
        x_off,
        title_height + 16 * 3,
        b"Developed in Rust\0".as_ptr() as *const u8,
    );
}

unsafe fn draw_confirm_dialog(canvas: *mut sys::Canvas, state: &AppState) {
    sys::canvas_set_font(canvas, sys::FontSecondary);
    sys::canvas_set_color(canvas, sys::ColorBlack);

    let msg = match state.confirm_action {
        ConfirmAction::DeleteWallet => b"Delete wallet?     \0",
        ConfirmAction::ExportMnemonic => b"Export mnemonic?   \0",
        ConfirmAction::SaveWallet => b"Save wallet to SD? \0",
        ConfirmAction::ClearPassphrase => b"Clear passphrase   \0",
        ConfirmAction::RevealPrivate => b"Reveal Private Key?\0",
        ConfirmAction::None => b"Confirm?           \0",
    };

    sys::canvas_draw_str(canvas, 8, 8, msg.as_ptr() as *const u8);
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
        sys::canvas_draw_str(canvas, text_x, text_y, buf.as_ptr() as *const u8);
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
        sys::canvas_draw_str(canvas, margin + 6, text_y, items[idx].as_ptr() as *const u8);
    }
    // draw scrollbar if needed
    if count > visible {
        let track_x = DISPLAY_WIDTH - 6;
        let track_top = start_y - 2;
        draw_scrollbar(canvas, scroll, visible, count, track_x, track_top, line_h);
    }
}

// Compute prefix suggestions into state (no heap) based on current fragment.
fn compute_suggestions_for_prefix(state: &mut AppState, prefix: &str) {
    let pbytes = prefix.as_bytes();
    let plen = pbytes.len();
    state.suggestion_count = 0;
    state.suggestion_total = 0;
    if plen < 2 {
        return;
    }
    for (i, &w) in ENGLISH_WORD_LIST.iter().enumerate() {
        let wb = w.as_bytes();
        if wb.len() < plen {
            continue;
        }
        let mut matched = true;
        for j in 0..plen {
            let a = wb[j];
            let b = pbytes[j];
            let b_lower = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
            if a != b_lower {
                matched = false;
                break;
            }
        }
        if matched {
            if state.suggestion_count < SUGGESTION_MAX {
                state.suggestion_indices[state.suggestion_count] = i;
                state.suggestion_count += 1;
            }
            state.suggestion_total += 1;
        }
    }
    if state.suggestion_selected >= state.suggestion_count {
        state.suggestion_selected = 0;
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

        // Prefer handling Short and Repeat events to avoid double-processing
        // (some hardware sends both Press and Short for a single tap).
        if !(evt.type_ == sys::InputTypeShort || evt.type_ == sys::InputTypeRepeat) {
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
    // If selecting a word from the BIP39 list, handle wordlist navigation and selection
    if state.selecting_word {
        match evt.key {
            sys::InputKeyUp => {
                if state.wordlist_index > 0 {
                    state.wordlist_index -= 1;
                } else if state.import_word_index > 0 {
                    // go back to previous word (do not delete)
                    state.import_word_index = state.import_word_index.saturating_sub(1);
                }
            }
            sys::InputKeyDown => {
                if state.wordlist_index + 1 < ENGLISH_WORD_LIST.len() {
                    state.wordlist_index += 1;
                }
            }
            sys::InputKeyLeft => {
                // page up
                let page = MAIN_MENU_VISIBLE;
                state.wordlist_index = state.wordlist_index.saturating_sub(page);
            }
            sys::InputKeyRight => {
                // page down
                let page = MAIN_MENU_VISIBLE;
                state.wordlist_index =
                    core::cmp::min(state.wordlist_index + page, ENGLISH_WORD_LIST.len() - 1);
            }
            sys::InputKeyOk => {
                // ensure import_words capacity
                if state.import_words.len() < state.import_total_words {
                    while state.import_words.len() < state.import_total_words {
                        state.import_words.push(alloc::string::String::new());
                    }
                }
                // choose highlighted word
                let chosen = ENGLISH_WORD_LIST[state.wordlist_index];
                state.import_words[state.import_word_index] = alloc::string::String::from(chosen);
                if state.import_word_index + 1 < state.import_total_words {
                    state.import_word_index += 1;
                    state.wordlist_index = 0;
                } else {
                    // finished entering words
                    state.selecting_word = false;
                    state.input_mode = InputMode::Navigation;
                    state.menu_index = 0;
                }
            }
            sys::InputKeyBack => {
                // cancel selection, keep entered words
                state.selecting_word = false;
                state.input_mode = InputMode::Navigation;
            }
            _ => {}
        }
        return;
    }

    // If we're in text input mode for entering words, handle navigation/accept/backspace here.
    if state.input_mode == InputMode::TextInput {
        // recompute suggestions based on current fragment so navigation works, but skip for passphrase
        if !state.editing_passphrase {
            // copy fragment into stack buffer inside a small scope so immutable borrows end before mutable borrow
            let mut prefix_buf: [u8; 32] = [0u8; 32];
            let copy_len = {
                if state.import_words.len() > state.import_word_index {
                    let src = state.import_words[state.import_word_index].as_bytes();
                    let len = core::cmp::min(src.len(), prefix_buf.len() - 1);
                    prefix_buf[..len].copy_from_slice(&src[..len]);
                    len
                } else {
                    0
                }
            };
            let prefix_str = match core::str::from_utf8(&prefix_buf[..copy_len]) {
                Ok(s) => s,
                Err(_) => "",
            };
            compute_suggestions_for_prefix(state, prefix_str);
        }
        match evt.key {
            sys::InputKeyUp => {
                // if suggestions available, move selection up; otherwise cycle charset backward
                if state.suggestion_count > 0 {
                    if state.suggestion_selected > 0 {
                        state.suggestion_selected -= 1;
                    }
                } else {
                    if state.char_index == 0 {
                        state.char_index = CHARSET.len() - 1;
                    } else {
                        state.char_index -= 1;
                    }
                }
            }
            sys::InputKeyDown => {
                // if suggestions available, move selection down; otherwise cycle charset forward
                if state.suggestion_count > 0 {
                    if state.suggestion_selected + 1 < state.suggestion_count {
                        state.suggestion_selected += 1;
                    }
                } else {
                    state.char_index = (state.char_index + 1) % CHARSET.len();
                }
            }
            sys::InputKeyLeft => {
                // delete last character
                if state.editing_passphrase {
                    if state.passphrase_len > 0 {
                        state.passphrase_len -= 1;
                        state.passphrase_buffer[state.passphrase_len] = 0;
                    }
                } else {
                    if state.import_words.len() <= state.import_word_index {
                        while state.import_words.len() <= state.import_word_index {
                            state.import_words.push(alloc::string::String::new());
                        }
                    }
                    let s = &mut state.import_words[state.import_word_index];
                    s.pop();
                    // recompute suggestions
                    let mut pbuf: [u8; 32] = [0u8; 32];
                    let plen = {
                        if state.import_words.len() > state.import_word_index {
                            let src = state.import_words[state.import_word_index].as_bytes();
                            let len = core::cmp::min(src.len(), pbuf.len() - 1);
                            pbuf[..len].copy_from_slice(&src[..len]);
                            len
                        } else {
                            0
                        }
                    };
                    let prefix_str = match core::str::from_utf8(&pbuf[..plen]) {
                        Ok(s) => s,
                        Err(_) => "",
                    };
                    compute_suggestions_for_prefix(state, prefix_str);
                }
            }
            sys::InputKeyRight => {
                // accept highlighted suggestion if present; otherwise accept current fragment (advance)
                if state.editing_passphrase {
                    state.input_mode = InputMode::Navigation;
                    state.use_system_keyboard = false;
                } else if state.suggestion_count > 0 {
                    let sel = if state.suggestion_selected < state.suggestion_count {
                        state.suggestion_selected
                    } else {
                        0usize
                    };
                    let chosen_idx = state.suggestion_indices[sel];
                    let chosen = ENGLISH_WORD_LIST[chosen_idx];
                    if state.import_words.len() <= state.import_word_index {
                        while state.import_words.len() <= state.import_word_index {
                            state.import_words.push(alloc::string::String::new());
                        }
                    }
                    state.import_words[state.import_word_index] =
                        alloc::string::String::from(chosen);
                    if state.import_word_index + 1 < state.import_total_words {
                        state.import_word_index += 1;
                        if state.import_words.len() <= state.import_word_index {
                            state.import_words.push(alloc::string::String::new());
                        } else {
                            state.import_words[state.import_word_index].clear();
                        }
                        state.suggestion_count = 0;
                        state.suggestion_selected = 0;
                    } else {
                        state.input_mode = InputMode::Navigation;
                        state.use_system_keyboard = false;
                    }
                } else {
                    if state.import_words.len() <= state.import_word_index {
                        while state.import_words.len() <= state.import_word_index {
                            state.import_words.push(alloc::string::String::new());
                        }
                    }
                    let frag = state.import_words[state.import_word_index].trim();
                    if !frag.is_empty() {
                        if state.import_word_index + 1 < state.import_total_words {
                            state.import_word_index += 1;
                            if state.import_words.len() <= state.import_word_index {
                                state.import_words.push(alloc::string::String::new());
                            } else {
                                state.import_words[state.import_word_index].clear();
                            }
                        } else {
                            state.input_mode = InputMode::Navigation;
                            state.use_system_keyboard = false;
                        }
                    }
                }
            }
            sys::InputKeyOk => {
                // insert currently selected CHARSET character (or do nothing if CHARSET invalid)
                let key = CHARSET[state.char_index];
                if state.editing_passphrase {
                    let kb = key.as_bytes();
                    for &b in kb.iter() {
                        if state.passphrase_len + 1 < state.passphrase_buffer.len() {
                            state.passphrase_buffer[state.passphrase_len] = b;
                            state.passphrase_len += 1;
                        }
                    }
                    if state.passphrase_len < state.passphrase_buffer.len() {
                        state.passphrase_buffer[state.passphrase_len] = 0;
                    }
                } else {
                    if state.import_words.len() <= state.import_word_index {
                        while state.import_words.len() <= state.import_word_index {
                            state.import_words.push(alloc::string::String::new());
                        }
                    }
                    let s = &mut state.import_words[state.import_word_index];
                    s.push_str(key);
                    // recompute suggestions
                    let mut pbuf: [u8; 32] = [0u8; 32];
                    let plen = {
                        if state.import_words.len() > state.import_word_index {
                            let src = state.import_words[state.import_word_index].as_bytes();
                            let len = core::cmp::min(src.len(), pbuf.len() - 1);
                            pbuf[..len].copy_from_slice(&src[..len]);
                            len
                        } else {
                            0
                        }
                    };
                    let prefix_str = match core::str::from_utf8(&pbuf[..plen]) {
                        Ok(s) => s,
                        Err(_) => "",
                    };
                    compute_suggestions_for_prefix(state, prefix_str);
                }
            }
            sys::InputKeyBack => {
                // exit text input
                state.input_mode = InputMode::Navigation;
                state.use_system_keyboard = false;
                state.suggestion_count = 0;
                state.suggestion_selected = 0;
            }
            _ => {}
        }
        return;
    }
    // Normal import menu navigation
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
            0 => {
                // begin manual word entry using on-screen keyboard (per-word manual input)
                // switch to text input and mark that we will use the system keyboard/dialog
                state.selecting_word = false;
                state.input_mode = InputMode::TextInput;
                state.use_system_keyboard = true;
                state.editing_passphrase = false;
                state.import_total_words = state.bip39_word_count;
                state.import_word_index = 0;
                state.wordlist_index = 0;
                state.import_words.clear();
                while state.import_words.len() < state.import_total_words {
                    state.import_words.push(alloc::string::String::new());
                }
                state.keyboard_index = 0;
                state.suggestion_count = 0;
                state.suggestion_selected = 0;
            }
            1 => {
                // edit BIP39 passphrase via on-screen keyboard
                state.input_mode = InputMode::TextInput;
                state.use_system_keyboard = true;
                state.editing_passphrase = true;
                state.keyboard_index = 0;
                // clear current passphrase buffer
                state.clear_passphrase();
                state.suggestion_count = 0;
                state.suggestion_selected = 0;
            }
            2 => {
                // Confirm import: validate mnemonic and create wallet in-memory
                let mut phrase = alloc::string::String::new();
                for (i, w) in state.import_words.iter().enumerate() {
                    if i > 0 {
                        phrase.push(' ');
                    }
                    phrase.push_str(w.as_str());
                }
                let words_vec: alloc::vec::Vec<&str> = phrase.split_whitespace().collect();
                if words_vec.len() == state.import_total_words
                    && crate::bip39::validate_mnemonic(&words_vec)
                {
                    if let Ok(mut wallet) = Wallet::from_mnemonic(
                        phrase.as_str(),
                        core::str::from_utf8(&state.passphrase_buffer[..state.passphrase_len])
                            .unwrap_or(""),
                    ) {
                        // add default first account for display
                        let _ = wallet.add_account(crate::address::Cryptocurrency::Bitcoin, 0, 0);
                        state.wallets.push(wallet);
                        state.current_wallet = state.wallets.len().saturating_sub(1);
                        state.current_screen = Screen::ViewWallets;
                        state.menu_index = 0;
                    } else {
                        // invalid mnemonic -> show error confirmation
                        state.confirm_action = ConfirmAction::ExportMnemonic;
                        state.confirm_index = 1;
                        state.current_screen = Screen::ConfirmAction;
                    }
                } else {
                    state.confirm_action = ConfirmAction::ExportMnemonic;
                    state.confirm_index = 1;
                    state.current_screen = Screen::ConfirmAction;
                }
            }
            _ => {}
        },
        sys::InputKeyBack => {
            state.current_screen = Screen::MainMenu;
            state.menu_index = 1;
            state.clear_mnemonic();
            state.clear_passphrase();
            state.import_words.clear();
            state.selecting_word = false;
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
            // clear one-time AES display
            state.last_saved_aes_len = 0;
            state.last_saved_path.clear();
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
                let max_per_line =
                    core::cmp::max(1, ((display_w - left_pad * 2) / char_w) as usize);
                let total_lines = (hex_str.as_bytes().len() + max_per_line - 1) / max_per_line;
                let avail_h = 64 - ((8 + 12) + 12); // title_height + label_y + reserve
                let line_h = 12usize;
                let visible = core::cmp::max(1, (avail_h as usize) / line_h);
                let max_scroll = if total_lines > visible {
                    total_lines - visible
                } else {
                    0
                };
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
        sys::InputKeyOk => {
            // Prompt to save this wallet to SD card (confirm dialog)
            state.confirm_action = ConfirmAction::SaveWallet;
            state.confirm_index = 0;
            state.current_screen = Screen::ConfirmAction;
        }
        sys::InputKeyLeft => {
            // if QR is showing, return to words view; otherwise go back
            if state.showing_qr {
                state.showing_qr = false;
            } else {
                state.current_screen = Screen::MainMenu;
                state.menu_index = 0;
                // clear one-time AES display
                state.last_saved_aes_len = 0;
                state.last_saved_path.clear();
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
                    ConfirmAction::ExportMnemonic => {
                        // legacy action used elsewhere as an export/validation marker; no-op here
                    }
                    ConfirmAction::SaveWallet => {
                        // For stability, perform an immediate in-memory save (no heavy crypto/IO here).
                        // Build wallet from current mnemonic/passphrase and add to memory.
                        let mnemonic_str = match core::str::from_utf8(&state.mnemonic_buffer) {
                            Ok(s) => s.trim(),
                            Err(_) => "",
                        };
                        if !mnemonic_str.is_empty() {
                            if let Ok(mut wallet) = Wallet::from_mnemonic(
                                mnemonic_str,
                                core::str::from_utf8(&state.passphrase_buffer[..state.passphrase_len])
                                    .unwrap_or(""),
                            ) {
                                let _ = wallet.add_account(
                                    crate::address::Cryptocurrency::Bitcoin,
                                    0,
                                    0,
                                );
                                state.wallets.push(wallet);
                                state.current_wallet = state.wallets.len().saturating_sub(1);
                            }
                        }
                        state.save_error = 0;
                        // Navigate to ViewWallets
                        state.current_screen = Screen::ViewWallets;
                        state.menu_index = 0;
                    }
                    _ => {}
                }
            }
            // If the confirm action was RevealPrivate and user confirmed, keep ShowMnemonic.
            // Otherwise return to main menu (unless we already switched screen).
            if state.confirm_action != ConfirmAction::RevealPrivate
                && state.confirm_action != ConfirmAction::ExportMnemonic
            {
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
