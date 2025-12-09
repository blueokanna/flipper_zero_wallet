use core::ffi::c_void;
use flipperzero_sys as sys;

pub fn app_main() -> i32 {
    unsafe {
        // 打开 GUI 服务
        let gui_name = b"gui\0";
        let gui = sys::furi_record_open(gui_name.as_ptr() as *const i8);
        if gui.is_null() {
            return -1;
        }

        let viewport = sys::view_port_alloc();
        if viewport.is_null() {
            sys::furi_record_close(gui_name.as_ptr() as *const i8);
            return -1;
        }

        let mut state = AppState {
            exit_requested: false,
            menu_index: 0,
            screen: Screen::MainMenu,
            selected_crypto: 0,
        };

        let state_ptr = &mut state as *mut _ as *mut c_void;

        // 设置回调
        sys::view_port_draw_callback_set(viewport, Some(draw_callback), state_ptr);
        sys::view_port_input_callback_set(viewport, Some(input_callback), state_ptr);

        // 添加到 GUI
        sys::gui_add_view_port(gui as *mut sys::Gui, viewport, sys::GuiLayerFullscreen);

        // 请求绘制
        sys::view_port_update(viewport);

        // 事件循环
        while !state.exit_requested {
            sys::furi_delay_ms(50);
            sys::view_port_update(viewport);
        }

        // 清理资源
        sys::gui_remove_view_port(gui as *mut sys::Gui, viewport);
        sys::view_port_free(viewport);
        sys::furi_record_close(gui_name.as_ptr() as *const i8);
    }

    0
}

#[repr(C)]
pub struct AppState {
    exit_requested: bool,
    menu_index: usize,
    screen: Screen,
    selected_crypto: usize,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
enum Screen {
    MainMenu,
    CryptoList,
    CryptoDetail,
    About,
}

const CRYPTO_LIST: &[&str] = &[
    "Bitcoin",
    "Ethereum",
    "Litecoin",
    "Dash",
    "Dogecoin",
    "Ripple",
    "Ravencoin",
];
const CRYPTO_SYMBOLS: &[&str] = &["BTC", "ETH", "LTC", "DASH", "DOGE", "XRP", "RVN"];

extern "C" fn draw_callback(canvas: *mut sys::Canvas, ctx: *mut c_void) {
    unsafe {
        if canvas.is_null() || ctx.is_null() {
            return;
        }

        let state = &*(ctx as *const AppState);

        sys::canvas_clear(canvas);
        sys::canvas_set_font(canvas, sys::FontPrimary);

        // 标题
        match state.screen {
            Screen::MainMenu => {
                let title = b"Flipper Wallet\0";
                sys::canvas_draw_str_aligned(
                    canvas,
                    64,
                    5,
                    sys::AlignCenter,
                    sys::AlignTop,
                    title.as_ptr() as *const i8,
                );
                draw_main_menu(canvas, state);
            }
            Screen::CryptoList => {
                let title = b"Crypto List\0";
                sys::canvas_draw_str_aligned(
                    canvas,
                    64,
                    5,
                    sys::AlignCenter,
                    sys::AlignTop,
                    title.as_ptr() as *const i8,
                );
                draw_crypto_list(canvas, state);
            }
            Screen::CryptoDetail => {
                let title = b"Crypto Detail\0";
                sys::canvas_draw_str_aligned(
                    canvas,
                    64,
                    5,
                    sys::AlignCenter,
                    sys::AlignTop,
                    title.as_ptr() as *const i8,
                );
                draw_crypto_detail(canvas, state);
            }
            Screen::About => {
                let title = b"About\0";
                sys::canvas_draw_str_aligned(
                    canvas,
                    64,
                    5,
                    sys::AlignCenter,
                    sys::AlignTop,
                    title.as_ptr() as *const i8,
                );
                draw_about(canvas);
            }
        }

        // 分隔线
        sys::canvas_draw_line(canvas, 0, 14, 128, 14);
    }
}

unsafe fn draw_main_menu(canvas: *mut sys::Canvas, state: &AppState) {
    sys::canvas_set_font(canvas, sys::FontSecondary);

    let items = ["View Wallets", "View Prices", "Settings", "About"];

    for (i, item) in items.iter().enumerate() {
        let y = 25 + (i as i32) * 12;

        if state.menu_index == i {
            sys::canvas_draw_box(canvas, 2, y, 124, 10);
        }

        sys::canvas_draw_str(canvas, 8, y + 2, item.as_ptr() as *const i8);
    }
}

unsafe fn draw_crypto_list(canvas: *mut sys::Canvas, state: &AppState) {
    sys::canvas_set_font(canvas, sys::FontSecondary);

    for (i, idx) in (0..7).enumerate() {
        if idx >= 7 {
            break;
        }

        let y = 20 + (i as i32) * 8;

        if state.selected_crypto == idx {
            sys::canvas_draw_box(canvas, 2, y, 124, 8);
        }

        sys::canvas_draw_str(canvas, 8, y, CRYPTO_LIST[idx].as_ptr() as *const i8);
    }
}

unsafe fn draw_crypto_detail(canvas: *mut sys::Canvas, state: &AppState) {
    sys::canvas_set_font(canvas, sys::FontSecondary);

    if state.selected_crypto < 7 {
        sys::canvas_draw_str(
            canvas,
            20,
            25,
            CRYPTO_LIST[state.selected_crypto].as_ptr() as *const i8,
        );
        sys::canvas_draw_str(
            canvas,
            30,
            35,
            CRYPTO_SYMBOLS[state.selected_crypto].as_ptr() as *const i8,
        );
        let balance = b"Balance: 0.00\0";
        sys::canvas_draw_str(canvas, 20, 45, balance.as_ptr() as *const i8);
    }
}

unsafe fn draw_about(canvas: *mut sys::Canvas) {
    sys::canvas_set_font(canvas, sys::FontSecondary);

    let line1 = b"Flipper Wallet\0";
    let line2 = b"v1.0.0\0";
    let line3 = b"Multi-Crypto Manager\0";

    sys::canvas_draw_str(canvas, 20, 25, line1.as_ptr() as *const i8);
    sys::canvas_draw_str(canvas, 20, 35, line2.as_ptr() as *const i8);
    sys::canvas_draw_str(canvas, 20, 45, line3.as_ptr() as *const i8);
}

extern "C" fn input_callback(event: *mut sys::InputEvent, ctx: *mut c_void) {
    unsafe {
        if event.is_null() || ctx.is_null() {
            return;
        }

        let event_ref = &*event;
        let state = &mut *(ctx as *mut AppState);

        // 仅处理按下事件
        if event_ref.type_ != sys::InputTypePress {
            return;
        }

        match state.screen {
            Screen::MainMenu => match event_ref.key {
                sys::InputKeyUp => {
                    if state.menu_index > 0 {
                        state.menu_index -= 1;
                    }
                }
                sys::InputKeyDown => {
                    if state.menu_index < 3 {
                        state.menu_index += 1;
                    }
                }
                sys::InputKeyOk => match state.menu_index {
                    0 | 1 | 2 => state.screen = Screen::CryptoList,
                    3 => state.screen = Screen::About,
                    _ => {}
                },
                sys::InputKeyBack => {
                    state.exit_requested = true;
                }
                _ => {}
            },
            Screen::CryptoList => match event_ref.key {
                sys::InputKeyUp => {
                    if state.selected_crypto > 0 {
                        state.selected_crypto -= 1;
                    }
                }
                sys::InputKeyDown => {
                    if state.selected_crypto < 6 {
                        state.selected_crypto += 1;
                    }
                }
                sys::InputKeyOk => {
                    state.screen = Screen::CryptoDetail;
                }
                sys::InputKeyBack => {
                    state.screen = Screen::MainMenu;
                    state.menu_index = 0;
                }
                _ => {}
            },
            Screen::CryptoDetail => match event_ref.key {
                sys::InputKeyBack | sys::InputKeyOk => {
                    state.screen = Screen::CryptoList;
                }
                _ => {}
            },
            Screen::About => match event_ref.key {
                sys::InputKeyBack | sys::InputKeyOk => {
                    state.screen = Screen::MainMenu;
                    state.menu_index = 0;
                }
                _ => {}
            },
        }
    }
}
