pub mod vault;

use std::time::Duration;
use tauri::{Emitter, Manager};

pub fn run() {
    tauri::Builder::default()
        .manage(vault::AppState::default())
        .setup(|app| {
            let handle = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(5));
                let state = handle.state::<vault::AppState>();
                if state.idle_expired() {
                    let _ = handle.emit("ddd://locked", ());
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault::pick_vault,
            vault::create_vault,
            vault::open_vault,
            vault::lock_vault,
            vault::vault_snapshot,
            vault::add_files,
            vault::export_entry,
            vault::rename_entry,
            vault::delete_entry,
            vault::change_password,
            vault::verify_vault,
            vault::compact_vault,
            vault::open_author_profile,
            vault::set_auto_lock,
            vault::touch_vault
        ])
        .run(tauri::generate_context!())
        .expect("failed to start the application");
}
