use std::process;

use log::error;

use wmi_mev_tool::Config;

fn main() {
    // Setup Logger
    // No timestamps because systemd does that already.
    env_logger::builder().init();
    // TODO(Add help)
    let config = Config::new().unwrap_or_else(|err| {
        error!("Problem reading environment: {}", err);

        process::exit(1)
    });
    if let Err(e) = wmi_mev_tool::run(&config) {
        error!("Unhandled application error, panicking.");
        panic!("{}", e);

        // Later, when there are handled cases: process::exit(2..n);
    }
}
