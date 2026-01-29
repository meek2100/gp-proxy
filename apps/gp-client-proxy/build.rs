// File: apps/gp-client-proxy/build.rs
fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        // This path is relative to Cargo.toml
        res.set_icon("assets/icon.ico");
        res.compile().unwrap();
    }
}
