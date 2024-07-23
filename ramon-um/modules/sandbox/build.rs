fn main() {
    println!("cargo:rustc-link-search=..\\Sandbox");
    //let path = format!("{};{}", std::env::var("PATH").unwrap(), "..\\Sandbox");
    //println!("cargo:rustc-env=PATH={}", path);
}
