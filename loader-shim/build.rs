fn main() {
    // Avoid linking default C runtime startup files so our _start entry is used.
    println!("cargo:rustc-link-arg=-nostartfiles");
}

