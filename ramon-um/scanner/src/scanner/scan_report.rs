#![allow(unused)]

#[derive(Default)]
pub(crate) struct ScanReport {
    clean: Vec<String>,
    malicious: Vec<String>,
}

impl ScanReport {
    pub fn new() -> Self {
        Self { clean: vec![], malicious: vec![] }
    }

    pub fn push_clean(&mut self, c: String) {
        self.clean.push(c)
    }

    pub fn push_malicious(&mut self, m: String) {
        self.malicious.push(m)
    }
}
