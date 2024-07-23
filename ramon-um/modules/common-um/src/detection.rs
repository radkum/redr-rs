use std::fmt::{Display, Formatter};

pub struct DetectionReport {
    pub name: String,
    pub desc: String,
    pub cause: String,
}

impl Display for DetectionReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Detection {{ name: \"{}\", desc: \"{}\", cause: \"{}\" }}",
            self.name, self.desc, self.cause
        )
    }
}
