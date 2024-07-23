use snafu::Snafu;

#[derive(Snafu, Debug)]
pub enum ExtractError {
    #[snafu(display("{error}"))]
    IoError { error: std::io::Error },
    #[snafu(display("{error}"))]
    OleError { error: ole::Error },
}

impl From<std::io::Error> for ExtractError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError { error }
    }
}

impl From<ole::Error> for ExtractError {
    fn from(error: ole::Error) -> Self {
        Self::OleError { error }
    }
}
