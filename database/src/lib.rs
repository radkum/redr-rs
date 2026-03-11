mod quarantines;

use std::path::Path;
use shared::RedrResult;
use std::{
    str::FromStr,
};

use sqlx::{
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions,
    },
};

pub type Pool = SqlitePool;

#[derive(Clone)]
pub struct Database {
    pool: Pool,
}

impl Database {
    pub async fn in_memory() -> RedrResult<Self> {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")?
            .journal_mode(SqliteJournalMode::Wal)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;

        Ok(Self {
            pool,
        })
    }

    /// Establish a new connection pool to the local database.
    pub async fn new(db_path: &Path) -> RedrResult<Self> {
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))?
            .journal_mode(SqliteJournalMode::Wal)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;

        Ok(Self {
            pool,
        })
    }

    pub async fn init(&self) -> RedrResult<()> {
        //let mut state = self.load_state().await.unwrap_or_default();

        //self.migrate(&mut state).await?;
        //self.set_state(state);
        //self.save_state().await?;
        self.quarantine_files_table().await?;
        Ok(())
    }
}