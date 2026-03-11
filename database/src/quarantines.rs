
use super::Database;
use shared::RedrResult;
use chrono::{DateTime, Utc};
use shared::quarantine::QuarantineInfo;

impl Database {
    pub async fn quarantine_files_table(&self) -> RedrResult<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS quarantine_files
                (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    quarantine_id INTEGER NOT NULL,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    date DATETIME NOT NULL,
                    qid BYTES NOT NULL,
                    key BYTES NOT NULL,
                    sha BYTES NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(original_path, quarantine_path)
                )"#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn save_quarantine_entry(
        &self,
        info: QuarantineInfo,
    ) -> RedrResult<()> {
        let affected = sqlx::query(
            r#"INSERT OR REPLACE INTO quarantine_files (original_path, quarantine_path, date, qid, key, sha) VALUES(?1, ?2, ?3, ?4, ?5, ?6)"#,
        )
        .bind(info.original_path)
        .bind(info.quarantine_path)
        .bind(info.date)
        .bind(&info.id[..])
        .bind(&info.key[..])
        .bind(&info.sha[..])
        .execute(&self.pool)
        .await?
        .rows_affected();

        if affected > 0 {
            log::info!("Quarantine entry updated: {affected}");
        }
        Ok(())
    }

    pub async fn get_all_quarantines(&self) -> RedrResult<Vec<QuarantineInfo>> {
        use futures::{TryStreamExt};
        use sqlx::Row;

        let mut rows =
            sqlx::query("SELECT original_path, quarantine_path, date, qid, key, sha FROM quarantine_files ORDER BY date DESC")
                .fetch(&self.pool);

        let mut items = Vec::new();

        while let Some(row) = rows.try_next().await? {
            if let Ok(original_path) = row.try_get::<String, _>(0) {
                let quarantine_path: String = row.try_get(1)?;
                let date = row.try_get::<DateTime<Utc>, _>(2)?;
                let id_vec: Vec<u8> = row.try_get(3)?;
                let key_vec: Vec<u8> = row.try_get(4)?;
                let sha_vec: Vec<u8> = row.try_get(5)?;

                // Convert Vec<u8> to fixed-size arrays
                let id: [u8; 16] = id_vec.try_into().map_err(|_| "Invalid id length")?;
                let key: [u8; 32] = key_vec.try_into().map_err(|_| "Invalid key length")?;
                let sha: [u8; 32] = sha_vec.try_into().map_err(|_| "Invalid sha length")?;

                items.push(QuarantineInfo {
                    original_path,
                    quarantine_path,
                    date,
                    id,
                    key,
                    sha
                });
            }
        }

        Ok(items)
    }
}