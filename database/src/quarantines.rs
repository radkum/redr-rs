use super::Database;
use chrono::{DateTime, Utc};
use shared::{RedrResult, quarantine::QuarantineInfo};
use utils::sha256_utils::Sha256Buff;

impl Database {
    pub async fn quarantine_files_table(&self) -> RedrResult<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS quarantine_files
                (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    date DATETIME NOT NULL,
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

    pub async fn save_quarantine_entry(&self, info: QuarantineInfo) -> RedrResult<()> {
        let affected = sqlx::query(
            r#"INSERT OR REPLACE INTO quarantine_files (original_path, quarantine_path, date, key, sha) VALUES(?1, ?2, ?3, ?4, ?5)"#,
        )
        .bind(info.original_path)
        .bind(info.quarantine_path)
        .bind(info.date)
        .bind(&info.key.0[..])
        .bind(&info.sha.0[..])
        .execute(&self.pool)
        .await?
        .rows_affected();

        if affected > 0 {
            log::info!("Quarantine entry updated: {affected}");
        }
        Ok(())
    }

    pub async fn get_all_quarantines(&self) -> RedrResult<Vec<QuarantineInfo>> {
        use futures::TryStreamExt;
        use sqlx::Row;

        let mut rows = sqlx::query(
            "SELECT original_path, quarantine_path, date, key, sha FROM quarantine_files ORDER BY \
             date DESC",
        )
        .fetch(&self.pool);

        let mut items = Vec::new();

        while let Some(row) = rows.try_next().await? {
            if let Ok(original_path) = row.try_get::<String, _>(0) {
                let quarantine_path: String = row.try_get(1)?;
                let date = row.try_get::<DateTime<Utc>, _>(2)?;
                let key_vec: Vec<u8> = row.try_get(3)?;
                let sha_vec: Vec<u8> = row.try_get(4)?;

                // Convert Vec<u8> to fixed-size arrays
                let key: Sha256Buff = Sha256Buff::from_vec(key_vec)?;
                let sha: Sha256Buff = Sha256Buff::from_vec(sha_vec)?;

                items.push(QuarantineInfo {
                    original_path,
                    quarantine_path,
                    date,
                    key,
                    sha,
                });
            }
        }

        Ok(items)
    }

    pub async fn get_quarantine_entry(&self, sha: &Sha256Buff) -> RedrResult<QuarantineInfo> {
        use sqlx::Row;

        let row = sqlx::query(
            "SELECT original_path, quarantine_path, date, key, sha FROM quarantine_files WHERE \
             sha = ?1",
        )
        .bind(&sha.0[..])
        .fetch_one(&self.pool)
        .await?;

        let original_path: String = row.try_get(0)?;
        let quarantine_path: String = row.try_get(1)?;
        let date = row.try_get::<DateTime<Utc>, _>(2)?;
        let key_vec: Vec<u8> = row.try_get(3)?;
        let sha_vec: Vec<u8> = row.try_get(4)?;

        // Convert Vec<u8> to fixed-size arrays
        let key: Sha256Buff = Sha256Buff::from_vec(key_vec)?;
        let sha: Sha256Buff = Sha256Buff::from_vec(sha_vec)?;

        Ok(QuarantineInfo {
            original_path,
            quarantine_path,
            date,
            key,
            sha,
        })
    }

    pub async fn delete_quarantine_entry(&self, sha: &Sha256Buff) -> RedrResult<()> {
        let affected = sqlx::query("DELETE FROM quarantine_files WHERE sha = ?1")
            .bind(&sha.0[..])
            .execute(&self.pool)
            .await?
            .rows_affected();

        if affected > 0 {
            log::info!("Quarantine entry deleted: {affected}");
        } else {
            log::warn!("No quarantine entry found with the given SHA");
        }
        Ok(())
    }
}
