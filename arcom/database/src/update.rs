impl Database {
    pub async fn create_update_table(&self) -> Result<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS update
                (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    type TEXT
                )"#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS update_timestamp ON update(timestamp)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS update_type ON update(type);")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

pub async fn get_update_attempts<S: AsRef<str>>(&self, table: S) -> Result<i64> {
        let row = sqlx::query(
            "SELECT COUNT(*) FROM update WHERE type = ?1 AND timestamp >= datetime('now', '-24 \
             hours')",
        )
        .bind(table.as_ref())
        .fetch_one(&self.pool)
        .await?;
        let raw = row.try_get(0);

        raw.map_err(|_| anyhow!("No valid value for update attempts in database"))
    }

    pub async fn add_update_attempt<S: AsRef<str>>(&self, table: S) -> Result<()> {
        sqlx::query("INSERT INTO update (type) VALUES(?1)")
            .bind(table.as_ref())
            .execute(&self.pool)
            .await?;

        let delete = "DELETE FROM update WHERE type = ?1 AND timestamp < datetime('now', '-24')";

        sqlx::query(delete)
            .bind(table.as_ref())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

