mod batch_count_query;
pub mod datto_av;
mod query;
mod state;

use std::{
    collections::HashMap,
    env::current_exe,
    str::FromStr,
    sync::{atomic::Ordering, Arc, Mutex},
    time::Duration as StdDuration,
};

use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Timelike, Utc};
use collections::Insertable;
use futures::{StreamExt, TryStreamExt};
use log::{debug, error, info, max_level, trace, warn, LevelFilter};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{from_value, json, Value as JsonValue};
use shared::{
    message::{ScanEntry, ScanType},
    or_error,
};
use sqlx::{
    sqlite::{
        SqliteArguments, SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions,
        SqliteRow,
    },
    Arguments, Column, Row, TypeInfo,
};
use tokio::{runtime::Handle as RuntimeHandle, task::block_in_place, time::Instant};

use self::state::State;
pub use self::{batch_count_query::*, query::*, state::COLLECTIONS};

pub type Pool = SqlitePool;

#[derive(Clone)]
pub struct Database {
    pool: Pool,
    state: Arc<State>,
    metrics: Arc<Mutex<HashMap<String, i64>>>,
}

impl Database {
    pub async fn in_memory() -> Result<Self> {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")?
            .journal_mode(SqliteJournalMode::Wal)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;

        Ok(Self {
            pool,
            state: Default::default(),
            metrics: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Establish a new connection pool to the local database.
    pub async fn new(db_path: Option<std::path::PathBuf>) -> Result<Self> {
        let db_path = current_exe()?
            .with_file_name(db_path.ok_or_else(|| anyhow!("No database configured"))?);
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))?
            .journal_mode(SqliteJournalMode::Wal)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;

        Ok(Self {
            pool,
            state: Default::default(),
            metrics: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn init(&self) -> Result<()> {
        let mut state = self.load_state().await.unwrap_or_default();

        self.migrate(&mut state).await?;
        self.build_persistant_tables().await?;
        self.set_state(state);
        self.save_state().await?;

        Ok(())
    }

    /// Create required persistent collection tables
    /// - rts_type: used to cache RTS data using batch numbers and counts
    /// - type_temp: used to cache ad-hoc scan data before deduplicating
    async fn build_persistant_tables(&self) -> Result<()> {
        //self.updates_table().await?;
        //self.scan_history_table().await?;
        //self.threats_table().await?;
        //self.response_table().await?;
        self.quarantines_table().await?;

        Ok(())
    }

    // pub async fn create_evergreen_table(&self) -> Result<()> {
    //     sqlx::query(
    //         r#"CREATE TABLE IF NOT EXISTS evergreen
    //             (
    //                 id INTEGER PRIMARY KEY AUTOINCREMENT,
    //                 timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    //                 type TEXT
    //             )"#,
    //     )
    //     .execute(&self.pool)
    //     .await?;

    //     sqlx::query("CREATE INDEX IF NOT EXISTS evergreen_timestamp ON evergreen(timestamp)")
    //         .execute(&self.pool)
    //         .await?;

    //     sqlx::query("CREATE INDEX IF NOT EXISTS evergreen_type ON evergreen(type);")
    //         .execute(&self.pool)
    //         .await?;

    //     Ok(())
    // }

    /// Retrieve an `Insertable` from the database
    pub async fn select<I: Insertable + DeserializeOwned>(
        &self,
        query: Query,
    ) -> Result<Vec<(i32, I)>> {
        let table = query.table();

        let start = Instant::now();

        let sql = query.sql()?;

        let mut rows = sqlx::query(&sql).fetch(&self.pool);

        let stop = Instant::now();

        self.log_metric(&table, stop - start).await;

        let mut items = Vec::new();

        while let Some(row) = rows.try_next().await? {
            let id: i32 = row.try_get(0)?;
            let json: JsonValue = row.try_get(1)?;
            let agg: Option<String> = row.try_get(2).ok();

            // not every collection will have this
            let count: Option<i32> = row.try_get(3).ok();

            let i: serde_json::Result<I> = from_value(json);

            match i {
                Ok(item) => {
                    items.push((id, item.with_aggregation(agg).with_count(count)));
                },
                Err(err) => {
                    error!("Could not deserialize ({table}): {err}");
                },
            }
        }

        Ok(items)
    }

    /// Insert an object into the database. The table is is automatically
    /// detected from the `Insertable` trait and aggregations/batch numbers
    /// are also updated.
    pub async fn insert<I: Insertable + Serialize>(&self, item: &I) -> Result<bool> {
        let table = match item.is_temp_type() {
            false => item.table(),
            true => format!("{}_temp", item.table()),
        };

        let start = Instant::now();

        let sql_result = match item.aggregation_value() {
            Some(agg) => {
                let sql = format!(
                    "INSERT INTO {table} (unique_id, item, agg) VALUES (?1,?2,?3) ON CONFLICT \
                     (unique_id) DO UPDATE SET agg = agg || ',' || ?3, count = count + 1",
                );

                sqlx::query(&sql)
                    .bind(item.unique_id())
                    .bind(serde_json::to_value(item).ok())
                    .bind(agg)
                    .execute(&self.pool)
                    .await
                    .map_err(|err| anyhow!("Aggregation insert failed: {err}"))?
            },
            None => {
                if !item.is_temp_type() {
                    let batch = self.state.get_insert_batch();

                    let sql = format!(
                        "INSERT OR IGNORE INTO {table} (unique_id, item, batch) VALUES (?1, ?2, \
                         ?3) ON CONFLICT (unique_id, batch) DO UPDATE SET count = count + 1",
                    );

                    sqlx::query(&sql)
                        .bind(item.unique_id())
                        .bind(serde_json::to_value(item).ok())
                        .bind(batch)
                        .execute(&self.pool)
                        .await
                        .map_err(|err| anyhow!("Batch insert failed: {err}"))?
                } else {
                    let sql = format!(
                        "INSERT OR IGNORE INTO {table} (unique_id, item) VALUES (?1, ?2) ON \
                         CONFLICT (unique_id) DO UPDATE SET count = count + 1",
                    );

                    sqlx::query(&sql)
                        .bind(item.unique_id())
                        .bind(serde_json::to_value(item).ok())
                        .execute(&self.pool)
                        .await
                        .map_err(|err| anyhow!("Insert failed: {err}"))?
                }
            },
        };

        let stop = Instant::now();

        self.log_metric(table, stop - start).await;

        Ok(sql_result.rows_affected() > 0)
    }

    /// Insert an object into the database. The table is is automatically
    /// detected from the `Insertable` trait and aggregations/batch numbers
    /// are also updated.
    pub fn insert_sync<I: Insertable + Serialize>(&self, item: &I) -> Result<bool> {
        let handle = RuntimeHandle::current();

        block_in_place(|| handle.block_on(self.insert(item)))
    }

    pub async fn insert_raw<S: AsRef<str>>(
        &self,
        sql: S,
        params: SqliteArguments<'_>,
    ) -> Result<usize> {
        let stmt = sqlx::query_with(sql.as_ref(), params);

        let result = stmt.execute(&self.pool).await?;

        Ok(result.rows_affected() as _)
    }

    pub async fn select_raw<S: AsRef<str>>(
        &self,
        sql: S,
        params: SqliteArguments<'_>,
    ) -> Result<Vec<Vec<JsonValue>>> {
        let stmt = sqlx::query_with(sql.as_ref(), params);

        let mut query_rows = stmt.fetch(&self.pool);

        let mut results = Vec::new();

        while let Ok(Some(query_row)) = query_rows.try_next().await {
            let row = Self::parse_raw_query(&query_row)?;

            results.push(row);
        }

        Ok(results)
    }

    fn parse_raw_query(query_row: &SqliteRow) -> Result<Vec<JsonValue>> {
        let mut row: Vec<JsonValue> = Vec::new();

        for (idx, column) in query_row.columns().iter().enumerate() {
            let column_name = column.name();

            let data_type = column.type_info();

            match data_type.name() {
                "TEXT" => {
                    if let Ok(json) = query_row.try_get::<JsonValue, _>(idx) {
                        row.push(json);
                    } else if let Ok(text) = query_row.try_get::<String, _>(idx) {
                        row.push(JsonValue::String(text));
                    } else {
                        return Err(anyhow!("Unable to parse text field in {column_name}"));
                    }
                },
                other => match query_row.try_get::<JsonValue, _>(idx) {
                    Ok(json) => row.push(json),
                    Err(err) => {
                        warn!(
                            "Unable to automatically handle type {other} for column \
                             {column_name}: {err}"
                        );
                    },
                },
            }
        }

        Ok(row)
    }

    /// Insert a set of `Insertable` items
    pub async fn bulk_insert<I: std::fmt::Debug + Insertable + Serialize>(
        &self,
        items: &[I],
    ) -> Result<()> {
        let trans = self.pool.begin().await?;

        for item in items {
            let table = item.table();

            match item.aggregation_value() {
                Some(agg) => {
                    let sql = format!(
                        "INSERT OR IGNORE INTO {table}_temp (unique_id, item, agg) VALUES (?1, \
                         ?2, ?3) ON CONFLICT (unique_id) DO UPDATE SET agg = agg || ',' || ?3, \
                         count = count + 1",
                    );

                    sqlx::query(&sql)
                        .bind(item.unique_id())
                        .bind(serde_json::to_value(item).ok())
                        .bind(agg)
                        .execute(&self.pool)
                        .await?;
                },
                None => {
                    let sql = format!(
                        "INSERT OR IGNORE INTO {table}_temp (unique_id, item) VALUES (?1, ?2) ON \
                         CONFLICT (unique_id) DO UPDATE SET count = count + 1",
                    );

                    sqlx::query(&sql)
                        .bind(item.unique_id())
                        .bind(serde_json::to_value(item).ok())
                        .execute(&self.pool)
                        .await?;
                },
            }
        }

        trans.commit().await?;

        Ok(())
    }

    /// Returns the state persisted in the database (does not change the state
    /// maintained in the `Database` instance, call `set_state()`)
    async fn load_state(&self) -> Result<State> {
        let row = sqlx::query("SELECT data FROM state WHERE key = '_state'")
            .fetch_one(&self.pool)
            .await?;

        let raw: String = row.try_get(0)?;

        let state: Result<State, _> = serde_json::from_str(&raw);

        state.map_err(|_| anyhow!("No valid state in database"))
    }

    /// Update the state maintained by the database (does not persist the
    /// changes, call `save_state()`)
    fn set_state(&self, state: State) {
        self.state.set_schema_version(state.get_schema_version());

        let last_evergreen = *state.last_evergreen.lock().unwrap();
        let last_vacuumed = *state.last_vacuumed.lock().unwrap();
        let evergreen_target = state.evergreen_target.lock().unwrap();

        *self.state.last_evergreen.lock().unwrap() = last_evergreen;
        *self.state.last_vacuumed.lock().unwrap() = last_vacuumed;
        *self.state.evergreen_target.lock().unwrap() = (*evergreen_target).clone();
    }

    /// Writes the current schema/scan data to the database
    pub async fn save_state(&self) -> Result<()> {
        let state = self.state.clone();

        sqlx::query("INSERT OR REPLACE INTO state(key, data) VALUES('_state', ?1)")
            .bind(serde_json::to_string(&state).ok())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Detect old schema version and run appropriate migration steps
    async fn migrate(&self, state: &mut State) -> Result<()> {
        let mut current_version = state.get_schema_version();
        let mut force_vacuum = false;

        if current_version < 300 {
            info!("Agent v2 schema detected, removing old tables");

            let stale = ["state", "event", "interface", "epp_alert"];

            for table in stale {
                sqlx::query(&format!("DROP TABLE IF EXISTS {table}",))
                    .execute(&self.pool)
                    .await?;
            }

            for collection in &*state::COLLECTIONS {
                sqlx::query(&format!("DROP TABLE IF EXISTS {collection}",))
                    .execute(&self.pool)
                    .await?;

                sqlx::query(&format!("DROP TABLE IF EXISTS {collection}_temp",))
                    .execute(&self.pool)
                    .await?;

                sqlx::query(&format!("DROP TABLE IF EXISTS rts_{collection}",))
                    .execute(&self.pool)
                    .await?;
            }
            force_vacuum = true;
        }

        for (version, sql) in &*state::SCHEMAS {
            if *version > state.get_schema_version() {
                for part in sql.split(';') {
                    let sql = part.trim();
                    if !sql.is_empty() {
                        sqlx::query(sql).execute(&self.pool).await?;
                    }
                }
                current_version = *version;
            }
        }

        {
            let batch = state.get_insert_batch();

            for collection in &*state::RTS_COLLECTIONS {
                match sqlx::query(&format!("DELETE FROM rts_{collection} WHERE batch > ?1"))
                    .bind(batch)
                    .execute(&self.pool)
                    .await
                {
                    Ok(query) => force_vacuum |= query.rows_affected() > 0,
                    Err(err) => {
                        if max_level() > LevelFilter::Debug {
                            error!("Unable to remove old RTS data: {err}");
                        }
                    },
                }
            }
        }

        state.set_schema_version(current_version);
        self.vacuum(force_vacuum).await?;

        Ok(())
    }

    /// Delete all records in a given table
    /// TODO: test efficiency vs deleting/re-creating
    pub async fn clear_table<S: AsRef<str>>(&self, table: S) -> Result<()> {
        let table = table.as_ref();

        sqlx::query(&format!("DROP TABLE IF EXISTS {table}"))
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub fn state(&self) -> Arc<State> {
        self.state.clone()
    }

    pub async fn begin_rwd_collection(&self) {
        self.state()
            .rts_state
            .bump_for_fetching
            .store(true, Ordering::SeqCst);
    }

    pub async fn end_rwd_collection(&self) {
        let batch = self.state().rts_state.get_insert_batch();

        self.state
            .rts_state
            .batch
            .store(batch + 1, Ordering::SeqCst);

        self.state()
            .rts_state
            .bump_for_fetching
            .store(false, Ordering::SeqCst);

        or_error!(self.save_state().await);
    }

    pub async fn create_av_update_table(&self) -> Result<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS av_update
                (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    update_attempts INTEGER NOT NULL DEFAULT 0
                )"#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_av_update_attempts(&self) -> Result<i64> {
        let row = sqlx::query("SELECT SUM(update_attempts) FROM av_update")
            .fetch_optional(&self.pool)
            .await?;

        let count = match row {
            Some(row) => row.try_get::<i64, _>(0)?,
            None => 0,
        };
        Ok(count)
    }

    pub async fn add_av_update_attempt(&self) -> Result<()> {
        sqlx::query("UPDATE av_update SET update_attempts = update_attempts + 1")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn reset_av_update_attempts(&self) -> Result<()> {
        sqlx::query("DELETE FROM av_update")
            .execute(&self.pool)
            .await?;
        // Insert default row with value of 0
        sqlx::query("INSERT INTO av_update (update_attempts) VALUES (0)")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn create_epp_alert_table(&self) -> Result<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS epp_alert
                (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detection uuid NOT NULL,
                    alert JSON,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(detection)
                )"#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn create_quarantine_history_table(&self) -> Result<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS quarantine_history
                (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT NOT NULL,
                    date DATETIME NOT NULL,
                    status TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(path, date, status)
                )"#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn create_threats_found_table(&self) -> Result<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS threats_found
                (
                    id INTEGER PRIMARY KEY,
                    count INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )"#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn save_epp_alert<S: AsRef<str>, A: Serialize>(
        &self,
        id: S,
        alert: A,
    ) -> Result<u64> {
        let value = serde_json::to_value(alert)?;

        Ok(sqlx::query(
            r#"INSERT INTO epp_alert (detection, alert) VALUES(?1, ?2) ON CONFLICT(detection) DO NOTHING"#,
        )
            .bind(id.as_ref()).bind(value)
        .execute(&self.pool)
        .await?.rows_affected())
    }

    pub async fn check_epp_alert<S: AsRef<str>>(&self, id: S) -> Result<bool> {
        let row = sqlx::query(r#"SELECT COUNT(*) FROM epp_alert WHERE detection = ?1"#)
            .bind(id.as_ref())
            .fetch_one(&self.pool)
            .await?;

        let x: i64 = row.get(0);

        Ok(x > 0)
    }

    pub async fn save_epp_state<S: AsRef<str>>(&self, epp_state: S) -> Result<()> {
        sqlx::query("INSERT OR REPLACE INTO state(key, data) VALUES('epp_state', ?1)")
            .bind(epp_state.as_ref())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn get_epp_state(&self) -> Result<JsonValue> {
        match sqlx::query("SELECT data FROM state WHERE key='epp_state'")
            .fetch_one(&self.pool)
            .await
        {
            Ok(query_row) => Ok(query_row.try_get::<JsonValue, _>(0)?),
            Err(sqlx::Error::RowNotFound) => Ok(JsonValue::Object(Default::default())),
            Err(err) => Err(err.into()),
        }
    }

    async fn log_metric<T: AsRef<str>>(&self, table: T, metric: StdDuration) {
        use convert_case::{Case, Casing};

        let table = table.as_ref();

        let table = if table.starts_with("rts_") {
            table.into()
        } else if table.ends_with("_temp") {
            format!("survey_{}", table.replace("_temp", ""))
        } else {
            table.into()
        }
        .to_case(Case::Camel);

        let metric = metric.as_millis() as i64;

        let entry = self
            .metrics
            .lock()
            .unwrap()
            .get(&table)
            .cloned()
            .unwrap_or(metric);

        self.metrics
            .lock()
            .unwrap()
            .insert(table, (entry + metric) / 2);
    }

    pub fn query_times(&self) -> Option<JsonValue> {
        let mut output = json!({});

        for (name, metric) in self.metrics.lock().unwrap().iter() {
            output[name] = JsonValue::Number((*metric).into());
        }

        Some(output)
    }

    pub async fn remove_old_rts_data(&self) -> Result<()> {
        let batch = self.state().rts_state.get_insert_batch();

        debug!("Removing old RTS data");

        for collection in &*state::RTS_COLLECTIONS {
            trace!("Removing old {collection} data");

            sqlx::query(&format!(
                "DELETE FROM rts_{collection} WHERE batch < {batch}"
            ))
            .execute(&self.pool)
            .await?;
        }

        {
            trace!("Removing old connection cache data");

            let ttl = Duration::try_hours(24)
                .ok_or_else(|| anyhow!("Unable to clean RTS connection cache data"))?;

            sqlx::query("DELETE FROM rts_connection_cache WHERE timestamp < ?1")
                .bind(Utc::now() - ttl)
                .execute(&self.pool)
                .await?;
        }

        debug!("Cleaning up database");

        self.vacuum(false).await?;

        Ok(())
    }

    pub async fn create_connection_cache_table(&self) -> Result<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS rts_connection_cache
                (
                    unique_id TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(unique_id)
                )"#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn insert_connection_cache<S: AsRef<str>>(&self, unique_id: S) -> Result<bool> {
        let result = sqlx::query(
            r#"INSERT INTO rts_connection_cache (unique_id) VALUES(?1)
                ON CONFLICT(unique_id) DO NOTHING"#,
        )
        .bind(unique_id.as_ref())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn create_dav_exclusion_cache(&self) -> Result<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS dav_exclusion_cache
                (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    quaname TEXT,
                    sha256 TEXT,
                    path TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )"#,
        )
        .execute(&self.pool)
        .await?;

        for idx in ["quaname", "sha256", "path"] {
            let sql = format!(
                r#"CREATE INDEX IF NOT EXISTS dav_exclusion_cache_{idx}_idx
                    ON dav_exclusion_cache ({idx})"#
            );
            sqlx::query(&sql).execute(&self.pool).await?;
        }

        Ok(())
    }

    pub async fn insert_dav_exclusion<S: AsRef<str>, P: AsRef<str>, Q: AsRef<str>>(
        &self,
        sha256: S,
        path: P,
        quaname: Q,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"INSERT INTO dav_exclusion_cache (quaname, sha256, path) VALUES(?1, ?2, ?3)"#,
        )
        .bind(quaname.as_ref())
        .bind(sha256.as_ref())
        .bind(path.as_ref())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn get_dav_exclusion(&self) -> Result<Vec<String>> {
        let rows = sqlx::query(r#"SELECT path FROM dav_exclusion_cache ORDER BY id DESC"#)
            .fetch_all(&self.pool)
            .await
            .map_err(|err| anyhow!("Unable to query DAV exclusion cache: {err}"))?;

        rows.into_iter()
            .map(|row| {
                row.try_get::<String, _>(0)
                    .map_err(|err| anyhow!("Unable to parse path from row: {err}"))
            })
            .collect::<Result<Vec<_>, _>>()
    }

    pub async fn vacuum(&self, force: bool) -> Result<()> {
        static VACUUM_HOURS: i64 = 24;

        let last_vacuumed = self
            .state
            .last_vacuumed
            .lock()
            .map_err(|err| anyhow!("Unable to get vacuum data: {err}"))?
            .unwrap_or(Utc::now());

        let diff = Utc::now() - last_vacuumed;

        if force || diff.num_hours() > VACUUM_HOURS {
            sqlx::query("VACUUM").execute(&self.pool).await?;

            *self
                .state
                .last_vacuumed
                .lock()
                .map_err(|err| anyhow!("Unable to set vacuum data: {err}"))? = Some(Utc::now());

            self.save_state().await
        } else {
            debug!(
                "Skipping vacuum for {} more hours",
                VACUUM_HOURS - diff.num_hours()
            );
            Ok(())
        }
    }

    pub async fn save_features(&self, features: Option<String>) -> Result<bool> {
        let result =
            sqlx::query(r"INSERT OR REPLACE INTO state(key, data) VALUES('_features', ?1)")
                .bind(features)
                .execute(&self.pool)
                .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn get_features(&self) -> Result<String> {
        let row = sqlx::query("SELECT data FROM state WHERE key = '_features' LIMIT 1")
            .fetch_optional(&self.pool)
            .await?;

        if let Some(row) = row {
            let raw: String = row.try_get(0)?;
            Ok(raw)
        } else {
            Ok(Default::default())
        }
    }

    pub async fn query_extension(&self, id: Option<String>) -> Result<Vec<Vec<JsonValue>>> {
        let mut args = SqliteArguments::default();

        args.add(id)
            .map_err(|err| anyhow!("Unable to add extension id: {err}"))?;

        self.select_raw(
            "SELECT entry FROM extension_output WHERE extension_id = ?1",
            args,
        )
        .await
    }

    /// Saves a reboot timestamp field
    pub async fn save_reboot_timestamp(&self, timestamp: DateTime<Utc>) -> Result<bool> {
        let result = sqlx::query(
            r#"
            INSERT INTO reboot_state (key, timestamp)
            VALUES ('reboot_timestamp', $1)
            ON CONFLICT(key) DO UPDATE SET timestamp = $1
            "#,
        )
        .bind(timestamp)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Retrieves the reboot timestamp field
    pub async fn get_reboot_timestamp(&self) -> Result<Option<DateTime<Utc>>> {
        let row = sqlx::query(
            "SELECT timestamp FROM reboot_state WHERE key = 'reboot_timestamp' LIMIT 1",
        )
        .map(|r: SqliteRow| r.try_get("timestamp"))
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(Ok(t)) => Ok(Some(t)),
            _ => Ok(None),
        }
    }

    /// Checks if the reboot timestamp field is present
    pub async fn is_reboot_timestamp_present(&self) -> Result<bool> {
        let row =
            sqlx::query("SELECT EXISTS(SELECT 1 FROM reboot_state WHERE key = 'reboot_timestamp')")
                .fetch_one(&self.pool)
                .await?;

        let exists: bool = row.try_get(0)?;
        Ok(exists)
    }

    /// Checks if the stored reboot timestamp is within a certain time delta
    /// from now
    pub async fn is_reboot_timestamp_within_delta(&self, delta: Duration) -> Result<bool> {
        if let Some(stored_time) = self.get_reboot_timestamp().await? {
            // Compare stored_time with (Utc::now() - delta)
            Ok(stored_time > Utc::now() - delta)
        } else {
            // No reboot timestamp saved yet
            Ok(false)
        }
    }

    pub async fn create_scan_history_table(&self) -> Result<()> {
        // New schema: database is source of truth for scans
        // - started_at: when scan started
        // - finished_at: when scan ended (nullable)
        // - scan_kind: 'edr' | 'datto_quick' | 'datto_full'
        // - status: 'Active' | 'Finished' | 'Cancelled' | 'Failed'
        // - Unique by (started_at, scan_kind) to avoid duplicates for same started
        //   time/kind
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS scan_history
                (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    finished_at DATETIME,
                    scan_kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    UNIQUE(started_at, scan_kind)
                )"#,
        )
        .execute(&self.pool)
        .await?;

        // Helpful indexes
        sqlx::query(
            r#"CREATE INDEX IF NOT EXISTS scan_history_status_idx ON scan_history(status)"#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"CREATE INDEX IF NOT EXISTS scan_history_kind_started_idx ON scan_history(scan_kind, started_at)"#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    fn scan_kind_from_type(scan_type: &ScanType) -> &'static str {
        match scan_type {
            ScanType::Edr(_) => "edr",
            ScanType::QuickDattoAV(_) => "datto_quick",
            ScanType::FullDattoAV(_) => "datto_full",
        }
    }

    fn scan_type_string(kind: &str, status: &str) -> String {
        match kind {
            "edr" => format!("Edr({status})"),
            "datto_quick" => format!("QuickDattoAV({status})"),
            "datto_full" => format!("FullDattoAV({status})"),
            _ => format!("Unknown({status})"),
        }
    }

    pub async fn save_scan_entry(
        &self,
        scan_type: ScanType,
        started_at: DateTime<Utc>,
    ) -> Result<u64> {
        // New incoming scans are marked Active regardless of provided status
        // Truncate nanoseconds from the timestamp for consistency
        let truncated_at = started_at.with_nanosecond(0).unwrap_or(started_at);

        let kind = Self::scan_kind_from_type(&scan_type);
        Ok(sqlx::query(
            r#"INSERT INTO scan_history (scan_kind, status, started_at) VALUES(?1, 'Active', ?2)
                           ON CONFLICT(started_at, scan_kind) DO NOTHING"#,
        )
        .bind(kind)
        .bind(truncated_at)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    pub async fn finish_last_scan(&self, scan_type: ScanType) -> Result<u64> {
        let kind = Self::scan_kind_from_type(&scan_type);

        // Get current time and truncate nanoseconds
        let now = Utc::now().with_nanosecond(0).unwrap_or_else(Utc::now);

        let result = sqlx::query(
            r#"UPDATE scan_history
                SET status='Finished', finished_at=?2
              WHERE id = (
                SELECT id FROM scan_history
                 WHERE scan_kind = ?1 AND status = 'Active'
                 ORDER BY started_at DESC LIMIT 1
              )"#,
        )
        .bind(kind)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn cancel_active_datto_scan(&self) -> Result<u64> {
        // Only Datto quick/full are cancellable, assume at most one active
        // Get current time and truncate nanoseconds
        let now = Utc::now().with_nanosecond(0).unwrap_or_else(Utc::now);

        let result = sqlx::query(
            r#"UPDATE scan_history
                SET status='Cancelled', finished_at=?1
              WHERE id = (
                SELECT id FROM scan_history
                 WHERE status='Active' AND scan_kind IN ('datto_quick','datto_full')
                 ORDER BY started_at DESC LIMIT 1
              )"#,
        )
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn is_active_datto_scan(&self) -> Result<bool> {
        // Only Datto quick/full are cancellable, assume at most one active
        let rows = sqlx::query(
            r#"SELECT scan_history.*
              FROM scan_history
              WHERE id = (
                SELECT id FROM scan_history
                 WHERE status='Active' AND scan_kind IN ('datto_quick','datto_full')
                 ORDER BY started_at DESC LIMIT 1
              )"#,
        )
        .fetch(&self.pool);

        Ok(rows.count().await > 0)
    }

    pub async fn mark_stale_active_as_failed(&self, timeout_hours: i64) -> Result<u64> {
        // Any Active older than now - timeout becomes Failed
        // Get current time and truncate nanoseconds
        let now = Utc::now().with_nanosecond(0).unwrap_or_else(Utc::now);

        // Calculate the cutoff time (now - timeout_hours)
        let cutoff = now - chrono::Duration::hours(timeout_hours);

        let result = sqlx::query(
            r#"UPDATE scan_history
                SET status='Failed', finished_at=?1
              WHERE status='Active' AND started_at < ?2"#,
        )
        .bind(now)
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn get_last_scan(&self) -> Result<String> {
        let mut rows = sqlx::query(
            "SELECT scan_kind, status FROM scan_history ORDER BY started_at DESC LIMIT 1",
        )
        .fetch(&self.pool);

        if let Ok(Some(row)) = rows.try_next().await {
            let kind: String = row.try_get(0)?;
            let status: String = row.try_get(1)?;
            return Ok(Self::scan_type_string(&kind, &status));
        }

        Ok(String::new())
    }

    pub async fn get_all_scan_history(&self) -> Result<Vec<(DateTime<Utc>, String)>> {
        let mut rows = sqlx::query(
            "SELECT started_at, scan_kind, status FROM scan_history ORDER BY started_at ASC",
        )
        .fetch(&self.pool);

        let mut items = Vec::new();

        while let Some(row) = rows.try_next().await? {
            if let Ok(timestamp) = row.try_get::<DateTime<Utc>, _>(0) {
                let kind: String = row.try_get(1)?;
                let status: String = row.try_get(2)?;
                items.push((timestamp, Self::scan_type_string(&kind, &status)));
            }
        }

        Ok(items)
    }

    pub async fn save_server_scan_history(&self, scans: Vec<ScanEntry>) -> Result<()> {
        // Save scans from server - but local status wins in conflicts
        for entry in scans.iter() {
            let date = entry.date;
            // Persist kind + status from server entry
            let kind = Self::scan_kind_from_type(&entry.scan_type).to_string();
            let mut status: String = match &entry.scan_type {
                ScanType::Edr(s) | ScanType::QuickDattoAV(s) | ScanType::FullDattoAV(s) => {
                    let s: String = (*s).clone().into();
                    s
                },
            };

            if status.is_empty() {
                warn!(
                    "Received scan history entry with empty status for kind '{}' at {}. \
                     Defaulting to 'Finished'.",
                    kind, date
                );
                status = "Finished".to_string();
            }

            // Truncate nanoseconds from timestamp
            let truncated_date = date.with_nanosecond(0).unwrap_or(date);

            // Insert new entries, but on conflict keep local status (assume local is newer)
            sqlx::query(
                r#"INSERT INTO scan_history (scan_kind, status, started_at)
                    VALUES(?1, ?2, ?3)
                   ON CONFLICT(started_at, scan_kind) DO NOTHING"#,
            )
            .bind(&kind)
            .bind(&status)
            .bind(truncated_date)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    pub async fn save_quarantine_entry<S: AsRef<str>>(
        &self,
        path: S,
        date: DateTime<Utc>,
        status: S,
    ) -> Result<u64> {
        Ok(sqlx::query(
            r#"INSERT OR REPLACE INTO quarantine_history (path, date, status) VALUES(?1, ?2, ?3)"#,
        )
        .bind(path.as_ref())
        .bind(date)
        .bind(status.as_ref())
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    pub async fn clean_up_database(&self) -> Result<()> {
        let tables = ["scan_history", "quarantine_history", "threats_found"];

        for table in tables {
            sqlx::query(&format!(
                "DELETE FROM {} WHERE timestamp < datetime('now', '-30 days')",
                table
            ))
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    pub async fn get_all_quarantine(&self) -> Result<Vec<(String, DateTime<Utc>, String)>> {
        let mut rows =
            sqlx::query("SELECT path, date, status FROM quarantine_history ORDER BY date DESC")
                .fetch(&self.pool);

        let mut items = Vec::new();

        while let Some(row) = rows.try_next().await? {
            if let Ok(path) = row.try_get(0) {
                let date = row.try_get::<DateTime<Utc>, _>(1)?;
                let status: String = row.try_get(2)?;

                items.push((path, date, status));
            }
        }

        Ok(items)
    }

    pub async fn save_threats_found_entry(&self, count: u32) -> Result<u64> {
        Ok(
            sqlx::query(r#"INSERT INTO threats_found (count) VALUES(?1)"#)
                .bind(count)
                .execute(&self.pool)
                .await?
                .rows_affected(),
        )
    }

    pub async fn get_threats_found(&self) -> Result<u32> {
        let mut rows = sqlx::query("SELECT count FROM threats_found").fetch(&self.pool);

        let mut count = 0;

        while let Some(row) = rows.try_next().await? {
            if let Ok(entry_count) = row.try_get::<u32, _>(0) {
                count += entry_count;
            }
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use sqlx::{Pool, Row, Sqlite};

    pub use super::*;
    use crate::SqliteRow;

    pub async fn save_reboot_timestamp(
        pool: &Pool<Sqlite>,
        timestamp: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO reboot_state (key, timestamp)
            VALUES ('reboot_timestamp', $1)
            ON CONFLICT(key) DO UPDATE SET timestamp = $1
            "#,
        )
        .bind(timestamp)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn get_reboot_timestamp(
        pool: &Pool<Sqlite>,
    ) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT timestamp FROM reboot_state WHERE key = 'reboot_timestamp' LIMIT 1",
        )
        .map(|r: SqliteRow| r.try_get("timestamp"))
        .fetch_optional(pool)
        .await?;

        match row {
            Some(Ok(t)) => Ok(Some(t)),
            _ => Ok(None),
        }
    }

    pub async fn is_reboot_timestamp_present(pool: &Pool<Sqlite>) -> Result<bool, sqlx::Error> {
        let row =
            sqlx::query("SELECT EXISTS(SELECT 1 FROM reboot_state WHERE key = 'reboot_timestamp')")
                .fetch_one(pool)
                .await?;

        let exists: bool = row.try_get(0)?;
        Ok(exists)
    }

    pub async fn is_reboot_timestamp_within_delta(
        pool: &Pool<Sqlite>,
        delta: Duration,
    ) -> Result<bool, sqlx::Error> {
        if let Some(stored_time) = get_reboot_timestamp(pool).await? {
            // Compare stored_time with (Utc::now() - delta)
            Ok(stored_time > Utc::now() - delta)
        } else {
            // No reboot timestamp saved yet
            Ok(false)
        }
    }

    async fn create_reboot_state_table(pool: &Pool<Sqlite>) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS reboot_state (
                key TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL
            )
            "#,
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_save_reboot_timestamp() -> Result<(), sqlx::Error> {
        let pool = Pool::<Sqlite>::connect("sqlite::memory:").await?;
        create_reboot_state_table(&pool).await?;

        let timestamp = Utc::now();
        let result = save_reboot_timestamp(&pool, timestamp).await?;
        assert!(result);

        let saved_timestamp: (DateTime<Utc>,) =
            sqlx::query_as("SELECT timestamp FROM reboot_state WHERE key = 'reboot_timestamp'")
                .fetch_one(&pool)
                .await?;

        assert_eq!(saved_timestamp.0, timestamp);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_reboot_timestamp() -> Result<(), sqlx::Error> {
        let pool = Pool::<Sqlite>::connect("sqlite::memory:").await?;
        create_reboot_state_table(&pool).await?;

        let timestamp = Utc.with_ymd_and_hms(2022, 1, 1, 0, 0, 0).unwrap();
        sqlx::query("INSERT INTO reboot_state (key, timestamp) VALUES ('reboot_timestamp', ?)")
            .bind(timestamp)
            .execute(&pool)
            .await?;

        let fetched_timestamp = get_reboot_timestamp(&pool).await?;
        assert_eq!(fetched_timestamp, Some(timestamp));

        Ok(())
    }

    #[tokio::test]
    async fn test_is_reboot_timestamp_present() -> Result<(), sqlx::Error> {
        let pool = Pool::<Sqlite>::connect("sqlite::memory:").await?;
        create_reboot_state_table(&pool).await?;

        let exists = is_reboot_timestamp_present(&pool).await?;
        assert!(!exists);

        let timestamp = Utc::now();
        sqlx::query("INSERT INTO reboot_state (key, timestamp) VALUES ('reboot_timestamp', ?)")
            .bind(timestamp)
            .execute(&pool)
            .await?;

        let exists = is_reboot_timestamp_present(&pool).await?;
        assert!(exists);

        Ok(())
    }

    #[tokio::test]
    async fn test_is_reboot_timestamp_within_delta() -> Result<(), sqlx::Error> {
        let pool = Pool::<Sqlite>::connect("sqlite::memory:").await?;
        create_reboot_state_table(&pool).await?;

        let timestamp = Utc::now() - Duration::minutes(5);
        sqlx::query("INSERT INTO reboot_state (key, timestamp) VALUES ('reboot_timestamp', ?)")
            .bind(timestamp)
            .execute(&pool)
            .await?;

        let within_delta = is_reboot_timestamp_within_delta(&pool, Duration::minutes(10)).await?;
        assert!(within_delta);

        let within_delta = is_reboot_timestamp_within_delta(&pool, Duration::minutes(1)).await?;
        assert!(!within_delta);

        Ok(())
    }

    mod desktop_ui {
        use chrono::{DateTime, Utc};
        use shared::message::{ScanStatus, ScanType};

        use crate::Database;
        async fn test_scan_history_table_async() {
            let database = Database::in_memory().await.unwrap();
            database.create_scan_history_table().await.unwrap();

            let time1 = DateTime::<Utc>::default();
            let time2 = time1 + chrono::Duration::minutes(1);

            database
                .save_scan_entry(ScanType::Edr(ScanStatus::Finished), time1)
                .await
                .unwrap();
            database
                .save_scan_entry(ScanType::Edr(ScanStatus::Finished), time2)
                .await
                .unwrap();

            let scans = database.get_all_scan_history().await.unwrap();
            assert_eq!(scans.len(), 2);
            let (_, type1) = scans[0].clone();
            let (_, type2) = scans[1].clone();
            assert_eq!("Edr(Active)".to_string(), type1);
            assert_eq!("Edr(Active)".to_string(), type2);
        }

        #[test]
        fn test_scan_history_table() {
            tokio_test::block_on(test_scan_history_table_async());
        }

        async fn test_quarantine_history_table_async() {
            let database = Database::in_memory().await.unwrap();

            database.create_quarantine_history_table().await.unwrap();
            database
                .save_quarantine_entry("d1", DateTime::<Utc>::default(), "s1")
                .await
                .unwrap();
            database
                .save_quarantine_entry("d1", DateTime::<Utc>::default(), "s2")
                .await
                .unwrap();
            let quarantines = database.get_all_quarantine().await.unwrap();
            assert_eq!(quarantines.len(), 1); // INSERT OR REPLACE should result in only 1 entry
            let q1 = quarantines[0].clone();
            assert_eq!(
                (
                    "d1".to_string(),
                    DateTime::<Utc>::default(),
                    "s2".to_string() // Latest status should be s2
                ),
                q1
            );
        }

        #[test]
        fn test_quarantine_history_table() {
            tokio_test::block_on(test_quarantine_history_table_async());
        }

        async fn test_threats_count_table_async() {
            let database = Database::in_memory().await.unwrap();

            database.create_threats_found_table().await.unwrap();

            database.save_threats_found_entry(5).await.unwrap();
            database.save_threats_found_entry(3).await.unwrap();
            assert_eq!(8, database.get_threats_found().await.unwrap());

            database.save_threats_found_entry(120).await.unwrap();
            assert_eq!(128, database.get_threats_found().await.unwrap());
        }

        #[test]
        fn test_threats_count_table() {
            tokio_test::block_on(test_threats_count_table_async());
        }
    }

    mod scan_operations {
        use chrono::{Duration, Utc};
        use shared::message::{ScanEntry, ScanStatus, ScanType};

        use crate::Database;
        // BASIC SCAN OPERATIONS TESTS
        async fn test_scan_operations_async() {
            let database = Database::in_memory().await.unwrap();
            database.create_scan_history_table().await.unwrap();

            // Test save_scan_entry with different scan types
            let test_time = Utc::now();

            // Test EDR scan
            let rows_affected = database
                .save_scan_entry(ScanType::Edr(ScanStatus::Active), test_time)
                .await
                .unwrap();
            assert_eq!(rows_affected, 1);

            // Test Quick Datto AV scan
            let rows_affected = database
                .save_scan_entry(
                    ScanType::QuickDattoAV(ScanStatus::Active),
                    test_time + Duration::minutes(1),
                )
                .await
                .unwrap();
            assert_eq!(rows_affected, 1);

            // Test Full Datto AV scan
            let rows_affected = database
                .save_scan_entry(
                    ScanType::FullDattoAV(ScanStatus::Active),
                    test_time + Duration::minutes(2),
                )
                .await
                .unwrap();
            assert_eq!(rows_affected, 1);

            // Test duplicate entry (should be ignored due to ON CONFLICT)
            let rows_affected = database
                .save_scan_entry(ScanType::Edr(ScanStatus::Finished), test_time)
                .await
                .unwrap();
            assert_eq!(rows_affected, 0);

            // Verify scan history
            let history = database.get_all_scan_history().await.unwrap();
            assert_eq!(history.len(), 3);

            // Check that scans are ordered by started_at ASC
            assert_eq!(history[0].1, "Edr(Active)");
            assert_eq!(history[1].1, "QuickDattoAV(Active)");
            assert_eq!(history[2].1, "FullDattoAV(Active)");
        }

        async fn test_finish_last_scan_async() {
            let database = Database::in_memory().await.unwrap();
            database.create_scan_history_table().await.unwrap();

            let test_time = Utc::now();

            // Start multiple scans
            database
                .save_scan_entry(ScanType::Edr(ScanStatus::Active), test_time)
                .await
                .unwrap();
            database
                .save_scan_entry(
                    ScanType::QuickDattoAV(ScanStatus::Active),
                    test_time + Duration::minutes(1),
                )
                .await
                .unwrap();

            // Finish the last EDR scan
            let rows_affected = database
                .finish_last_scan(ScanType::Edr(ScanStatus::Finished))
                .await
                .unwrap();
            assert_eq!(rows_affected, 1);

            // Verify that the EDR scan is now finished
            let history = database.get_all_scan_history().await.unwrap();
            let edr_scan = history
                .iter()
                .find(|(_, scan_type)| scan_type.starts_with("Edr"))
                .unwrap();
            assert_eq!(edr_scan.1, "Edr(Finished)");

            // QuickDattoAV should still be active
            let datto_scan = history
                .iter()
                .find(|(_, scan_type)| scan_type.starts_with("QuickDattoAV"))
                .unwrap();
            assert_eq!(datto_scan.1, "QuickDattoAV(Active)");

            // Try to finish a scan type that has no active scans
            let rows_affected = database
                .finish_last_scan(ScanType::FullDattoAV(ScanStatus::Finished))
                .await
                .unwrap();
            assert_eq!(rows_affected, 0);
        }

        async fn test_cancel_active_datto_scan_async() {
            let database = Database::in_memory().await.unwrap();
            database.create_scan_history_table().await.unwrap();

            let test_time = Utc::now();

            // Start EDR and Datto scans
            database
                .save_scan_entry(ScanType::Edr(ScanStatus::Active), test_time)
                .await
                .unwrap();
            database
                .save_scan_entry(
                    ScanType::QuickDattoAV(ScanStatus::Active),
                    test_time + Duration::minutes(1),
                )
                .await
                .unwrap();
            database
                .save_scan_entry(
                    ScanType::FullDattoAV(ScanStatus::Active),
                    test_time + Duration::minutes(2),
                )
                .await
                .unwrap();

            // Cancel active Datto scan (should cancel the most recent one)
            let rows_affected = database.cancel_active_datto_scan().await.unwrap();
            assert_eq!(rows_affected, 1);

            // Verify that the Full Datto scan is cancelled but others remain active
            let history = database.get_all_scan_history().await.unwrap();
            let full_datto_scan = history
                .iter()
                .find(|(_, scan_type)| scan_type.starts_with("FullDattoAV"))
                .unwrap();
            assert_eq!(full_datto_scan.1, "FullDattoAV(Cancelled)");

            let edr_scan = history
                .iter()
                .find(|(_, scan_type)| scan_type.starts_with("Edr"))
                .unwrap();
            assert_eq!(edr_scan.1, "Edr(Active)");

            let quick_datto_scan = history
                .iter()
                .find(|(_, scan_type)| scan_type.starts_with("QuickDattoAV"))
                .unwrap();
            assert_eq!(quick_datto_scan.1, "QuickDattoAV(Active)");

            // Cancel again (should cancel the QuickDattoAV now)
            let rows_affected = database.cancel_active_datto_scan().await.unwrap();
            assert_eq!(rows_affected, 1);

            // Cancel when no Datto scans are active
            let rows_affected = database.cancel_active_datto_scan().await.unwrap();
            assert_eq!(rows_affected, 0);
        }

        async fn test_mark_stale_active_as_failed_async() {
            let database = Database::in_memory().await.unwrap();
            database.create_scan_history_table().await.unwrap();

            let old_time = Utc::now() - Duration::hours(5);
            let recent_time = Utc::now() - Duration::minutes(30);

            // Start scans at different times
            database
                .save_scan_entry(ScanType::Edr(ScanStatus::Active), old_time)
                .await
                .unwrap();
            database
                .save_scan_entry(ScanType::QuickDattoAV(ScanStatus::Active), recent_time)
                .await
                .unwrap();

            // Mark scans older than 2 hours as failed
            let rows_affected = database.mark_stale_active_as_failed(2).await.unwrap();
            assert_eq!(rows_affected, 1);

            // Verify that only the old scan is marked as failed
            let history = database.get_all_scan_history().await.unwrap();
            let edr_scan = history
                .iter()
                .find(|(_, scan_type)| scan_type.starts_with("Edr"))
                .unwrap();
            assert_eq!(edr_scan.1, "Edr(Failed)");

            let datto_scan = history
                .iter()
                .find(|(_, scan_type)| scan_type.starts_with("QuickDattoAV"))
                .unwrap();
            assert_eq!(datto_scan.1, "QuickDattoAV(Active)");
        }

        async fn test_get_last_scan_async() {
            let database = Database::in_memory().await.unwrap();
            database.create_scan_history_table().await.unwrap();

            // Test empty database
            let last_scan = database.get_last_scan().await.unwrap();
            assert_eq!(last_scan, "");

            let test_time = Utc::now();

            // Add scans in order - save_scan_entry always creates Active scans
            database
                .save_scan_entry(ScanType::Edr(ScanStatus::Active), test_time)
                .await
                .unwrap();
            database
                .save_scan_entry(
                    ScanType::QuickDattoAV(ScanStatus::Active),
                    test_time + Duration::minutes(1),
                )
                .await
                .unwrap();

            // Finish the QuickDattoAV scan
            database
                .finish_last_scan(ScanType::QuickDattoAV(ScanStatus::Finished))
                .await
                .unwrap();

            // Last scan should be the most recent one (QuickDattoAV, now Finished)
            let last_scan = database.get_last_scan().await.unwrap();
            assert_eq!(last_scan, "QuickDattoAV(Finished)");

            // Add another scan
            database
                .save_scan_entry(
                    ScanType::FullDattoAV(ScanStatus::Active),
                    test_time + Duration::minutes(2),
                )
                .await
                .unwrap();

            // Cancel it
            database.cancel_active_datto_scan().await.unwrap();

            let last_scan = database.get_last_scan().await.unwrap();
            assert_eq!(last_scan, "FullDattoAV(Cancelled)");
        }

        async fn test_save_server_scan_history_async() {
            let database = Database::in_memory().await.unwrap();
            database.create_scan_history_table().await.unwrap();

            let test_time = Utc::now();

            // Create scan entries from server
            let server_scans = vec![
                ScanEntry {
                    date: test_time,
                    scan_type: ScanType::Edr(ScanStatus::Finished),
                },
                ScanEntry {
                    date: test_time + Duration::minutes(1),
                    scan_type: ScanType::QuickDattoAV(ScanStatus::Failed),
                },
                ScanEntry {
                    date: test_time + Duration::minutes(2),
                    scan_type: ScanType::FullDattoAV(ScanStatus::Cancelled),
                },
            ];

            // Save server scan history
            database
                .save_server_scan_history(server_scans)
                .await
                .unwrap();

            // Verify all scans were saved
            let history = database.get_all_scan_history().await.unwrap();
            assert_eq!(history.len(), 3);
            assert_eq!(history[0].1, "Edr(Finished)");
            assert_eq!(history[1].1, "QuickDattoAV(Failed)");
            assert_eq!(history[2].1, "FullDattoAV(Cancelled)");

            // Try to save the same scans again (should be ignored due to conflict)
            database
                .save_server_scan_history(vec![ScanEntry {
                    date: test_time,
                    scan_type: ScanType::Edr(ScanStatus::Active), // Different status
                }])
                .await
                .unwrap();

            // Should still have the original status (local wins)
            let history = database.get_all_scan_history().await.unwrap();
            let edr_scan = history
                .iter()
                .find(|(_, scan_type)| scan_type.starts_with("Edr"))
                .unwrap();
            assert_eq!(edr_scan.1, "Edr(Finished)");
        }

        async fn test_scan_operations_integration_async() {
            let database = Database::in_memory().await.unwrap();
            database.create_scan_history_table().await.unwrap();

            let test_time = Utc::now();

            // Simulate a complete scan lifecycle
            // 1. Start a scan
            database
                .save_scan_entry(ScanType::QuickDattoAV(ScanStatus::Active), test_time)
                .await
                .unwrap();

            // 2. Verify it's active
            let last_scan = database.get_last_scan().await.unwrap();
            assert_eq!(last_scan, "QuickDattoAV(Active)");

            // 3. Finish the scan
            let rows_affected = database
                .finish_last_scan(ScanType::QuickDattoAV(ScanStatus::Finished))
                .await
                .unwrap();
            assert_eq!(rows_affected, 1);

            // 4. Verify it's finished
            let last_scan = database.get_last_scan().await.unwrap();
            assert_eq!(last_scan, "QuickDattoAV(Finished)");

            // 5. Start another scan and cancel it
            database
                .save_scan_entry(
                    ScanType::FullDattoAV(ScanStatus::Active),
                    test_time + Duration::minutes(1),
                )
                .await
                .unwrap();

            let rows_affected = database.cancel_active_datto_scan().await.unwrap();
            assert_eq!(rows_affected, 1);

            // 6. Verify final state
            let history = database.get_all_scan_history().await.unwrap();
            assert_eq!(history.len(), 2);
            assert_eq!(history[0].1, "QuickDattoAV(Finished)");
            assert_eq!(history[1].1, "FullDattoAV(Cancelled)");
        }

        #[test]
        fn test_scan_operations() {
            tokio_test::block_on(test_scan_operations_async());
        }

        #[test]
        fn test_finish_last_scan() {
            tokio_test::block_on(test_finish_last_scan_async());
        }

        #[test]
        fn test_cancel_active_datto_scan() {
            tokio_test::block_on(test_cancel_active_datto_scan_async());
        }

        #[test]
        fn test_mark_stale_active_as_failed() {
            tokio_test::block_on(test_mark_stale_active_as_failed_async());
        }

        #[test]
        fn test_get_last_scan() {
            tokio_test::block_on(test_get_last_scan_async());
        }

        #[test]
        fn test_save_server_scan_history() {
            tokio_test::block_on(test_save_server_scan_history_async());
        }

        #[test]
        fn test_scan_operations_integration() {
            tokio_test::block_on(test_scan_operations_integration_async());
        }

        // CRAZY EDGE CASE TESTS
        async fn test_scan_operations_stress_test_async() {
            let database = Database::in_memory().await.unwrap();
            database.create_scan_history_table().await.unwrap();

            let base_time = Utc::now();

            // Stress test: Add 100 EDR scans (can be multiple active)
            // But only alternate between Quick and Full Datto (only 1 active at a time)
            for i in 0..100 {
                let timestamp = base_time + Duration::minutes(i as i64);

                // EDR scans can coexist
                database
                    .save_scan_entry(ScanType::Edr(ScanStatus::Active), timestamp)
                    .await
                    .unwrap();

                // Alternate between Quick and Full Datto, but finish previous before starting
                // new
                if i > 0 {
                    // Finish the previous Datto scan before starting a new one
                    if i % 2 == 1 {
                        database
                            .finish_last_scan(ScanType::QuickDattoAV(ScanStatus::Finished))
                            .await
                            .unwrap();
                    } else {
                        database
                            .finish_last_scan(ScanType::FullDattoAV(ScanStatus::Finished))
                            .await
                            .unwrap();
                    }
                }

                // Start new Datto scan (only one active at a time)
                if i % 2 == 0 {
                    database
                        .save_scan_entry(
                            ScanType::QuickDattoAV(ScanStatus::Active),
                            timestamp + Duration::seconds(10),
                        )
                        .await
                        .unwrap();
                } else {
                    database
                        .save_scan_entry(
                            ScanType::FullDattoAV(ScanStatus::Active),
                            timestamp + Duration::seconds(10),
                        )
                        .await
                        .unwrap();
                }
            }

            let history = database.get_all_scan_history().await.unwrap();
            // Should have 100 EDR + 100 Datto scans = 200 total
            assert_eq!(history.len(), 200);

            // At any point, there should be only 1 active Datto scan
            let active_datto_scans = history
                .iter()
                .filter(|(_, scan)| {
                    scan.contains("Active")
                        && (scan.contains("QuickDattoAV") || scan.contains("FullDattoAV"))
                })
                .count();
            assert_eq!(active_datto_scans, 1); // Only 1 active Datto scan

            // But multiple active EDR scans are allowed
            let active_edr_scans = history
                .iter()
                .filter(|(_, scan)| scan.contains("Active") && scan.contains("Edr"))
                .count();
            assert_eq!(active_edr_scans, 100); // All 100 EDR scans are active

            // Test mass finish of EDR scans
            let mut finished_count = 0;
            for _ in 0..100 {
                let rows = database
                    .finish_last_scan(ScanType::Edr(ScanStatus::Finished))
                    .await
                    .unwrap();
                if rows == 0 {
                    break;
                }
                finished_count += rows;
            }
            assert_eq!(finished_count, 100); // Should finish all 100 EDR scans

            // Cancel the one remaining active Datto scan
            let cancelled = database.cancel_active_datto_scan().await.unwrap();
            assert_eq!(cancelled, 1); // Should cancel exactly 1 Datto scan

            // Verify no active scans remain
            let final_history = database.get_all_scan_history().await.unwrap();
            let active_scans = final_history
                .iter()
                .filter(|(_, scan)| scan.contains("Active"))
                .count();
            assert_eq!(active_scans, 0);
        }

        async fn test_scan_operations_concurrent_simulation_async() {
            let database = Database::in_memory().await.unwrap();
            database.create_scan_history_table().await.unwrap();

            let base_time = Utc::now();

            // Test constraint: Only 1 active Datto scan at a time
            // Start a Quick Datto scan
            database
                .save_scan_entry(ScanType::QuickDattoAV(ScanStatus::Active), base_time)
                .await
                .unwrap();

            // Start multiple EDR scans (these can coexist)
            for i in 1..4 {
                database
                    .save_scan_entry(
                        ScanType::Edr(ScanStatus::Active),
                        base_time + Duration::minutes(i),
                    )
                    .await
                    .unwrap();
            }

            // Verify we have 1 active Datto + 3 active EDR scans
            let history = database.get_all_scan_history().await.unwrap();
            let active_datto = history
                .iter()
                .filter(|(_, scan)| {
                    scan.contains("Active")
                        && (scan.contains("QuickDattoAV") || scan.contains("FullDattoAV"))
                })
                .count();
            let active_edr = history
                .iter()
                .filter(|(_, scan)| scan.contains("Active") && scan.contains("Edr"))
                .count();
            assert_eq!(active_datto, 1);
            assert_eq!(active_edr, 3);

            // Try to start a Full Datto scan while Quick is active (this should fail
            // business logic, but DB allows it) In real implementation, the
            // application layer would prevent this, but we test DB behavior
            database
                .save_scan_entry(
                    ScanType::FullDattoAV(ScanStatus::Active),
                    base_time + Duration::minutes(10),
                )
                .await
                .unwrap();

            // Now we have 2 active Datto scans (violating business rule, but DB allows)
            let updated_history = database.get_all_scan_history().await.unwrap();
            let active_datto_after = updated_history
                .iter()
                .filter(|(_, scan)| {
                    scan.contains("Active")
                        && (scan.contains("QuickDattoAV") || scan.contains("FullDattoAV"))
                })
                .count();
            assert_eq!(active_datto_after, 2); // DB doesn't enforce business rule

            // Cancel active Datto scan (should cancel the most recent one - FullDattoAV)
            let cancelled = database.cancel_active_datto_scan().await.unwrap();
            assert_eq!(cancelled, 1);

            // Verify that FullDattoAV was cancelled, QuickDattoAV still active
            let final_history = database.get_all_scan_history().await.unwrap();
            let quick_active = final_history
                .iter()
                .any(|(_, scan)| scan == "QuickDattoAV(Active)");
            let full_cancelled = final_history
                .iter()
                .any(|(_, scan)| scan == "FullDattoAV(Cancelled)");
            assert!(quick_active);
            assert!(full_cancelled);

            // Finish all EDR scans individually
            for _ in 0..3 {
                let finished = database
                    .finish_last_scan(ScanType::Edr(ScanStatus::Finished))
                    .await
                    .unwrap();
                assert_eq!(finished, 1);
            }

            // Finish the remaining Quick Datto scan
            let finished = database
                .finish_last_scan(ScanType::QuickDattoAV(ScanStatus::Finished))
                .await
                .unwrap();
            assert_eq!(finished, 1);

            // Verify no active scans remain
            let final_final_history = database.get_all_scan_history().await.unwrap();
            let active_count = final_final_history
                .iter()
                .filter(|(_, scan)| scan.contains("Active"))
                .count();
            assert_eq!(active_count, 0);
        }

        async fn test_scan_operations_invalid_data_handling_async() {
            let database = Database::in_memory().await.unwrap();
            database.create_scan_history_table().await.unwrap();

            let base_time = Utc::now();

            // Test with empty server scan history
            database.save_server_scan_history(vec![]).await.unwrap();
            let history = database.get_all_scan_history().await.unwrap();
            assert_eq!(history.len(), 0);

            // Test server scan history with duplicate timestamps but different scan types
            let server_scans = vec![
                ScanEntry {
                    date: base_time,
                    scan_type: ScanType::Edr(ScanStatus::Finished),
                },
                ScanEntry {
                    date: base_time, // Same timestamp
                    scan_type: ScanType::QuickDattoAV(ScanStatus::Failed),
                },
                ScanEntry {
                    date: base_time, // Same timestamp again
                    scan_type: ScanType::FullDattoAV(ScanStatus::Cancelled),
                },
            ];

            database
                .save_server_scan_history(server_scans)
                .await
                .unwrap();
            let history = database.get_all_scan_history().await.unwrap();
            assert_eq!(history.len(), 3); // All should be saved due to unique (timestamp, scan_kind)

            // Test operations on non-existent scans
            let rows = database
                .finish_last_scan(ScanType::Edr(ScanStatus::Finished))
                .await
                .unwrap();
            assert_eq!(rows, 0); // No active EDR scans to finish

            let rows = database.cancel_active_datto_scan().await.unwrap();
            assert_eq!(rows, 0); // No active Datto scans to cancel

            // Test with very large timeout values
            let rows = database.mark_stale_active_as_failed(99999).await.unwrap();
            assert_eq!(rows, 0); // Nothing should be marked as failed with such a large timeout

            // Test with zero timeout
            database
                .save_scan_entry(
                    ScanType::Edr(ScanStatus::Active),
                    base_time - Duration::minutes(1),
                )
                .await
                .unwrap();
            let rows = database.mark_stale_active_as_failed(0).await.unwrap();
            assert_eq!(rows, 1); // Should mark the 1-minute-old scan as failed
        }

        #[test]
        fn test_scan_operations_stress_test() {
            tokio_test::block_on(test_scan_operations_stress_test_async());
        }

        #[test]
        fn test_scan_operations_concurrent_simulation() {
            tokio_test::block_on(test_scan_operations_concurrent_simulation_async());
        }

        #[test]
        fn test_scan_operations_invalid_data_handling() {
            tokio_test::block_on(test_scan_operations_invalid_data_handling_async());
        }

        // CONSTRAINT-SPECIFIC TESTS
        async fn test_datto_av_single_active_constraint_async() {
            let database = Database::in_memory().await.unwrap();
            database.create_scan_history_table().await.unwrap();

            let base_time = Utc::now();

            // Test the business rule: Only 1 active Datto AV scan at a time
            // But multiple EDR scans can coexist

            // Start multiple EDR scans (allowed)
            database
                .save_scan_entry(ScanType::Edr(ScanStatus::Active), base_time)
                .await
                .unwrap();
            database
                .save_scan_entry(
                    ScanType::Edr(ScanStatus::Active),
                    base_time + Duration::minutes(1),
                )
                .await
                .unwrap();
            database
                .save_scan_entry(
                    ScanType::Edr(ScanStatus::Active),
                    base_time + Duration::minutes(2),
                )
                .await
                .unwrap();

            // Start a Quick Datto scan
            database
                .save_scan_entry(
                    ScanType::QuickDattoAV(ScanStatus::Active),
                    base_time + Duration::minutes(3),
                )
                .await
                .unwrap();

            // Verify: 3 active EDR + 1 active Datto
            let history = database.get_all_scan_history().await.unwrap();
            let active_edr = history
                .iter()
                .filter(|(_, scan)| scan.contains("Edr(Active)"))
                .count();
            let active_datto = history
                .iter()
                .filter(|(_, scan)| {
                    scan.contains("Active")
                        && (scan.contains("QuickDattoAV") || scan.contains("FullDattoAV"))
                })
                .count();
            assert_eq!(active_edr, 3);
            assert_eq!(active_datto, 1);

            // Attempt to start a Full Datto scan while Quick is active
            // Note: The database layer doesn't enforce this constraint - that's application
            // layer responsibility But we test what happens if it gets through
            database
                .save_scan_entry(
                    ScanType::FullDattoAV(ScanStatus::Active),
                    base_time + Duration::minutes(4),
                )
                .await
                .unwrap();

            // Now we have constraint violation at DB level (2 active Datto scans)
            let updated_history = database.get_all_scan_history().await.unwrap();
            let active_datto_violation = updated_history
                .iter()
                .filter(|(_, scan)| {
                    scan.contains("Active")
                        && (scan.contains("QuickDattoAV") || scan.contains("FullDattoAV"))
                })
                .count();
            assert_eq!(active_datto_violation, 2); // DB allows violation

            // Test that cancel_active_datto_scan respects LIFO (Last In, First Out)
            // It should cancel the most recent Datto scan first
            let cancelled = database.cancel_active_datto_scan().await.unwrap();
            assert_eq!(cancelled, 1);

            // Verify that FullDattoAV (most recent) was cancelled
            let after_cancel = database.get_all_scan_history().await.unwrap();
            let full_cancelled = after_cancel
                .iter()
                .any(|(_, scan)| scan == "FullDattoAV(Cancelled)");
            let quick_still_active = after_cancel
                .iter()
                .any(|(_, scan)| scan == "QuickDattoAV(Active)");
            assert!(full_cancelled);
            assert!(quick_still_active);

            // Now we're back to the constraint: 1 active Datto scan
            let final_active_datto = after_cancel
                .iter()
                .filter(|(_, scan)| {
                    scan.contains("Active")
                        && (scan.contains("QuickDattoAV") || scan.contains("FullDattoAV"))
                })
                .count();
            assert_eq!(final_active_datto, 1);

            // EDR scans should be unaffected
            let final_active_edr = after_cancel
                .iter()
                .filter(|(_, scan)| scan.contains("Edr(Active)"))
                .count();
            assert_eq!(final_active_edr, 3);
        }

        async fn test_scan_lifecycle_with_constraints_async() {
            let database = Database::in_memory().await.unwrap();
            database.create_scan_history_table().await.unwrap();

            let base_time = Utc::now();

            // Simulate a realistic scan lifecycle respecting constraints

            // Phase 1: Start EDR scan and Quick Datto scan
            database
                .save_scan_entry(ScanType::Edr(ScanStatus::Active), base_time)
                .await
                .unwrap();
            database
                .save_scan_entry(
                    ScanType::QuickDattoAV(ScanStatus::Active),
                    base_time + Duration::minutes(1),
                )
                .await
                .unwrap();

            // Phase 2: Add more EDR scans (can coexist)
            database
                .save_scan_entry(
                    ScanType::Edr(ScanStatus::Active),
                    base_time + Duration::minutes(2),
                )
                .await
                .unwrap();
            database
                .save_scan_entry(
                    ScanType::Edr(ScanStatus::Active),
                    base_time + Duration::minutes(3),
                )
                .await
                .unwrap();

            // Phase 3: Quick Datto scan finishes
            let finished = database
                .finish_last_scan(ScanType::QuickDattoAV(ScanStatus::Finished))
                .await
                .unwrap();
            assert_eq!(finished, 1);

            // Phase 4: Now we can start a Full Datto scan (Quick is no longer active)
            database
                .save_scan_entry(
                    ScanType::FullDattoAV(ScanStatus::Active),
                    base_time + Duration::minutes(4),
                )
                .await
                .unwrap();

            // Verify constraint is maintained: only 1 active Datto scan
            let history = database.get_all_scan_history().await.unwrap();
            let active_datto = history
                .iter()
                .filter(|(_, scan)| {
                    scan.contains("Active")
                        && (scan.contains("QuickDattoAV") || scan.contains("FullDattoAV"))
                })
                .count();
            assert_eq!(active_datto, 1); // Only FullDattoAV should be active

            // Multiple EDR scans still active
            let active_edr = history
                .iter()
                .filter(|(_, scan)| scan.contains("Edr(Active)"))
                .count();
            assert_eq!(active_edr, 3);

            // Phase 5: Full Datto scan gets cancelled
            let cancelled = database.cancel_active_datto_scan().await.unwrap();
            assert_eq!(cancelled, 1);

            // Phase 6: Finish some EDR scans
            database
                .finish_last_scan(ScanType::Edr(ScanStatus::Finished))
                .await
                .unwrap();
            database
                .finish_last_scan(ScanType::Edr(ScanStatus::Finished))
                .await
                .unwrap();

            // Phase 7: Start another Quick Datto scan (now that Full is cancelled)
            database
                .save_scan_entry(
                    ScanType::QuickDattoAV(ScanStatus::Active),
                    base_time + Duration::minutes(5),
                )
                .await
                .unwrap();

            // Final verification
            let final_history = database.get_all_scan_history().await.unwrap();
            let final_active_datto = final_history
                .iter()
                .filter(|(_, scan)| {
                    scan.contains("Active")
                        && (scan.contains("QuickDattoAV") || scan.contains("FullDattoAV"))
                })
                .count();
            let final_active_edr = final_history
                .iter()
                .filter(|(_, scan)| scan.contains("Edr(Active)"))
                .count();

            assert_eq!(final_active_datto, 1); // One QuickDattoAV active
            assert_eq!(final_active_edr, 1); // One EDR still active

            // Verify scan type distribution
            let quick_active = final_history
                .iter()
                .any(|(_, scan)| scan == "QuickDattoAV(Active)");
            let full_cancelled = final_history
                .iter()
                .any(|(_, scan)| scan == "FullDattoAV(Cancelled)");
            let quick_finished = final_history
                .iter()
                .any(|(_, scan)| scan == "QuickDattoAV(Finished)");

            assert!(quick_active);
            assert!(full_cancelled);
            assert!(quick_finished);
        }

        async fn test_constraint_violation_recovery_async() {
            let database = Database::in_memory().await.unwrap();
            database.create_scan_history_table().await.unwrap();

            let base_time = Utc::now();

            // Simulate a scenario where the constraint gets violated
            // (e.g., due to race condition or system restart)

            // Create violation: 2 active Datto scans
            database
                .save_scan_entry(ScanType::QuickDattoAV(ScanStatus::Active), base_time)
                .await
                .unwrap();
            database
                .save_scan_entry(
                    ScanType::FullDattoAV(ScanStatus::Active),
                    base_time + Duration::minutes(1),
                )
                .await
                .unwrap();

            // Add some EDR scans too
            database
                .save_scan_entry(
                    ScanType::Edr(ScanStatus::Active),
                    base_time + Duration::minutes(2),
                )
                .await
                .unwrap();
            database
                .save_scan_entry(
                    ScanType::Edr(ScanStatus::Active),
                    base_time + Duration::minutes(3),
                )
                .await
                .unwrap();

            // Verify violation exists
            let history = database.get_all_scan_history().await.unwrap();
            let active_datto = history
                .iter()
                .filter(|(_, scan)| {
                    scan.contains("Active")
                        && (scan.contains("QuickDattoAV") || scan.contains("FullDattoAV"))
                })
                .count();
            assert_eq!(active_datto, 2); // Constraint violated

            // Recovery strategy: Cancel all but the most recent Datto scan
            // cancel_active_datto_scan should handle this by cancelling most recent first

            let first_cancel = database.cancel_active_datto_scan().await.unwrap();
            assert_eq!(first_cancel, 1); // Cancel most recent (FullDattoAV)

            // Verify we're back to 1 active Datto scan
            let after_recovery = database.get_all_scan_history().await.unwrap();
            let recovered_active_datto = after_recovery
                .iter()
                .filter(|(_, scan)| {
                    scan.contains("Active")
                        && (scan.contains("QuickDattoAV") || scan.contains("FullDattoAV"))
                })
                .count();
            assert_eq!(recovered_active_datto, 1); // Constraint restored

            // EDR scans should be unaffected
            let edr_active = after_recovery
                .iter()
                .filter(|(_, scan)| scan.contains("Edr(Active)"))
                .count();
            assert_eq!(edr_active, 2); // EDR scans untouched

            // Verify which scan survived
            let quick_still_active = after_recovery
                .iter()
                .any(|(_, scan)| scan == "QuickDattoAV(Active)");
            let full_cancelled = after_recovery
                .iter()
                .any(|(_, scan)| scan == "FullDattoAV(Cancelled)");
            assert!(quick_still_active); // Older scan survived
            assert!(full_cancelled); // Newer scan was cancelled
        }

        #[test]
        fn test_datto_av_single_active_constraint() {
            tokio_test::block_on(test_datto_av_single_active_constraint_async());
        }

        #[test]
        fn test_scan_lifecycle_with_constraints() {
            tokio_test::block_on(test_scan_lifecycle_with_constraints_async());
        }

        #[test]
        fn test_constraint_violation_recovery() {
            tokio_test::block_on(test_constraint_violation_recovery_async());
        }
    }
}
