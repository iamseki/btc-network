use clickhouse::Client;

/// Connection settings for the ClickHouse crawler storage adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct ClickHouseConnectionConfig {
    url: String,
    database: String,
    user: Option<String>,
    password: Option<String>,
}

impl ClickHouseConnectionConfig {
    /// Creates a config from the ClickHouse HTTP URL and target database name.
    pub fn new(url: impl Into<String>, database: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            database: database.into(),
            user: None,
            password: None,
        }
    }

    /// Returns a copy of the config with an explicit ClickHouse user.
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Returns a copy of the config with an explicit ClickHouse password.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Returns the configured ClickHouse server URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns the configured application database name.
    pub fn database(&self) -> &str {
        &self.database
    }

    /// Builds a ClickHouse client scoped to the configured application database.
    pub fn client(&self) -> Client {
        let mut client = Client::default()
            .with_url(self.url.clone())
            .with_database(self.database.clone());

        if let Some(user) = &self.user {
            client = client.with_user(user.clone());
        }

        if let Some(password) = &self.password {
            client = client.with_password(password.clone());
        }

        client
    }

    /// Builds an admin client without selecting the application database.
    ///
    /// This is used for bootstrapping tasks such as database creation and
    /// migrations.
    pub fn admin_client(&self) -> Client {
        let mut client = Client::default().with_url(self.url.clone());

        if let Some(user) = &self.user {
            client = client.with_user(user.clone());
        }

        if let Some(password) = &self.password {
            client = client.with_password(password.clone());
        }

        client
    }
}

impl Default for ClickHouseConnectionConfig {
    fn default() -> Self {
        Self::new("http://localhost:8123", "btc_network")
    }
}
