use clickhouse::Client;

#[derive(Clone, PartialEq, Eq)]
pub struct ClickHouseConnectionConfig {
    url: String,
    database: String,
    user: Option<String>,
    password: Option<String>,
}

impl ClickHouseConnectionConfig {
    pub fn new(url: impl Into<String>, database: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            database: database.into(),
            user: None,
            password: None,
        }
    }

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn database(&self) -> &str {
        &self.database
    }

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
