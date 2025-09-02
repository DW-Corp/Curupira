// [rust] Module declarations - organize database-related functionality
pub mod models; // Data structures representing database entities and API responses
pub mod queries; // Database query implementations and business logic

// [rust] Re-export all public items from child modules for easier imports
// This creates a "facade" pattern - external code can import from db:: instead of db::models::
pub use models::*;
pub use queries::*;

// [library] SQLx - Rust SQL toolkit with async support and compile-time checked queries
use sqlx::{PgPool, Pool, Postgres}; // PostgreSQL connection pool types
use std::sync::Arc; // [rust] Atomic Reference Counting for shared ownership

// [rust] Type alias - creates a more readable name for Arc<Pool<Postgres>>
// Arc enables sharing the database connection pool across multiple async tasks safely
// Pool<Postgres> provides connection pooling for efficient database resource management
pub type Database = Arc<Pool<Postgres>>;

// [business] Database connection factory - establishes pool and runs migrations
// Returns Result<Database, sqlx::Error> for proper error handling
pub async fn create_pool(database_url: &str) -> Result<Database, sqlx::Error> {
    // [library] Create PostgreSQL connection pool with automatic connection management
    // PgPool handles connection lifecycle, reconnection, and load balancing
    let pool = PgPool::connect(database_url).await?; // [rust] ? operator propagates connection errors

    // [business] Run database migrations automatically on startup
    // sqlx::migrate! is a compile-time macro that embeds migration files into the binary
    // This ensures the database schema is always up-to-date when the application starts
    sqlx::migrate!("./migrations") // [business] Path to migration files
        .run(&pool) // [rust] Execute all pending migrations
        .await?; // [rust] Await completion and propagate errors

    // [rust] Wrap pool in Arc for cheap cloning and sharing across async tasks
    // Arc<T> provides shared ownership without requiring lifetime management
    Ok(Arc::new(pool))
}
