# OxideAuth: High-Performance IAM Service

![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)
![Axum](https://img.shields.io/badge/Framework-Axum-blue)
![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-blue)
![Redis](https://img.shields.io/badge/Cache-Redis-red)
![License](https://img.shields.io/badge/License-MIT-green.svg)

OxideAuth is a secure, asynchronous Authentication, and Identity Management service built with Rust.

Designed as a robust backend microservice, it demonstrates systems-level performance, memory-safe concurrency, and modern security best practices. It provides a complete foundation for user registration, role-based access control (RBAC), and session management.

## Technology Stack

| Component         | Technology                | Purpose                                             |
|:------------------|:--------------------------|:----------------------------------------------------|
| **Language**      | Rust (Edition 2021)       | Memory safety, zero-cost abstractions, performance  |
| **Web Framework** | `axum` + `tower`          | Ergonomic, modular routing and middleware           |
| **Database**      | `sqlx` + PostgreSQL       | Async, purely Rust SQL driver with query macros     |
| **Cache**         | `redis-rs` + Redis        | Extremely fast state for rate limits and blocklists |
| **Crypto**        | `argon2` & `jsonwebtoken` | Industry-standard password hashing and signing      |

## Getting Started

### Prerequisites

* Rust toolchain (latest stable)
* Docker & Docker Compose
* `sqlx-cli` (`cargo install sqlx-cli --no-default-features --features rustls,postgres`)

### Local Setup

1. **Clone the repository**
   ```bash
   git clone [https://github.com/yourusername/oxide-auth.git](https://github.com/yourusername/oxide-auth.git)
   cd oxide-auth
   ```
2. **Spin up the infrastructure (Postgres & Redis)**
    ```bash
   docker-compose up -d
    ```
3. **Set up the environment**
   
    Copy the example environment file:
    
    ```bash
    cp .env.example .env
    ```

## Author
**Mohammed Ifkirne**
- Website & Blog: 0xghost.dev

## License

This project is licensed under the MIT License – see the [LICENSE](./LICENSE) file for details.