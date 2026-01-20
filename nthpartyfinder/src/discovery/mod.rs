//! Discovery modules for finding third-party vendor relationships
//! through subdomain enumeration, SaaS tenant probing, and CT log analysis.

pub mod subfinder;
pub mod saas_tenant;
pub mod ct_logs;

pub use subfinder::{SubfinderDiscovery, InstallOption};
pub use saas_tenant::{SaasTenantDiscovery, TenantStatus};
pub use ct_logs::{CtLogDiscovery, CtDiscoveryResult};
