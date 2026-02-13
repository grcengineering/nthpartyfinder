//! Discovery modules for finding third-party vendor relationships
//! through subdomain enumeration, SaaS tenant probing, CT log analysis,
//! and web traffic & component analysis.

pub mod subfinder;
pub mod saas_tenant;
pub mod ct_logs;
pub mod web_traffic;

pub use subfinder::{SubfinderDiscovery, InstallOption};
pub use saas_tenant::{SaasTenantDiscovery, TenantStatus};
pub use ct_logs::CtLogDiscovery;
pub use web_traffic::WebTrafficDiscovery;
