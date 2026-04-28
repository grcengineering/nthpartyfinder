//! Discovery modules for finding third-party vendor relationships
//! through subdomain enumeration, SaaS tenant probing, CT log analysis,
//! and web traffic & component analysis.

pub mod ct_logs;
pub mod saas_tenant;
pub mod subfinder;
pub mod web_traffic;

pub use ct_logs::CtLogDiscovery;
pub use saas_tenant::{SaasTenantDiscovery, TenantStatus};
pub use subfinder::{InstallOption, SubfinderDiscovery};
pub use web_traffic::WebTrafficDiscovery;
