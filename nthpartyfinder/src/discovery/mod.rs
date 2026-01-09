//! Discovery modules for finding third-party vendor relationships
//! through subdomain enumeration and SaaS tenant probing.

pub mod subfinder;
pub mod saas_tenant;

pub use subfinder::SubfinderDiscovery;
pub use saas_tenant::SaasTenantDiscovery;
