// SAST canary fixture — intentionally contains patterns that trip Opengrep
// ERROR-level rules. Do NOT fix these; they validate that the SAST gate works.
// If this file stops tripping the canary CI step, a rule is broken.

fn sast_canary() {
    let password = "hunter2";
    error!("Login failed for password {}", password);
}
