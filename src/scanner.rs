use crate::{
    config::Config,
    evasion,
    fingerprints::{DetectionResponse, WafDetector},
    http::{build_client, send_request},
    payloads::PayloadManager,
    types::{Finding, ScanResults, ScanSummary},
};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};

/// WAF scanner
pub struct Scanner {
    config: Config,
    client: reqwest::Client,
    payload_manager: PayloadManager,
    waf_detector: WafDetector,
}

impl Scanner {
    /// Create a new scanner
    pub async fn new(config: Config) -> crate::error::Result<Self> {
        config.validate()?;

        let client = build_client(&config)?;

        let payload_manager = if let Some(ref payload_file) = config.payload_file {
            tracing::info!("Loading custom payloads from: {}", payload_file);
            PayloadManager::from_file(payload_file).await?
        } else {
            tracing::info!("Loading default embedded payloads");
            PayloadManager::with_defaults()?
        };

        let waf_detector = WafDetector::new()?;

        Ok(Self {
            config,
            client,
            payload_manager,
            waf_detector,
        })
    }

    /// Perform the WAF bypass scan
    #[tracing::instrument(skip(self), fields(target = %self.config.target))]
    pub async fn scan(&self) -> crate::error::Result<ScanResults> {
        let start_time = Instant::now();

        tracing::info!("Starting WAF scan on {}", self.config.target);

        // Step 1: Detect WAF
        let waf_detected = self.detect_waf().await?;

        if let Some(ref waf_name) = waf_detected {
            tracing::info!("Detected WAF: {}", waf_name);
        } else {
            tracing::info!("No WAF detected");
        }

        // Step 2: Run payload tests
        let mut results = ScanResults::new(self.config.target.clone(), waf_detected);
        let findings = self.test_payloads().await?;

        for finding in findings {
            results.add_finding(finding);
        }

        // Step 3: Calculate summary
        results.sort_by_severity();

        let techniques_used: HashSet<_> = results
            .findings
            .iter()
            .filter_map(|f| f.technique_used.as_ref())
            .collect();

        results.summary = ScanSummary {
            total_payloads: self.payload_manager.payloads().len(),
            successful_bypasses: results.findings.len(),
            techniques_effective: techniques_used.len(),
            duration_secs: start_time.elapsed().as_secs_f64(),
        };

        tracing::info!(
            "Scan complete. Found {} successful bypasses in {:.2}s",
            results.summary.successful_bypasses,
            results.summary.duration_secs
        );

        Ok(results)
    }

    /// Detect WAF by sending a baseline request
    async fn detect_waf(&self) -> crate::error::Result<Option<String>> {
        tracing::debug!("Sending baseline request for WAF detection");

        let response = send_request(&self.client, &self.config.target, None).await?;

        let detection_response = DetectionResponse::new(
            response.status_code,
            response.headers,
            response.body,
            response.cookies,
        );

        Ok(self.waf_detector.detect(&detection_response))
    }

    /// Test all payloads with evasion techniques
    async fn test_payloads(&self) -> crate::error::Result<Vec<Finding>> {
        let payloads = self.payload_manager.payloads();
        let semaphore = Arc::new(Semaphore::new(self.config.concurrency));
        let mut tasks = Vec::new();

        tracing::info!("Testing {} payloads", payloads.len());

        for payload in payloads {
            for payload_test in &payload.payloads {
                // Apply all evasion techniques
                let technique_variants = evasion::apply_all_techniques(
                    &payload_test.value,
                    self.config.enabled_techniques.as_deref(),
                );

                for (technique_name, transformed_payload) in technique_variants {
                    let sem = semaphore.clone();
                    let client = self.client.clone();
                    let target = self.config.target.clone();
                    let delay_ms = self.config.delay_ms;
                    let payload_id = payload.id.clone();
                    let severity = payload.info.severity;
                    let category = payload.info.category.clone();
                    let description = payload.info.description.clone();
                    let matchers = payload.matchers.clone();

                    let task = tokio::spawn(async move {
                        let _permit = sem.acquire().await.unwrap();

                        // Rate limiting delay
                        if delay_ms > 0 {
                            sleep(Duration::from_millis(delay_ms)).await;
                        }

                        // Send request with payload as query parameter
                        let response = send_request(
                            &client,
                            &target,
                            Some(("test", &transformed_payload)),
                        )
                        .await;

                        match response {
                            Ok(resp) => {
                                // Check if payload matched
                                let matched = check_matchers(&resp, &matchers);

                                if matched {
                                    tracing::debug!(
                                        "Payload {} matched with technique: {}",
                                        payload_id,
                                        technique_name
                                    );

                                    Some(Finding {
                                        payload_id,
                                        severity,
                                        category,
                                        payload_value: transformed_payload,
                                        technique_used: if technique_name == "Original" {
                                            None
                                        } else {
                                            Some(technique_name)
                                        },
                                        response_status: resp.status_code,
                                        description,
                                    })
                                } else {
                                    None
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Request failed for payload {}: {}", payload_id, e);
                                None
                            }
                        }
                    });

                    tasks.push(task);
                }
            }
        }

        // Wait for all tasks to complete
        let results = futures::future::join_all(tasks).await;

        // Collect findings
        let findings: Vec<Finding> = results
            .into_iter()
            .filter_map(|r| r.ok())
            .flatten()
            .collect();

        Ok(findings)
    }
}

/// Check if response matches any of the matchers
fn check_matchers(
    response: &crate::http::HttpResponse,
    matchers: &[crate::payloads::Matcher],
) -> bool {
    for matcher in matchers {
        match matcher.matcher_type.as_str() {
            "response_body" => {
                if matcher.condition == "contains" {
                    for pattern in &matcher.patterns {
                        if response.body.contains(pattern) {
                            return true;
                        }
                    }
                } else if matcher.condition == "not_contains" {
                    let mut all_not_found = true;
                    for pattern in &matcher.patterns {
                        if response.body.contains(pattern) {
                            all_not_found = false;
                            break;
                        }
                    }
                    if all_not_found {
                        return true;
                    }
                }
            }
            "response_time" => {
                if matcher.condition == "greater_than" {
                    if let Some(threshold) = matcher.patterns.first() {
                        if let Ok(threshold_ms) = threshold.parse::<u64>() {
                            if response.response_time_ms > threshold_ms {
                                return true;
                            }
                        }
                    }
                }
            }
            _ => {
                tracing::warn!("Unknown matcher type: {}", matcher.matcher_type);
            }
        }
    }

    false
}
