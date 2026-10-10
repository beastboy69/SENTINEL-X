# SENTINEL-X — Project Standard Operating Procedure (SOP)

**Event:** SITAMS × HACKSPHERE Hackathon  
**Date:** 10 October 2026  
**Official domain:** Domain 5 — AI for Cybersecurity  
**Project:** SENTINEL-X — Personal AI-Assisted Cybersecurity Analyst  
**Version:** 1.0 — Proposed project SOP  
**Repository:** https://github.com/beastboy69/SENTINEL-X

## 1. Project overview

SENTINEL-X is a personal cybersecurity analyst prototype intended to help individual Windows users review available security telemetry through a web dashboard. Its current repository includes a Python backend, Windows event collector, web interface, tests, and a local SQLite database. The project aims to make security events easier to inspect and provide a foundation for rule-based detection and AI-assisted explanations.

SENTINEL-X supplements existing controls such as Microsoft Defender; it is not a replacement for antivirus, a firewall, or professional incident response. Any capability not verified in the current code and tests must be described as planned, not implemented.

## 2. Problem statement

Individual users and students may find Windows security logs difficult to interpret. Important events can be overlooked, while benign activity may be mistaken for an attack. The project asks: **How can individual Windows users review relevant security events and understand potential risks through an accessible, privacy-conscious tool?**

This matters because logs can be technical, suspicious activity may require investigation, and security telemetry can contain sensitive personal or system information.

## 3. Target users

- Students learning cybersecurity and digital forensics.
- Individual Windows laptop and desktop users.
- Beginners learning to interpret system security events.
- Learners performing authorized lab investigations.
- Small teams seeking a lightweight educational monitoring prototype.

The initial scope is an individual Windows machine, not enterprise-wide endpoint monitoring.

## 4. Objectives and success criteria

Objectives:
- Collect and display supported Windows security-related events.
- Present events and timestamps in a readable dashboard.
- Support near-real-time monitoring through periodic collection, where implemented.
- Apply documented detection rules and communicate uncertainty.
- Protect local databases, credentials, and telemetry.
- Provide repeatable tests, setup instructions, and an honest demonstration.

Success criteria:
- Backend starts in the supported Windows environment.
- Dashboard communicates with the backend.
- Available events can be collected and displayed.
- Empty results are distinguished from collection failures.
- Detection tests pass.
- Secrets and private event data are excluded from public source control.
- The deployment architecture and limitations are documented.
- Cross-device/browser testing is completed if required for the submission.

## 5. Proposed solution and modules

The intended architecture uses a local Windows collector, Python backend, database, and browser dashboard.

### 5.1 Windows event monitoring
- Read supported Windows event sources with appropriate permissions.
- Query a defined time window and display relevant event details.
- Handle missing permissions, inaccessible logs, and errors explicitly.

### 5.2 Event processing and detection
- Normalize supported event fields.
- Apply documented rules to identify records that warrant review.
- Distinguish observed events from rule-generated findings.
- Do not label an event malicious solely because it matches a broad rule.

### 5.3 Dashboard
- Display events, timestamps, collection status, and available summaries.
- Provide clear loading, empty, and error states.
- Avoid presenting stale data as current.

### 5.4 Local storage
- Store only data needed by the prototype.
- Keep local databases and private logs out of Git.
- Document retention, backup, and deletion behavior.

### 5.5 Proposed future modules (not to be claimed as implemented without evidence)
- **Phishing analysis:** inspect user-submitted URL/email text for indicators without automatically opening URLs.
- **Sensitive-data scanner:** scan only user-authorized folders and minimize exposure of file contents.
- **Breach-awareness checks:** use a reputable service where configured; never send plaintext passwords or imply that no match proves an account is safe.
- **AI-assisted analysis:** summarize selected evidence, explain terms, suggest investigative steps, and communicate uncertainty. Treat logs and user content as untrusted input; do not allow model output to execute commands automatically.

## 6. Functional requirements

| ID | Requirement | Verification |
|---|---|---|
| FR-01 | Backend starts in the supported environment. | Startup test |
| FR-02 | Dashboard accesses the backend. | API/UI integration test |
| FR-03 | Collector reads supported event sources. | Controlled Windows test |
| FR-04 | Events include relevant timestamps and metadata. | Record validation |
| FR-05 | Detection rules match expected outcomes. | Automated unit tests |
| FR-06 | Empty results differ from collection failures. | Empty/error-state tests |
| FR-07 | Local database is excluded from source control. | Git inspection |
| FR-08 | Setup and usage are documented. | Fresh setup test |
| FR-09 | AI explanations are evidence-based, if implemented. | Scenario evaluation |
| FR-10 | Deployed functionality is tested after deployment. | Deployment checklist |

Requirements for proposed modules remain incomplete until implemented and tested.

## 7. Non-functional requirements

- **Performance:** bounded queries, reasonable polling, and visible latest-successful-collection time.
- **Reliability:** handle missing dependencies, inaccessible logs, database errors, and stale data.
- **Usability:** clear labels and actionable explanations without overstating findings.
- **Privacy:** local-first handling where possible, data minimization, and disclosure of external transfers.
- **Maintainability:** separate collection, processing, storage, and presentation; document configuration and tests.

## 8. Technology stack

The repository structure indicates the following; confirm exact versions and dependencies from source before submission.

| Layer | Technology / role |
|---|---|
| Frontend | HTML/CSS/JavaScript web interface |
| Backend | Python (`backend/server.py`) |
| Windows telemetry | Windows event collector (`backend/windows_collector.py`) |
| Database | SQLite (local `sentinel_x.db` file exists locally) |
| Tests | Python tests under `tests/` |
| Version control | Git and GitHub |
| Local launch | Windows startup script |
| Deployment | To be selected and validated |
| AI service/model | To be documented if actually integrated |

**Architecture constraint:** a cloud server cannot directly read event logs on a user's private Windows laptop. Live endpoint telemetry needs a local collector and secure, authenticated data transfer, or the application must run locally. Hosting only the dashboard does not provide access to local Windows logs.

## 9. System workflow

**Proposed flow:** Windows Event Logs → Local Collector → Event Processing/Detection Rules → SQLite → Backend API → Web Dashboard → User investigation.

1. User starts the application.
2. Backend initializes required components.
3. Collector queries supported event sources.
4. Records are validated and normalized.
5. Configured rules process events.
6. Data is stored or retrieved according to the actual implementation.
7. Dashboard requests available records from the backend.
8. User reviews events and supported findings.
9. Collection timestamps and errors are displayed.
10. User decides whether further investigation is required.

Periodic polling is near-real-time, not instantaneous detection. If the code uses a roughly 30-second interval, verify that in code and during testing before documenting it as a confirmed specification.

## 10. AI usage plan

AI tools may assist with research, architecture, UI/UX, coding, debugging, testing, and documentation, subject to event rules. If an AI service is integrated, it may summarize selected events, explain terminology, suggest investigative questions, and state uncertainty.

Controls:
- Review and understand AI-generated code.
- Never commit API keys, passwords, or tokens.
- Validate outputs against available evidence and deterministic rules.
- Treat logs, URLs, and email text as untrusted input.
- Do not let AI output execute commands or make consequential changes automatically.
- Document the model/provider, information sent, and limitations for any external service.
- If no AI model is integrated, describe AI analysis as planned rather than completed.

## 11. Security and privacy plan

### Secrets and access
- Keep secrets outside source control; use environment variables or a secrets manager for deployment.
- Apply least privilege when reading Windows logs.
- Protect remotely accessible APIs with authentication and authorization.
- Do not put credentials in frontend JavaScript or public documentation.

### Data protection
- Exclude local databases and private security records from Git.
- Minimize personal information in stored events and reports.
- Use encrypted transport for remote telemetry.
- Define retention and deletion behavior.
- Do not send raw telemetry to external AI services unless necessary and disclosed.

### Web security
- Validate inputs and safely render untrusted event content.
- Configure CORS and security headers appropriately.
- Avoid exposing stack traces or secrets in production errors.
- Test API access controls where implemented.

### Honest reporting
- No recent events does not prove the system is secure.
- A rule match does not prove an attack.
- Collection failure must not be shown as a clean scan.
- Do not claim antivirus protection, complete breach detection, or guaranteed prevention without implementation and validation.

## 12. Testing plan

### Unit tests
- Test rules with benign, suspicious, malformed, incomplete, and boundary-case inputs.
- Compare actual outputs with documented expected results.

### Integration tests
- Verify backend/database connectivity.
- Verify dashboard/API communication.
- Check field mapping, timestamps, and error handling.
- Test empty-result behavior.

### Windows collector tests
- Verify supported event sources and permissions.
- Use benign, controlled activity on an authorized machine.
- Confirm records appear within the configured polling window.
- Test inaccessible logs and unavailable sources.

### Security tests
- Search staged files and Git history for secrets.
- Confirm local database and private logs are not tracked.
- Test API access controls and untrusted input handling where applicable.
- Ensure tests do not trigger destructive or unauthorized actions.

### UI and AI tests
- Test navigation and loading, empty, error, and populated states.
- Test another browser/device where supported.
- If AI is implemented, test benign, suspicious, ambiguous, and prompt-injection-like content; document false positives, missed findings, and limitations.

Maintain test evidence with test case, expected result, actual result, pass/fail status, date, and sanitized evidence. Mark tests passed only after execution.

## 13. Research plan

Research and document:
1. Windows event logging and available security telemetry.
2. Capabilities of built-in Windows security tools.
3. SIEM/endpoint-monitoring approaches relevant to individuals.
4. Usability challenges for cybersecurity beginners.
5. False-positive risks in rule-based detection.
6. Privacy risks of external AI services.
7. Comparable tools and the specific gap this prototype addresses.

Use verifiable sources, distinguish facts from assumptions, and do not claim no comparable product exists without evidence.

## 14. Development procedure

1. Review the existing repository and identify implemented features.
2. Finalize scope and problem statement.
3. Separate current features from planned enhancements in documentation.
4. Review architecture and dependencies.
5. Make small, testable changes.
6. Run automated and controlled integration tests.
7. Review privacy, security, and failure handling.
8. Update README setup, usage, testing, and limitations.
9. Review tracked files and commit history before pushing.
10. Push source to GitHub.
11. Deploy using an architecture appropriate for local telemetry.
12. Test the live application and prepare a truthful demo.

## 15. GitHub and source-code management

**Repository:** https://github.com/beastboy69/SENTINEL-X

The initial source commit has been pushed to the `main` branch. Before submission:
- Confirm repository visibility matches event requirements.
- Review all tracked files and the full Git history for secrets.
- Keep databases, personal logs, and sensitive artifacts out of the repository.
- Maintain a professional README with overview, features, prerequisites, setup, usage, tests, and limitations.
- Add screenshots/demo instructions where useful.
- Choose a license deliberately rather than implying one exists.
- Correct claims for any feature not implemented.

## 16. Deployment plan

The hackathon requires a live URL that judges can open and test from another device/browser.

1. Select a platform appropriate for frontend and backend.
2. Decide which components must run on the Windows endpoint.
3. Configure environment variables securely.
4. Exclude secrets and private local data from deployment artifacts.
5. Secure any remote telemetry with authentication and encrypted transport.
6. Deploy the web UI and required API components.
7. Verify health checks, supported APIs, and database behavior.
8. Test from another browser/device.
9. Document features that still require the local collector.
10. Record the live URL and demo prerequisites.

Do not expose an unauthenticated endpoint that accepts private Windows telemetry. Do not claim the cloud deployment monitors a laptop unless the local agent-to-server path is implemented and tested.

## 17. Demonstration plan

1. Introduce the problem and target users.
2. Explain the proposed solution.
3. Open the dashboard.
4. Show real, authorized test-machine events if available.
5. Explain a representative event or implemented detection rule.
6. Demonstrate empty and error states.
7. Explain privacy controls and limitations.
8. Show the GitHub repository.
9. Open the live deployment if complete.
10. Clearly label planned features and known limitations.

Use sanitized, non-sensitive data and demonstrate only features that have been tested.

## 18. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Insufficient Windows permissions | Document prerequisites and show explicit errors |
| No recent events | Display query window and latest successful collection |
| False positives | Document rules and require human review |
| Data exposure | Minimize data, restrict access, exclude private data from Git |
| AI misinformation | Validate evidence and communicate uncertainty |
| Cloud/local mismatch | Keep collector local or build a secure agent |
| Deployment failure | Run health checks and cross-device tests |
| Overstated features | Maintain a verified feature checklist |

## 19. Deliverables

1. This SOP.
2. Problem statement and research summary.
3. Working application with documented scope.
4. GitHub source and professional README.
5. Test report and sanitized evidence.
6. Security/privacy notes.
7. Live URL when deployment is complete.
8. Short demonstration and project explanation.
9. Final checklist for functionality, repository safety, and deployment.

## 20. Final submission checklist

- [x] Selected Domain 5 — AI for Cybersecurity.
- [x] Defined the real-world problem and target users in this SOP.
- [ ] Completed research with verifiable sources.
- [x] Prepared this SOP.
- [ ] Verified implemented features against source code.
- [ ] Tested backend, collector, dashboard, and detection rules.
- [ ] Reviewed privacy, security, and error handling.
- [ ] Audited Git history for secrets and private data.
- [x] Pushed the initial source commit to GitHub.
- [ ] Completed README and setup documentation review.
- [ ] Deployed the application.
- [ ] Tested live application from another device/browser.
- [ ] Prepared final GitHub and live URLs.
- [ ] Prepared a short, accurate demonstration.

## 21. Conclusion

SENTINEL-X aims to make Windows security telemetry easier to understand through an accessible cybersecurity analysis interface. Its initial scope emphasizes local event monitoring, structured presentation, and testable detection logic. Additional AI-assisted capabilities remain subject to implementation and validation. The project should be presented as a credible prototype with transparent limitations, documented testing, secure data handling, and an architecture suitable for local monitoring.
