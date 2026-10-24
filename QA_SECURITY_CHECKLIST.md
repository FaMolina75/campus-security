# SecurityCampus — QA checklist (development only)

This checklist is for `security-development`, not production.
Use mock users and a non-production database only.

## Authentication
- [ ] Login with valid credentials and CAPTCHA.
- [ ] Reject wrong, expired, and reused CAPTCHA.
- [ ] Reject unauthenticated API requests (401).
- [ ] Reject expired sessions after 120 seconds of inactivity (401).
- [ ] Reject blocked users on protected routes (403).
- [ ] Confirm session-status endpoint rejects blocked accounts.
- [ ] Reject unsafe methods without valid CSRF token (403).
- [ ] Verify logout and subsequent protected requests.

## Role isolation
- [ ] Student cannot access another student's records.
- [ ] Teacher cannot view or grade another teacher's group.
- [ ] Coordinator can query students in their assigned career.
- [ ] Coordinator cannot enroll students from other careers.
- [ ] Admin permissions do not leak to other roles.

## Browser compatibility
- [ ] Check credentials and cookies on Chrome, Firefox and Safari.
- [ ] Confirm Secure, HttpOnly and SameSite attributes.
- [ ] Check cross-site cookies between frontend and backend hosts.
- [ ] Verify CORS allows only configured frontend origins.

## Release blockers
- [ ] Migrate legacy plaintext passwords before strict mode.
- [ ] Configure a stable SECRET_KEY.
- [ ] Review exposed credentials and rotate safely.
- [ ] Confirm rate-limit storage behavior across restarts.
- [ ] Verify session revocation strategy.
- [ ] Confirm rollback plan and explicit release approval.

A passing CI run is not a substitute for these checks.
