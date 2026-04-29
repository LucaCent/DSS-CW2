# Security Test Plan

This document outlines manual security tests to verify that all mitigations are working correctly. Each test simulates a real attack scenario.

## Pre-requisites
- The application is running on `http://localhost:3000`
- A test user account has been created (e.g. `testuser` / `Test@Pass1`)
- A second test user account has been created (e.g. `testuser2` / `Test@Pass2`)
- Both users have 2FA enabled
- `testuser` has at least one blog post created

---

## Security Test Cases

| Test ID | Vulnerability | Attack Simulation | Steps | Expected Result | Actual Result | Pass/Fail |
|---------|--------------|-------------------|-------|-----------------|---------------|-----------|
| SEC-01 | SQL Injection via Login | Inject SQL in username field | 1. Go to Login page. 2. Enter `' OR '1'='1' --` as username. 3. Enter any password. 4. Submit form. | Login fails with generic "Invalid credentials" message. No SQL error shown. Database unaffected. | | |
| SEC-02 | SQL Injection via Login (password) | Inject SQL in password field | 1. Go to Login page. 2. Enter a valid username. 3. Enter `' OR '1'='1' --` as password. 4. Submit form. | Login fails with generic "Invalid credentials" message. No SQL error or stack trace exposed. | | |
| SEC-03 | SQL Injection via Search | Inject SQL in search query | 1. Go to Search page. 2. Enter `'; DROP TABLE posts; --` in search box. 3. Submit search. | Search returns no results or an error. Posts table remains intact. No SQL error shown to user. | | |
| SEC-04 | SQL Injection via Post Creation | Inject SQL in post title | 1. Log in as testuser. 2. Create new post with title: `'); DELETE FROM posts; --` 3. Submit. | Post is created with the literal text as its title. No SQL execution. Other posts unaffected. | | |
| SEC-05 | Stored XSS via Post Body | Inject script in post content | 1. Log in as testuser. 2. Create post with content: `<script>alert('XSS')</script>` 3. View the post on the public listing. | The script tag is displayed as visible text (HTML-encoded), not executed. No alert box appears. | | |
| SEC-06 | Stored XSS via Post Title | Inject script in post title | 1. Log in. 2. Create post with title: `<img src=x onerror=alert(1)>` 3. View on homepage. | The img tag is displayed as text. No JavaScript executes. No alert or image error. | | |
| SEC-07 | Reflected XSS via Search | Inject script in search parameter | 1. Navigate to `/posts/search?q=<script>alert('XSS')</script>` or enter the script in the search box. | The script is HTML-encoded in the results or URL. No script execution in the browser. | | |
| SEC-08 | CSRF on Post Deletion | Forge a cross-site delete request | 1. Log in as testuser in Browser A. 2. In Browser B (or curl), send DELETE `/posts/1` with a forged/missing CSRF token. 3. Check if the post is deleted. | Request is rejected with 403 "Invalid or missing security token". Post remains in database. | | |
| SEC-09 | CSRF on Post Creation | Forge a cross-site create request | 1. Create an HTML page on another origin with a form that POSTs to `/posts`. 2. Open it while logged in. | Request is rejected with 403 due to missing/invalid CSRF token. No post created. | | |
| SEC-10 | Session Fixation | Attempt to fixate a session ID | 1. Note the session cookie value before login. 2. Log in successfully. 3. Check if the session cookie value has changed. | The session ID is regenerated upon login. The old session ID is no longer valid. | | |
| SEC-11 | Account Enumeration via Error Messages | Test login with non-existent username | 1. Go to Login. 2. Enter `nonexistentuser999` as username. 3. Enter any password. 4. Note the error message. 5. Try with a real username and wrong password. 6. Compare messages. | Both attempts return the identical message: "Invalid credentials". No way to distinguish. | | |
| SEC-12 | Account Enumeration via Response Timing | Time login responses | 1. Use curl/Postman with timing. 2. Send login with non-existent username. 3. Send login with real username but wrong password. 4. Compare response times. | Both responses take approximately the same time (within ~50ms) due to artificial delay. | | |
| SEC-13 | Brute Force Login | Attempt many failed logins | 1. Send 5 incorrect login attempts for a valid username. 2. Send a 6th attempt (even with correct password). | After 5 failures, the account is locked. The 6th attempt returns "Invalid credentials" even if the password is correct. Account unlocks after 15 minutes. | | |
| SEC-14 | IDOR on Edit Post | Edit another user's post | 1. Log in as testuser2. 2. Send PUT `/posts/{testuser1_post_id}` with new title/content and valid CSRF token. | Request is rejected with 403 "You do not have permission to edit this post". Post unchanged. | | |
| SEC-15 | IDOR on Delete Post | Delete another user's post | 1. Log in as testuser2. 2. Send DELETE `/posts/{testuser1_post_id}` with valid CSRF token. | Request is rejected with 403 "You do not have permission to delete this post". Post remains. | | |
| SEC-16 | Session Idle Timeout | Test inactivity expiry | 1. Log in successfully. 2. Wait 16 minutes without making any requests. 3. Attempt to access a protected route. | Session is expired. User receives "Session timed out due to inactivity" and must re-login. | | |
| SEC-17 | Missing CSRF Token | Submit form without token | 1. Log in. 2. Using browser dev tools or curl, send a POST to `/posts` without the `_csrf` field or `x-csrf-token` header. | Request is rejected with 403 "Invalid or missing security token". | | |
| SEC-18 | Password Reset Token Expiry | Use expired token | 1. Request a password reset. 2. Wait 16 minutes. 3. Attempt to use the token. | Token is rejected as expired. User must request a new one. | | |
| SEC-19 | 2FA Bypass Attempt | Login without TOTP code | 1. Log in with correct username and password (2FA enabled). 2. Do not provide a TOTP code. | Server responds with `requires2FA: true`. User is not granted a session until valid TOTP code is provided. | | |
| SEC-20 | Content Security Policy | Attempt inline script execution | 1. Open browser dev tools Console. 2. Check response headers for Content-Security-Policy. 3. Verify script-src is `'self'` only. | CSP header is present. Inline scripts are blocked by the browser. Console shows CSP violation. | | |

---

## Notes
- All tests should be performed on `http://localhost:3000`
- Use browser developer tools (Network tab, Console) to inspect responses and headers
- Use tools like curl, Postman, or Burp Suite for manual HTTP request crafting
- Record actual results and pass/fail status after executing each test
