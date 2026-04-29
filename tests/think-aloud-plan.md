# Think-Aloud User Test Plan

This document provides a structured plan for conducting a think-aloud usability test of the Secure Blog application. The purpose is to evaluate whether security features are implemented without compromising usability.

---

## Test Overview

| Item | Details |
|------|---------|
| **Application** | Secure Blog (localhost:3000) |
| **Test Method** | Concurrent think-aloud protocol |
| **Participants** | 3–5 representative users |
| **Duration** | 20–30 minutes per participant |
| **Equipment** | Computer with browser, screen recording (optional), observer notes sheet |

---

## Participant Tasks

Each participant should be asked to complete the following tasks in order. The facilitator reads each task aloud and asks the participant to narrate their thoughts as they work.

### Task 1: Register a New Account
**Instruction to participant:**
> "Please create a new account on this blog. Choose any username, email, and password you like."

**Success criteria:** Account is created, user reaches the 2FA setup page.

---

### Task 2: Set Up Two-Factor Authentication (2FA)
**Instruction to participant:**
> "The application is now asking you to set up two-factor authentication. Please follow the on-screen instructions to complete this. You can use Google Authenticator or a similar app on your phone."

**Success criteria:** User scans QR code, enters verification code, 2FA is enabled.

---

### Task 3: Log In with 2FA
**Instruction to participant:**
> "Please log out (if still logged in) and log back in using your new account, including the 2FA step."

**Success criteria:** User logs in with username, password, and TOTP code.

---

### Task 4: Create a Blog Post
**Instruction to participant:**
> "Please write and publish a new blog post about any topic you like."

**Success criteria:** Post is created and appears on the homepage.

---

### Task 5: Search for a Post
**Instruction to participant:**
> "Please use the search feature to find a blog post by keyword."

**Success criteria:** User finds and views search results.

---

### Task 6: Edit a Blog Post
**Instruction to participant:**
> "Please find the blog post you just created and edit its title or content."

**Success criteria:** Post is updated with new content.

---

### Task 7: Delete a Blog Post
**Instruction to participant:**
> "Please delete the blog post you created."

**Success criteria:** Post is deleted after confirmation.

---

### Task 8: Log Out
**Instruction to participant:**
> "Please log out of the application."

**Success criteria:** User is logged out and returned to the public view.

---

## Observer Instruction Sheet

### Before the Test
1. Ensure the application is running at `http://localhost:3000`
2. Prepare a fresh database (or clear test data)
3. Have the participant install an authenticator app if they don't have one
4. Explain the think-aloud method: "Please say out loud everything you are thinking as you use the application — what you're looking at, what you're trying to do, what confuses you, etc."
5. Reassure the participant: "We are testing the application, not you. There are no wrong answers."

### During the Test
- **Do not** help the participant unless they are completely stuck for more than 2 minutes
- Note the **time** each task starts and ends
- Record **verbatim quotes** from the participant where possible
- Note any **hesitations**, **errors**, **confusion**, or **frustration**
- Note whether the participant read and understood **on-screen instructions** (especially for 2FA)
- Note whether **error messages** were helpful or confusing

### After the Test
- Ask the participant: "What was the easiest part of using this application?"
- Ask: "What was the most confusing or difficult part?"
- Ask: "Did you feel the security features (2FA, error messages) were easy to understand?"
- Ask: "Is there anything you would change about the application?"

---

## Observation Recording Table

| Task # | Task Description | Time Taken | Completed? (Y/N) | Errors/Difficulties Observed | Participant Comments (Verbatim) |
|--------|-----------------|------------|-------------------|------------------------------|-------------------------------|
| 1 | Register | | | | |
| 2 | Set up 2FA | | | | |
| 3 | Log in with 2FA | | | | |
| 4 | Create a post | | | | |
| 5 | Search for a post | | | | |
| 6 | Edit a post | | | | |
| 7 | Delete a post | | | | |
| 8 | Log out | | | | |

---

## Results Summary Template

### Participant Information
| Field | Details |
|-------|---------|
| Participant ID | P__ |
| Date | |
| Technical Experience Level | Beginner / Intermediate / Advanced |

### Task Completion Summary
| Task | Completed | Time | Difficulty (1–5) | Notes |
|------|-----------|------|-------------------|-------|
| 1. Register | | | | |
| 2. Set up 2FA | | | | |
| 3. Log in with 2FA | | | | |
| 4. Create post | | | | |
| 5. Search | | | | |
| 6. Edit post | | | | |
| 7. Delete post | | | | |
| 8. Log out | | | | |

### Key Observations
- **Positive findings:**
  - (list what worked well)

- **Usability issues found:**
  - (list issues with severity: Low / Medium / High)

- **Security vs usability conflicts:**
  - (list any cases where security made tasks harder)

### Overall Assessment
- Task completion rate: __/8 tasks
- Average difficulty rating: __/5
- Recommendation: (Pass / Pass with changes / Fail)

### Post-Test Questionnaire Responses
1. Easiest part:
2. Most confusing part:
3. Security features (clear/unclear):
4. Suggested improvements:
