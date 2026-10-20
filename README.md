# WebNest

> **"Create. Host. Manage."**

WebNest is a production-ready, self-service HTML hosting platform. It allows users to upload single-file HTML sites and instantly serves them on isolated URLs.

---

## Architecture & Security Highlights

1. **Untrusted HTML Sandboxing**:
   - Uploaded websites are served at `/sites/:slug`.
   - Content-Security-Policy sandbox enforcement prevents hosted scripts from accessing parent origins or hijacking session states.
   - Authentication cookies are restricted to `Path=/api`. Uploaded HTML files on `/sites/:slug` **cannot read, intercept, or transfer WebNest authentication credentials**.
2. **Persistent Hosting on Ephemeral Systems**:
   - The platform stores the full HTML document directly within SQLite in addition to creating localized filesystem entries.
   - Even if deployed to an ephemeral Render web service instance without persistent disks, hosted websites survive instance restarts and redeploys without reliance on external paid services (e.g., S3).
3. **Automatic Slug Generator**:
   - Creates sanitized, collision-free slugs (e.g., `my-portfolio`, `my-portfolio-2`).

---

## Local Development Setup

1. **Clone & Install Dependencies**:
   ```bash
   git clone <your-repo-url>
   cd webnest
   npm install
