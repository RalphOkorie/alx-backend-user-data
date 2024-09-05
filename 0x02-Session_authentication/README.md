# Session authentication
Authentication verifies user identity. Session authentication uses server-stored sessions, identified by cookies. Cookies are small data stored on the client. Send cookies via Set-Cookie header; parse with cookie-parser. REST API session auth uses cookies for user sessions. HTTP Cookie stores session dataFlask uses Flask-HTTPAuth for session management
