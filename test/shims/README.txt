Minimal stand-ins for express, express-session and bcryptjs, used ONLY by test/server-e2e.js when the real packages are
not installed (NODE_PATH puts this folder last, so real packages always win). They implement just what server.js uses.
Run `npm ci` to test against the real Express (CI does).
