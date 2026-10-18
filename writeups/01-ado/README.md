# Ado

| Field | Value |
|---|---|
| Challenge | Ado |
| Category | Web |
| Team name | B2F1 |

Ado was an "Ado fan community" site, and it came as a source bundle (AdonisJS /
TypeScript) alongside a live instance that greets you with a login wall. The theme hint
"4don1s" was basically a wink at the AdonisJS framework. Since the live site wanted
credentials I didn't have, I knew the win wasn't going to be a trivia prompt. I'd need to read
the bundle's routes and controllers and find a chain that actually worked against the live box.


## Challenge details and overview

- Supplied file(s) / service: An "Ado fan community" web application shipped as a
      source bundle (AdonisJS / TypeScript) plus a live, login-gated instance. The live
      instance uses different credentials than the bundle.
- Category: Web.
- Initial observation: The theme hint "4don1s" points at the AdonisJS framework. The
      live site presents a login wall rather than a trivia prompt, so the solve required
      reading the bundle's routes/controllers to find a chain that works against the live
      instance.
- DeepSeek Conversation Link: https://chat.deepseek.com/share/db30vteapme42ystes


## Enumeration and analysis

So I went straight to the bundle's start/routes.ts to map the attack surface. These are the
routes I confirmed in the source (not invented):

- Route.post('/api/v1/auth/login', 'AuthController.login')
- Route.post('/api/v1/auth/logout', 'AuthController.logout')
- Route.get('/api/v1/auth/me', 'AuthController.me')
- Route.get('/api/v1/internal/accounts/:id', 'AccountsController.show')
- Route.post('/api/v1/comments', 'CommentsController.store')
- Route.get('/posts/:postId/comments', 'CommentsController.publicIndex')
- Route.get('/admin/comments', ...): admin-only moderation view
- Route.post('/admin/upload', ...): admin-only attachment upload
- Route.get('/admin/generate-report', ...): admin-only report generator

Two sinks jumped out at me.

First, AccountsController.show returns the raw user record including password:
user.password, and the /api/v1/internal/accounts/:id route carries no auth middleware, so
any id can be dereferenced unauthenticated.


Second, the admin generate-report handler reads a template file and executes it via
vm.runInContext, a weak sandbox that's trivially escaped. I also noted that the upload
handler (/admin/upload) stores the uploaded filename, and that the session cookie is
adonis-session (config/session.ts). And the Dockerfile told me exactly where the prize
lived:

- COPY --chown=node:node flag.txt /app/flag.txt
- RUN chmod 400 /app/flag.txt

From here the chain more or less wrote itself: leak a login, ride a member into the admin,
traverse a file over the sandbox template, then break out of the sandbox to read the flag.


## Chained web exploitation

Here's the full chain, validated against the live instance. I also walked the chain through
[DeepSeek](https://chat.deepseek.com/share/db30vteapme42ystes) before running it end
to end:

1. Unauthenticated account disclosure. GET /api/v1/internal/accounts/:id returns a valid
       user's credentials (the source returns user.password). That recovered me a working
       member login (e.g. user Hana), since the live admin password differs from the
       bundle's .env (ADMIN_BOT_PASSWORD=testing123, a bundle-only value that I
       treated as a decoy for the live box).
2. Stored XSS → admin cookie theft. Logged in as the recovered member, I posted a
       comment via POST /api/v1/comments whose body is a script. When the admin bot
       views /admin/comments, the script fires in the admin context and exfiltrates the
       admin's adonis-session cookie back into a new comment. Login as recovered user,
       then store the XSS comment; the stored XSS body exfiltrates admin cookie as a
       comment on postId 1 via fetch to /api/v1/comments with body
       ADMIN_COOKIE:+document.cookie.
3. Admin-only upload path traversal. Replaying the stolen adonis-session as admin, I
       uploaded an attachment whose multipart filename traverses out of the upload
       directory into the reports directory, overwriting storage/reports/template.js: curl -b
       admin_cookie -F "attachment=@payload.js;filename=../reports/template.js"
       "$base/admin/upload"
4. vm sandbox escape → read /app/flag.txt. My malicious template.js breaks out of the
       vm context via constructor.constructor('return process')() to regain the real require,
       then reads the flag file. Triggering GET /admin/generate-report runs it and returns the
       flag inside the JSON result. The template.generate() does: processRef =
       this.constructor.constructor('return process')(); fs =
       processRef.mainModule.require('fs'); return fs.readFileSync('/app/flag.txt', 'utf8').
       Then: curl -b admin_cookie "$base/admin/generate-report" → {"message":"Report
       generated","result":"nexsec26{...}"}

## Flag retrieval and proof

For proof, the value was read directly from /app/flag.txt through the chain above
(generate-report returning the fs.readFileSync('/app/flag.txt') output), not from any decoy.
The flag string itself confirms the "4don1s" (Adonis) CVE theme.


## Recovered CTF flag

nexsec26{Did_you_enjoy_DnD_song?kinda_g00d_actually_oh_btw_this_is_4don1s_cve_d675e0183239518f848d5ea6bdfac3375e54f7608ebd1dda8662d39509a5f282}


Ado attack-surface routes

## Source Figures

![DeepSeek collaboration thread for the Ado exploit chain](../../assets/ado/deepseek.png)

![Ado attack-surface routes and chain proof](../../assets/ado/figure-000.png)
