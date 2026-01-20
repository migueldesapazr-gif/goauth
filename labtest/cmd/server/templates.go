package main

const homeHTML = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.AppName}} - GoAuth Test</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>
<body class="bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 min-h-screen text-white">
    <div class="container mx-auto px-4 py-16">
        <div class="text-center mb-12">
            <h1 class="text-5xl font-bold mb-4 bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
                🔐 {{.AppName}}
            </h1>
            <p class="text-xl text-gray-300">GoAuth Authentication Test Server</p>
            <p class="text-sm text-gray-500 mt-2">{{.AppURL}}</p>
        </div>

        <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-6xl mx-auto">
            <!-- Login Card -->
            <a href="/login" class="block p-6 bg-white/10 backdrop-blur-lg rounded-2xl border border-white/20 hover:bg-white/20 transition-all hover:scale-105">
                <div class="text-4xl mb-4">🔑</div>
                <h2 class="text-2xl font-bold mb-2">Login</h2>
                <p class="text-gray-400">Email/password, OAuth, Magic Link</p>
            </a>

            <!-- Register Card -->
            <a href="/register" class="block p-6 bg-white/10 backdrop-blur-lg rounded-2xl border border-white/20 hover:bg-white/20 transition-all hover:scale-105">
                <div class="text-4xl mb-4">📝</div>
                <h2 class="text-2xl font-bold mb-2">Register</h2>
                <p class="text-gray-400">Create new account with CAPTCHA</p>
            </a>

            <!-- Dashboard Card -->
            <a href="/dashboard" class="block p-6 bg-white/10 backdrop-blur-lg rounded-2xl border border-white/20 hover:bg-white/20 transition-all hover:scale-105">
                <div class="text-4xl mb-4">📊</div>
                <h2 class="text-2xl font-bold mb-2">Dashboard</h2>
                <p class="text-gray-400">Protected area (requires auth)</p>
            </a>

            <!-- Test Page Card -->
            <a href="/test" class="block p-6 bg-white/10 backdrop-blur-lg rounded-2xl border border-white/20 hover:bg-white/20 transition-all hover:scale-105">
                <div class="text-4xl mb-4">🧪</div>
                <h2 class="text-2xl font-bold mb-2">Test Page</h2>
                <p class="text-gray-400">Test all features manually</p>
            </a>

            <!-- Health Check Card -->
            <a href="/api/health" class="block p-6 bg-white/10 backdrop-blur-lg rounded-2xl border border-white/20 hover:bg-white/20 transition-all hover:scale-105">
                <div class="text-4xl mb-4">💚</div>
                <h2 class="text-2xl font-bold mb-2">Health Check</h2>
                <p class="text-gray-400">API health endpoint</p>
            </a>

            <!-- Config Card -->
            <a href="/api/config" class="block p-6 bg-white/10 backdrop-blur-lg rounded-2xl border border-white/20 hover:bg-white/20 transition-all hover:scale-105">
                <div class="text-4xl mb-4">⚙️</div>
                <h2 class="text-2xl font-bold mb-2">Config</h2>
                <p class="text-gray-400">View enabled features</p>
            </a>
        </div>

        <!-- OAuth Providers Status -->
        <div class="mt-12 max-w-2xl mx-auto">
            <h3 class="text-xl font-bold mb-4 text-center">Enabled OAuth Providers</h3>
            <div class="flex justify-center gap-4 flex-wrap">
                {{if .HasGoogle}}
                <span class="px-4 py-2 bg-green-500/20 border border-green-500 rounded-full text-green-400">✓ Google</span>
                {{end}}
                {{if .HasDiscord}}
                <span class="px-4 py-2 bg-indigo-500/20 border border-indigo-500 rounded-full text-indigo-400">✓ Discord</span>
                {{end}}
                {{if .HasGitHub}}
                <span class="px-4 py-2 bg-gray-500/20 border border-gray-500 rounded-full text-gray-300">✓ GitHub</span>
                {{end}}
            </div>
        </div>

        <!-- CAPTCHA Status -->
        <div class="mt-8 max-w-2xl mx-auto">
            <h3 class="text-xl font-bold mb-4 text-center">CAPTCHA Providers</h3>
            <div class="flex justify-center gap-4 flex-wrap">
                {{if .TurnstileSite}}
                <span class="px-4 py-2 bg-orange-500/20 border border-orange-500 rounded-full text-orange-400">✓ Turnstile</span>
                {{end}}
                {{if .RecaptchaSite}}
                <span class="px-4 py-2 bg-blue-500/20 border border-blue-500 rounded-full text-blue-400">✓ reCAPTCHA</span>
                {{end}}
                {{if .HcaptchaSite}}
                <span class="px-4 py-2 bg-yellow-500/20 border border-yellow-500 rounded-full text-yellow-400">✓ hCaptcha</span>
                {{end}}
            </div>
        </div>
    </div>
</body>
</html>`

const loginHTML = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - {{.AppName}}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>
<body class="bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 min-h-screen text-white flex items-center justify-center">
    <div class="w-full max-w-md p-8">
        <div class="bg-white/10 backdrop-blur-lg rounded-2xl border border-white/20 p-8">
            <h1 class="text-3xl font-bold text-center mb-8">🔑 Login</h1>
            
            <!-- Email/Password Form -->
            <form id="loginForm" class="space-y-4">
                <div>
                    <label class="block text-sm font-medium mb-2">Email or Username</label>
                    <input type="text" name="identifier" required
                        class="w-full px-4 py-3 bg-white/5 border border-white/20 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500">
                </div>
                <div>
                    <label class="block text-sm font-medium mb-2">Password</label>
                    <input type="password" name="password" required
                        class="w-full px-4 py-3 bg-white/5 border border-white/20 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500">
                </div>
                
                {{if .TurnstileSite}}
                <div class="cf-turnstile" data-sitekey="{{.TurnstileSite}}" data-theme="dark"></div>
                {{end}}

                <button type="submit" class="w-full py-3 bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg font-bold hover:opacity-90 transition">
                    Login
                </button>
            </form>

            <div id="result" class="mt-4 p-4 rounded-lg hidden"></div>

            <!-- Divider -->
            <div class="flex items-center my-6">
                <hr class="flex-1 border-white/20">
                <span class="px-4 text-gray-400">or</span>
                <hr class="flex-1 border-white/20">
            </div>

            <!-- OAuth Buttons -->
            <div class="space-y-3">
                {{if .HasGoogle}}
                <a href="/auth/google" class="flex items-center justify-center gap-3 w-full py-3 bg-white text-gray-800 rounded-lg font-medium hover:bg-gray-100 transition">
                    <svg class="w-5 h-5" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
                    Continue with Google
                </a>
                {{end}}
                {{if .HasDiscord}}
                <a href="/auth/discord" class="flex items-center justify-center gap-3 w-full py-3 bg-[#5865F2] text-white rounded-lg font-medium hover:bg-[#4752C4] transition">
                    <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>
                    Continue with Discord
                </a>
                {{end}}
                {{if .HasGitHub}}
                <a href="/auth/github" class="flex items-center justify-center gap-3 w-full py-3 bg-gray-800 text-white rounded-lg font-medium hover:bg-gray-700 transition">
                    <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
                    Continue with GitHub
                </a>
                {{end}}
            </div>

            <!-- Magic Link -->
            <div class="mt-6 pt-6 border-t border-white/20">
                <form id="magicLinkForm" class="space-y-3">
                    <input type="email" name="email" placeholder="Email for Magic Link" required
                        class="w-full px-4 py-3 bg-white/5 border border-white/20 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500">
                    <button type="submit" class="w-full py-3 bg-gradient-to-r from-pink-500 to-orange-500 rounded-lg font-bold hover:opacity-90 transition">
                        ✨ Send Magic Link
                    </button>
                </form>
            </div>

            <p class="text-center mt-6 text-gray-400">
                Don't have an account? <a href="/register" class="text-purple-400 hover:underline">Register</a>
            </p>
            <p class="text-center mt-2">
                <a href="/" class="text-gray-500 hover:text-white">← Back to Home</a>
            </p>
        </div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const form = e.target;
            const result = document.getElementById('result');
            
            try {
                const response = await fetch('/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        identifier: form.identifier.value,
                        password: form.password.value,
                        captcha_token: document.querySelector('[name="cf-turnstile-response"]')?.value || ''
                    })
                });
                
                const data = await response.json();
                result.classList.remove('hidden', 'bg-green-500/20', 'bg-red-500/20');
                
                if (response.ok) {
                    result.classList.add('bg-green-500/20');
                    result.innerHTML = '<p class="text-green-400">✓ Login successful!</p><pre class="mt-2 text-xs overflow-auto">' + JSON.stringify(data, null, 2) + '</pre>';
                    localStorage.setItem('access_token', data.access_token);
                    localStorage.setItem('refresh_token', data.refresh_token);
                } else {
                    result.classList.add('bg-red-500/20');
                    result.innerHTML = '<p class="text-red-400">✗ ' + (data.message || data.error || 'Login failed') + '</p>';
                }
            } catch (err) {
                result.classList.remove('hidden');
                result.classList.add('bg-red-500/20');
                result.innerHTML = '<p class="text-red-400">✗ Network error: ' + err.message + '</p>';
            }
        });

        document.getElementById('magicLinkForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const form = e.target;
            const result = document.getElementById('result');
            
            try {
                const response = await fetch('/auth/magic-link', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: form.email.value })
                });
                
                const data = await response.json();
                result.classList.remove('hidden', 'bg-green-500/20', 'bg-red-500/20');
                
                if (response.ok) {
                    result.classList.add('bg-green-500/20');
                    result.innerHTML = '<p class="text-green-400">✓ Magic link sent! Check your email.</p>';
                } else {
                    result.classList.add('bg-red-500/20');
                    result.innerHTML = '<p class="text-red-400">✗ ' + (data.message || 'Failed to send magic link') + '</p>';
                }
            } catch (err) {
                result.classList.remove('hidden');
                result.classList.add('bg-red-500/20');
                result.innerHTML = '<p class="text-red-400">✗ Network error: ' + err.message + '</p>';
            }
        });
    </script>
</body>
</html>`

const registerHTML = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - {{.AppName}}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>
<body class="bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 min-h-screen text-white flex items-center justify-center">
    <div class="w-full max-w-md p-8">
        <div class="bg-white/10 backdrop-blur-lg rounded-2xl border border-white/20 p-8">
            <h1 class="text-3xl font-bold text-center mb-8">📝 Register</h1>
            
            <form id="registerForm" class="space-y-4">
                <div>
                    <label class="block text-sm font-medium mb-2">Email</label>
                    <input type="email" name="email" required
                        class="w-full px-4 py-3 bg-white/5 border border-white/20 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500">
                </div>
                <div>
                    <label class="block text-sm font-medium mb-2">Username (optional)</label>
                    <input type="text" name="username"
                        class="w-full px-4 py-3 bg-white/5 border border-white/20 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500">
                </div>
                <div>
                    <label class="block text-sm font-medium mb-2">Password</label>
                    <input type="password" name="password" required minlength="8"
                        class="w-full px-4 py-3 bg-white/5 border border-white/20 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500">
                    <p class="text-xs text-gray-400 mt-1">Min 8 chars, uppercase, lowercase, number, symbol</p>
                </div>
                <div>
                    <label class="block text-sm font-medium mb-2">Confirm Password</label>
                    <input type="password" name="password_confirm" required
                        class="w-full px-4 py-3 bg-white/5 border border-white/20 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500">
                </div>
                
                {{if .TurnstileSite}}
                <div class="cf-turnstile" data-sitekey="{{.TurnstileSite}}" data-theme="dark"></div>
                {{end}}

                <button type="submit" class="w-full py-3 bg-gradient-to-r from-green-500 to-blue-600 rounded-lg font-bold hover:opacity-90 transition">
                    Create Account
                </button>
            </form>

            <div id="result" class="mt-4 p-4 rounded-lg hidden"></div>

            <p class="text-center mt-6 text-gray-400">
                Already have an account? <a href="/login" class="text-purple-400 hover:underline">Login</a>
            </p>
            <p class="text-center mt-2">
                <a href="/" class="text-gray-500 hover:text-white">← Back to Home</a>
            </p>
        </div>
    </div>

    <script>
        document.getElementById('registerForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const form = e.target;
            const result = document.getElementById('result');
            
            if (form.password.value !== form.password_confirm.value) {
                result.classList.remove('hidden', 'bg-green-500/20');
                result.classList.add('bg-red-500/20');
                result.innerHTML = '<p class="text-red-400">✗ Passwords do not match</p>';
                return;
            }
            
            try {
                const response = await fetch('/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: form.email.value,
                        username: form.username.value || undefined,
                        password: form.password.value,
                        captcha_token: document.querySelector('[name="cf-turnstile-response"]')?.value || ''
                    })
                });
                
                const data = await response.json();
                result.classList.remove('hidden', 'bg-green-500/20', 'bg-red-500/20');
                
                if (response.ok) {
                    result.classList.add('bg-green-500/20');
                    result.innerHTML = '<p class="text-green-400">✓ Registration successful! Check your email for verification.</p><pre class="mt-2 text-xs overflow-auto">' + JSON.stringify(data, null, 2) + '</pre>';
                } else {
                    result.classList.add('bg-red-500/20');
                    result.innerHTML = '<p class="text-red-400">✗ ' + (data.message || data.error || 'Registration failed') + '</p>';
                }
            } catch (err) {
                result.classList.remove('hidden');
                result.classList.add('bg-red-500/20');
                result.innerHTML = '<p class="text-red-400">✗ Network error: ' + err.message + '</p>';
            }
        });
    </script>
</body>
</html>`

const dashboardHTML = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - {{.AppName}}</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 min-h-screen text-white">
    <div class="container mx-auto px-4 py-16">
        <div class="max-w-4xl mx-auto">
            <div class="bg-white/10 backdrop-blur-lg rounded-2xl border border-white/20 p-8">
                <h1 class="text-3xl font-bold mb-8">📊 Dashboard</h1>
                
                <div id="authStatus" class="mb-8 p-4 rounded-lg bg-yellow-500/20 border border-yellow-500">
                    <p class="text-yellow-400">Checking authentication...</p>
                </div>

                <div id="userInfo" class="hidden">
                    <h2 class="text-xl font-bold mb-4">User Info</h2>
                    <pre id="userInfoData" class="bg-black/30 p-4 rounded-lg overflow-auto text-sm"></pre>
                </div>

                <div class="grid md:grid-cols-2 gap-4 mt-8">
                    <button onclick="testRefresh()" class="p-4 bg-blue-500/20 border border-blue-500 rounded-lg hover:bg-blue-500/30 transition">
                        🔄 Refresh Token
                    </button>
                    <button onclick="testLogout()" class="p-4 bg-red-500/20 border border-red-500 rounded-lg hover:bg-red-500/30 transition">
                        🚪 Logout
                    </button>
                    <button onclick="test2FASetup()" class="p-4 bg-purple-500/20 border border-purple-500 rounded-lg hover:bg-purple-500/30 transition">
                        🔐 Setup 2FA
                    </button>
                    <button onclick="testPasswordChange()" class="p-4 bg-orange-500/20 border border-orange-500 rounded-lg hover:bg-orange-500/30 transition">
                        🔑 Change Password
                    </button>
                </div>

                <div id="actionResult" class="mt-4 p-4 rounded-lg hidden"></div>

                <p class="text-center mt-8">
                    <a href="/" class="text-gray-500 hover:text-white">← Back to Home</a>
                </p>
            </div>
        </div>
    </div>

    <script>
        const accessToken = localStorage.getItem('access_token');
        const authStatus = document.getElementById('authStatus');
        const userInfo = document.getElementById('userInfo');
        const userInfoData = document.getElementById('userInfoData');

        if (!accessToken) {
            authStatus.classList.remove('bg-yellow-500/20', 'border-yellow-500');
            authStatus.classList.add('bg-red-500/20', 'border-red-500');
            authStatus.innerHTML = '<p class="text-red-400">✗ Not authenticated. <a href="/login" class="underline">Login</a></p>';
        } else {
            // Verify token by calling /auth/me
            fetch('/auth/me', {
                headers: { 'Authorization': 'Bearer ' + accessToken }
            })
            .then(res => res.json())
            .then(data => {
                if (data.user) {
                    authStatus.classList.remove('bg-yellow-500/20', 'border-yellow-500');
                    authStatus.classList.add('bg-green-500/20', 'border-green-500');
                    authStatus.innerHTML = '<p class="text-green-400">✓ Authenticated as: ' + (data.user.email || data.user.username) + '</p>';
                    userInfo.classList.remove('hidden');
                    userInfoData.textContent = JSON.stringify(data, null, 2);
                } else {
                    throw new Error('Invalid response');
                }
            })
            .catch(err => {
                authStatus.classList.remove('bg-yellow-500/20', 'border-yellow-500');
                authStatus.classList.add('bg-red-500/20', 'border-red-500');
                authStatus.innerHTML = '<p class="text-red-400">✗ Token invalid or expired. <a href="/login" class="underline">Login again</a></p>';
            });
        }

        async function testRefresh() {
            const result = document.getElementById('actionResult');
            const refreshToken = localStorage.getItem('refresh_token');
            
            try {
                const response = await fetch('/auth/refresh', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ refresh_token: refreshToken })
                });
                const data = await response.json();
                
                result.classList.remove('hidden', 'bg-green-500/20', 'bg-red-500/20');
                if (response.ok) {
                    localStorage.setItem('access_token', data.access_token);
                    if (data.refresh_token) localStorage.setItem('refresh_token', data.refresh_token);
                    result.classList.add('bg-green-500/20');
                    result.innerHTML = '<p class="text-green-400">✓ Token refreshed!</p>';
                } else {
                    result.classList.add('bg-red-500/20');
                    result.innerHTML = '<p class="text-red-400">✗ ' + (data.message || 'Refresh failed') + '</p>';
                }
            } catch (err) {
                result.classList.remove('hidden');
                result.classList.add('bg-red-500/20');
                result.innerHTML = '<p class="text-red-400">✗ ' + err.message + '</p>';
            }
        }

        async function testLogout() {
            const result = document.getElementById('actionResult');
            
            try {
                const response = await fetch('/auth/logout', {
                    method: 'POST',
                    headers: { 
                        'Authorization': 'Bearer ' + accessToken,
                        'Content-Type': 'application/json'
                    }
                });
                
                localStorage.removeItem('access_token');
                localStorage.removeItem('refresh_token');
                
                result.classList.remove('hidden', 'bg-green-500/20', 'bg-red-500/20');
                result.classList.add('bg-green-500/20');
                result.innerHTML = '<p class="text-green-400">✓ Logged out! Redirecting...</p>';
                
                setTimeout(() => window.location.href = '/login', 1500);
            } catch (err) {
                result.classList.remove('hidden');
                result.classList.add('bg-red-500/20');
                result.innerHTML = '<p class="text-red-400">✗ ' + err.message + '</p>';
            }
        }

        async function test2FASetup() {
            const result = document.getElementById('actionResult');
            
            try {
                const response = await fetch('/auth/2fa/setup', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + accessToken }
                });
                const data = await response.json();
                
                result.classList.remove('hidden', 'bg-green-500/20', 'bg-red-500/20');
                if (response.ok) {
                    result.classList.add('bg-green-500/20');
                    result.innerHTML = '<p class="text-green-400">✓ 2FA Setup initiated!</p>' +
                        (data.qr_code ? '<img src="' + data.qr_code + '" class="mt-4 mx-auto">' : '') +
                        '<pre class="mt-2 text-xs overflow-auto">' + JSON.stringify(data, null, 2) + '</pre>';
                } else {
                    result.classList.add('bg-red-500/20');
                    result.innerHTML = '<p class="text-red-400">✗ ' + (data.message || '2FA setup failed') + '</p>';
                }
            } catch (err) {
                result.classList.remove('hidden');
                result.classList.add('bg-red-500/20');
                result.innerHTML = '<p class="text-red-400">✗ ' + err.message + '</p>';
            }
        }

        function testPasswordChange() {
            const newPassword = prompt('Enter new password:');
            if (!newPassword) return;
            
            const currentPassword = prompt('Enter current password:');
            if (!currentPassword) return;
            
            fetch('/auth/password', {
                method: 'PUT',
                headers: { 
                    'Authorization': 'Bearer ' + accessToken,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    current_password: currentPassword,
                    new_password: newPassword
                })
            })
            .then(res => res.json())
            .then(data => {
                const result = document.getElementById('actionResult');
                result.classList.remove('hidden', 'bg-green-500/20', 'bg-red-500/20');
                if (data.success || data.message?.includes('success')) {
                    result.classList.add('bg-green-500/20');
                    result.innerHTML = '<p class="text-green-400">✓ Password changed!</p>';
                } else {
                    result.classList.add('bg-red-500/20');
                    result.innerHTML = '<p class="text-red-400">✗ ' + (data.message || 'Password change failed') + '</p>';
                }
            });
        }
    </script>
</body>
</html>`

const testPageHTML = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test All Features - {{.AppName}}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>
<body class="bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 min-h-screen text-white">
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-4xl font-bold text-center mb-8">🧪 GoAuth Feature Tests</h1>
        
        <div class="grid lg:grid-cols-2 gap-6 max-w-6xl mx-auto">
            <!-- API Test Section -->
            <div class="bg-white/10 backdrop-blur-lg rounded-2xl border border-white/20 p-6">
                <h2 class="text-xl font-bold mb-4">🔌 API Endpoints</h2>
                <div class="space-y-2">
                    <button onclick="testEndpoint('GET', '/api/health')" class="w-full text-left p-3 bg-white/5 rounded-lg hover:bg-white/10 transition">
                        GET /api/health
                    </button>
                    <button onclick="testEndpoint('GET', '/api/config')" class="w-full text-left p-3 bg-white/5 rounded-lg hover:bg-white/10 transition">
                        GET /api/config
                    </button>
                    <button onclick="testEndpoint('GET', '/auth/me')" class="w-full text-left p-3 bg-white/5 rounded-lg hover:bg-white/10 transition">
                        GET /auth/me (requires auth)
                    </button>
                </div>
            </div>

            <!-- CAPTCHA Test Section -->
            <div class="bg-white/10 backdrop-blur-lg rounded-2xl border border-white/20 p-6">
                <h2 class="text-xl font-bold mb-4">🤖 CAPTCHA Test</h2>
                {{if .TurnstileSite}}
                <p class="text-sm text-gray-400 mb-4">Turnstile widget:</p>
                <div class="cf-turnstile" data-sitekey="{{.TurnstileSite}}" data-theme="dark" data-callback="onTurnstileSuccess"></div>
                <p id="turnstileResult" class="mt-2 text-sm"></p>
                {{else}}
                <p class="text-gray-400">No CAPTCHA configured</p>
                {{end}}
            </div>

            <!-- Console Log -->
            <div class="lg:col-span-2 bg-white/10 backdrop-blur-lg rounded-2xl border border-white/20 p-6">
                <h2 class="text-xl font-bold mb-4">📋 Response Log</h2>
                <div id="log" class="bg-black/50 rounded-lg p-4 h-64 overflow-auto font-mono text-sm">
                    <p class="text-gray-500">Click a test button to see results...</p>
                </div>
                <button onclick="clearLog()" class="mt-4 px-4 py-2 bg-red-500/20 border border-red-500 rounded-lg hover:bg-red-500/30">
                    Clear Log
                </button>
            </div>
        </div>

        <p class="text-center mt-8">
            <a href="/" class="text-gray-500 hover:text-white">← Back to Home</a>
        </p>
    </div>

    <script>
        const logDiv = document.getElementById('log');
        const accessToken = localStorage.getItem('access_token');

        function log(message, type = 'info') {
            const colors = {
                info: 'text-blue-400',
                success: 'text-green-400',
                error: 'text-red-400',
                data: 'text-gray-300'
            };
            const time = new Date().toLocaleTimeString();
            logDiv.innerHTML += '<p class="' + colors[type] + '">[' + time + '] ' + message + '</p>';
            logDiv.scrollTop = logDiv.scrollHeight;
        }

        function clearLog() {
            logDiv.innerHTML = '<p class="text-gray-500">Log cleared...</p>';
        }

        async function testEndpoint(method, path) {
            log('Testing: ' + method + ' ' + path);
            
            try {
                const headers = { 'Content-Type': 'application/json' };
                if (accessToken) {
                    headers['Authorization'] = 'Bearer ' + accessToken;
                }
                
                const response = await fetch(path, { method, headers });
                const data = await response.json();
                
                if (response.ok) {
                    log('✓ Status: ' + response.status, 'success');
                } else {
                    log('✗ Status: ' + response.status, 'error');
                }
                log('Response: ' + JSON.stringify(data, null, 2), 'data');
            } catch (err) {
                log('✗ Error: ' + err.message, 'error');
            }
        }

        function onTurnstileSuccess(token) {
            document.getElementById('turnstileResult').innerHTML = 
                '<span class="text-green-400">✓ Token received: ' + token.substring(0, 20) + '...</span>';
            log('Turnstile token received!', 'success');
        }
    </script>
</body>
</html>`
