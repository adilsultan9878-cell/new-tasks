import { defineConfig, devices } from '@playwright/test'

// End-to-end tests start a throwaway backend (SQLite) and the Vite dev server automatically.
// Run `npx playwright install chromium` once on a new machine.
const win = process.platform === 'win32'
const python = process.env.E2E_PYTHON ?? (win ? '..\\backend\\.venv\\Scripts\\python.exe' : '../backend/.venv/bin/python')
const dbFile = 'e2e_sentinel.db'

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  use: {
    baseURL: 'http://127.0.0.1:5173',
    trace: 'off',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: [
    {
      command: `${python} -m alembic upgrade head && ${python} -m uvicorn app.main:app --host 127.0.0.1 --port 8000`,
      cwd: '../backend',
      url: 'http://127.0.0.1:8000/health',
      reuseExistingServer: !process.env.CI,
      env: {
        DATABASE_URL: `sqlite:///./${dbFile}`,
        MIGRATION_DATABASE_URL: '',
        ENVIRONMENT: 'development',
        JWT_SECRET: 'e2e-only-secret-not-for-production-use-0123456789',
        RATE_LIMIT_AUTH_PER_MINUTE: '200',
        // Deterministic CI: no calls to third-party intelligence services.
        INTEL_OFFLINE: 'true',
      },
      timeout: 60_000,
    },
    {
      command: 'npx vite --host 127.0.0.1 --port 5173 --strictPort',
      url: 'http://127.0.0.1:5173',
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
  ],
})
