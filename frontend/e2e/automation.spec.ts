import { createHmac } from 'node:crypto'
import { createServer, type IncomingHttpHeaders } from 'node:http'
import type { AddressInfo } from 'node:net'

import { expect, test, type Page } from '@playwright/test'

async function signUpWithOrg(page: Page, org: string) {
  await page.goto('/register')
  await page.getByLabel('Full name').fill('Ali Automator')
  await page.getByLabel('Work email').fill(`auto-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`)
  await page.getByLabel('Password', { exact: true }).fill('Blue-Team-Lab-2026!')
  await page.getByRole('button', { name: 'Create account' }).click()
  await page.getByLabel('Organization name').fill(org)
  await page.getByRole('button', { name: 'Create organization' }).click()
  await expect(page).toHaveURL(/\/org\/[0-9a-f-]{36}$/)
  return page.url()
}

type Hit = { headers: IncomingHttpHeaders; body: Buffer }

test('signed webhook, recipe workflows and an approval gate', async ({ page }) => {
  // A stand-in for n8n: records what SENTINEL X sends.
  const hits: Hit[] = []
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      hits.push({ headers: req.headers, body: Buffer.concat(chunks) })
      res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}')
    })
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = (server.address() as AddressInfo).port

  try {
    const orgUrl = await signUpWithOrg(page, 'Automation Lab')
    await page.goto(`${orgUrl}/automation`)
    await expect(page.getByText('Start from a recipe')).toBeVisible()

    // 1. A webhook; its secret is shown exactly once.
    await page.getByRole('button', { name: 'Add webhook' }).click()
    const add = page.getByRole('dialog', { name: 'Add a webhook' })
    await add.getByLabel('Name').fill('Local n8n')
    await add.getByLabel('URL').fill(`http://127.0.0.1:${port}/webhook/sentinel`)
    await add.getByRole('button', { name: 'Add webhook' }).click()
    const shown = page.getByRole('dialog', { name: 'Webhook “Local n8n” added' })
    const secret = ((await shown.locator('pre').first().textContent()) ?? '').trim()
    expect(secret).toMatch(/^whsec_/)
    await shown.getByRole('button', { name: 'I saved it' }).click()

    // 2. A test delivery arrives signed with that secret.
    await page.getByRole('tab', { name: /Webhooks/ }).click()
    await page.getByRole('button', { name: 'Send test' }).click()
    await expect(page.getByText(/Test delivered \(HTTP 200/)).toBeVisible()
    const verify = (hit: Hit) => {
      const ts = String(hit.headers['x-sentinel-timestamp'])
      const expected = 'v1=' + createHmac('sha256', secret).update(`${ts}.`).update(hit.body).digest('hex')
      return hit.headers['x-sentinel-signature'] === expected
    }
    expect(hits).toHaveLength(1)
    expect(verify(hits[0]!)).toBe(true)
    expect(JSON.parse(hits[0]!.body.toString()).type).toBe('test')

    // 3. Two recipes: one runs automatically, one waits for an approver.
    await page.getByRole('tab', { name: /Workflows/ }).click()
    await page.getByRole('group', { name: 'Send serious alerts to n8n' }).getByRole('button', { name: 'Use this' }).click()
    const builder = page.getByRole('dialog', { name: 'New workflow' })
    await expect(builder.getByLabel('Webhook')).toHaveValue(/[0-9a-f-]{36}/)
    await builder.getByRole('button', { name: 'Create workflow' }).click()
    const forward = page.getByRole('article', { name: 'Send serious alerts to n8n' })
    await expect(forward.getByText('A new alert is raised (high or above)')).toBeVisible()
    await expect(forward.getByText('Send to Local n8n')).toBeVisible()
    await expect(forward.getByText('Runs automatically')).toBeVisible()

    await page.getByText('More ideas').click()
    await page.getByRole('group', { name: 'Open an incident for critical alerts' }).getByRole('button', { name: 'Use this' }).click()
    await expect(page.getByRole('dialog', { name: 'New workflow' }).getByRole('switch', { name: 'Ask an approver before each run' })).toBeDisabled()
    await page.getByRole('dialog', { name: 'New workflow' }).getByRole('button', { name: 'Create workflow' }).click()
    await expect(page.getByRole('article', { name: 'Open an incident for critical alerts' }).getByText('Needs approval')).toBeVisible()

    // 4. A critical event: forwarded to "n8n" by the worker, and an incident waits for approval.
    await page.goto(`${orgUrl}/events`)
    await page.getByRole('button', { name: 'Report event' }).click()
    const report = page.getByRole('dialog', { name: 'Report a security event' })
    await report.getByLabel('Title', { exact: true }).fill('Domain admin account created at 03:12')
    await report.getByLabel('Severity').selectOption('critical')
    await report.getByRole('button', { name: 'Submit event' }).click()
    await expect(report).toBeHidden()

    await expect.poll(() => hits.filter((h) => h.headers['x-sentinel-event'] === 'alert.created').length, { timeout: 20_000 }).toBe(1)
    const forwarded = hits.find((h) => h.headers['x-sentinel-event'] === 'alert.created')!
    expect(verify(forwarded)).toBe(true)
    expect(JSON.parse(forwarded.body.toString()).data.alert.title).toBe('Domain admin account created at 03:12')

    await page.goto(`${orgUrl}/automation?tab=activity`)
    await expect(page.getByText('Waiting for approval (1)')).toBeVisible()
    await page.getByRole('button', { name: 'Approve and run' }).click()
    await expect(page.getByText('Waiting for approval (1)')).toBeHidden()
    await page.getByRole('button', { name: /Open an incident for critical alerts/ }).click()
    await expect(page.getByText(/Opened INC-\d{4}-0001/)).toBeVisible()
    await page.getByRole('link', { name: 'Open' }).first().click()
    await expect(page).toHaveURL(/\/incidents\/[0-9a-f-]{36}$/)
    await expect(page.getByText('Domain admin account created at 03:12').first()).toBeVisible()
  } finally {
    server.close()
  }
})
