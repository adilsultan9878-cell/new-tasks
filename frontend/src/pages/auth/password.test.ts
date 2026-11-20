import { describe, expect, it } from 'vitest'

import { passwordChecks } from './password'

describe('passwordChecks (mirrors server policy)', () => {
  it('rejects short, repetitive or email-derived passwords', () => {
    expect(passwordChecks('short', 'a@b.c').every((c) => c.ok)).toBe(false)
    expect(passwordChecks('aaaaaaaaaaaaaaa', 'a@b.c').every((c) => c.ok)).toBe(false)
    expect(passwordChecks('ayesha-secure-2026', 'ayesha@example.com').every((c) => c.ok)).toBe(false)
  })
  it('accepts a long, varied password', () => {
    expect(passwordChecks('Blue-Team-Lab-2026!', 'ayesha@example.com').every((c) => c.ok)).toBe(true)
  })
})
