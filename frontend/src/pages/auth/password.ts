export const MIN_PASSWORD = 12

/** Client-side mirror of the server's password policy (the server remains authoritative). */
export function passwordChecks(password: string, email: string) {
  const local = email.split('@')[0]?.toLowerCase() ?? ''
  return [
    { label: `At least ${MIN_PASSWORD} characters`, ok: password.length >= MIN_PASSWORD },
    { label: 'Not repetitive (5+ distinct characters)', ok: new Set(password).size >= 5 },
    { label: 'Does not contain your email name', ok: !(local.length >= 4 && password.toLowerCase().includes(local)) },
  ]
}
