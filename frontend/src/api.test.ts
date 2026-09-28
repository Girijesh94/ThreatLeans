import {describe, expect, it} from 'vitest'
import {safeLink, date} from './api'
describe('Evidence rendering helpers', () => {
  it('rejects script and data URLs from source content', () => {
    expect(safeLink('javascript:alert(1)')).toBeUndefined()
    expect(safeLink('data:text/html,<script>')).toBeUndefined()
    expect(safeLink('https://nvd.nist.gov/vuln/detail/CVE-2021-44228')).toMatch(/^https:/)
  })
  it('labels an invalid date instead of displaying a misleading value', () => {
    expect(date('not-a-date')).toBe('Unknown observation date')
  })
})
