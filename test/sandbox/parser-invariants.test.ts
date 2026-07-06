import { describe, it, expect } from 'bun:test'
import * as fs from 'node:fs'
import { join } from 'node:path'

/**
 * Failure-mode research hard-close (llhttp CVE lineage): the filtering
 * proxy's safety rests on two standing invariants that a stray patch
 * could silently break — pin them.
 */
describe('HTTP parser invariants', () => {
  it('insecureHTTPParser is never enabled anywhere in src', () => {
    const offenders: string[] = []
    const walk = (dir: string) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, e.name)
        if (e.isDirectory()) walk(p)
        else if (/\.(ts|js)$/.test(e.name)) {
          if (fs.readFileSync(p, 'utf8').includes('insecureHTTPParser')) {
            offenders.push(p)
          }
        }
      }
    }
    walk('src')
    expect(offenders).toEqual([])
  })

  it('engines floor stays at/above the last llhttp smuggling fix (20.3)', () => {
    const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'))
    const floor = String(pkg.engines?.node ?? '')
    const m = /(\d+)\.(\d+)/.exec(floor)
    expect(m).not.toBeNull()
    const [maj, min] = [Number(m![1]), Number(m![2])]
    expect(maj > 20 || (maj === 20 && min >= 3)).toBe(true)
  })
})
