// Runs in an environment where /proc is not readable: the process's own
// pid-namespace identity is unavailable. A fresh session dir whose lock
// also recorded an unavailable namespace id must be kept (age-gated),
// not reclaimed as if it provably belonged to this namespace.
import * as fs from 'node:fs'
import {
  getTransparentAssetDir,
  transparentAssetParentDir,
} from '../../../src/sandbox/transparent-net.ts'

const parent = transparentAssetParentDir()
fs.mkdirSync(parent, { recursive: true, mode: 0o700 })
const victim = `${parent}/session-ns-identity-check`
fs.mkdirSync(victim, { recursive: true, mode: 0o700 })
fs.writeFileSync(`${victim}/lock`, '999999999 12345 unknown')

getTransparentAssetDir() // triggers the sweep

console.log(`victim-survives=${fs.existsSync(victim)}`)
