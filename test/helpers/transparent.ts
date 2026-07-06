import { execFileSync } from 'node:child_process'
import { isLinux } from './platform.js'
import { whichSync } from '../../src/utils/which.js'
import { checkTransparentDependencies } from '../../src/sandbox/transparent-net.js'

/**
 * Gate for transparent-networking tests: Linux with bwrap plus the SAME
 * dependency check production uses (vendored netns-config present +
 * helper resolvable). No namespace-capability probe exists anymore: the
 * host configures bwrap's netns via setns, which works wherever bwrap
 * itself does.
 */
export function hasTransparentPrereqs(): boolean {
  return (
    isLinux &&
    whichSync('bwrap') !== null &&
    checkTransparentDependencies().errors.length === 0
  )
}

/**
 * Whether this process may create AF_UNIX listeners — the host-side proxy
 * bridge needs them, and some dev sandboxes deny socket(AF_UNIX) via
 * seccomp. Probed in a child so a denial cannot disturb this process.
 */
export function canListenUnixSockets(): boolean {
  try {
    execFileSync(
      process.execPath,
      [
        '-e',
        `const net=require('net');const p='/tmp/srt-tp-probe-'+process.pid+'.sock';` +
          `const s=net.createServer();s.on('error',()=>process.exit(1));` +
          `s.listen(p,()=>{s.close();require('fs').rmSync(p,{force:true});process.exit(0);});`,
      ],
      { stdio: 'ignore' },
    )
    return true
  } catch {
    return false
  }
}
