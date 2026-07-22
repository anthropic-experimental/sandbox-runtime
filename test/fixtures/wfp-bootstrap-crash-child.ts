import { verifyWindowsWfpEgressWithAclBootstrap } from '../../src/sandbox/windows-sandbox-utils.js'

const [statePath, nodeExe, fakeCli, target] = process.argv.slice(2)
if (!statePath || !nodeExe || !fakeCli || !target) {
  throw new Error(
    'usage: wfp-bootstrap-crash-child <state> <node> <fake-cli> <target>',
  )
}

await verifyWindowsWfpEgressWithAclBootstrap({
  sandboxUserSid: 'S-1-5-21-111-222-333-1007',
  target,
  srtWin: {
    exe: nodeExe,
    prependArgs: [fakeCli, '--state', statePath],
  },
})
