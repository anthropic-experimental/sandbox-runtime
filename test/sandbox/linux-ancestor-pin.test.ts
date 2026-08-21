import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

// Every directory strictly between a deny bind's dest and its covering
// allowWrite root is pinned with a self --bind so it is a mountpoint:
// rename/rmdir of it fail EBUSY, so the deny cannot be moved aside and the
// path recreated unprotected. Reads and writes inside it are unchanged.
describe.if(isLinux)('Linux sandbox — denyWrite ancestor pinning', () => {
  let BASE: string
  let PROJECT: string
  const savedCwd = process.cwd()

  const BWRAP_CAN_NAMESPACE =
    spawnSync(
      'bwrap',
      [
        '--unshare-pid',
        '--unshare-user',
        '--cap-drop',
        'ALL',
        '--ro-bind',
        '/',
        '/',
        '--proc',
        '/proc',
        'true',
      ],
      { timeout: 5000 },
    ).status === 0

  function mkTree(root: string, tree: Record<string, unknown>): void {
    for (const [name, value] of Object.entries(tree)) {
      const p = join(root, name)
      if (typeof value === 'string') {
        writeFileSync(p, value)
      } else {
        mkdirSync(p, { recursive: true })
        mkTree(p, value as Record<string, unknown>)
      }
    }
  }

  beforeEach(() => {
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'ancestor-pin-')))
    PROJECT = join(BASE, 'project')
    mkdirSync(PROJECT)
    writeFileSync(join(PROJECT, 'README.md'), '# test\n')
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(BASE, { recursive: true, force: true })
  })

  async function wrap(
    filesystem: {
      allowWrite?: string[]
      denyWrite?: string[]
      denyRead?: string[]
    } = {},
    command = 'echo ok',
  ): Promise<string> {
    // Mandatory denies (.git/config, .git/hooks, dotfiles) are relative to
    // process.cwd(); the project is the sandbox's cwd like a real session.
    process.chdir(PROJECT)
    return wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      readConfig: { denyOnly: filesystem.denyRead ?? [] },
      writeConfig: {
        allowOnly: [PROJECT, ...(filesystem.allowWrite ?? [])],
        denyWithinAllow: filesystem.denyWrite ?? [],
      },
    })
  }

  function run(command: string) {
    return spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 15000,
      cwd: PROJECT,
    })
  }

  it('pins the directories between a mandatory deny leaf and the allowWrite root', async () => {
    mkTree(PROJECT, { '.git': { hooks: {}, config: '[core]\n' } })
    const gitDir = join(PROJECT, '.git')

    const command = await wrap()

    expect(command).toContain('--ro-bind / /')
    const configBind = `--ro-bind ${gitDir}/config ${gitDir}/config`
    expect(command).toContain(configBind)
    // .git sits strictly between the leaf denies and the allowWrite root.
    const gitPin = `--bind ${gitDir} ${gitDir}`
    expect(command).toContain(gitPin)
    // The pin must land before the leaf ro-bind, or its writable bind would
    // shadow the read-only one.
    expect(command.indexOf(gitPin)).toBeLessThan(command.indexOf(configBind))
    // Nothing outside the writable set is pinned.
    const outside = dirname(PROJECT)
    expect(command).not.toContain(`--bind ${outside} ${outside}`)
    // The allowWrite root is bound exactly once (its allow bind); a pin there
    // would add nothing.
    const rootBind = `--bind ${PROJECT} ${PROJECT}`
    expect(command.split(rootBind).length - 1).toBe(1)
  })

  it('pins ancestors of absent-path stub dests', async () => {
    // .git exists but neither config nor hooks does: every deny dest on this
    // chain is a stub, so the .git pin can only come from stub dests.
    mkTree(PROJECT, { '.git': {} })
    const gitDir = join(PROJECT, '.git')

    const command = await wrap()

    expect(command).toContain(`--ro-bind /dev/null ${gitDir}/hooks`)
    expect(command).toContain(`--ro-bind /dev/null ${gitDir}/config`)
    expect(command).toContain(`--bind ${gitDir} ${gitDir}`)
  })

  it('pins every intermediate directory above a nested repo found by the depth scan', async () => {
    mkTree(PROJECT, { nested: { '.git': { hooks: {}, config: '[core]\n' } } })
    const nestedDir = join(PROJECT, 'nested')
    const nestedGit = join(nestedDir, '.git')

    const command = await wrap()

    expect(command).toContain(
      `--ro-bind ${nestedGit}/config ${nestedGit}/config`,
    )
    expect(command).toContain(`--bind ${nestedGit} ${nestedGit}`)
    expect(command).toContain(`--bind ${nestedDir} ${nestedDir}`)
  })

  it('keeps leaf denies enforced when a denyRead tmpfs sits between nested allowWrite roots', async () => {
    // x contains the read-denied y, so x gets no pin (it would land after
    // the tmpfs and bury it); the denyRead section's restore of the nested
    // allowWrite z runs before the buffered deny binds, so the .git pin and
    // the config deny land on top of it.
    mkTree(PROJECT, {
      x: { y: { z: { '.git': { hooks: {}, config: '[core]\n' } } } },
    })
    const yDir = join(PROJECT, 'x', 'y')
    const zDir = join(yDir, 'z')
    const configPath = join(zDir, '.git', 'config')
    const filesystem = {
      allowWrite: [zDir],
      denyRead: [yDir],
      denyWrite: [configPath],
    }

    const command = await wrap(
      filesystem,
      `echo evil >> ${configPath} && echo PLANTED`,
    )

    const configBind = `--ro-bind ${configPath} ${configPath}`
    const zBind = `--bind ${zDir} ${zDir}`
    expect(command).toContain(configBind)
    expect(command).toContain(zBind)
    expect(command.lastIndexOf(configBind)).toBeGreaterThan(
      command.lastIndexOf(zBind),
    )

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(result.stdout ?? '').not.toContain('PLANTED')
      expect(result.status).not.toBe(0)
      expect(readFileSync(configPath, 'utf8')).toBe('[core]\n')

      const writable = await wrap(
        filesystem,
        `echo n > ${zDir}/newfile.txt && echo Z_WRITE_OK`,
      )
      expect(run(writable).stdout).toContain('Z_WRITE_OK')
      expect(existsSync(join(zDir, 'newfile.txt'))).toBe(true)
    }
  })

  it('does not pin an ancestor that contains a denyRead dir, but keeps pinning the repo chain below it', async () => {
    mkTree(PROJECT, {
      x: {
        y: {
          z: {
            app: {
              data: { 'secret.txt': 'TOPSECRET\n' },
              repo: { '.git': { hooks: {}, config: '[core]\n' } },
            },
          },
        },
      },
    })
    const yDir = join(PROJECT, 'x', 'y')
    const zDir = join(yDir, 'z')
    const appDir = join(zDir, 'app')
    const dataDir = join(appDir, 'data')
    const secretPath = join(dataDir, 'secret.txt')
    const configPath = join(appDir, 'repo', '.git', 'config')

    const command = await wrap(
      {
        allowWrite: [zDir],
        denyRead: [yDir, dataDir],
        denyWrite: [configPath],
      },
      `cat ${secretPath} 2>&1; echo evil >> ${secretPath} 2>&1; echo evil >> ${configPath} 2>&1; echo DONE`,
    )

    expect(command).toContain(`--tmpfs ${dataDir}`)
    expect(command).not.toContain(`--bind ${appDir} ${appDir}`)
    expect(command).toContain(
      `--bind ${join(appDir, 'repo')} ${join(appDir, 'repo')}`,
    )
    expect(command).not.toContain(
      `--bind ${join(PROJECT, 'x')} ${join(PROJECT, 'x')}`,
    )

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(result.stdout ?? '').not.toContain('TOPSECRET')
      expect(readFileSync(secretPath, 'utf8')).toBe('TOPSECRET\n')
      expect(readFileSync(configPath, 'utf8')).toBe('[core]\n')
    }
  })

  it('refuses to pin an ancestor that contains a symlink-spelled denyRead tmpfs location', async () => {
    // A pin on data would land after the tmpfs (mounted at data/secrets via
    // the symlink spelling) and bury it. data stays renameable — the known
    // residual — while the nested .git is still pinned.
    mkTree(PROJECT, {
      data: {
        secrets: { 'secret.txt': 'TOPSECRET\n' },
        '.git': { hooks: {}, config: '[core]\n' },
      },
    })
    const dataDir = join(PROJECT, 'data')
    const secretsLink = join(PROJECT, 'secrets')
    symlinkSync(join('data', 'secrets'), secretsLink)
    const secretCanonical = join(dataDir, 'secrets', 'secret.txt')

    const command = await wrap(
      { denyRead: [secretsLink] },
      `cat ${secretCanonical} 2>&1; cat ${secretsLink}/secret.txt 2>&1; echo evil >> ${secretCanonical} 2>&1; echo DONE`,
    )

    expect(command).toContain(`--tmpfs ${secretsLink}`)
    expect(command).not.toContain(`--bind ${dataDir} ${dataDir}`)
    expect(command).toContain(
      `--bind ${join(dataDir, '.git')} ${join(dataDir, '.git')}`,
    )

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(result.stdout ?? '').not.toContain('TOPSECRET')
      expect(readFileSync(secretCanonical, 'utf8')).toBe('TOPSECRET\n')
    }
  })

  it('restores a canonical allowWrite carve-out inside a symlink-spelled denyRead', async () => {
    mkTree(PROJECT, {
      data: {
        d: { w: { secret: 'DENYTEST\n' }, 'elsewhere.txt': 'ALSOSECRET\n' },
      },
    })
    const dDir = join(PROJECT, 'data', 'd')
    const wDir = join(dDir, 'w')
    const secretPath = join(wDir, 'secret')
    const linkD = join(PROJECT, 'link-d')
    symlinkSync(join('data', 'd'), linkD)

    const command = await wrap(
      { allowWrite: [wDir], denyRead: [linkD], denyWrite: [secretPath] },
      `echo n > ${wDir}/newfile.txt 2>&1; echo evil >> ${secretPath} 2>&1; cat ${dDir}/elsewhere.txt 2>&1; echo DONE`,
    )

    // The carve-out's writable re-bind must follow the tmpfs.
    const tmpfsOp = `--tmpfs ${linkD}`
    const wBind = `--bind ${wDir} ${wDir}`
    expect(command).toContain(tmpfsOp)
    expect(command.lastIndexOf(wBind)).toBeGreaterThan(
      command.lastIndexOf(tmpfsOp),
    )

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(existsSync(join(wDir, 'newfile.txt'))).toBe(true)
      expect(readFileSync(secretPath, 'utf8')).toBe('DENYTEST\n')
      expect(result.stdout ?? '').not.toContain('ALSOSECRET')
    }
  })

  it('never pins inside a write-denied directory', async () => {
    mkTree(PROJECT, {
      x: {
        y: {
          z: {
            app: {
              repo: { '.git': { hooks: {}, config: '[core]\n' } },
              'owned.txt': 'KEEP\n',
            },
          },
        },
      },
    })
    const yDir = join(PROJECT, 'x', 'y')
    const zDir = join(yDir, 'z')
    const appDir = join(zDir, 'app')
    const repoDir = join(appDir, 'repo')
    const configPath = join(repoDir, '.git', 'config')

    const command = await wrap(
      { allowWrite: [zDir], denyRead: [yDir], denyWrite: [appDir, configPath] },
      `echo evil > ${repoDir}/.git/planted 2>&1; echo evil >> ${appDir}/owned.txt 2>&1; echo DONE`,
    )

    expect(command).not.toContain(`--bind ${repoDir} ${repoDir}`)
    expect(command).not.toContain(`--bind ${repoDir}/.git ${repoDir}/.git`)
    expect(command).toContain(`--ro-bind ${appDir} ${appDir}`)

    if (BWRAP_CAN_NAMESPACE) {
      run(command)
      expect(existsSync(join(repoDir, '.git', 'planted'))).toBe(false)
      expect(readFileSync(join(appDir, 'owned.txt'), 'utf8')).toBe('KEEP\n')
    }
  })

  it('still pins inside a denied directory when an allowWrite carve-out inside it makes the corridor writable', async () => {
    // repo is denyRead-hidden (its own read-only bind is dropped as
    // tmpfs-hidden), but the carve-out sub inside it is restored writable,
    // so the corridor between sub and the deeper leaf still needs its pin.
    mkTree(PROJECT, {
      repo: { sub: { x: { secret: 'DENYTEST\n' } }, 'hidden.txt': 'X\n' },
    })
    const repoDir = join(PROJECT, 'repo')
    const subDir = join(repoDir, 'sub')
    const xDir = join(subDir, 'x')
    const secretPath = join(xDir, 'secret')

    const command = await wrap(
      {
        allowWrite: [subDir],
        denyRead: [repoDir],
        denyWrite: [repoDir, secretPath],
      },
      `cd ${subDir} && mv x x2 && mkdir -p x && echo evil > ${secretPath}`,
    )

    expect(command).toContain(`--bind ${xDir} ${xDir}`)

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(result.status).not.toBe(0)
      expect(result.stderr ?? '').toMatch(/busy/i)
      expect(existsSync(join(subDir, 'x2'))).toBe(false)
      expect(readFileSync(secretPath, 'utf8')).toBe('DENYTEST\n')
    }
  })

  it('keeps a deny leaf protected when its carve-out sits inside a denyRead inside a denied directory', async () => {
    // denyWrite dir ⊃ denyRead ⊃ allowWrite carve-out ⊃ denyWrite leaf: the
    // tmpfs re-application must not restore a write path with an emitted
    // deny bind under it.
    mkTree(PROJECT, { d: { t: { w: { secret: 'PROTECT\n' } }, 'o.txt': 'X' } })
    const dDir = join(PROJECT, 'd')
    const tDir = join(dDir, 't')
    const wDir = join(tDir, 'w')
    const secretPath = join(wDir, 'secret')

    const command = await wrap(
      { allowWrite: [wDir], denyRead: [tDir], denyWrite: [dDir, secretPath] },
      `echo evil >> ${secretPath} 2>&1; echo DONE`,
    )

    const secretRo = `--ro-bind ${secretPath} ${secretPath}`
    const wBind = `--bind ${wDir} ${wDir}`
    expect(command).toContain(secretRo)
    expect(command.lastIndexOf(wBind)).toBeLessThan(
      command.lastIndexOf(secretRo),
    )

    if (BWRAP_CAN_NAMESPACE) {
      run(command)
      expect(readFileSync(secretPath, 'utf8')).toBe('PROTECT\n')
    }
  })

  it('pins ancestors of denyRead file masks', async () => {
    mkTree(PROJECT, { config: { 'secrets.json': '{"k":"REAL"}\n' } })
    const configDir = join(PROJECT, 'config')
    const secretPath = join(configDir, 'secrets.json')

    const command = await wrap(
      { denyRead: [secretPath] },
      `cd ${PROJECT} && mv config config-moved && mkdir config && echo attacker > ${secretPath}`,
    )

    expect(command).toContain(`--ro-bind /dev/null ${secretPath}`)
    expect(command).toContain(`--bind ${configDir} ${configDir}`)

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(result.status).not.toBe(0)
      expect(existsSync(join(PROJECT, 'config-moved'))).toBe(false)
      expect(readFileSync(secretPath, 'utf8')).toBe('{"k":"REAL"}\n')
    }
  })

  it('pins ancestors of credential masks and re-applies the buried mask', async () => {
    mkTree(PROJECT, {
      creds: { 'token.txt': 'REAL\n' },
      fakes: { 'token.txt': 'FAKE\n' },
    })
    const credsDir = join(PROJECT, 'creds')
    const realPath = join(credsDir, 'token.txt')
    const fakePath = join(PROJECT, 'fakes', 'token.txt')
    process.chdir(PROJECT)

    const command = await wrapCommandWithSandboxLinux({
      command: 'true',
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      writeConfig: { allowOnly: [PROJECT], denyWithinAllow: [] },
      maskedFileBinds: [{ realPath, fakePath }],
    })

    expect(command).toContain(`--bind ${credsDir} ${credsDir}`)
    // The pin lands after the mask and buries it; the mask re-application
    // pass must re-emit the fake on top.
    const maskBind = `--ro-bind ${fakePath} ${realPath}`
    expect(command.lastIndexOf(maskBind)).toBeGreaterThan(
      command.indexOf(`--bind ${credsDir} ${credsDir}`),
    )
  })

  it('never restores a write path that canonically contains another read-deny location', async () => {
    mkTree(PROJECT, { d: { w: { secret: 'MASKME\n', 'other.txt': 'ok\n' } } })
    const wDir = join(PROJECT, 'd', 'w')
    const secretCanonical = join(wDir, 'secret')
    const sLink = join(PROJECT, 's-link')
    const dLink = join(PROJECT, 'link')
    symlinkSync(join('d', 'w', 'secret'), sLink)
    symlinkSync('d', dLink)

    const command = await wrap(
      { denyRead: [sLink, dLink], allowWrite: [wDir] },
      `cat ${secretCanonical} 2>&1; echo evil >> ${secretCanonical} 2>&1; echo DONE`,
    )

    const tmpfsOp = `--tmpfs ${dLink}`
    const wBind = `--bind ${wDir} ${wDir}`
    expect(command).toContain(tmpfsOp)
    expect(command.lastIndexOf(wBind)).toBeLessThan(
      command.lastIndexOf(tmpfsOp),
    )

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(result.stdout ?? '').not.toContain('MASKME')
      expect(readFileSync(secretCanonical, 'utf8')).toBe('MASKME\n')
    }
  })

  it('keeps a carve-out inside an emitted denied directory read-only across re-application', async () => {
    mkTree(PROJECT, { D: { t: { w: { 'file.txt': 'KEEP\n' } } } })
    const DDir = join(PROJECT, 'D')
    const tDir = join(DDir, 't')
    const wDir = join(tDir, 'w')

    const command = await wrap(
      { allowWrite: [wDir], denyWrite: [DDir], denyRead: [tDir] },
      `echo evil > ${wDir}/planted.txt 2>&1; echo DONE`,
    )

    const DRo = `--ro-bind ${DDir} ${DDir}`
    const wBind = `--bind ${wDir} ${wDir}`
    expect(command).toContain(DRo)
    expect(command.lastIndexOf(wBind)).toBeLessThan(command.lastIndexOf(DRo))

    if (BWRAP_CAN_NAMESPACE) {
      run(command)
      expect(existsSync(join(wDir, 'planted.txt'))).toBe(false)
    }
  })

  it('never restores an allow entry sitting exactly at a masked location', async () => {
    mkTree(PROJECT, { d: { w: { secret: 'MASKME\n' } } })
    const secretCanonical = join(PROJECT, 'd', 'w', 'secret')
    const sLink = join(PROJECT, 's-link')
    const dLink = join(PROJECT, 'link')
    symlinkSync(join('d', 'w', 'secret'), sLink)
    symlinkSync('d', dLink)

    const command = await wrap(
      { denyRead: [sLink, dLink], allowWrite: [secretCanonical] },
      `cat ${secretCanonical} 2>&1; echo evil >> ${secretCanonical} 2>&1; echo DONE`,
    )

    const tmpfsOp = `--tmpfs ${dLink}`
    const fileBind = `--bind ${secretCanonical} ${secretCanonical}`
    expect(command).toContain(tmpfsOp)
    expect(command.lastIndexOf(fileBind)).toBeLessThan(
      command.lastIndexOf(tmpfsOp),
    )

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(result.stdout ?? '').not.toContain('MASKME')
      expect(readFileSync(secretCanonical, 'utf8')).toBe('MASKME\n')
    }
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'blocks renaming .git aside inside the sandbox, and the host tree is untouched',
    async () => {
      mkTree(PROJECT, { '.git': { hooks: {}, config: '[core]\n' } })

      const command = await wrap(
        {},
        `cd ${PROJECT} && mv .git .git-moved && mkdir .git && echo planted > .git/config`,
      )
      const result = run(command)

      expect(result.status).not.toBe(0)
      expect(result.stderr ?? '').toMatch(/busy/i)
      expect(existsSync(join(PROJECT, '.git-moved'))).toBe(false)
      expect(readFileSync(join(PROJECT, '.git', 'config'), 'utf8')).toBe(
        '[core]\n',
      )
    },
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'blocks rmdir and exchange-rename of the pinned directory',
    async () => {
      mkTree(PROJECT, { '.git': { hooks: {}, config: '[core]\n' } })

      // renameat2(RENAME_EXCHANGE) must fail EBUSY (errno 16): the python
      // probe exits 0 only in that case.
      const exchangeProbe =
        Bun.which('python3') === null
          ? 'true'
          : `mkdir exch && python3 -c "import ctypes, os, sys; libc = ctypes.CDLL('libc.so.6', use_errno=True); r = libc.renameat2(-100, b'.git', -100, b'exch', 2); sys.exit(0 if r != 0 and ctypes.get_errno() == 16 else 1)"`
      const command = await wrap(
        {},
        `cd ${PROJECT} && rmdir .git 2>&1; ${exchangeProbe}`,
      )
      const result = run(command)

      expect(result.status).toBe(0)
      expect(result.stdout + (result.stderr ?? '')).toMatch(/busy/i)
      expect(existsSync(join(PROJECT, '.git'))).toBe(true)
    },
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'leaves normal work inside the pinned directory and the project intact',
    async () => {
      mkTree(PROJECT, {
        '.git': { hooks: {}, config: '[core]\n' },
        sub: { 'file.txt': 'data\n' },
      })

      const command = await wrap(
        {},
        `cd ${PROJECT} && echo idx > .git/index && mkdir .git/objects && echo n > newfile.txt && mv sub sub-renamed && echo ALL_OK`,
      )
      const result = run(command)

      expect(result.stdout).toContain('ALL_OK')
      expect(result.status).toBe(0)
      expect(existsSync(join(PROJECT, '.git', 'index'))).toBe(true)
      expect(existsSync(join(PROJECT, 'sub-renamed'))).toBe(true)

      // A rename STRADDLING the pin boundary crosses vfsmounts and fails
      // EXDEV for callers without a copy fallback (os.rename); mv copies.
      if (Bun.which('python3') !== null) {
        const exdev = await wrap(
          {},
          `cd ${PROJECT} && python3 -c "import os, errno, sys; e = 0\ntry: os.rename('README.md', '.git/README.md')\nexcept OSError as err: e = err.errno\nsys.exit(0 if e == errno.EXDEV else 1)"`,
        )
        expect(run(exdev).status).toBe(0)
      }
    },
  )

  it.if(BWRAP_CAN_NAMESPACE && Bun.which('git') !== null)(
    'lets git and cross-directory renames work in a nested repo whose ancestors are pinned',
    async () => {
      // packages/app is a nested repo: packages and packages/app/.git are
      // pinned (packages/app/.git/config and hooks are mandatory denies
      // found by the depth scan; packages/app itself is the .git's parent).
      mkTree(PROJECT, {
        packages: {
          app: {
            'index.js': 'console.log(1)\n',
            node_modules: {
              '.staging': { 'left-pad-abc': { 'index.js': 'x' } },
            },
          },
        },
      })
      const appDir = join(PROJECT, 'packages', 'app')
      const gitInit = spawnSync(
        'git',
        ['-c', 'init.defaultBranch=main', 'init', '-q', appDir],
        { encoding: 'utf8' },
      )
      expect(gitInit.status).toBe(0)

      const command = await wrap({})
      expect(command).toContain(
        `--bind ${join(PROJECT, 'packages')} ${join(PROJECT, 'packages')}`,
      )
      expect(command).toContain(`--bind ${appDir} ${appDir}`)
      expect(command).toContain(
        `--bind ${join(appDir, '.git')} ${join(appDir, '.git')}`,
      )

      // git's ordinary object/index/ref writes, including its atomic
      // rename-into-place of lockfiles within .git, all stay inside one
      // vfsmount and work as before.
      const gitWork = await wrap(
        {},
        `cd ${appDir} && git add index.js && git -c user.name=t -c user.email=t@t commit -q -m init && git log --oneline | wc -l && echo GIT_OK`,
      )
      const gitResult = run(gitWork)
      expect(gitResult.status).toBe(0)
      expect(gitResult.stdout).toContain('GIT_OK')
      expect(existsSync(join(appDir, '.git', 'refs', 'heads', 'main'))).toBe(
        true,
      )

      // The npm-style staging rename (node_modules/.staging/x -> node_modules/
      // x) does not cross a pin: neither directory is a mountpoint, both
      // live in the packages/app vfsmount.
      const staged = join(appDir, 'node_modules', '.staging', 'left-pad-abc')
      const final = join(appDir, 'node_modules', 'left-pad')
      const npmLike = await wrap(
        {},
        `${process.execPath} -e "require('fs').renameSync(${JSON.stringify(staged)}, ${JSON.stringify(final)})" && echo RENAME_OK`,
      )
      const npmResult = run(npmLike)
      expect(npmResult.stdout).toContain('RENAME_OK')
      expect(existsSync(join(final, 'index.js'))).toBe(true)

      // A rename that straddles a pin boundary (packages/app -> packages,
      // i.e. out of the app vfsmount into its parent's) fails EXDEV from
      // fs.rename; mv detects EXDEV and falls back to copy + unlink.
      const straddle = await wrap(
        {},
        `cd ${appDir} && ${process.execPath} -e "try { require('fs').renameSync('index.js', '../index.js'); console.log('NO_ERROR') } catch (e) { console.log('CODE=' + e.code) }" && mv index.js ../moved.js && echo MV_OK`,
      )
      const straddleResult = run(straddle)
      expect(straddleResult.stdout).toContain('CODE=EXDEV')
      expect(straddleResult.stdout).toContain('MV_OK')
      expect(existsSync(join(PROJECT, 'packages', 'moved.js'))).toBe(true)
      expect(existsSync(join(appDir, 'index.js'))).toBe(false)
    },
  )
})
