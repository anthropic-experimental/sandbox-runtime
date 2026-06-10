import { getPlatform } from '../../src/utils/platform.js'

const platform = getPlatform()

export const isLinux = platform === 'linux'
export const isMacOS = platform === 'macos'
export const isWindows = platform === 'windows'
export const isSupportedPlatform = isLinux || isMacOS || isWindows
