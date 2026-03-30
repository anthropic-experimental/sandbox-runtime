import { getPlatform } from '../../src/utils/platform.js'

const platform = getPlatform()

export const isLinux = platform === 'linux'
export const isMacos = platform === 'macos'
export const isSupportedPlatform = isLinux || isMacos
