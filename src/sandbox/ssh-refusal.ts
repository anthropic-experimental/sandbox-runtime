/**
 * In-band SSH refusal, shared by the SOCKS and HTTP CONNECT front-ends.
 *
 * When the sandbox blocks a connection to an SSH destination, the client is
 * ssh — it speaks no HTTP and no SOCKS, and a bare transport-level refusal
 * reaches the user as "Connection closed by UNKNOWN port 65535" with no
 * explanation. Answering in SSH's own protocol instead makes OpenSSH print
 * the policy reason verbatim ("Received disconnect from ...: <reason>"), so
 * a git-over-ssh user or agent learns why the connection was refused.
 *
 * Both front-ends may emit their own protocol's refusal first: OpenSSH
 * discards any lines preceding the SSH identification string (RFC 4253
 * §4.2), so an HTTP status line and headers are skipped by the client.
 */

/** Minimal SSH server identification. Must end with CRLF (RFC 4253 §4.2). */
export const SSH_REFUSAL_BANNER = 'SSH-2.0-policy_refusal\r\n'

/** The port an SSH destination is recognised by. */
export const SSH_PORT = 22

/**
 * A plaintext SSH_MSG_DISCONNECT, legal before key exchange (RFC 4253:
 * SSH_MSG_DISCONNECT may be sent at any time; pre-NEWKEYS packets carry no
 * MAC and no encryption). reason code 1 = HOST_NOT_ALLOWED_TO_CONNECT.
 * The description is what OpenSSH prints; collapse control characters so a
 * configured reason can't fabricate extra log lines, and cap the length.
 */
export function sshDisconnectPacket(description: string): Buffer {
  const text = description
    // eslint-disable-next-line no-control-regex -- stripping control chars is the point
    .replace(/[\x00-\x1f\x7f-\x9f]+/g, ' ')
    .slice(0, 1000)
  const desc = Buffer.from(text, 'utf8')
  const lang = Buffer.alloc(0)
  const payload = Buffer.concat([
    Buffer.from([0x01]), // SSH_MSG_DISCONNECT
    uint32(1), // SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT
    uint32(desc.length),
    desc,
    uint32(lang.length),
    lang,
  ])
  // packet_length = padding_length byte + payload + padding;
  // (4 + packet_length) must be a multiple of 8, padding >= 4.
  let padding = 8 - ((4 + 1 + payload.length) % 8)
  if (padding < 4) padding += 8
  return Buffer.concat([
    uint32(1 + payload.length + padding),
    Buffer.from([padding]),
    payload,
    Buffer.alloc(padding),
  ])
}

/** Identification string plus disconnect packet, ready to write and close. */
export function sshRefusalBytes(description: string): Buffer {
  return Buffer.concat([
    Buffer.from(SSH_REFUSAL_BANNER),
    sshDisconnectPacket(description),
  ])
}

function uint32(n: number): Buffer {
  const b = Buffer.alloc(4)
  b.writeUInt32BE(n, 0)
  return b
}
