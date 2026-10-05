/**
 * Configuration loaded from environment variables.
 *
 * Required:
 *   NETSCALER_NSIP    - Management IP of the primary NetScaler node
 *   NETSCALER_USER    - NITRO read-only account (every Reader tool except run_nsconmsg)
 *   NETSCALER_PASS    - its password
 *
 * Optional:
 *   NETSCALER_PEER_NSIP  - Peer node NSIP (for HA operations)
 *   NETSCALER_PROTOCOL   - "https" (default) or "http"
 *   NETSCALER_TIMEOUT    - Request timeout in ms (default: 15000)
 *   NETSCALER_ADMIN_USER / NETSCALER_ADMIN_PASS - NITRO account for admin tools (writes, get_system_file)
 *   NETSCALER_SSH_USER / NETSCALER_SSH_PASS - SSH account for run_nsconmsg
 *   NETSCALER_FORENSICS_USER / NETSCALER_FORENSICS_PASS - SSH account for the forensic tools
 *   NETSCALER_SSH_PORT   - SSH port (default: 22)
 *   NETSCALER_SSH_TIMEOUT - SSH command timeout in ms (default: 30000)
 *   NETSCALER_TLS_SHA256 - Comma-separated SHA-256 cert fingerprints to pin (one per node)
 *   NETSCALER_SSH_SHA256 - Comma-separated SSH host key fingerprints to pin (SHA256:... form)
 *
 *   NETSCALER_BLOCK_PROTECT - Comma-separated /24s that block_ip_acl refuses (global, every appliance)
 *
 * Several appliances (either mode): NETSCALER_TARGETS=east,west reads each one's
 * settings under its own prefix (NS_EAST_NSIP, NS_EAST_USER, ...); see loadTargets.
 */

/** Error when a tool is asked for the peer node and the appliance has none configured. */
export const NO_PEER = "Peer node requested but no peer NSIP is configured for this appliance (NETSCALER_PEER_NSIP, or NS_<NAME>_PEER_NSIP with NETSCALER_TARGETS).";

export interface Config {
  nsip: string;
  peerNsip: string;
  username: string;
  password: string;
  /** Admin NITRO account; empty means admin tools are not registered. */
  adminUser: string;
  adminPass: string;
  protocol: "http" | "https";
  timeout: number;
  sshUser: string;
  sshPass: string;
  /** Forensics SSH account; empty means forensic tools are not registered. */
  forensicsUser: string;
  forensicsPass: string;
  sshPort: number;
  sshTimeout: number;
  /** Allowed SHA-256 TLS cert fingerprints (hex), one per node. Empty = unpinned. */
  tlsSha256: string[];
  /** Allowed SHA-256 SSH host key fingerprints (base64, as ssh-keygen -l prints). Empty = unpinned. */
  sshSha256: string[];
}

function list(value: string | undefined, normalize: (v: string) => string): string[] {
  return (value ?? "")
    .split(",")
    .map((v) => normalize(v.trim()))
    .filter(Boolean);
}

/**
 * Read one appliance's settings. The default prefix gives the original
 * NETSCALER_* names; each NETSCALER_TARGETS entry reads its own prefix
 * (e.g. NS_PROD_NSIP, NS_PROD_USER).
 */
export function loadConfig(prefix = "NETSCALER_"): Config {
  const env = (name: string) => process.env[prefix + name];
  const nsip = env("NSIP");
  const username = env("USER");
  const password = env("PASS");

  if (!nsip || !username || !password) {
    throw new Error(
      `Missing required environment variables: ${prefix}NSIP, ${prefix}USER, ${prefix}PASS`
    );
  }

  // Optional accounts come in pairs; half a pair is a configuration mistake.
  const pair = (name: string): [string, string] => {
    const user = env(`${name}_USER`) ?? "";
    const pass = env(`${name}_PASS`) ?? "";
    if (!user !== !pass) throw new Error(`Set both ${prefix}${name}_USER and ${prefix}${name}_PASS, or neither.`);
    return [user, pass];
  };
  // A whole decimal number in range; parseInt would take "1000ms" and setTimeout fires at once on NaN or past 2^31-1 ms.
  const int = (name: string, fallback: number, max: number): number => {
    const raw = env(name);
    if (raw === undefined || raw === "") return fallback;
    const n = /^[0-9]+$/.test(raw.trim()) ? Number(raw.trim()) : NaN;
    if (!(n >= 1 && n <= max)) throw new Error(`${prefix}${name} must be a whole number from 1 to ${max}, got "${raw}".`);
    return n;
  };
  const [adminUser, adminPass] = pair("ADMIN");
  const [sshUser, sshPass] = pair("SSH");
  const [forensicsUser, forensicsPass] = pair("FORENSICS");

  return {
    nsip,
    peerNsip: env("PEER_NSIP") ?? "",
    username,
    password,
    adminUser,
    adminPass,
    protocol: env("PROTOCOL") === "http" ? "http" : "https",
    timeout: int("TIMEOUT", 15000, 2_147_483_647),
    sshUser,
    sshPass,
    forensicsUser,
    forensicsPass,
    sshPort: int("SSH_PORT", 22, 65535),
    sshTimeout: int("SSH_TIMEOUT", 30000, 2_147_483_647),
    tlsSha256: list(env("TLS_SHA256"), (v) => v.replace(/:/g, "").toUpperCase()),
    sshSha256: list(env("SSH_SHA256"), (v) => v.replace(/^SHA256:/, "").replace(/=+$/, "")),
  };
}

/** NETSCALER_TARGETS=east,west: one Config per name, read under NS_<NAME>_. Empty map when unset. */
export function loadTargets(): Map<string, Config> {
  const targets = new Map<string, Config>();
  for (const name of list(process.env.NETSCALER_TARGETS, (t) => t.toLowerCase())) {
    if (!/^[a-z0-9]+$/.test(name)) throw new Error(`Target name "${name}" must be lowercase letters and digits`);
    targets.set(name, loadConfig(`NS_${name.toUpperCase()}_`));
  }
  return targets;
}
