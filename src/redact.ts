/**
 * Strips secrets from everything read off the appliance before it reaches the model.
 * Field names come from the NITRO 13.1 spec's GET response schemas. The list is exact
 * on purpose: a loose match on "key" or "password" would hide file paths and
 * ENABLED/DISABLED settings that troubleshooting needs.
 */

const SECRET_FIELDS = [
  "password", "secondarypassword", "ldapbinddnpassword", "kcdpassword", "domainuserpasswd",
  "sitepassword", "adcpassword", "proxypassword", "sopassword", "oldsopassword", "userpassword",
  "authpasswd", "privpasswd", "passplain", "passcrypt", "passphrase", "cookiepassphrase",
  "radkey", "tacacssecret", "clientsecret", "sharedsecret", "applicationsecret", "secretkey",
  "servicekey", "signingkey", "keyvalue", "psk", "communityname", "sessionkey",
  "authtoken", "analyticsauthtoken", "apikey", "snmpcommunity", "challengepassword", "pempassphrase",
  "sourcesecret", "targetsecret",
];
export const FIELD_SET = new Set(SECRET_FIELDS);
const REDACTED = "[redacted]";

// CLI text (running/saved config, logs): "-ldapBindDnPassword 1a2b... -encrypted", quoted or bare.
// [ \t] not \s, so a flag at end of line never swallows the next line; escaped quotes and spaces stay inside the value.
const CLI_FLAG = new RegExp(String.raw`(-(?:${SECRET_FIELDS.join("|")})[ \t]+)("(?:\\.|[^"\\])*"|(?:\\.|[^\s"])+)`, "gi");
// Saved config marks every stored secret with a trailing -encrypted, including positional ones
// (system user hash, "-inform PFX <passphrase> -encrypted"): mask the token right before it, anywhere in a line.
const BEFORE_ENCRYPTED = /([ \t])("(?:\\.|[^"\\])*"|[^\s"]+)(?=[ \t]+-encrypted\b)/gi;
// Typed (plaintext) forms with no -encrypted: "add system user <name> <password>", "-inform PFX <passphrase>".
const PLAIN_POSITIONAL = /(\b(?:add|set)[ \t]+system[ \t]+user[ \t]+[^\s"]+[ \t]+|-inform[ \t]+PFX[ \t]+)(?!-)("(?:\\.|[^"\\])*"|[^\s"]+)/gi;
// "add snmp community <name> <permissions>": the community string is positional, also inside quoted audit-log commands.
const SNMP_COMMUNITY = /(\b(?:add|set|rm)[ \t]+snmp[ \t]+community[ \t]+)("(?:\\.|[^"\\])*"|[^\s"]+)/gi;
// "password:x" inside NITRO args strings (e.g. a tool call logged for audit).
const ARG_PAIR = new RegExp(String.raw`((?:^|[,\s])(?:${SECRET_FIELDS.join("|")}):[ \t]*)("(?:\\.|[^"\\])*"|[^,\s"]+)`, "gi");
const PRIVATE_KEY = /-----BEGIN ([A-Z ]*)PRIVATE KEY-----[\s\S]*?-----END \1PRIVATE KEY-----/g;
// user:pass@ in import URLs. Scheme names are short; the bound keeps this linear on long word runs.
const URL_CREDS = /(\b[A-Za-z][A-Za-z0-9+.-]{0,15}:\/\/[^\s/:@"]+:)[^\s/@"]+@/g;

export function redactText(text: string): string {
  return text
    .replace(PRIVATE_KEY, `-----BEGIN $1PRIVATE KEY----- ${REDACTED} -----END $1PRIVATE KEY-----`)
    .replace(CLI_FLAG, `$1${REDACTED}`)
    .replace(BEFORE_ENCRYPTED, `$1${REDACTED}`)
    .replace(PLAIN_POSITIONAL, `$1${REDACTED}`)
    .replace(SNMP_COMMUNITY, `$1${REDACTED}`)
    .replace(ARG_PAIR, `$1${REDACTED}`)
    .replace(URL_CREDS, `$1${REDACTED}@`);
}

// Secrets in process memory and the nsaaad debug stream. Forensic output only: in config text the
// same shapes appear inside policy expressions troubleshooting needs.
const FORENSIC_PATTERNS = [
  /((?:passw(?:or)?d\d*|pwd|secret)=)[^&\s]+/gi, // form and query encoding: passwd=x&, password=x
  /(Authorization:[ \t]*(?:Basic|Bearer|Negotiate|NTLM)[ \t]+)\S+/gi, // HTTP auth headers
  /(\bNSC_[A-Za-z0-9_.-]+=)[^;\s]+/g, // NetScaler session cookies (NSC_AAAC, NSC_TMAS, ...): a live Gateway session
  /("[a-z_]*(?:passw(?:or)?d\d*|pwd|secret)"[ \t]*:[ \t]*")(?:\\.|[^"\\])*/gi, // JSON: "password":"x"
];

/** redactText plus the forensic patterns, for core dumps and the authentication debug stream. */
export function redactForensic(text: string): string {
  return FORENSIC_PATTERNS.reduce((t, re) => t.replace(re, `$1${REDACTED}`), redactText(text));
}

/** Deep copy with secret-named string fields replaced and every string scrubbed as CLI text. */
export function redact<T>(value: T): T {
  if (typeof value === "string") return redactText(value) as T;
  if (Array.isArray(value)) return value.map(redact) as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      // A secret-named key is masked whatever its type (a numeric PIN, a nested object); only "" stays visible.
      out[k] = FIELD_SET.has(k.toLowerCase()) ? (v === "" || v === undefined || v === null ? v : REDACTED) : redact(v);
    }
    return out as T;
  }
  return value;
}
