import { execFile } from "node:child_process";

export type AccountDatabaseReader = (database: "passwd" | "group") => Promise<string>;
const MAX_BYTES = 4 * 1024 * 1024;
const MAX_RECORDS = 65_536;
const ID = /^(0|[1-9][0-9]*)$/u;

const readHostDatabase: AccountDatabaseReader = (database) => new Promise((resolve, reject) => {
  // Fixed executable and arguments: never a shell, caller-controlled command, or PATH search.
  execFile("/usr/bin/getent", [database], { encoding: "utf8", timeout: 5000, maxBuffer: MAX_BYTES, killSignal: "SIGKILL", env: { LANG: "C", LC_ALL: "C" } }, (error, stdout, stderr) => {
    if (error !== null || stderr.length !== 0) reject(new Error("client group account database enumeration failed"));
    else resolve(stdout);
  });
});

function lines(raw: string): string[] {
  if (Buffer.byteLength(raw) > MAX_BYTES || raw.includes("\0") || !raw.endsWith("\n")) throw new Error("client group account database enumeration is invalid");
  const records = raw.slice(0, -1).split("\n");
  if (records.length > MAX_RECORDS || records.some((line) => line.length === 0)) throw new Error("client group account database enumeration is invalid");
  return records;
}
function id(raw: string): number {
  if (!ID.test(raw) || !Number.isSafeInteger(Number(raw))) throw new Error("client group account identity is invalid");
  return Number(raw);
}

/** Requires complete NSS enumeration. Non-enumerating NSS backends are unsupported. */
export async function resolveClientGroupMembers(gid: number, read: AccountDatabaseReader = readHostDatabase): Promise<readonly number[]> {
  try {
    const passwd = lines(await read("passwd"));
    const accounts = new Map<string, { uid: number; gid: number }>();
    const uids = new Set<number>();
    for (const line of passwd) {
      const fields = line.split(":");
      if (fields.length !== 7 || !fields[0] || accounts.has(fields[0])) throw new Error("duplicate or invalid account");
      const uid = id(fields[2]!); const primary = id(fields[3]!);
      // Aliased UIDs obscure the exact two-identity boundary; fail closed.
      if (uids.has(uid)) throw new Error("aliased account identity");
      accounts.set(fields[0], { uid, gid: primary }); uids.add(uid);
    }
    const members = new Set([...accounts.values()].filter((account) => account.gid === gid).map((account) => account.uid));
    let found = false;
    const groupNames = new Set<string>(); const groupIds = new Set<number>();
    for (const line of lines(await read("group"))) {
      const fields = line.split(":");
      if (fields.length !== 4 || !fields[0] || groupNames.has(fields[0])) throw new Error("duplicate or invalid group");
      const groupId = id(fields[2]!);
      if (groupIds.has(groupId)) throw new Error("aliased group identity");
      groupNames.add(fields[0]); groupIds.add(groupId);
      if (groupId !== gid) continue;
      found = true;
      for (const name of fields[3] === "" ? [] : fields[3]!.split(",")) {
        const account = accounts.get(name);
        if (account === undefined) throw new Error("unresolved supplementary account");
        members.add(account.uid);
      }
    }
    if (!found) throw new Error("client group does not exist");
    return Object.freeze([...members].sort((a, b) => a - b));
  } catch { throw new Error("client group account database enumeration or resolution failed"); }
}
