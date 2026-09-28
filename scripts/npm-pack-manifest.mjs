function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isSafeRelativePath(value) {
  return typeof value === "string" && value.length > 0 &&
    !value.startsWith("/") && !value.includes("\\") &&
    value.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

export function parseNpmPackManifest(output) {
  let parsed;
  try {
    parsed = JSON.parse(output);
  } catch (error) {
    throw new Error("npm pack returned invalid JSON", { cause: error });
  }

  let manifests;
  let keyedName;
  if (Array.isArray(parsed)) {
    manifests = parsed;
  } else if (isRecord(parsed)) {
    const keyedEntries = Object.entries(parsed);
    if (keyedEntries.length !== 1) {
      throw new Error(`npm pack must return exactly one manifest; received ${keyedEntries.length}`);
    }
    const [key, manifest] = keyedEntries[0];
    keyedName = key;
    manifests = [manifest];
  } else {
    throw new Error("npm pack result must be an array or keyed object");
  }

  if (manifests.length !== 1) {
    throw new Error(`npm pack must return exactly one manifest; received ${manifests.length}`);
  }

  const manifest = manifests[0];
  if (!isRecord(manifest)) throw new Error("npm pack manifest must be an object");
  if (typeof manifest.name !== "string" || manifest.name.length === 0) {
    throw new Error("npm pack manifest is missing a package name");
  }
  if (keyedName !== undefined && keyedName !== manifest.name) {
    throw new Error("npm pack manifest key does not match its package name");
  }
  if (!isSafeRelativePath(manifest.filename) || manifest.filename.includes("/") || !manifest.filename.endsWith(".tgz")) {
    throw new Error("npm pack manifest has an invalid tarball filename");
  }
  if (!Number.isFinite(manifest.size) || manifest.size < 0) {
    throw new Error("npm pack manifest has an invalid package size");
  }
  if (!Array.isArray(manifest.files) || manifest.files.some((file) =>
    !isRecord(file) || !isSafeRelativePath(file.path))) {
    throw new Error("npm pack manifest has an invalid files list");
  }

  return manifest;
}
