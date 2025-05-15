import { pbkdf2, createDecipheriv } from "crypto";
import * as fs from "fs/promises";
import * as os from "os";
import * as path from "path";
import { promisify } from "util";

import * as sqlite3 from "sqlite3";

import { passwords } from "@bitwarden/desktop-napi";

// Temp stub
class windows_crypto {
  static async unprotectData(encrypted: Buffer): Promise<Buffer> {
    return Buffer.from("");
  }
}

export type BrowserConfig = {
  name: string;
  company: string;
  product: string;
};

export type ProfileInfo = {
  name: string;
  accountName: string;
  accountEmail: string;
  folder: string;
};

type LocalState = {
  profile: {
    info_cache: {
      [key: string]: {
        name: string;
        gaia_name?: string | null;
        user_name?: string | null;
      };
    };
  };
  os_crypt: {
    encrypted_key?: string | null;
  };
};

type EncryptedLoginSqlite = {
  url: string;
  username: string;
  encryptedPasswordHex: string;
  encryptedNoteHex: string;
};

type EncryptedLogin = {
  url: string;
  username: string;
  encryptedPassword: Buffer;
  encryptedNote: Buffer;
};

type Login = {
  url: string;
  username: string;
  password: string;
  note: string;
};

type LoginImportFailure = {
  url: string;
  username: string;
  error: string;
  cause?: Error;
};

type LoginImportResult = Login | LoginImportFailure;

const supportedBrowsers: BrowserConfig[] = [
  {
    name: "Chrome",
    company: "Google",
    product: "Chrome",
  },
  {
    name: "Edge",
    company: "Microsoft",
    product: "Edge",
  },
  {
    name: "Brave",
    company: "BraveSoftware",
    product: "Brave-Browser",
  },
];

abstract class CryptoService {
  constructor(localState: LocalState) {
    this.localState = localState;
  }

  abstract decryptToString(encrypted: Buffer): Promise<string>;

  //
  // Protected
  //

  protected localState: LocalState;

  protected splitEncryptedString(encrypted: Buffer): [string, Buffer] {
    if (encrypted.length < 3) {
      throw makeError(
        `Corrupted entry: invalid encrypted string length, expected at least 3 bytes, got ${encrypted.length}`,
      );
    }

    return [encrypted.subarray(0, 3).toString(), encrypted.subarray(3)];
  }

  protected splitEncryptedStringAndValidate(
    encrypted: Buffer,
    ...supportedVersions: string[]
  ): [string, Buffer] {
    const [version, password] = this.splitEncryptedString(encrypted);
    if (!supportedVersions.includes(version)) {
      throw makeError(`Unsupported encryption version: ${version}`);
    }

    return [version, password];
  }
}

class MacCryptoService extends CryptoService {
  async decryptToString(encrypted: Buffer): Promise<string> {
    if (encrypted.length === 0) {
      return "";
    }

    // On macOS only v10 is supported
    const [, noPrefix] = this.splitEncryptedStringAndValidate(encrypted, "v10");

    // This might bring up the admin password prompt
    this.masterKey ??= await this.getMasterKey();

    try {
      const decipher = createDecipheriv("aes-128-cbc", this.masterKey, MacCryptoService.iv);
      const plaintext = Buffer.concat([decipher.update(noPrefix), decipher.final()]);
      return plaintext.toString("utf8");
    } catch (error) {
      // Provide a less cryptic error message
      throw makeError("Decryption failed", error as Error);
    }
  }

  //
  // Private
  //

  private static iv = Buffer.alloc(16, 0x20); // 16 bytes of 0x20 (space character)
  private static pbkdf2 = promisify(pbkdf2);

  private masterKey: Buffer | null = null;

  private async getMasterKey(): Promise<Buffer> {
    return await this.deriveKey(await this.getMasterPassword());
  }

  private async getMasterPassword(): Promise<Buffer> {
    // TODO: Configure this for Chromium and possibly other browsers!
    const service = "Chrome Safe Storage";
    const account = "Chrome";

    const password = await passwords.getPassword(service, account);
    if (!password) {
      throw makeError("Failed to get master password from the macOS keychain");
    }

    return Buffer.from(password, "utf-8");
  }

  private async deriveKey(masterPassword: Buffer): Promise<Buffer> {
    const iterations = 1003;
    const keyLength = 16;
    return await MacCryptoService.pbkdf2(
      masterPassword,
      "saltysalt",
      iterations,
      keyLength,
      "sha1",
    );
  }
}

class WindowsCryptoService extends CryptoService {
  async decryptToString(encrypted: Buffer): Promise<string> {
    if (encrypted.length === 0) {
      return "";
    }

    // On Windows only v10 is supported
    const [, noPrefix] = this.splitEncryptedStringAndValidate(encrypted, "v10");

    // v10 is already stripped from the password
    // On Windows Chrome uses AES-GCM: [12 bytes IV][ciphertext][16 bytes authTag]
    const minLength = 12 + 16;

    if (noPrefix.length < minLength) {
      throw makeError(
        `Corrupted entry: entry length, expected at least ${minLength} bytes, got ${noPrefix.length}`,
      );
    }

    const iv = noPrefix.subarray(0, 12);
    const ciphertext = noPrefix.subarray(12, noPrefix.length - 16);
    const authTag = noPrefix.subarray(noPrefix.length - 16);

    // Allow empty passwords
    if (ciphertext.length === 0) {
      return "";
    }

    this.masterKey ??= await this.getMasterKey();

    try {
      const decipher = createDecipheriv("aes-256-gcm", this.masterKey, iv);
      decipher.setAuthTag(authTag);

      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return plaintext.toString("utf8");
    } catch (error) {
      // Provide a less cryptic error message
      throw makeError("Decryption failed", error as Error);
    }
  }

  //
  // Private
  //

  private masterKey: Buffer | null = null;

  private async getMasterKey(): Promise<Buffer> {
    if (!this.localState.os_crypt?.encrypted_key || this.localState.os_crypt.encrypted_key === "") {
      throw makeError("Encrypted key is not found in the browser's local state");
    }

    return this.decryptMasterKey(this.localState.os_crypt.encrypted_key);
  }

  private async decryptMasterKey(encryptedBase64: string): Promise<Buffer> {
    const prefix = "DPAPI";

    const encrypted = Buffer.from(encryptedBase64, "base64");
    if (encrypted.length < prefix.length) {
      throw makeError(
        `Invalid encrypted key length, expected at least ${prefix.length} bytes, got ${encrypted.length}`,
      );
    }

    if (!encrypted.subarray(0, prefix.length).equals(Buffer.from(prefix))) {
      throw makeError("Encrypted master key is not encrypted with DPAPI");
    }

    try {
      return await windows_crypto.unprotectData(encrypted.subarray(prefix.length));
    } catch (error) {
      throw makeError("Failed to decrypt master key", error as Error);
    }
  }
}

class LinuxCryptoService extends CryptoService {
  async decryptToString(encrypted: Buffer): Promise<string> {
    if (encrypted.length === 0) {
      return "";
    }

    const [version, noPrefix] = this.splitEncryptedStringAndValidate(encrypted, "v10", "v11");
    switch (version) {
      case "v10":
        return await this.decryptV10(noPrefix);
      case "v11":
        return await this.decryptV11(noPrefix);
      default:
        throw makeError("Logic error: unreachable code");
    }
  }

  //
  // Private
  //

  private v10Key = Buffer.from("fd621fe5a2b402539dfa147ca9272778", "hex");
  private iv = Buffer.alloc(16, 0x20); // 16 bytes of 0x20 (space character)
  private pbkdf2 = promisify(pbkdf2);

  private v11Key: Buffer | null = null;

  private async decryptV10(encrypted: Buffer): Promise<string> {
    try {
      const decipher = createDecipheriv("aes-128-cbc", this.v10Key, this.iv);
      const plaintext = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      return plaintext.toString("utf8");
    } catch (error) {
      // Provide a less cryptic error message
      throw makeError("Decryption failed", error as Error);
    }
  }

  private async decryptV11(encrypted: Buffer): Promise<string> {
    this.v11Key ??= await this.getMasterPasswordV11();

    try {
      const decipher = createDecipheriv("aes-128-cbc", this.v11Key, this.iv);
      const plaintext = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      return plaintext.toString("utf8");
    } catch (error) {
      // Provide a less cryptic error message
      throw makeError("Decryption failed", error as Error);
    }
  }

  private async getMasterPasswordV11(): Promise<Buffer> {
    const masterPassword = await passwords.getPassword("chrome", "");
    const iterations = 1;
    const keyLength = 16;
    return await this.pbkdf2(masterPassword, "saltysalt", iterations, keyLength, "sha1");
  }
}

function getBrowserSettingsDirectory(config: BrowserConfig): string {
  switch (os.platform()) {
    case "darwin":
      return path.join(
        os.homedir(),
        "Library",
        "Application Support",
        config.company,
        config.product,
      );
    case "win32":
      return path.join(
        os.homedir(),
        "AppData",
        "Local",
        config.company,
        config.product,
        "User Data",
      );
    case "linux":
      return path.join(os.homedir(), ".config", "google-chrome"); // TODO: Fix Linux!!!
    default:
      throw makeError(`Unsupported platform: ${os.platform()}`);
  }
}

function getCryptoService(localState: LocalState): CryptoService {
  switch (os.platform()) {
    case "darwin":
      return new MacCryptoService(localState);
    case "win32":
      return new WindowsCryptoService(localState);
    case "linux":
      return new LinuxCryptoService(localState);
    default:
      throw makeError(`Unsupported platform: ${os.platform()}`);
  }
}

function getRandomId(): string {
  return Math.random().toString(36).slice(2);
}

async function loadLocalState(browserDir: string): Promise<LocalState> {
  const localStatePath = path.join(browserDir, "Local State");
  try {
    const data = await fs.readFile(localStatePath, "utf8");
    return JSON.parse(data);
  } catch (error) {
    throw makeError(`Failed to read Local State file at ${localStatePath}`, error as Error);
  }
}

function getProfileInfo(localState: LocalState): ProfileInfo[] {
  return Object.entries(localState.profile.info_cache).map(([folder, profile]: [string, any]) => ({
    name: profile.name,
    accountName: profile.gaia_name ?? "",
    accountEmail: profile.user_name ?? "",
    folder: folder,
  }));
}

async function queryLogins(dbPath: string): Promise<EncryptedLogin[]> {
  // TODO: There's a lot of promisification going on in this function. Would be good to abstract it away.

  const db = await new Promise<sqlite3.Database>((resolve, reject) => {
    const database = new sqlite3.Database(dbPath, sqlite3.OPEN_READONLY, (err: Error | null) => {
      if (err) {
        reject(err);
      } else {
        resolve(database);
      }
    });
  });

  try {
    const haveLogins = await doesTableExist(db, "logins");
    const havePasswordNotes = await doesTableExist(db, "password_notes");

    if (!haveLogins || !havePasswordNotes) {
      return [];
    }

    const logins = await new Promise<EncryptedLoginSqlite[]>((resolve, reject) => {
      db.serialize(() => {
        db.all<EncryptedLoginSqlite>(
          `
        SELECT
          l.origin_url          AS url,
          l.username_value      AS username,
          hex(l.password_value) AS encryptedPasswordHex,
          hex(pn.value)         AS encryptedNoteHex
        FROM
          logins l
        LEFT JOIN
          password_notes pn ON l.id = pn.parent_id
        WHERE
          l.blacklisted_by_user = 0
      `,
          (err, rows) => {
            if (err) {
              reject(err);
            } else {
              resolve(rows);
            }
          },
        );
      });
    });

    return logins.map(ensureValidLogin);
  } finally {
    db.close();
  }
}

async function doesTableExist(db: sqlite3.Database, tableName: string): Promise<boolean> {
  return await new Promise<boolean>((resolve, reject) => {
    db.serialize(() => {
      db.get(
        `SELECT name FROM sqlite_master WHERE type='table' AND name='${tableName}'`,
        (err, row) => {
          if (err) {
            resolve(false);
          } else {
            resolve(!!row);
          }
        },
      );
    });
  });
}

function ensureValidLogin(login: any): EncryptedLogin {
  return {
    url: ensureValidString(login.url),
    username: ensureValidString(login.username),
    encryptedPassword: bufferFromHex(login.encryptedPassword),
    encryptedNote: bufferFromHex(login.encryptedNote),
  };
}

function ensureValidString(value: string | null): string {
  return value === null || value === undefined ? "" : value;
}

function bufferFromHex(value: string | null): Buffer {
  return value === null || value === undefined ? Buffer.from("") : Buffer.from(value, "hex");
}

async function getProfileLogins(
  browserDir: string,
  profile: ProfileInfo,
): Promise<EncryptedLogin[]> {
  return await getLogins(browserDir, profile, "Login Data");
}

async function getAccountLogins(
  browserDir: string,
  profile: ProfileInfo,
): Promise<EncryptedLogin[]> {
  return await getLogins(browserDir, profile, "Login Data For Account");
}

async function getLogins(
  browserDir: string,
  profile: ProfileInfo,
  filename: string,
): Promise<EncryptedLogin[]> {
  const loginDataPath = path.join(browserDir, profile.folder, filename);

  // Sometimes database files are not present, so nothing to import
  if (!(await exists(loginDataPath))) {
    return [];
  }

  // When the browser with the current profile is open the database file is locked.
  // To access it we need to copy it to a temporary location.
  const tmpDbPath = path.join(os.tmpdir(), `tmp-logins-${Date.now()}-${getRandomId()}.db`);
  const copyError = await copyFile(loginDataPath, tmpDbPath);
  if (copyError) {
    throw makeError(`Failed to copy the password database file at ${loginDataPath}`, copyError);
  }

  try {
    return await queryLogins(tmpDbPath);
  } finally {
    await deleteFile(tmpDbPath);
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await fs.access(path);
    return true;
  } catch {
    return false;
  }
}

async function copyFile(src: string, dest: string): Promise<Error | null> {
  // Try multiple times to allow the browser to write the file now and then
  const maxAttempts = 3;
  for (let i = 0; i < maxAttempts; i++) {
    try {
      await fs.copyFile(src, dest);
      return null;
    } catch (error) {
      if (i === maxAttempts - 1) {
        return error as Error;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  throw makeError("Logic error: unreachable code");
}

async function deleteFile(path: string): Promise<void> {
  try {
    await fs.unlink(path);
  } catch {
    // Ignore unlink errors
  }
}

async function decryptLogins(
  encryptedLogins: EncryptedLogin[],
  cryptoService: CryptoService,
): Promise<LoginImportResult[]> {
  return Promise.all(
    encryptedLogins.map((encryptedLogin) => decryptLogin(encryptedLogin, cryptoService)),
  );
}

async function decryptLogin(
  encryptedLogin: EncryptedLogin,
  cryptoService: CryptoService,
): Promise<LoginImportResult> {
  try {
    return {
      url: encryptedLogin.url,
      username: encryptedLogin.username,
      password: await cryptoService.decryptToString(encryptedLogin.encryptedPassword),
      note: await cryptoService.decryptToString(encryptedLogin.encryptedNote),
    };
  } catch (error) {
    return {
      url: encryptedLogin.url,
      username: encryptedLogin.username,
      error: error.message,
      cause: error as Error,
    };
  }
}

//
// Public API
//

export async function getInstalledBrowsers(): Promise<BrowserConfig[]> {
  const browsers: BrowserConfig[] = [];
  for (const config of supportedBrowsers) {
    if (await exists(getBrowserSettingsDirectory(config))) {
      browsers.push(config);
    }
  }
  return browsers;
}

export async function getAvailableProfiles(config: BrowserConfig): Promise<ProfileInfo[]> {
  const browserDir = getBrowserSettingsDirectory(config);
  if (!(await exists(browserDir))) {
    throw makeError(`Browser directory ${browserDir} doesn't exist`);
  }

  const localState = await loadLocalState(browserDir);
  return getProfileInfo(localState);
}

export async function importLogins(
  config: BrowserConfig,
  profile: ProfileInfo,
): Promise<LoginImportResult[]> {
  const browserDir = getBrowserSettingsDirectory(config);
  if (!(await exists(browserDir))) {
    throw makeError(`Browser directory ${browserDir} doesn't exist`);
  }

  const localState = await loadLocalState(browserDir);
  const cryptoService = getCryptoService(localState);

  // TODO: Make this configurable, not all browsers have both local and cloud account logins
  const getLogins = [
    { name: "Local logins", get: getProfileLogins },
    { name: "Cloud account login cache", get: getAccountLogins },
  ];

  const results: LoginImportResult[][] = [];
  for (const { get } of getLogins) {
    const logins = await decryptLogins(await get(browserDir, profile), cryptoService);
    results.push(logins);
  }

  // TODO: Merge results from different sources to remove duplicates
  return results.flat();
}

function makeError(message: string, cause?: Error): Error {
  // `cause` is ignored here as the compilation target is es2016.
  // TODO: Uncomment the cause when the target is updated to es2022
  return new Error(message /*, { cause: cause as Error }*/);
}
