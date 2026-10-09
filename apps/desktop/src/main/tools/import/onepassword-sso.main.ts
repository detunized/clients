import { randomUUID } from "crypto";

import { BrowserWindow, Session, ipcMain, session } from "electron";

import { LogService } from "@bitwarden/common/platform/abstractions/log.service";

import { WindowMain } from "../../window.main";

/** A page with no preload that cannot reach Node, so a bad identity provider gets no foothold. */
function loginWebPreferences(partition: string) {
  return {
    partition,
    sandbox: true,
    contextIsolation: true,
    nodeIntegration: false,
  };
}

type LoginWebPreferences = ReturnType<typeof loginWebPreferences>;

/** Some identity providers refuse to sign in an embedded browser that says what it is. */
export function withoutAppTokens(userAgent: string): string {
  return userAgent.replace(/\s(?:Bitwarden[\w-]*|Electron)\/\S+/g, "");
}

function parseUrl(address: unknown): URL | undefined {
  try {
    return new URL(String(address));
  } catch {
    return undefined;
  }
}

function trimTrailingSlashes(path: string): string {
  return path.replace(/\/+$/, "");
}

/**
 * Whether `address` is the identity provider handing the user back to 1Password: the same scheme,
 * host and path as `redirectTo`, whether that is a page of 1Password or an address of the 1Password
 * app. The authorization code that follows, in the query or the fragment, is left to the SDK.
 */
export function isSsoRedirect(address: string, redirectTo: URL): boolean {
  const url = parseUrl(address);
  return (
    url != null &&
    url.protocol === redirectTo.protocol &&
    url.host === redirectTo.host &&
    trimTrailingSlashes(url.pathname) === trimTrailingSlashes(redirectTo.pathname)
  );
}

/** Ends the login, unless it ended already, and tells whether this call was the one to end it. */
type Settle = (redirectedTo: string | undefined) => boolean;

interface PendingLogin {
  window: BrowserWindow;
  settle: Settle;
}

/**
 * Signs the user in to a 1Password account with its identity provider in a window of its own, for
 * the importer, and hands the address the identity provider redirects to back to the renderer.
 *
 * The window is a throwaway browser: its session is a new one in memory for every login and is
 * cleared when the login ends, it has no preload, and the redirect is stopped before it is followed. That keeps
 * 1Password's own page from consuming the authorization code, and the operating system from
 * handing an address of the `onepassword://` scheme to the 1Password app.
 */
export class OnePasswordSsoMain {
  private pending: PendingLogin | undefined;

  constructor(
    private logService: LogService,
    private windowMain: WindowMain,
  ) {
    ipcMain.handle("onePasswordSso.login", (_event, ssoLoginUrl: unknown, redirectTo: unknown) =>
      this.login(ssoLoginUrl, redirectTo),
    );
    ipcMain.handle("onePasswordSso.cancel", () => this.cancel());
  }

  private login(ssoLoginUrl: unknown, redirectTo: unknown): Promise<string | undefined> {
    const loginUrl = parseUrl(ssoLoginUrl);
    const redirectUrl = parseUrl(redirectTo);
    if (loginUrl?.protocol !== "https:" || redirectUrl == null) {
      return Promise.reject(new Error("The 1Password sign-in address is not valid."));
    }

    this.cancel();

    return new Promise((resolve) => {
      const webPreferences = loginWebPreferences(`onepassword-sso-${randomUUID()}`);
      const loginSession = this.configureSession(webPreferences.partition);
      const window = this.createWindow(webPreferences);

      let settled = false;
      const settle: Settle = (redirectedTo) => {
        if (settled) {
          return false;
        }
        settled = true;
        if (this.pending?.window === window) {
          this.pending = undefined;
        }
        resolve(redirectedTo);
        // Unlike close(), destroy() cannot be vetoed by the page, and it takes the popups along.
        if (!window.isDestroyed()) {
          window.destroy();
        }
        this.clearSession(loginSession);
        return true;
      };

      this.pending = { window, settle };
      window.on("closed", () => settle(undefined));
      this.watch(window, redirectUrl, settle, webPreferences);

      window.loadURL(loginUrl.href).catch(() => {
        // Navigating away to the redirect aborts the load, which is not a failure.
        this.logService.debug("1Password SSO login page stopped loading");
      });
    });
  }

  private cancel(): void {
    this.pending?.settle(undefined);
  }

  private configureSession(partition: string): Session {
    const loginSession = session.fromPartition(partition);
    loginSession.setUserAgent(withoutAppTokens(loginSession.getUserAgent()));
    loginSession.setPermissionRequestHandler((_webContents, _permission, callback) =>
      callback(false),
    );
    return loginSession;
  }

  /** Nothing the identity provider stored may outlive the login: storage and HTTP credentials. */
  private clearSession(loginSession: Session): void {
    Promise.all([loginSession.clearStorageData(), loginSession.clearAuthCache()]).catch(() =>
      this.logService.debug("1Password SSO session could not be cleared"),
    );
  }

  private createWindow(webPreferences: LoginWebPreferences): BrowserWindow {
    const parent = this.windowMain.win;
    return new BrowserWindow({
      parent: parent != null && !parent.isDestroyed() ? parent : undefined,
      width: 520,
      height: 720,
      title: "1Password",
      autoHideMenuBar: true,
      webPreferences,
    });
  }

  /**
   * Settles with the address the window is sent to once that is the redirect. Where the navigation
   * can still be stopped it is, so the page behind the redirect never loads. A popup of the
   * identity provider is watched the same way, since the login may end there.
   */
  private watch(
    window: BrowserWindow,
    redirectTo: URL,
    settle: Settle,
    webPreferences: LoginWebPreferences,
  ): void {
    const capture = (eventName: string, url: string, event?: { preventDefault: () => void }) => {
      if (!isSsoRedirect(url, redirectTo)) {
        return false;
      }
      event?.preventDefault();
      if (settle(url)) {
        this.logService.info(`1Password SSO redirect captured on ${eventName}`);
      }
      return true;
    };

    const contents = window.webContents;
    // A page that vetoes unloading must not keep the user from closing the window.
    contents.on("will-prevent-unload", (event) => event.preventDefault());
    contents.on("will-redirect", (event) => {
      if (event.isMainFrame) {
        capture("will-redirect", event.url, event);
      }
    });
    contents.on("will-navigate", (event) => capture("will-navigate", event.url, event));
    contents.on("will-frame-navigate", (event) => {
      if (event.isMainFrame) {
        capture("will-frame-navigate", event.url, event);
      }
    });
    contents.on("did-navigate", (_event, url) => capture("did-navigate", url));
    contents.on("did-navigate-in-page", (_event, url, isMainFrame) => {
      if (isMainFrame) {
        capture("did-navigate-in-page", url);
      }
    });

    contents.setWindowOpenHandler(({ url }) => {
      if (capture("window-open", url)) {
        return { action: "deny" };
      }
      if (url !== "about:blank" && parseUrl(url)?.protocol !== "https:") {
        return { action: "deny" };
      }
      return { action: "allow", overrideBrowserWindowOptions: { parent: window, webPreferences } };
    });
    contents.on("did-create-window", (popup) =>
      this.watch(popup, redirectTo, settle, webPreferences),
    );
  }
}
