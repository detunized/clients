import { ipcMain } from "electron";

import {
  getInstalledBrowsers,
  getAvailableProfiles,
  importLogins,
  type BrowserConfig,
  type ProfileInfo,
} from "../../importers/chromium";

// TODO: Temporarily converting all the data to primitive types, fix this!
type BrowserInfo = {
  config: BrowserConfig;
  profiles: Map<string, ProfileInfo>;
};

export class ChromiumImportService {
  // TODO: Temporarily converting all the data to primitive types, fix this!
  private browsers: Map<string, BrowserInfo> = new Map();

  constructor() {
    ipcMain.handle("chromiumImport.getInstalledBrowsers", async (): Promise<string[]> => {
      const browsers = await getInstalledBrowsers();
      this.browsers.clear();
      browsers.forEach((browser) => {
        this.browsers.set(browser.name, { config: browser, profiles: new Map() });
      });
      return Array.from(this.browsers.keys());
    });

    ipcMain.handle(
      "chromiumImport.getAvailableProfiles",
      async (event, browserName: string): Promise<string[]> => {
        const browserInfo = this.browsers.get(browserName);
        if (!browserInfo) {
          throw new Error(`Browser ${browserName} not found`);
        }

        // Map profile info to a user-friendly name
        const profiles = await getAvailableProfiles(browserInfo.config);
        browserInfo.profiles.clear();
        profiles.forEach((profile) => {
          const name = profile.accountName
            ? `${profile.name} (${profile.accountName} | ${profile.accountEmail})`
            : profile.name;
          browserInfo.profiles.set(name, profile);
        });
        return Array.from(browserInfo.profiles.keys());
      },
    );

    ipcMain.handle(
      "chromiumImport.importLogins",
      async (event, browserName: string, profileName: string): Promise<any> => {
        const browserInfo = this.browsers.get(browserName);
        if (!browserInfo) {
          throw new Error(`Browser ${browserName} not found`);
        }

        const profileInfo = browserInfo.profiles.get(profileName);
        if (!profileInfo) {
          throw new Error(`Profile ${profileName} not found`);
        }

        try {
          return await importLogins(browserInfo.config, profileInfo);
        } catch (error) {
          throw new Error(
            `Failed to import logins from ${browserName} (${profileName}): ${error.message}`,
          );
        }
      },
    );
  }
}
