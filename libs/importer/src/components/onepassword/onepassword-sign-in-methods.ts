/** How the 1Password account signs in. */
export type OnePasswordSignInMethod = "password" | "sso";

/** The sign-in methods the import form offers, labelled by the i18n key of their name. */
export const onePasswordSignInMethods: { value: OnePasswordSignInMethod; labelKey: string }[] = [
  { value: "password", labelKey: "password" },
  { value: "sso", labelKey: "singleSignOn" },
];
