import { ChangeDetectionStrategy, Component } from "@angular/core";
import { ComponentFixture, TestBed } from "@angular/core/testing";
import { AbstractControl, FormGroup, ReactiveFormsModule } from "@angular/forms";
import { By } from "@angular/platform-browser";
import { mock, MockProxy } from "jest-mock-extended";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { LogService } from "@bitwarden/common/platform/abstractions/log.service";
import { ToastService } from "@bitwarden/components";

import {
  ImportOnePasswordComponent,
  OnePasswordImportContext,
} from "./import-onepassword.component";
import { OnePasswordDirectImportService } from "./onepassword-direct-import.service";
import { OnePasswordSsoBrowser } from "./onepassword-sso-browser";

@Component({
  template: `<import-onepassword [formGroup]="formGroup"></import-onepassword>`,
  imports: [ImportOnePasswordComponent, ReactiveFormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
class HostComponent {
  readonly formGroup = new FormGroup<Record<string, AbstractControl>>({});
}

describe("ImportOnePasswordComponent", () => {
  const signInMethodSelector = "#import-onepassword_bit-select_sign-in-method";
  const passwordOnlyHint = "onePasswordOnlyPasswordLogin";

  const context: OnePasswordImportContext = {
    organizationId: undefined,
    selectedImportTarget: undefined,
    canAccessImportExport: false,
  };

  let fixture: ComponentFixture<HostComponent>;
  let directImportService: MockProxy<OnePasswordDirectImportService>;

  function render(ssoSupported: boolean) {
    directImportService = mock<OnePasswordDirectImportService>();
    const i18nService = mock<I18nService>();
    i18nService.t.mockImplementation((key) => key);

    TestBed.configureTestingModule({
      imports: [HostComponent],
      providers: [
        { provide: I18nService, useValue: i18nService },
        { provide: LogService, useValue: mock<LogService>() },
        { provide: ToastService, useValue: mock<ToastService>() },
        { provide: OnePasswordSsoBrowser, useValue: { supported: ssoSupported } },
      ],
    });
    TestBed.overrideComponent(ImportOnePasswordComponent, {
      set: {
        providers: [{ provide: OnePasswordDirectImportService, useValue: directImportService }],
      },
    });

    fixture = TestBed.createComponent(HostComponent);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  describe("when the client supports single sign-on", () => {
    it("offers the sign-in method and no password only hint", () => {
      const element = render(true);

      expect(element.querySelector(signInMethodSelector)).not.toBeNull();
      expect(element.textContent).not.toContain(passwordOnlyHint);
    });
  });

  describe("when 1Password refuses the account", () => {
    function component(): ImportOnePasswordComponent {
      return fixture.debugElement.query(By.directive(ImportOnePasswordComponent)).componentInstance;
    }

    function options() {
      return fixture.componentInstance.formGroup.get("onepasswordOptions")!;
    }

    async function submitRefused(field: "email" | "signInAddress") {
      directImportService.handleImport.mockRejectedValueOnce(new Error("refused"));
      directImportService.describeError.mockReturnValueOnce({ field, message: "refused" });
      await component().submitDirect(context, jest.fn());
    }

    beforeEach(() => {
      render(true);
      options().patchValue({ email: "user@example.com" });
    });

    it("marks the refused email and does not retry it", async () => {
      await submitRefused("email");

      expect(options().get("email")!.hasError("rejected")).toBe(true);

      await component().submitDirect(context, jest.fn());
      expect(directImportService.handleImport).toHaveBeenCalledTimes(1);
    });

    it.each([
      ["email", "email"],
      ["signInAddress", "subdomain"],
    ] as const)(
      "lets the %s be tried again with the other sign-in method",
      async (field, control) => {
        await submitRefused(field);
        expect(options().get(control)!.hasError("rejected")).toBe(true);

        options().patchValue({ signInMethod: "sso" });

        expect(options().get(control)!.hasError("rejected")).toBe(false);
        expect(options().valid).toBe(true);

        await component().submitDirect(context, jest.fn());
        expect(directImportService.handleSsoImport).toHaveBeenCalled();
      },
    );

    it("marks the email again when the other sign-in method refuses it too", async () => {
      await submitRefused("email");
      options().patchValue({ signInMethod: "sso" });
      directImportService.handleSsoImport.mockRejectedValueOnce(new Error("refused"));
      directImportService.describeError.mockReturnValueOnce({
        field: "email",
        message: "refused",
      });

      await component().submitDirect(context, jest.fn());

      expect(options().get("email")!.hasError("rejected")).toBe(true);
    });
  });

  describe("when the client does not support single sign-on", () => {
    it("offers no sign-in method and tells that only the password works", () => {
      const element = render(false);

      expect(element.querySelector(signInMethodSelector)).toBeNull();
      expect(element.textContent).toContain(passwordOnlyHint);
    });

    it("imports with the password", async () => {
      render(false);
      const component: ImportOnePasswordComponent = fixture.debugElement.query(
        By.directive(ImportOnePasswordComponent),
      ).componentInstance;
      fixture.componentInstance.formGroup.get("onepasswordOptions")!.patchValue({
        email: "user@example.com",
      });

      await component.submitDirect(context, jest.fn());

      expect(directImportService.handleImport).toHaveBeenCalled();
      expect(directImportService.handleSsoImport).not.toHaveBeenCalled();
    });
  });
});
