import { cfRequest, type CfRequestOptions } from "./http";
import { generateWireGuardKeys } from "./keys";

export function isWarpLicenseFormat(key: string): boolean {
  return typeof key === "string" && /^[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}$/.test(key.trim());
}

const WARP_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

export function generateWarpKey(): string {
  const seg = () =>
    Array.from({ length: 8 }, () => WARP_CHARSET[Math.floor(Math.random() * WARP_CHARSET.length)]).join("");
  return `${seg()}-${seg()}-${seg()}`;
}

const iosReg = (pub: string) => ({
  install_id: "",
  tos: new Date().toISOString(),
  key: pub,
  fcm_token: "",
  type: "ios",
  locale: "en_US",
});

export interface LicenseCheckResult {
  valid: boolean;
  accountType: string;
  referralCount: number | null;
  effectiveLicense: string | null;
  checkedLicense: string;
  message: string;
}

export async function checkLicense(rawKey: string): Promise<LicenseCheckResult> {
  const key = rawKey.trim();
  if (!key) throw new Error("Введите ключ WARP+ для проверки.");
  if (!isWarpLicenseFormat(key)) {
    throw new Error("Неверный формат ключа. Ожидается XXXXXXXX-XXXXXXXX-XXXXXXXX.");
  }

  let userId = "";
  let token = "";
  try {
    const { pub } = generateWireGuardKeys();
    const reg = await cfRequest("POST", "reg", null, iosReg(pub));
    if (reg.status !== 200 || !reg.body?.result?.id) {
      throw new Error(`Cloudflare registration failed (HTTP ${reg.status})`);
    }
    userId = reg.body.result.id;
    token = reg.body.result.token;

    const apply = await cfRequest("PUT", `reg/${userId}/account`, token, { license: key });
    const details = await cfRequest("GET", `reg/${userId}/account`, token, null);
    const applyBody = apply.body || {};
    const detail = details.body?.result || {};
    const accountType =
      detail.account_type ||
      applyBody?.result?.account_type ||
      applyBody?.result?.account?.account_type ||
      applyBody?.result?.type ||
      (applyBody?.result?.warp_plus ? "warp_plus" : "free");
    const errorMessage = applyBody?.errors?.[0]?.message || applyBody?.error || null;
    const valid =
      !errorMessage && (accountType === "warp_plus" || accountType === "unlimited" || applyBody?.success === true);

    return {
      valid,
      accountType,
      referralCount: typeof detail.referral_count === "number" ? detail.referral_count : null,
      effectiveLicense: detail.license || null,
      checkedLicense: key,
      message: errorMessage || (valid ? "Ключ принят Cloudflare." : "Ключ не дал WARP+ статус."),
    };
  } finally {
    if (userId && token) {
      try {
        await cfRequest("DELETE", `reg/${userId}`, token, null);
      } catch {
        /* ignore cleanup error */
      }
    }
  }
}

export interface TestLicenseResult {
  accountType: string;
  license: string;
  id: string | null;
}

export async function generateTestLicense(): Promise<TestLicenseResult> {
  const { pub } = generateWireGuardKeys();
  const reg = await cfRequest("POST", "reg", null, iosReg(pub));
  if (reg.status !== 200 || !reg.body?.result?.id) {
    throw new Error(`Cloudflare registration failed (HTTP ${reg.status})`);
  }
  const result = reg.body.result;
  const account = result.account || {};
  const license = account.license || null;
  if (!license) throw new Error("Cloudflare не вернул license key для нового аккаунта.");
  return { accountType: account.account_type || "free", license, id: result.id || null };
}

export interface WarpKeyResult {
  key: string;
  valid: boolean;
  accountType?: string;
  error: string | null;
}

// Used by the bruteforce checker: register+apply through a rotating proxy, then
// clean up. Uses the mobile API version/UA the original bruteforcer relied on.
export async function checkWarpKey(licenseKey: string, proxyUrl?: string): Promise<WarpKeyResult> {
  let userId = "";
  let token = "";
  const opts: CfRequestOptions = {
    apiVersion: "v0a1922",
    userAgent: "okhttp/3.14.9",
    proxy: proxyUrl,
    connectTimeout: 5000,
  };
  try {
    const { pub } = generateWireGuardKeys();
    const reg = await cfRequest(
      "POST",
      "reg",
      null,
      {
        install_id: "",
        tos: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
        key: pub,
        fcm_token: "",
        type: "Android",
        locale: "en_US",
        referrer: "",
      },
      opts,
    );
    if (reg.status !== 200 || !reg.body?.result?.id) {
      return { key: licenseKey, valid: false, error: `reg_fail:${reg.status}` };
    }
    userId = reg.body.result.id;
    token = reg.body.result.token;

    const apply = await cfRequest("PUT", `reg/${userId}/account`, token, { license: licenseKey }, opts);
    const body = apply.body || {};
    const accountType =
      body?.result?.account_type ||
      body?.result?.account?.account_type ||
      body?.result?.type ||
      (body?.result?.warp_plus ? "warp_plus" : null);
    const errorMessage = body?.errors?.[0]?.message || body?.error || null;
    const valid =
      !errorMessage && (accountType === "warp_plus" || accountType === "unlimited" || body?.success === true);

    return { key: licenseKey, valid, accountType: accountType || "free", error: errorMessage || null };
  } catch (err) {
    return { key: licenseKey, valid: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    if (userId && token) {
      cfRequest("DELETE", `reg/${userId}`, token, null, opts).catch(() => {});
    }
  }
}
