// Small helper for pages (login/signup/topup/withdraw)
export const API = {
  token: localStorage.getItem("token") || null,
  setToken(t) {
    this.token = t;
    if (t) localStorage.setItem("token", t);
    else localStorage.removeItem("token");
  },
  async req(path, opts = {}) {
    const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const res = await fetch(path, { ...opts, headers });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data?.error || "Request failed");
    return data;
  }
};

export function mustBeLoggedIn() {
  if (!API.token) window.location.href = "/login.html";
}