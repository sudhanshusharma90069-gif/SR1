(function () {
  const KEY = "sr1_theme";
  const root = document.documentElement;
  const prefersDark = () => window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  const current = () => localStorage.getItem(KEY) || (prefersDark() ? "dark" : "light");
  const apply = (t) => { root.classList.toggle("dark", t === "dark"); root.dataset.theme = t; };
  apply(current());
  window.SR1Theme = {
    get: current,
    set(t) { localStorage.setItem(KEY, t); apply(t); document.dispatchEvent(new CustomEvent("sr1:theme", { detail: t })); },
    toggle() { this.set(current() === "dark" ? "light" : "dark"); },
  };
})();
