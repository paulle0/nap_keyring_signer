// js/main.js — App boot
import { state, setState, subscribe } from "./state.js";
import { getThemePref } from "./storage.js";
import { applyView, wireTopNav } from "./router.js";
import { toggleTheme } from "./ui-utils.js";
import { lockSession } from "./keyring.js";
import { disposeTunnel } from "./relays.js";

function init() {
  const theme = getThemePref();
  document.documentElement.setAttribute("data-theme", theme);
  state.theme = theme;

  if (!state.masterkey) state.view = "login";

  document.getElementById("themeToggle").addEventListener("click", toggleTheme);
  document.getElementById("logoutBtn").addEventListener("click", () => {
    lockSession();
    disposeTunnel();
    setState({
      masterkey: null,
      keyring: [],
      view: "login",
      _newSubkey: false,
      _importKey: false,
    });
  });
  wireTopNav();

  subscribe(() => { applyView(); });
  applyView();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
