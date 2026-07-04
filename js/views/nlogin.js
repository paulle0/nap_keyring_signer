// js/views/nlogin.js — Export nlogin view (simplified, export only)
import { renderExport } from "./export.js";

export async function renderNlogin() {
  const content = document.getElementById("nloginContent");
  content.innerHTML = `<div class="card" id="exportCard" style="max-width:580px;"></div>`;
  renderExport();
}

export async function leaveNlogin() {
  // no-op — scanner cleanup removed with import tab
}
