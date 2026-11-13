const $ = (id) => document.getElementById(id);
let stepsData = null;
let lastEncrypted = null;

async function post(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Something went wrong.");
  return data;
}

function params() {
  return { key: $("key").value, nonce: $("nonce").value, counter: $("counter").value };
}

function showError(msg) {
  const box = $("error");
  box.textContent = msg;
  box.classList.toggle("hidden", !msg);
}

// ---------- Generate ----------
$("btn-generate").onclick = async () => {
  showError("");
  try {
    const d = await post("/api/generate", {});
    $("key").value = d.key;
    $("nonce").value = d.nonce;
  } catch (e) { showError(e.message); }
};

// ---------- Encrypt ----------
$("btn-encrypt").onclick = async () => {
  showError("");
  try {
    const d = await post("/api/encrypt", { ...params(), plaintext: $("plaintext").value });
    $("cipher-hex").value = d.ciphertext_hex;
    $("enc-meta").textContent =
      `${d.length} bytes encrypted using ${d.blocks} keystream block(s). Base64: ${d.ciphertext_b64}`;
    $("enc-result").classList.remove("hidden");
    lastEncrypted = d;
    stepsData = d.steps;
    $("verify-result").classList.add("hidden");
    renderSteps();
  } catch (e) { showError(e.message); }
};

// ---------- Verify against library ----------
$("btn-verify").onclick = async () => {
  showError("");
  try {
    const d = await post("/api/verify", { ...params(), plaintext: $("plaintext").value });
    const box = $("verify-result");
    box.className = "meta " + (d.match ? "ok" : "bad");
    box.textContent = d.match
      ? "Match: our implementation produces exactly the same ciphertext as the 'cryptography' library."
      : "Mismatch with the library output!";
  } catch (e) { showError(e.message); }
};

// ---------- Copy / download / send ----------
$("btn-copy").onclick = async () => {
  try {
    await navigator.clipboard.writeText($("cipher-hex").value);
    $("btn-copy").textContent = "Copied!";
  } catch { $("cipher-hex").select(); document.execCommand("copy"); }
  setTimeout(() => ($("btn-copy").textContent = "Copy ciphertext"), 1500);
};

$("btn-download").onclick = () => {
  const p = params();
  const text =
    "ChaCha20 encryption result\n" +
    `Key:        ${p.key}\nNonce:      ${p.nonce}\nCounter:    ${p.counter}\n` +
    `Ciphertext: ${$("cipher-hex").value}\n`;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  a.download = "chacha20_result.txt";
  a.click();
  URL.revokeObjectURL(a.href);
};

$("btn-use").onclick = () => {
  $("ciphertext").value = $("cipher-hex").value;
  $("ciphertext").scrollIntoView({ behavior: "smooth", block: "center" });
};

// ---------- Decrypt ----------
$("btn-decrypt").onclick = async () => {
  showError("");
  try {
    const d = await post("/api/decrypt", { ...params(), ciphertext: $("ciphertext").value });
    $("decrypted").value = d.plaintext;
    $("dec-meta").textContent = d.valid_utf8
      ? "Decryption complete."
      : "Output is not valid text: the key, nonce or counter is probably wrong.";
    $("dec-meta").className = "meta " + (d.valid_utf8 ? "ok" : "bad");
    $("dec-result").classList.remove("hidden");
  } catch (e) { showError(e.message); }
};

// ---------- Step-by-step visualisation ----------
function cellClass(i) {
  if (i < 4) return "c-const";
  if (i < 12) return "c-key";
  if (i === 12) return "c-counter";
  return "c-nonce";
}

function renderMatrix() {
  const v = parseInt($("round-slider").value, 10);
  let words, label, mixed = true;
  if (v === 0) { words = stepsData.initial; label = "Initial state"; mixed = false; }
  else if (v <= 20) {
    words = stepsData.rounds[v - 1];
    label = `After round ${v} of 20 (${v % 2 ? "column" : "diagonal"} round)`;
  } else { words = stepsData.final; label = "Final state (after adding the initial state)"; }

  $("round-label").textContent = label;
  const m = $("matrix");
  m.className = "matrix" + (mixed ? " mixed" : "");
  m.innerHTML = words
    .map((w, i) => `<div class="cell ${mixed ? "" : cellClass(i)}">${w}</div>`)
    .join("");
}

function renderSteps() {
  $("steps-card").classList.remove("hidden");
  $("round-slider").value = 0;
  renderMatrix();
  $("keystream").textContent = stepsData.keystream_hex;
  $("xor-table").querySelector("tbody").innerHTML = stepsData.xor_rows
    .map((r) => `<tr><td>${r.char.replace("<", "&lt;")}</td><td>${r.plain}</td><td>${r.key}</td>
      <td>${r.cipher}</td><td>${r.plain_bin}</td><td>${r.key_bin}</td><td>${r.cipher_bin}</td></tr>`)
    .join("");
}

$("round-slider").oninput = () => stepsData && renderMatrix();

// Fill in random values on first load so the tool is ready to use
$("btn-generate").click();
