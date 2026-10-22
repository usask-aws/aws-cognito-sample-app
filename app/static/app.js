const input = document.getElementById("input");
const counter = document.getElementById("counter");
const output = document.getElementById("output");
const go = document.getElementById("go");
const emailMe = document.getElementById("email-me");
const MAX = window.MAX_CHARS;

function refreshCounter() {
  const n = input.value.length;
  counter.textContent = `${n}/${MAX} characters`;
  go.disabled = n === 0 || n > MAX;
}
input.addEventListener("input", refreshCounter);
refreshCounter();

go.addEventListener("click", async () => {
  output.textContent = "";
  go.disabled = true;
  const body = JSON.stringify({
    text: input.value,
    email: emailMe.checked,
  });
  // Untick so the next run doesn't email by accident.
  emailMe.checked = false;
  try {
    const resp = await fetch("/transform", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
    if (resp.status === 401) {
      // Signed out. fetch gets the 401 instead of a redirect, so go to sign-in.
      window.location.href = "/";
      return;
    }
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: "Request failed." }));
      output.textContent = err.error || "Request failed.";
      return;
    }
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const events = buffer.split("\n\n");
      buffer = events.pop();
      for (const evt of events) {
        if (evt.startsWith("event: error")) {
          output.textContent = "Something went wrong. Please try again.";
        } else if (evt.startsWith("event: done")) {
          // stream complete
        } else if (evt.startsWith("data: ")) {
          output.textContent += JSON.parse(evt.slice("data: ".length));
        }
      }
    }
  } catch (e) {
    output.textContent = "Network error. Please try again.";
  } finally {
    refreshCounter();
  }
});
