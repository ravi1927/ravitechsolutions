const form = document.getElementById('contact-form');
const statusEl = document.getElementById('form-status');
const nav = document.querySelector('.nav');
const menu = document.getElementById('menu');
const links = document.getElementById('nav-links');

window.addEventListener('scroll', () => nav.classList.toggle('scrolled', window.scrollY > 8));
menu?.addEventListener('click', () => links.classList.toggle('open'));
links?.querySelectorAll('a').forEach((a) => a.addEventListener('click', () => links.classList.remove('open')));

let csrf = '';
async function boot() {
  try {
    const res = await fetch('api/contact.php?boot=1', { credentials: 'same-origin' });
    const data = await res.json();
    csrf = data.token || '';
  } catch {
    csrf = '';
  }
}
boot();

form?.addEventListener('submit', async (e) => {
  e.preventDefault();
  statusEl.classList.remove('err');
  statusEl.textContent = 'Sending…';
  const payload = {
    token: csrf,
    name: form.name.value.trim(),
    email: form.email.value.trim(),
    org: form.org.value.trim(),
    message: form.message.value.trim(),
    company_url: form.company_url.value.trim(),
  };
  try {
    const res = await fetch('api/contact.php', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf,
      },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      statusEl.classList.add('err');
      statusEl.textContent = data.error || 'Could not send. Try again.';
      if (res.status === 403) await boot();
      return;
    }
    form.reset();
    statusEl.textContent = 'Message sent. The team will reply to your email.';
    await boot();
  } catch {
    statusEl.classList.add('err');
    statusEl.textContent = 'Could not reach the server. Try again in a moment.';
  }
});

const traffic = document.getElementById('traffic');
fetch('api/visit.php', { credentials: 'same-origin' })
  .then((r) => r.json())
  .then((d) => {
    if (!traffic || !d.ok) return;
    traffic.textContent = `Visitors today ${d.today} · All time ${d.total}`;
  })
  .catch(() => {});
