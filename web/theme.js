'use strict';
/* Theme switch. Loaded in <head>, before the stylesheets, so the page is painted in the right theme the first time.
   The choice lives in localStorage (this browser only; when storage is blocked the page simply starts in Modern).
   Escape hatch if a theme ever makes the page unusable: open /?theme=modern (or /chat?theme=modern). */
(function () {
    const KEY = 'terminet.theme';
    const LIST = ['modern', 'classic', 'cli'];
    const root = document.documentElement;
    const ok = (v) => (LIST.includes(v) ? v : null);
    const read = () => { try { return ok(localStorage.getItem(KEY)); } catch (e) { return null; } };
    const write = (v) => { try { localStorage.setItem(KEY, v); } catch (e) { /* private mode: nothing to remember with */ } };

    function mark() {
        document.querySelectorAll('[data-theme-set]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.themeSet === root.dataset.theme)));
    }
    function set(name, remember) {
        const v = ok(name);
        if (!v) return false;
        root.dataset.theme = v;
        if (remember !== false) write(v);
        mark();
        document.dispatchEvent(new Event('tn:theme'));
        return true;
    }

    const asked = ok((/[?&]theme=([a-z]+)/.exec(location.search) || [])[1]);
    root.dataset.theme = asked || read() || 'modern';
    if (asked) write(asked);

    window.TNTheme = { list: LIST, get: () => root.dataset.theme, set };
    document.addEventListener('click', (e) => {
        const b = e.target.closest && e.target.closest('[data-theme-set]');
        if (b) set(b.dataset.themeSet);
    });
    window.addEventListener('storage', (e) => { if (e.key === KEY && ok(e.newValue)) set(e.newValue, false); });   // another tab chose
    document.addEventListener('DOMContentLoaded', mark);
})();
