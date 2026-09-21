/**
 * Embedded JavaScript for Interactive HTML Security Report
 * Pure native JS, zero dependencies, accessible and XSS-safe.
 */

export const HTML_REPORT_SCRIPTS = `
document.addEventListener('DOMContentLoaded', () => {
  const searchInput = document.getElementById('finding-search-input');
  const filterPills = document.querySelectorAll('.filter-pill');
  const findingCards = document.querySelectorAll('.finding-card');
  const navItems = document.querySelectorAll('.finding-nav-item');
  let currentFilter = 'ALL';
  let currentSearch = '';

  function applyFilters() {
    const query = currentSearch.toLowerCase().trim();
    let visibleCount = 0;

    findingCards.forEach(card => {
      const severity = (card.getAttribute('data-severity') || '').toUpperCase();
      const status = (card.getAttribute('data-status') || '').toLowerCase();
      const textContent = (card.getAttribute('data-search') || '').toLowerCase();

      let matchesFilter = true;
      if (currentFilter === 'CRITICAL') matchesFilter = severity === 'CRITICAL';
      else if (currentFilter === 'HIGH') matchesFilter = severity === 'HIGH';
      else if (currentFilter === 'MEDIUM') matchesFilter = severity === 'MEDIUM';
      else if (currentFilter === 'LOW') matchesFilter = severity === 'LOW';
      else if (currentFilter === 'INFO') matchesFilter = severity === 'INFO';
      else if (currentFilter === 'CONFIRMED') matchesFilter = status === 'confirmed';

      let matchesQuery = true;
      if (query) {
        matchesQuery = textContent.includes(query);
      }

      const isVisible = matchesFilter && matchesQuery;
      card.style.display = isVisible ? 'block' : 'none';

      const findingId = card.getAttribute('id');
      const matchingNavItem = document.querySelector(\`.finding-nav-item[href="#\${findingId}"]\`);
      if (matchingNavItem) {
        matchingNavItem.style.display = isVisible ? 'flex' : 'none';
      }

      if (isVisible) visibleCount++;
    });

    const noResultsEl = document.getElementById('no-filter-results');
    if (noResultsEl) {
      noResultsEl.style.display = visibleCount === 0 ? 'block' : 'none';
    }
  }

  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      currentSearch = e.target.value;
      applyFilters();
    });
  }

  filterPills.forEach(pill => {
    pill.addEventListener('click', () => {
      filterPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentFilter = pill.getAttribute('data-severity-filter') || 'ALL';
      applyFilters();
    });
  });

  // Highlight active finding on click or hash change
  function syncActiveNav() {
    const hash = window.location.hash;
    if (!hash) return;
    navItems.forEach(item => {
      if (item.getAttribute('href') === hash) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });
  }

  window.addEventListener('hashchange', syncActiveNav);
  syncActiveNav();

  // Copy buttons
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const textToCopy = btn.getAttribute('data-copy-text') || '';
      if (!textToCopy) return;
      navigator.clipboard.writeText(textToCopy).then(() => {
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => {
          btn.textContent = originalText;
        }, 1800);
      });
    });
  });
});
`
