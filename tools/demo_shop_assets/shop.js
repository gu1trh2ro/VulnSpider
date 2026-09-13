(() => {
  'use strict';
  const products = {
    '101': ['sneakers', 'NORTHPEAK', '데일리 스웨이드 스니커즈', 89000, '부드러운 스웨이드와 편안한 쿠션. 어떤 옷에도 자연스럽게 어울리는 데일리 슈즈.'],
    '102': ['tote', 'FORM & FIELD', '에센셜 캔버스 토트', 59000, '탄탄한 캔버스와 부드러운 가죽 손잡이. 출근부터 주말 산책까지 가볍게 함께하세요.'],
    '103': ['headphones', 'STILL SOUND', '무선 오버이어 헤드폰', 149000, '오롯이 나만의 리듬에 집중하는 시간. 포근한 이어 쿠션과 차분한 그래파이트 컬러.'],
    '104': ['lamp', 'ROOM EDIT', '머쉬룸 테이블 램프', 69000, '둥근 실루엣과 따뜻한 테라코타 컬러. 좋아하는 공간에 은은한 빛을 더해보세요.']
  };
  let selected = '101';
  let quantity = 1;
  const put = (selector, value) => document.querySelectorAll(selector).forEach(el => { el.textContent = value; });
  const update = () => {
    const p = products[selected];
    document.querySelectorAll('[data-product-image]').forEach(el => { el.src = '/assets/' + p[0] + '.png'; el.alt = p[2]; });
    put('[data-product-brand]', p[1]); put('[data-product-name]', p[2]); put('[data-product-description]', p[4]);
    put('[data-product-price]', p[3].toLocaleString('ko-KR'));
    put('[data-total], [data-subtotal]', (p[3] * quantity).toLocaleString('ko-KR'));
    document.querySelectorAll('[data-quantity]').forEach(el => { el.value = String(quantity); });
    document.querySelectorAll('[data-cart]').forEach(el => { el.href = '/cart#item-' + selected + '-' + quantity; });
    document.querySelectorAll('[data-checkout]').forEach(el => { el.href = '/checkout#item-' + selected + '-' + quantity; });
    if (location.pathname === '/product' && location.hash.startsWith('#item-')) {
      const id = document.querySelector('form input[name="id"]');
      const qty = document.querySelector('form input[name="qty"]');
      if (id) id.value = selected;
      if (qty) qty.value = String(quantity);
    }
  };
  const route = () => {
    const query = new URLSearchParams(location.search);
    selected = Object.hasOwn(products, query.get('id')) ? query.get('id') : '101';
    quantity = /^[1-5]$/.test(query.get('qty') || '') ? Number(query.get('qty')) : 1;
    const item = /^#item-(101|102|103|104)(?:-([1-5]))?$/.exec(location.hash);
    if (item) { selected = item[1]; quantity = Number(item[2] || 1); }
    update();
    const category = /^#category-(all|shoes|bags|tech|home)$/.exec(location.hash);
    const field = document.querySelector('form select[name="category"]');
    const queryCategory = query.get('category');
    const acceptedCategory = /^(shoes|bags|tech|home)$/.test(queryCategory || '') ? queryCategory : null;
    const filter = category ? category[1] : (acceptedCategory || (field ? field.value : 'all'));
    if (field) {
      // An explicit all-category browse has no category condition. This is
      // client-only: the bare crawl form retains its original seed/options.
      const supportsAll = Array.from(field.options).some(option => option.value === 'all');
      const omitCategory = category !== null && filter === 'all' && !supportsAll;
      field.disabled = omitCategory;
      field.closest('.input-point-field').hidden = omitCategory;
      if (!omitCategory) field.value = filter;
      field.form.action = location.pathname + (omitCategory ? '#category-all' : '');
    }
    document.querySelectorAll('[data-category]').forEach(el => { el.hidden = filter !== 'all' && el.dataset.category !== filter; });
    document.querySelectorAll('[data-filter]').forEach(el => { el.setAttribute('aria-current', String(el.dataset.filter === filter)); });
  };
  document.querySelectorAll('[data-quantity]').forEach(el => el.addEventListener('change', () => {
    quantity = Math.min(5, Math.max(1, Number(el.value) || 1));
    history.replaceState(null, '', '#item-' + selected + '-' + quantity); update();
    const success = document.querySelector('[data-order-success]');
    if (success) success.hidden = true;
    document.querySelectorAll('[data-place-order]').forEach(button => {
      button.disabled = false; button.textContent = '주문 시연 완료하기';
    });
  }));
  document.querySelectorAll('[data-place-order]').forEach(el => el.addEventListener('click', () => {
    const result = document.querySelector('[data-order-success]');
    result.hidden = false; result.tabIndex = -1; result.focus();
    result.scrollIntoView({ block: 'center' }); el.disabled = true; el.textContent = '시연 완료';
  }));
  const revealInputs = () => {
    if (location.hash !== '#input-points') return;
    const section = document.getElementById('input-points');
    if (!section) return;
    section.open = true;
    const marker = section.querySelector('.input-point-field:not([hidden]) .input-marker');
    if (marker) marker.focus();
  };
  document.querySelectorAll('.surface-jump').forEach(link => link.addEventListener('click', event => {
    event.preventDefault();
    const section = document.getElementById('input-points');
    if (section) section.open = true;
    // Also handles clicking again when the fragment is already selected.
    const marker = section && section.querySelector('.input-point-field:not([hidden]) .input-marker');
    if (marker) marker.focus();
    if (section) section.scrollIntoView({ block: 'start' });
  }));
  window.addEventListener('hashchange', revealInputs);
  window.addEventListener('hashchange', route);
  route();
  revealInputs();
})();
