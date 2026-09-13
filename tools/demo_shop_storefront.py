"""Presentation-only storefront. Product selections never mutate server state."""

from html import escape
from pathlib import Path

ASSET_ROOT = Path(__file__).with_name("demo_shop_assets")
ASSETS = {
    f"/assets/{name}": (ASSET_ROOT / name, content_type)
    for name, content_type in (
        ("shop.css", "text/css; charset=utf-8"),
        ("shop.js", "text/javascript; charset=utf-8"),
        ("sneakers.png", "image/png"),
        ("tote.png", "image/png"),
        ("headphones.png", "image/png"),
        ("lamp.png", "image/png"),
    )
}

PRODUCTS = (
    ("101", "sneakers", "NORTHPEAK", "데일리 스웨이드 스니커즈", 89000, "shoes", "BEST"),
    ("102", "tote", "FORM & FIELD", "에센셜 캔버스 토트", 59000, "bags", "NEW"),
    ("103", "headphones", "STILL SOUND", "무선 오버이어 헤드폰", 149000, "tech", "PICK"),
    ("104", "lamp", "ROOM EDIT", "머쉬룸 테이블 램프", 69000, "home", "NEW"),
)


def product_cards() -> str:
    return '<div class="product-grid">' + "".join(
        f'<a class="product-card" href="/product#item-{pid}" data-category="{category}">'
        f'<div class="product-photo"><span class="product-badge">{badge}</span>'
        f'<img src="/assets/{photo}.png" alt="{name}" loading="lazy" width="1024" height="1024"></div>'
        f'<p class="maker">{brand}</p><h3>{name}</h3><p class="price">{price:,}<small>원</small></p>'
        '<p class="shipping">무료배송 · 선물하기 좋은 상품</p></a>'
        for pid, photo, brand, name, price, category, badge in PRODUCTS
    ) + '</div>'


def header() -> str:
    return '''<div class="announcement">좋은 취향의 시작, DemoShop &nbsp; · &nbsp; 전 상품 무료배송</div>
<header class="store-header"><div class="header-inner"><a class="wordmark" href="/">DemoShop<span>EVERYDAY, WELL CHOSEN.</span></a>
<a class="search-link" href="/search"><span>어떤 일상을 찾고 있나요?</span><b aria-hidden="true">⌕</b></a>
<div class="header-actions"><a href="/account/login">마이페이지</a><a href="/orders">주문조회</a><a class="cart-link" href="/cart">장바구니 <span>1</span></a></div></div>
<nav class="store-nav" aria-label="쇼핑 메뉴"><a href="/catalog#category-all">전체 상품</a><a href="/catalog#category-shoes">슈즈</a><a href="/catalog#category-bags">가방</a><a href="/catalog#category-tech">디지털</a><a href="/catalog#category-home">홈 & 리빙</a><a class="nav-edit" href="/promo/event">이번 주의 혜택 ↗</a></nav></header>'''


def footer() -> str:
    return '''<footer class="store-footer"><div><a class="wordmark" href="/">DemoShop</a><p>당신의 매일을 조금 더 좋아지게.<br>쓸수록 좋아지는 물건을 소개합니다.</p></div>
<div><strong>고객센터</strong><a href="/support/ticket">1:1 문의</a><a href="/orders">주문 및 배송 조회</a><a href="/support/faq">교환 · 반품</a></div>
<div><strong>쇼핑 안내</strong><a href="/catalog#category-all">전체 상품 보기</a><a href="/product/reviews">상품 리뷰</a><a href="/account/profile">내 정보</a></div>
<p class="demo-disclosure">VulnSpider 시연용 가상 쇼핑몰입니다. 상품 사진은 AI 생성 이미지이며, 실제 결제·주문·배송은 이루어지지 않습니다.</p></footer>'''


def home(directory: str) -> str:
    return '''<section class="hero"><div class="hero-copy"><p class="eyebrow">THE EVERYDAY EDIT / 2026</p><h1>일상에 오래 남을<br>좋은 취향.</h1><p>가볍게 나서는 아침부터 편안히 쉬는 저녁까지.<br>매일 손이 가는 물건들을 만나보세요.</p><a class="button dark" href="/catalog#category-all">컬렉션 둘러보기 <span>↗</span></a><div class="hero-note"><span>01 — 04</span><i></i><span>CURATED FOR YOU</span></div></div>
<a class="hero-visual" href="/product#item-101"><img src="/assets/sneakers.png" alt="따뜻한 샌드 컬러의 데일리 스웨이드 스니커즈" width="1024" height="1024"><span class="hero-sticker">LESS, BUT<br>BETTER.</span><span class="hero-caption">NORTHPEAK · DAILY SUEDE SNEAKERS <b>↗</b></span></a></section>
<div class="benefit-strip"><span><b>01</b> 오래 쓰는 디자인</span><span><b>02</b> 전 상품 무료배송</span><span><b>03</b> 매일 새로운 발견</span></div>
<section class="shop-section"><div class="section-heading"><div><p class="eyebrow">OUR FAVORITES</p><h2>지금, 가장 눈여겨볼 것들</h2></div><a href="/catalog#category-all">전체 상품 보기 ↗</a></div>''' + product_cards() + '''</section>
<section class="editorial"><img src="/assets/lamp.png" alt="따뜻한 빛의 테라코타 테이블 램프" loading="lazy" width="1024" height="1024"><div><p class="eyebrow">A LITTLE CHANGE, A BETTER DAY</p><h2>작은 조명 하나로<br>달라지는 저녁의 분위기.</h2><p>오늘의 공간에 포근한 색과 빛을 더해보세요.</p><a class="text-link" href="/product#item-104">룸 에디트 만나보기 ↗</a></div></section>
<details class="service-directory"><summary>쇼핑 서비스 전체보기 <span>+</span></summary><div class="sections">''' + directory + '</div></details>'


def route_intro(path: str, title: str) -> str:
    breadcrumb = f'<div class="breadcrumb"><a href="/">홈</a> / <span>{escape(title)}</span></div>'
    if path in ("/catalog", "/search"):
        return breadcrumb + '''<div class="collection-title"><p class="eyebrow">THE COLLECTION</p><h1>일상을 위한 좋은 선택</h1><p>취향에 맞는 물건을 천천히 골라보세요.</p></div>
<nav class="category-tabs" aria-label="상품 카테고리"><a href="#category-all" data-filter="all">전체</a><a href="#category-shoes" data-filter="shoes">슈즈</a><a href="#category-bags" data-filter="bags">가방</a><a href="#category-tech" data-filter="tech">디지털</a><a href="#category-home" data-filter="home">홈 & 리빙</a></nav>''' + product_cards()
    if path == "/product":
        return breadcrumb + '''<section class="product-detail"><div class="detail-photo"><img data-product-image src="/assets/sneakers.png" alt="데일리 스웨이드 스니커즈" width="1024" height="1024"></div><div class="product-info"><p class="eyebrow" data-product-brand>NORTHPEAK</p><h1 data-product-name>데일리 스웨이드 스니커즈</h1><p class="product-description" data-product-description>부드러운 스웨이드와 편안한 쿠션. 어떤 옷에도 자연스럽게 어울리는 데일리 슈즈.</p><p class="detail-price"><span data-product-price>89,000</span><small>원</small></p><div class="delivery-info"><p><span>배송</span>무료배송 · 일반 배송</p><p><span>안내</span>사진과 상품 정보는 시연용입니다.</p></div><label class="quantity-label">수량 <select data-quantity aria-label="상품 수량"><option>1</option><option>2</option><option>3</option><option>4</option><option>5</option></select></label><div class="purchase-total"><span>총 상품 금액</span><strong><span data-total>89,000</span>원</strong></div><div class="purchase-actions"><a class="button outline" data-cart href="/cart#item-101-1">장바구니 담기</a><a class="button dark" data-checkout href="/checkout#item-101-1">바로 구매</a></div><p class="microcopy">결제 없이 구매 과정을 체험할 수 있습니다.</p></div></section>'''
    if path in ("/cart", "/checkout"):
        checkout = path == "/checkout"
        action = '<button class="button dark" type="button" data-place-order>주문 시연 완료하기</button>' if checkout else '<a class="button dark" data-checkout href="/checkout#item-101-1">주문하기 ↗</a>'
        return breadcrumb + f'<div class="collection-title"><p class="eyebrow">YOUR SELECTION</p><h1>{"주문 / 결제" if checkout else "장바구니"}</h1><p>장바구니 <span aria-hidden="true">→</span> 주문 확인 <span aria-hidden="true">→</span> 시연 완료</p></div>' + '''<div class="cart-layout"><section class="cart-product"><img data-product-image src="/assets/sneakers.png" alt="데일리 스웨이드 스니커즈" width="1024" height="1024"><div><p class="eyebrow" data-product-brand>NORTHPEAK</p><h2 data-product-name>데일리 스웨이드 스니커즈</h2><p><span data-product-price>89,000</span>원 · 무료배송</p><label class="quantity-label">수량 <select data-quantity aria-label="상품 수량"><option>1</option><option>2</option><option>3</option><option>4</option><option>5</option></select></label><a class="text-link" href="/catalog#category-all">계속 쇼핑하기 ↗</a></div></section><aside class="order-summary"><h2>주문 예상 금액</h2><p><span>상품 금액</span><span><span data-subtotal>89,000</span>원</span></p><p><span>배송비</span><span>무료</span></p><div class="purchase-total"><span>총 결제 금액</span><strong><span data-total>89,000</span>원</strong></div>''' + action + '''<p class="microcopy">시연용 · 실제 결제가 발생하지 않습니다.</p></aside></div><div class="order-success" data-order-success role="status" hidden><h2>주문 과정을 모두 체험했어요.</h2><p>실제 주문이나 결제는 발생하지 않았습니다. 다른 상품도 둘러보세요.</p><a class="button dark" href="/catalog#category-all">쇼핑 계속하기 ↗</a></div>'''
    return breadcrumb + f'<div class="collection-title"><p class="eyebrow">DEMOSHOP SERVICES</p><h1>{escape(title)}</h1></div>'
