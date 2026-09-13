# DemoShop presentation assets

Four original product mockups were generated on 2026-09-13 using the built-in
ImageGen tool and copied byte-for-byte as PNG files. No third-party image host,
font CDN, runtime dependency or real product endorsement is involved. The
fictional names/prices are presentation data in `demo_shop_storefront.py`.

## Prompt set

All prompts requested a square, editorial ecommerce studio photograph for a
Korean lifestyle demo storefront, with realistic materials, soft directional
light, full product framing, and no text, logos or watermarks.

- `sneakers.png`: Premium unbranded ivory/sand suede everyday sneakers with a
  sculptural gum sole, three-quarter view, one shoe behind the other, warm pale
  seamless sand floor, morning light, realistic stitching, room around product.
- `tote.png`: Premium natural oatmeal canvas tote with dark brown leather handles,
  upright three-quarter view, warm off-white studio, realistic textile texture.
- `headphones.png`: Matte graphite over-ear headphones with a soft padded headband,
  three-quarter view, warm grey seamless studio, tactile material and soft light.
- `lamp.png`: Sculptural terracotta mushroom lamp with a broad rounded dome and
  short cylindrical base, gently lit, cream studio, matte powder-coated finish.

Only the six exact routes in `demo_shop_storefront.ASSETS` are served. Incoming
URL paths are never joined to a filesystem directory. CSS and JS are external
local assets so their size does not inflate each probe's HTML response body.

Product/category selections and quantities use bounded URL fragments and DOM
updates. Orders are a local visual simulation; no payment, persistence, remote
API calls or state-changing requests are implemented. The canonical GET forms,
seeds and vulnerability fragments remain the evaluation surface.

The storefront HTML and recommendation images change response-size baselines.
Historical ranking metrics should not be compared as if the target bytes were
unchanged; rerun evaluation and record the target revision for comparisons.
