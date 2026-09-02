# The slide deck

The talk deck lives here as **[`OWASP_Top_10_2025.pptx`](OWASP_Top_10_2025.pptx)**
— 23 slides, paced for 60 minutes (deep-dive A01/A05/A02/A03, survey the rest).
It's the visual companion to this repo; the facilitator notes are in
[`FACILITATOR.md`](FACILITATOR.md).

## Open it in Google Slides (about 20 seconds)

Google Slides imports PowerPoint natively, so there's no conversion step to
babysit — pick either route:

1. **Drag-and-drop** — open [drive.google.com](https://drive.google.com) and
   drag `OWASP_Top_10_2025.pptx` into the window. Double-click the uploaded
   file → **Open with → Google Slides**. Drive converts it to a native Slides
   deck you can edit and share.

2. **Import into an existing deck** — in Google Slides,
   **File → Import slides → Upload**, choose the `.pptx`, and **Select all**.

Once it's a Google Slides file, use **Share** to give your team access, or
**File → Make a copy** so everyone can have their own.

## Open it locally

Double-click to open in **PowerPoint** or **Keynote** (Keynote imports `.pptx`
directly). The deck is 16:9 and self-contained — no linked assets.

## Rebuild it from source

The deck is generated from [`../scripts/build_deck.py`](../scripts/build_deck.py):

```bash
python3 -m venv .venv && ./.venv/bin/pip install python-pptx
./.venv/bin/python scripts/build_deck.py
```

Edit the content lists in that script (each category is one `cat_break` /
`cat_fix` / `cat_survey` call) and re-run to regenerate the `.pptx`.
