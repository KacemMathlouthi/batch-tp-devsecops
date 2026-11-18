// Shared layout for the DevSecOps comptes rendus.
// Compile from the repo root:
//   typst compile --root . --font-path docs/fonts tpN/compte-rendu/main.typ

// ── Tokens (Geist light) ────────────────────
#let ink           = rgb("#171717")
#let ink-2         = rgb("#4d4d4d")
#let ink-3         = rgb("#8f8f8f")
#let white         = rgb("#ffffff")
#let surface-2     = rgb("#fafafa")
#let border        = rgb("#ebebeb")
#let border-strong = rgb("#d4d4d4")
#let success       = rgb("#16a34a")
#let warning       = rgb("#ca8a04")
#let danger        = rgb("#dc2626")

// ── Font family ─────────────────────────────
#let geist = "Geist"
#let geist-mono = "Geist Mono"
#let display = "Geist Serif"

// ── Notes: one neutral surface, colour only for state ──
#let note-block(label, body, dot: none) = block(
  width: 100%, radius: 6pt, breakable: false,
  fill: surface-2,
  stroke: 0.5pt + border,
  inset: (x: 14pt, y: 12pt),
)[
  #text(weight: 600, fill: ink, size: 9.5pt)[
    #if dot != none [#box(circle(radius: 2.5pt, fill: dot), baseline: -1pt) #h(4pt)]
    #label
  ]
  #v(4pt)
  #set text(fill: ink-2, size: 9.5pt)
  #body
]

#let info-box(title, body) = note-block(title, body)
#let success-box(body) = note-block([Résultat], body, dot: success)
#let warn-box(body) = note-block([Attention], body, dot: warning)
#let vuln-box(title, body) = note-block(title, body, dot: danger)

#let cmd(body) = box(
  fill: surface-2, radius: 3pt,
  stroke: 0.5pt + border,
  inset: (x: 2pt, y: 0pt), outset: (y: 2.5pt),
)[#text(font: geist-mono, size: 8.5pt, fill: ink)[#body]]

// ── Severity pill ───────────────────────────
#let sev(level) = {
  let c = if level == "High" or level == "Critical" { danger } else if level == "Medium" { warning } else { ink-3 }
  box(inset: (x: 4pt, y: 0pt), outset: (y: 2pt), radius: 3pt, stroke: 0.5pt + c)[
    #text(size: 7.5pt, weight: 600, fill: c)[#level]
  ]
}

// ── Label / value rows separated by hairlines ──
#let deflist(..rows) = { set par(justify: false); table(
  columns: (auto, 1fr),
  stroke: (x, y) => (top: 0.5pt + border, bottom: 0.5pt + border),
  inset: (left: 0pt, right: 18pt, y: 7pt),
  align: left + top,
  ..rows.pos().chunks(2).map(((k, v)) => (
    text(weight: 500, fill: ink)[#k], text(fill: ink-2)[#v],
  )).flatten(),
) }

// ── Hairline table with a header row ─────────
#let htable(columns: auto, header: (), ..cells) = { set par(justify: false); block(breakable: false, table(
  columns: columns,
  stroke: (x, y) => (top: 0.5pt + border, bottom: 0.5pt + border),
  inset: (x: 6pt, y: 6pt),
  align: left + top,
  table.header(..header.map(h => text(weight: 500, size: 9pt)[#h])),
  ..cells.pos().map(c => text(size: 9pt)[#c]),
)) }

// ── Screenshots ─────────────────────────────
// `dir` is a root-relative folder, e.g. "/tp1/compte-rendu/screenshots/"
#let shots(dir) = {
  let shot(name, caption, width: 100%) = figure(
    box(stroke: 0.5pt + border, radius: 4pt, clip: true,
      image(dir + name, width: width)),
    caption: caption,
  )
  let todo-shot(caption) = figure(
    block(
      width: 100%, height: 110pt, radius: 6pt,
      stroke: (paint: border-strong, thickness: 0.6pt, dash: "dashed"),
    )[#align(center + horizon)[#text(fill: ink-3, size: 9pt)[Capture à ajouter]]],
    caption: caption,
  )
  (shot, todo-shot)
}

// ── Demo divider: a page with only the demo name ──
#let demo-page(n) = page(header: none, footer: none)[
  #align(center + horizon)[
    #text(font: display, size: 64pt, weight: 400, fill: ink)[Démo #n]
  ]
]

// ═══════════════════════════════════════════
//  DOCUMENT
// ═══════════════════════════════════════════
#let conf(
  tp: "TP1",
  short-title: "",
  title: "",
  subtitle: "",
  repo: "github.com/KacemMathlouthi/batch-tp-devsecops",
  image-ref: none,
  body,
) = {
  // Code
  show raw.where(block: true): it => block(
    width: 100%, radius: 6pt, fill: surface-2, inset: 14pt, breakable: false,
    stroke: 0.5pt + border,
  )[
    #set text(fill: ink, font: geist-mono, size: 7.5pt)
    #set par(justify: false)
    #it
  ]
  show raw.where(block: false): it => box(
    fill: surface-2, radius: 3pt,
    stroke: 0.5pt + border,
    inset: (x: 2pt, y: 0pt), outset: (y: 2.5pt),
  )[#text(font: geist-mono, size: 8.5pt, fill: ink)[#it.text]]

  // Headings
  show heading.where(level: 1): it => {
    v(8pt)
    block(width: 100%, below: 18pt)[
      #set text(font: display, size: 26pt, weight: 400, fill: ink)
      #set par(justify: false)
      #it.body
    ]
  }
  show heading.where(level: 2): it => {
    v(14pt)
    block(width: 100%, below: 8pt)[
      #set text(font: display, size: 15pt, weight: 400, fill: ink)
      #it.body
    ]
  }
  show heading.where(level: 3): it => {
    v(8pt)
    block(width: 100%, below: 6pt)[
      #set text(font: geist, size: 10.5pt, weight: 600, fill: ink)
      #it.body
    ]
  }

  // Figures
  show figure: set block(above: 14pt, below: 18pt)
  show figure.caption: it => {
    set text(size: 8.5pt, fill: ink-2, font: geist)
    set par(justify: false)
    set align(left)
    it
  }
  set figure.caption(separator: [. ])

  // Lists, links
  set list(marker: text(fill: ink-3)[–], indent: 2pt, body-indent: 8pt, spacing: 0.75em)
  set enum(numbering: n => text(fill: ink-3, font: geist-mono, size: 8.5pt)[#str(n)], indent: 2pt, body-indent: 8pt)
  show link: it => underline(stroke: 0.5pt + border-strong, offset: 2.5pt, it)

  // Page
  set page(
    paper: "a4",
    fill: white,
    margin: (top: 26mm, bottom: 24mm, left: 24mm, right: 24mm),
    header: context {
      if counter(page).get().first() > 1 [
        #set text(size: 8pt, fill: ink-3, font: geist)
        #grid(
          columns: (1fr, 1fr),
          [#text(fill: ink, weight: 500)[#tp] #h(4pt) #short-title],
          align(right)[DevSecOps, 2026–2027]
        )
      ]
    },
    footer: context {
      if counter(page).get().first() > 1 [
        #set text(size: 8pt, fill: ink-3, font: geist)
        #grid(
          columns: (1fr, 1fr),
          [Mathlouthi, Kraiem, Haouas],
          align(right)[#counter(page).display("1 / 1", both: true)]
        )
      ]
    },
  )

  set text(font: geist, size: 10pt, fill: ink, lang: "fr", number-type: "lining")
  set par(justify: true, leading: 0.75em, spacing: 1.1em)
  set heading(numbering: none)

  // Cover
  page(margin: (top: 26mm, bottom: 26mm, left: 24mm, right: 24mm), header: none, footer: none)[
    #set par(justify: false)
    #grid(
      columns: (1fr, auto),
      align: (left + horizon, right + horizon),
      image("/docs/uni.png", width: 54pt),
      text(size: 9pt, fill: ink-3)[DevSecOps #linebreak() Année universitaire 2026–2027],
    )
    #v(1fr)
    #text(size: 10pt, fill: ink-2)[Travaux pratiques, #tp]
    #v(10pt)
    #block(width: 90%)[
      #text(font: display, size: 40pt, weight: 400, fill: ink)[#title]
    ]
    #v(14pt)
    #block(width: 72%)[
      #text(size: 13pt, fill: ink-2)[#subtitle]
    ]
    #v(1.4fr)
    #grid(
      columns: (1fr, 1fr),
      column-gutter: 24pt,
      [
        #text(size: 9pt, fill: ink-3)[Réalisé par]
        #v(6pt)
        #text(size: 10.5pt, weight: 500)[Kacem Mathlouthi #linebreak() Oussema Kraiem #linebreak() Med Amin Haouas]
      ],
      [
        #text(size: 9pt, fill: ink-3)[Dépôt]
        #v(6pt)
        #text(font: geist-mono, size: 9pt)[#repo]
        #if image-ref != none [
          #v(10pt)
          #text(size: 9pt, fill: ink-3)[Image]
          #v(6pt)
          #text(font: geist-mono, size: 9pt)[#image-ref]
        ]
      ],
    )
  ]

  // Table of contents
  show outline.entry.where(level: 1): it => {
    v(6pt)
    text(weight: 500, it)
  }
  outline(
    title: text(font: display, size: 26pt, weight: 400, fill: ink)[Table des matières],
    indent: 1.2em,
    depth: 2,
  )
  pagebreak()

  body
}
