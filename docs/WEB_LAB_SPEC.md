# Front-end lab module spec (LinkedIn-style profiles)

Each lab has ONE front-end module: `app/web/labs/aNN.js`, exporting a persona, a
feed post, a profile, and an interactive "bench". The server renders a LinkedIn
feed (one post per lab) and one interactive profile page per lab at `/lab/aNN`.

**Read these first:** `app/web/labs/a01.js` (canonical example), `app/public/bench.js`
(the client renderer — defines the action schema), and your lab's real endpoints
in `app/routes/aNN-*.js` (the bench must map to those exact paths/params).

## module.exports shape

```js
module.exports = {
  persona: {
    name, title, company,
    avatar,        // 2–3 char initials
    color,         // hex, distinct per lab (avatar background)
    banner,        // optional CSS gradient for the cover
    location, connections,
  },
  post: {          // the feed card
    time, reactions, comments, reposts,
    headline,      // bold line in the post's link card
    cta,           // sub-line in the link card
    text,          // multi-line, LinkedIn voice, end with #hashtags
  },
  profile: {
    headline,      // under the name on the profile
    about,         // multi-line "About" text — invite the reader to attack it
    highlights,    // array of short chips (the vuln techniques)
  },
  bench: {
    intro,
    actions: [ /* see schema below */ ],
  },
};
```

## Bench action schema (consumed by app/public/bench.js)

```js
{
  id, title, description, hint?,        // strings
  method: 'GET' | 'POST',
  path: '/invoices/{id}',              // appended to /vuln/aNN or /safe/aNN; {name} = input value
  query: { as: '{who}' },              // optional; values may reference {inputs}
  inputs: [
    { name:'id', label:'Invoice ID', default:'1004' },
    { name:'who', label:'Act as', default:'alice', options:['alice','bob'] },  // options -> <select>
    // { in:'body' } to send in POST body; { in:'query' } to force a GET query param; { size:360 } widens the input
  ],
  body: { url:'{url}' },               // POST JSON/form body (values reference {inputs})
  bodyType: 'json' | 'form',           // default 'json'
  headers: { cookie:'sid={sid}' },     // optional; values reference {inputs}
  sides: ['vuln','safe'],              // which run buttons (default both)
  render: 'json' | 'iframe',           // 'iframe' loads the endpoint URL live so XSS actually executes
  expect: { vuln:'…', safe:'…' },      // one-line expected outcomes
}
```

Rules:
- Every action must map to a REAL endpoint in `app/routes/aNN-*.js`. Verify params.
- Use `render:'iframe'` for reflected/stored XSS view actions so the payload runs.
- Personas are fictional and fun, thematically matched to the vulnerability, but
  never impersonate a real company/person. Keep avatar initials short; pick a
  distinct `color`.
- Do NOT edit shared files (server.js, render.js, bench.js, routes, metrics, db).
  Only your `app/web/labs/aNN.js`.
