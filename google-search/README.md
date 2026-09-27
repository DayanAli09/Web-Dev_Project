# Google Search Clone

A front-end clone of Google Search, Google Image Search, and Google Advanced Search.

## About

This project doesn't use any backend of its own. Instead, plain HTML `<form>` elements submit GET requests directly to Google's real search endpoints, so results come straight from Google.

## Pages

- **index.html** — Regular Google Search, with a centered, rounded search bar and an "I'm Feeling Lucky" button.
- **Images.html** — Google Image Search.
- **advanced.html** — Google Advanced Search, with fields for "all these words," "this exact word or phrase," "any of these words," and "none of these words."

## How it works

Each form's `action` points to `https://www.google.com/search`, and hidden/named `<input>` fields carry the right GET parameters (`q`, `tbm=isch`, `as_epq`, `as_oq`, `as_eq`) so submitting the form lands on the correct Google results page.

## Usage

Just open `index.html` in a browser — no server or build step needed.
