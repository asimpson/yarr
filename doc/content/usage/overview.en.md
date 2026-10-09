---
title: Overview
weight: 1
---

{{< img src="promo.png" alt="yarr overview" >}}

## JavaScript app

The main screen has three sections.

1. **Feed list** - Use this section to select a feed or a folder.
2. **Article list** - This section shows the articles from your selection.
3. **Article content** - This section shows the content of the article you select.

Each section has a top bar with actions for that section.

The top bar of the **feed list** contains:

- filters - filter the list by unread, starred, or all articles
- global settings menu - add or refresh feeds, change theme, set auto-refresh rate, choose sorting, import/export subscriptions, view shortcuts, and switch language

The top bar of the **article list** contains:

- search field - search within the current selection
- mark all read - mark all articles in the current selection as read; visible only if the unread filter is set
- settings menu for the selected feed or folder - open the website, rename, move, or delete

The top bar of the **article content** contains actions for the selected article:

- star toggle - mark the article as starred
- read toggle - mark the article as read or unread
- article appearance settings - choose the font and adjust the text size
- read here - fetch and display the full article content
- open in browser - open the article link in a new tab
- left chevron - navigate to the previous article in the list
- right chevron - navigate to the next article in the list
- close - close and unselect the current article

## HTML reader (no JavaScript)

For a lightweight, mobile-friendly alternative, open `/reader/` on your yarr server
(or `<base-path>/reader/` if you configured `-base`). The original app remains at
`/`; both views share the same feeds and article statuses.

The HTML reader uses ordinary links and forms instead of client-side JavaScript.
Browse all, unread, or starred articles; select a feed or folder; search, sort,
and page through results. Open an article to read its sanitized content, then
use the buttons to mark it read/unread or star/unstar it. **Opening an article
does not mark it read automatically.** Images are lazy-loaded, and audio/video
are not preloaded. You can add feeds and folders, refresh feeds, and import or
export OPML from the Subscriptions page. For editing or deleting subscriptions
and changing app settings, use the JavaScript app.
