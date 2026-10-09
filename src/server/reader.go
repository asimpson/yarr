package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nkanaev/yarr/src/content/htmlutil"
	"github.com/nkanaev/yarr/src/content/sanitizer"
	"github.com/nkanaev/yarr/src/storage/model"
)

// The reader uses its own routes rather than /static/, which already serves
// the assets for the JavaScript application.
const readerPageSize = 20

type readerState struct {
	Filter   string
	FeedID   int64
	FolderID int64
	Search   string
	Oldest   bool
	After    int64
}

func parseReaderState(r *http.Request) (readerState, bool) {
	q := r.URL.Query()
	state := readerState{Filter: q.Get("filter"), Search: strings.TrimSpace(q.Get("q"))}
	if state.Filter == "" {
		state.Filter = "unread"
	}
	if state.Filter != "unread" && state.Filter != "starred" && state.Filter != "all" {
		return state, false
	}
	if utf8.RuneCountInString(state.Search) > 200 {
		return state, false
	}
	var ok bool
	if state.FeedID, ok = readerID(q.Get("feed")); !ok {
		return state, false
	}
	if state.FolderID, ok = readerID(q.Get("folder")); !ok {
		return state, false
	}
	if state.After, ok = readerID(q.Get("after")); !ok {
		return state, false
	}
	if state.FeedID != 0 && state.FolderID != 0 {
		return state, false
	}
	if order := q.Get("order"); order != "" && order != "oldest" {
		return state, false
	}
	state.Oldest = q.Get("order") == "oldest"
	return state, true
}

func readerID(raw string) (int64, bool) {
	if raw == "" {
		return 0, true
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	return id, err == nil && id > 0
}

func (state readerState) values() url.Values {
	q := url.Values{}
	if state.Filter != "unread" {
		q.Set("filter", state.Filter)
	}
	if state.FeedID != 0 {
		q.Set("feed", strconv.FormatInt(state.FeedID, 10))
	}
	if state.FolderID != 0 {
		q.Set("folder", strconv.FormatInt(state.FolderID, 10))
	}
	if state.Search != "" {
		q.Set("q", state.Search)
	}
	if state.Oldest {
		q.Set("order", "oldest")
	}
	if state.After != 0 {
		q.Set("after", strconv.FormatInt(state.After, 10))
	}
	return q
}

func (state readerState) href(path string) string {
	q := state.values().Encode()
	if q != "" {
		return path + "?" + q
	}
	return path
}

func (state readerState) itemFilter() model.ItemFilter {
	filter := model.ItemFilter{}
	if state.FeedID != 0 {
		filter.FeedID = &state.FeedID
	}
	if state.FolderID != 0 {
		filter.FolderID = &state.FolderID
	}
	if state.Filter != "all" {
		status := model.StatusValues[state.Filter]
		filter.Status = &status
	}
	if state.Search != "" {
		filter.Search = &state.Search
	}
	if state.After != 0 {
		filter.After = &state.After
	}
	return filter
}

type readerFeed struct {
	Title  string
	URL    string
	Count  int64
	Active bool
}

type readerFolder struct {
	Title  string
	URL    string
	Count  int64
	Active bool
	Feeds  []readerFeed
}

type readerItem struct {
	Title     string
	FeedTitle string
	URL       string
	StatusURL string
	Date      time.Time
	Unread    bool
	Starred   bool
}

type readerMedia struct {
	URL         string
	Description template.HTML
	Type        string
}

type readerArticle struct {
	Title     string
	FeedTitle string
	FeedURL   string
	Link      string
	Date      time.Time
	Content   template.HTML
	Media     []readerMedia
	StatusURL string
	Unread    bool
	Starred   bool
}

type readerPage struct {
	Root, AppURL, CSSURL, Token string
	Login, RequiresAuth         bool
	Error                       string

	ListURL, UnreadURL, StarredURL, AllURL, AllFeedsURL string
	NewestURL, OldestURL, NextURL, MarkURL, RefreshURL  string
	Filter, Search                                      string
	FeedID, FolderID                                    int64
	Oldest, ShowCounts, CanRefresh                      bool
	UnreadCount                                         int64
	Folders                                             []readerFolder
	Feeds                                               []readerFeed
	Items                                               []readerItem
	Article                                             *readerArticle

	ManageFolders []model.Folder
	Choices       []FeedLink
	Added         bool
	Imported      bool
	FeedFolder    int64
	Manage        bool
}

func (s *Server) readerRoot() string { return s.BasePath + "/reader/" }

// The token is bound to this browser by an HttpOnly, same-site cookie. No
// state-changing reader route accepts a plain link or a cross-site form POST.
func (s *Server) readerToken(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie("reader_csrf"); err == nil && len(cookie.Value) == 64 {
		return cookie.Value
	}
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic(err) // crypto/rand failure makes it unsafe to serve forms
	}
	token := hex.EncodeToString(bytes[:])
	http.SetCookie(w, &http.Cookie{
		Name: "reader_csrf", Value: token, Path: s.readerRoot(),
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
	return token
}

func (s *Server) readerSecure(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
		}
		if s.Auth != nil && !s.Auth.IsAuthenticated(r) {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, s.readerRoot()+"login", http.StatusSeeOther)
			} else {
				http.Error(w, "Login required", http.StatusUnauthorized)
			}
			return
		}
		next(w, r)
	}
}

func (s *Server) readerValidPost(r *http.Request) bool {
	// Reject cross-origin form submissions even when the cookie's SameSite
	// protection is unavailable (for example on older browsers).
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host != r.Host || u.Scheme != "http" && u.Scheme != "https" {
			return false
		}
	}
	cookie, err := r.Cookie("reader_csrf")
	if err != nil || len(cookie.Value) != 64 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(r.FormValue("csrf"))) == 1
}

func (s *Server) newReaderPage(w http.ResponseWriter, r *http.Request) readerPage {
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'none'; style-src 'self'; img-src 'self' http: https: data:; media-src http: https:; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'")
	return readerPage{
		Root: s.readerRoot(), AppURL: s.BasePath + "/",
		CSSURL: s.BasePath + "/static/reader.css",
		Token:  s.readerToken(w, r), RequiresAuth: s.Auth != nil,
	}
}

func (s *Server) renderReader(w http.ResponseWriter, status int, page readerPage) {
	writeHTML(w, status, s.Template.Lookup("reader.html"), page)
}

func (s *Server) handleReaderLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	}
	if s.Auth == nil || s.Auth.IsAuthenticated(r) {
		http.Redirect(w, r, s.readerRoot(), http.StatusSeeOther)
		return
	}
	page := s.newReaderPage(w, r)
	page.Login = true
	if r.Method == http.MethodPost {
		if !s.readerValidPost(r) {
			http.Error(w, "Invalid form token", http.StatusForbidden)
			return
		}
		if s.Auth.Authenticate(w, r.FormValue("username"), r.FormValue("password")) {
			http.Redirect(w, r, s.readerRoot(), http.StatusSeeOther)
			return
		}
		page.Error = "Invalid username or password."
		s.renderReader(w, http.StatusUnauthorized, page)
		return
	}
	s.renderReader(w, http.StatusOK, page)
}

func (s *Server) handleReaderLogout(w http.ResponseWriter, r *http.Request) {
	if s.Auth != nil {
		s.Auth.Logout(w)
	}
	http.Redirect(w, r, s.readerRoot()+"login", http.StatusSeeOther)
}

func (s *Server) handleReaderList(w http.ResponseWriter, r *http.Request) {
	state, ok := parseReaderState(r)
	if !ok {
		http.Error(w, "Invalid reader filters", http.StatusBadRequest)
		return
	}
	store := s.db(r)
	root := s.readerRoot()
	page := s.newReaderPage(w, r)
	page.Filter, page.Search = state.Filter, state.Search
	page.FeedID, page.FolderID, page.Oldest = state.FeedID, state.FolderID, state.Oldest
	page.CanRefresh = s.Scheduler != nil
	page.ShowCounts = state.Filter != "all"
	page.ListURL = state.href(root)

	nav := state
	nav.After = 0
	nav.Filter = "unread"
	page.UnreadURL = nav.href(root)
	nav.Filter = "starred"
	page.StarredURL = nav.href(root)
	nav.Filter = "all"
	page.AllURL = nav.href(root)
	nav.Filter = state.Filter
	page.MarkURL = state.href(root + "mark-read")
	page.RefreshURL = state.href(root + "refresh")
	nav.FeedID, nav.FolderID = 0, 0
	page.AllFeedsURL = nav.href(root)
	nav.FeedID, nav.FolderID = state.FeedID, state.FolderID
	nav.Oldest = false
	page.NewestURL = nav.href(root)
	nav.Oldest = true
	page.OldestURL = nav.href(root)
	nav.Oldest = state.Oldest

	counts := map[int64]int64{}
	for _, stat := range store.FeedStats() {
		if state.Filter == "starred" {
			counts[stat.FeedId] = stat.StarredCount
		} else {
			counts[stat.FeedId] = stat.UnreadCount
		}
		page.UnreadCount += stat.UnreadCount
	}
	folderIndex := map[int64]int{}
	for _, folder := range store.ListFolders() {
		nav.FeedID, nav.FolderID = 0, folder.Id
		folderIndex[folder.Id] = len(page.Folders)
		page.Folders = append(page.Folders, readerFolder{
			Title: folder.Title, URL: nav.href(root), Active: state.FolderID == folder.Id,
		})
	}
	feedTitles := map[int64]string{}
	for _, feed := range store.ListFeeds() {
		feedTitles[feed.Id] = feed.Title
		nav.FeedID, nav.FolderID = feed.Id, 0
		entry := readerFeed{
			Title: feed.Title, URL: nav.href(root), Count: counts[feed.Id], Active: state.FeedID == feed.Id,
		}
		if feed.FolderId != nil {
			if i, found := folderIndex[*feed.FolderId]; found {
				page.Folders[i].Feeds = append(page.Folders[i].Feeds, entry)
				page.Folders[i].Count += entry.Count
				continue
			}
		}
		page.Feeds = append(page.Feeds, entry)
	}

	items := store.ListItems(state.itemFilter(), readerPageSize+1, !state.Oldest, false)
	if len(items) > readerPageSize {
		items = items[:readerPageSize]
		next := state
		next.After = items[len(items)-1].Id
		page.NextURL = next.href(root)
	}
	for _, item := range items {
		title := item.Title
		if title == "" {
			i := s.db(r).GetItem(item.Id)
			text := htmlutil.ExtractText(i.Content)
			title = htmlutil.TruncateText(text, 140)
		}
		path := root + "items/" + strconv.FormatInt(item.Id, 10)
		page.Items = append(page.Items, readerItem{
			Title: title, FeedTitle: feedTitles[item.FeedId], Date: item.Date,
			Unread: item.Status == model.UNREAD, Starred: item.Status == model.STARRED,
			URL: state.href(path), StatusURL: state.href(path + "/status"),
		})
	}
	s.renderReader(w, http.StatusOK, page)
}

func readerHTTPURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.String()
}

func (s *Server) handleReaderItem(w http.ResponseWriter, r *http.Request) {
	id, ok := readerID(r.PathValue("id"))
	if !ok || id == 0 {
		http.NotFound(w, r)
		return
	}
	state, ok := parseReaderState(r)
	if !ok {
		http.Error(w, "Invalid reader filters", http.StatusBadRequest)
		return
	}
	item := s.db(r).GetItem(id)
	if item == nil {
		http.NotFound(w, r)
		return
	}
	page := s.newReaderPage(w, r)
	page.ListURL = state.href(s.readerRoot())
	article := &readerArticle{
		Title: item.Title, Date: item.Date,
		Unread: item.Status == model.UNREAD, Starred: item.Status == model.STARRED,
		StatusURL: state.href(s.readerRoot() + "items/" + strconv.FormatInt(id, 10) + "/status"),
	}
	if feed := s.db(r).GetFeed(item.FeedId); feed != nil {
		article.FeedTitle = feed.Title
		selected := state
		selected.FeedID, selected.FolderID, selected.After = feed.Id, 0, 0
		article.FeedURL = selected.href(s.readerRoot())
		if !htmlutil.IsAPossibleLink(item.Link) {
			item.Link = htmlutil.AbsoluteUrl(item.Link, feed.Link)
		}
	}
	article.Link = readerHTTPURL(item.Link)
	// Only already-sanitized content is ever allowed through html/template.
	article.Content = template.HTML(sanitizer.Sanitize(article.Link, item.Content))
	for _, media := range item.MediaLinks {
		mediaURL := readerHTTPURL(htmlutil.AbsoluteUrl(media.URL, article.Link))
		if mediaURL == "" {
			continue
		}
		switch media.Type {
		case "image", "audio", "video":
			article.Media = append(article.Media, readerMedia{
				URL: mediaURL, Type: media.Type,
				Description: template.HTML(sanitizer.Sanitize(article.Link, media.Description)),
			})
		}
	}
	page.Article = article
	s.renderReader(w, http.StatusOK, page)
}

func (s *Server) handleReaderItemStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := readerID(r.PathValue("id"))
	if !ok || id == 0 {
		http.NotFound(w, r)
		return
	}
	state, ok := parseReaderState(r)
	if !ok {
		http.Error(w, "Invalid reader filters", http.StatusBadRequest)
		return
	}
	status, ok := model.StatusValues[r.FormValue("status")]
	if !ok || s.db(r).GetItem(id) == nil {
		http.Error(w, "Invalid article or status", http.StatusBadRequest)
		return
	}
	if !s.db(r).UpdateItem(id, model.UpdateItemParams{Status: &status}) {
		http.Error(w, "Could not update article", http.StatusInternalServerError)
		return
	}
	location := s.readerRoot() + "items/" + strconv.FormatInt(id, 10)
	if r.FormValue("view") == "list" {
		location = s.readerRoot()
	}
	http.Redirect(w, r, state.href(location), http.StatusSeeOther)
}

func (s *Server) handleReaderMarkRead(w http.ResponseWriter, r *http.Request) {
	state, ok := parseReaderState(r)
	if !ok || state.Filter != "unread" || state.Search != "" {
		http.Error(w, "Mark all is only available without a search", http.StatusBadRequest)
		return
	}
	filter := model.MarkFilter{}
	if state.FeedID != 0 {
		filter.FeedID = &state.FeedID
	}
	if state.FolderID != 0 {
		filter.FolderID = &state.FolderID
	}
	if !s.db(r).MarkItemsRead(filter) {
		http.Error(w, "Could not mark articles read", http.StatusInternalServerError)
		return
	}
	state.After = 0
	http.Redirect(w, r, state.href(s.readerRoot()), http.StatusSeeOther)
}

func (s *Server) handleReaderRefresh(w http.ResponseWriter, r *http.Request) {
	state, ok := parseReaderState(r)
	if !ok {
		http.Error(w, "Invalid reader filters", http.StatusBadRequest)
		return
	}
	if s.Scheduler != nil {
		s.Scheduler.RefreshFeeds()
	}
	http.Redirect(w, r, state.href(s.readerRoot()), http.StatusSeeOther)
}

func (s *Server) readerManagePage(w http.ResponseWriter, r *http.Request, message string) readerPage {
	page := s.newReaderPage(w, r)
	page.Manage = true
	page.ListURL = s.readerRoot()
	page.ManageFolders = s.db(r).ListFolders()
	page.Error = message
	page.Added = r.URL.Query().Get("added") == "1"
	page.Imported = r.URL.Query().Get("imported") == "1"
	return page
}

func (s *Server) handleReaderManage(w http.ResponseWriter, r *http.Request) {
	s.renderReader(w, http.StatusOK, s.readerManagePage(w, r, ""))
}

func (s *Server) handleReaderAddFeed(w http.ResponseWriter, r *http.Request) {
	// Discovering a feed can involve network requests; don't pass arbitrary
	// form data to the ingestor or trust the folder submitted by the browser.
	feedURL := readerHTTPURL(strings.TrimSpace(r.FormValue("url")))
	folderID, ok := readerID(r.FormValue("folder"))
	if !ok || feedURL == "" {
		s.renderReader(w, http.StatusBadRequest, s.readerManagePage(w, r, "Enter a valid feed URL and folder."))
		return
	}
	var folder *int64
	if folderID != 0 {
		valid := false
		for _, f := range s.db(r).ListFolders() {
			valid = valid || f.Id == folderID
		}
		if !valid {
			http.Error(w, "Folder not found", http.StatusBadRequest)
			return
		}
		folder = &folderID
	}
	if s.Ingestor == nil {
		http.Error(w, "Feed discovery unavailable", http.StatusServiceUnavailable)
		return
	}
	result, err := s.Ingestor.AddFeed(r.Context(), s.db(r), FeedLink{URL: feedURL})
	if err != nil {
		s.renderReader(w, http.StatusBadGateway, s.readerManagePage(w, r, "Could not add that feed."))
		return
	}
	if len(result.Choices) > 0 {
		page := s.readerManagePage(w, r, "")
		page.Choices, page.FeedFolder = result.Choices, folderID
		s.renderReader(w, http.StatusOK, page)
		return
	}
	if result.Feed == nil {
		s.renderReader(w, http.StatusBadRequest, s.readerManagePage(w, r, "No feeds found at that URL."))
		return
	}
	if ok, err := s.db(r).UpdateFeed(result.Feed.Id, model.UpdateFeedParams{FolderID: model.SetNullable(folder)}); !ok || err != nil {
		http.Error(w, "Could not save feed folder", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.readerRoot()+"manage?added=1", http.StatusSeeOther)
}

func (s *Server) handleReaderAddFolder(w http.ResponseWriter, r *http.Request) {
	title := strings.TrimSpace(r.FormValue("title"))
	if title == "" || utf8.RuneCountInString(title) > 200 {
		s.renderReader(w, http.StatusBadRequest, s.readerManagePage(w, r, "Enter a folder name (up to 200 characters)."))
		return
	}
	if s.db(r).CreateFolder(title) == nil {
		http.Error(w, "Could not create folder", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.readerRoot()+"manage", http.StatusSeeOther)
}

func (s *Server) handleReaderImport(w http.ResponseWriter, r *http.Request) {
	if s.Ingestor == nil {
		http.Error(w, "OPML import unavailable", http.StatusServiceUnavailable)
		return
	}
	file, _, err := r.FormFile("opml")
	if err != nil {
		http.Error(w, "Select an OPML file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	if err := s.Ingestor.AddOPML(r.Context(), s.db(r), file); err != nil {
		http.Error(w, "Could not import OPML", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, s.readerRoot()+"manage?imported=1", http.StatusSeeOther)
}
