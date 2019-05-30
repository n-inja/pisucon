package main

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"path/filepath"
	"flag"
	"crypto/sha512"
	"sync"
	"database/sql"

	_ "net/http/pprof"

	"github.com/bradfitz/gomemcache/memcache"
	gsm "github.com/bradleypeabody/gorilla-sessions-memcache"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
	"github.com/zenazn/goji"
	"github.com/zenazn/goji/web"
	"github.com/zenazn/goji/web/middleware"
)

var (
	db    *sqlx.DB
	store *gsm.MemcacheStore
)

const (
	postsPerPage   = 20
	ISO8601_FORMAT = "2006-01-02T15:04:05-07:00"
	UploadLimit    = 10 * 1024 * 1024 // 10mb

	// CSRF Token error
	StatusUnprocessableEntity = 422
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	CommentCount int
	Comments     []Comment
	User         User
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User
}

func init() {
	memcacheClient := memcache.New("localhost:11211")
	store = gsm.NewMemcacheStore(memcacheClient, "isucogram_", []byte("sendagaya"))
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}
}

func tryLogin(accountName, password string) *User {
	u := User{}
	err := db.Get(&u, "SELECT * FROM users WHERE account_name = ? AND del_flg = 0", accountName)
	if err != nil {
		return nil
	}

	if &u != nil && calculatePasshash(u.AccountName, password) == u.Passhash {
		return &u
	} else if &u == nil {
		return nil
	} else {
		return nil
	}
}

func validateUser(accountName, password string) bool {
	if !(regexp.MustCompile("\\A[0-9a-zA-Z_]{3,}\\z").MatchString(accountName) &&
		regexp.MustCompile("\\A[0-9a-zA-Z_]{6,}\\z").MatchString(password)) {
		return false
	}

	return true
}

// 今回のGo実装では言語側のエスケープの仕組みが使えないのでOSコマンドインジェクション対策できない
// 取り急ぎPHPのescapeshellarg関数を参考に自前で実装
// cf: http://jp2.php.net/manual/ja/function.escapeshellarg.php
func escapeshellarg(arg string) string {
	return "'" + strings.Replace(arg, "'", "'\\''", -1) + "'"
}

func digest(src string) string {
	// opensslのバージョンによっては (stdin)= というのがつくので取る
	out := sha512.Sum512([]byte(src))
//	out, err := exec.Command("/bin/bash", "-c", `printf "%s" `+escapeshellarg(src)+` | openssl dgst -sha512 | sed 's/^.*= //'`).Output()

	return fmt.Sprintf("%x", out)
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")

	return session
}

var sessionMap sync.Map
var s1 sync.Once

func getSessionUser(r *http.Request) User {
	s1.Do(func () {
		sessionMap = sync.Map{}
	})

	c, e := r.Cookie("isuconp-go.session")
	if e != nil {
		return User{}
	}
	var uid interface{}
	if user, ok := sessionMap.Load(c.Value); ok {
		return user.(User)
	} else {
		session := getSession(r)
		uid, ok = session.Values["user_id"]

		if !ok || uid == nil {
			return User{}
		}
	}

	u := User{}

	err := db.Get(&u, "SELECT * FROM `users` WHERE `id` = ?", uid)
	if err != nil {
		return User{}
	}
	sessionMap.Store(c.Value, u)

	return u
}

func deleteSession(r *http.Request) {
	s1.Do(func () {
		sessionMap = sync.Map{}
	})

	c, e := r.Cookie("isuconp-go.session")

	if e != nil {
		return
	}
	sessionMap.Delete(c.Value)
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

func makePosts(results []Post, CSRFToken string, allComments bool) ([]Post, error) {
	var posts []Post

	for _, p := range results {
		err := db.Get(&p.CommentCount, "SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` = ?", p.ID)
		if err != nil {
			return nil, err
		}

		query := "SELECT id, post_id, user_id, comment, created_at, account_name FROM comments WHERE post_id = ? ORDER BY created_at DESC"

		if !allComments {
			query += " LIMIT 3"
		}
		var comments []Comment
		rows, cerr := db.Query(query, p.ID)
		if cerr != nil {
			return nil, cerr
		}
		for rows.Next() {
			c := Comment{}
			e := rows.Scan(&c.ID, &c.PostID, &c.UserID, &c.Comment, &c.CreatedAt, &c.User.AccountName)
			if e != nil {
				return nil, e
			}
			c.User.ID = c.UserID
			comments = append(comments, c)
		}
		rows.Close()

		// reverse
		for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
			comments[i], comments[j] = comments[j], comments[i]
		}

		p.Comments = comments

		perr := db.Get(&p.User, "SELECT * FROM `users` WHERE `id` = ?", p.UserID)
		if perr != nil {
			return nil, perr
		}

		p.CSRFToken = CSRFToken

		if p.User.DelFlg == 0 {
			posts = append(posts, p)
		}
		if len(posts) >= postsPerPage {
			break
		}
	}

	return posts, nil
}

func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := io.ReadFull(crand.Reader, k); err != nil {
		panic("error reading from random source: " + err.Error())
	}
	return hex.EncodeToString(k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	dbInitialize()
	w.WriteHeader(http.StatusOK)
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("login.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		session.Values["user_id"] = u.ID
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ?", accountName)

	if exists == 1 {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, eerr := db.Exec(query, accountName, calculatePasshash(accountName, password))
	if eerr != nil {
		fmt.Println(eerr.Error())
		return
	}

	session := getSession(r)
	uid, lerr := result.LastInsertId()
	if lerr != nil {
		fmt.Println(lerr.Error())
		return
	}
	session.Values["user_id"] = uid
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	deleteSession(r)
	delete(session.Values, "user_id")

	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

var s2 sync.Once
var stmt, stmt2 *sql.Stmt
func getIndex(w http.ResponseWriter, r *http.Request) {
	s2.Do(func () {
		var err error
		stmt, err = db.Prepare("SELECT posts.id, `user_id`, `body`, `mime`, posts.created_at, users.account_name, users.authority FROM `posts` JOIN users ON posts.user_id = users.id WHERE users.del_flg = 0 ORDER BY posts.created_at DESC LIMIT 20")
		if err != nil {
			fmt.Println(err)
			return
		}
		stmt2, err = db.Prepare("SELECT id, post_id, user_id, comment, created_at, account_name FROM comments WHERE post_id IN (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ORDER BY created_at DESC")
		if err != nil {
			fmt.Println(err)
			return
		}
	})

	me := getSessionUser(r)

	results := []Post{}

	rows, err := stmt.Query()
	if err != nil {
		fmt.Println(err)
		return
	}
	count := 0
	args := make([]interface{}, 20)
	for rows.Next() {
		p := Post{}
		e := rows.Scan(&p.ID, &p.UserID, &p.Body, &p.Mime, &p.CreatedAt, &p.User.AccountName, &p.User.Authority)
		if e != nil {
			fmt.Println(e)
			return
		}
		args[count] = p.ID
		count += 1
		p.User.ID = p.UserID
		p.CSRFToken = getCSRFToken(r)

		results = append(results, p)
	}
	rows.Close()

	var rows2 *sql.Rows
	if count < 20 {
		q := ""
		for _, p := range results {
			if q == "" {
				q = strconv.Itoa(p.ID)
			} else {
				q += ", " + strconv.Itoa(p.ID)
			}
		}
		rows2, err = db.Query("SELECT id, post_id, user_id, comment, created_at, account_name FROM comments WHERE post_id IN (" + q + ") ORDER BY created_at DESC")
		if err != nil {
			fmt.Println(err)
			return
		}
	} else {
		rows2, err = stmt2.Query(args...)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	commentMap := make(map[int][]Comment, 20)
	countMap := make(map[int]int, 20)
	for rows2.Next() {
		c := Comment{}
		e := rows2.Scan(&c.ID, &c.PostID, &c.UserID, &c.Comment, &c.CreatedAt, &c.User.AccountName)
		c.User.ID = c.UserID
		if e != nil {
			fmt.Println(e)
			return
		}
		if cs, ok := commentMap[c.PostID]; ok {
			countMap[c.PostID] += 1
			if len(cs) > 2 {
				continue
			}
			commentMap[c.PostID] = append(cs, c)
		} else {
			countMap[c.PostID] = 1
			cs := []Comment{c}
			commentMap[c.PostID] = cs
		}
	}
	rows2.Close()

	for i := range results {
		// reverse
		comments := commentMap[results[i].ID]
		for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
			comments[i], comments[j] = comments[j], comments[i]
		}
		results[i].Comments = comments
		results[i].CommentCount = countMap[results[i].ID]
	}

	writeserve(w, results, me, getCSRFToken(r), getFlash(w, r, "notice"))
}

var s4 sync.Once
var stmt5, stmt6 *sql.Stmt
func getAccountName(c web.C, w http.ResponseWriter, r *http.Request) {
	s4.Do(func () {
		var err error
		stmt5, err = db.Prepare("SELECT posts.id, `user_id`, `body`, `mime`, posts.created_at, users.account_name, users.authority FROM `posts` JOIN users ON posts.user_id = users.id WHERE users.id = ? ORDER BY posts.created_at DESC LIMIT 20")
		if err != nil {
			fmt.Println(err)
			return
		}
		stmt6, err = db.Prepare("SELECT id, post_id, user_id, comment, created_at, account_name FROM comments WHERE post_id IN (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ORDER BY created_at DESC")
		if err != nil {
			fmt.Println(err)
			return
		}
	})
	user := User{}
	commentCount := 0
	postCount := 0

	uerr := db.QueryRow("SELECT users.id, users.account_name, users.del_flg, users.passhash, users.created_at, users.authority, count(*) FROM users LEFT JOIN comments ON users.id = comments.user_id WHERE users.account_name = ? AND users.del_flg = 0 GROUP BY users.id", c.URLParams["accountName"]).Scan(&user.ID, &user.AccountName, &user.DelFlg, &user.Passhash, &user.CreatedAt, &user.Authority, &commentCount)

	if uerr != nil {
		fmt.Println(uerr)
		return
	}

	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}

	rows, err := stmt5.Query(user.ID)
	if err != nil {
		fmt.Println(err)
		return
	}
	count := 0
	args := make([]interface{}, 20)
	for rows.Next() {
		p := Post{}
		e := rows.Scan(&p.ID, &p.UserID, &p.Body, &p.Mime, &p.CreatedAt, &p.User.AccountName, &p.User.Authority)
		if e != nil {
			fmt.Println(e)
			return
		}
		args[count] = p.ID
		count += 1
		p.User.ID = p.UserID
		p.CSRFToken = getCSRFToken(r)

		results = append(results, p)
	}
	rows.Close()

	var rows2 *sql.Rows
	if count < 20 {
		q := ""
		for _, p := range results {
			if q == "" {
				q = strconv.Itoa(p.ID)
			} else {
				q += ", " + strconv.Itoa(p.ID)
			}
		}
		rows2, err = db.Query("SELECT id, post_id, user_id, comment, created_at, account_name FROM comments WHERE post_id IN (" + q + ") ORDER BY created_at DESC")
		if err != nil {
			fmt.Println(err)
			return
		}
	} else {
		rows2, err = stmt6.Query(args...)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	commentMap := make(map[int][]Comment, 20)
	countMap := make(map[int]int, 20)
	for rows2.Next() {
		c := Comment{}
		e := rows2.Scan(&c.ID, &c.PostID, &c.UserID, &c.Comment, &c.CreatedAt, &c.User.AccountName)
		c.User.ID = c.UserID
		if e != nil {
			fmt.Println(e)
			return
		}
		if cs, ok := commentMap[c.PostID]; ok {
			countMap[c.PostID] += 1
			if len(cs) > 2 {
				continue
			}
			commentMap[c.PostID] = append(cs, c)
		} else {
			countMap[c.PostID] = 1
			cs := []Comment{c}
			commentMap[c.PostID] = cs
		}
	}
	rows2.Close()

	for i := range results {
		// reverse
		comments := commentMap[results[i].ID]
		for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
			comments[i], comments[j] = comments[j], comments[i]
		}
		results[i].Comments = comments
		results[i].CommentCount = countMap[results[i].ID]
	}
	
	commentedCount := 0
	perr := db.QueryRow("SELECT count(comments.id), count(DISTINCT posts.id) FROM posts LEFT JOIN comments ON posts.id = comments.post_id WHERE posts.user_id = ?", user.ID).Scan(&commentedCount, &postCount)
	if perr != nil {
		fmt.Println(perr)
		return
	}

	me := getSessionUser(r)

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("user.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	)).Execute(w, struct {
		Posts          []Post
		User           User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             User
	}{results, user, postCount, commentCount, commentedCount, me})
}

var s3 sync.Once
var stmt3, stmt4 *sql.Stmt

func getPosts(w http.ResponseWriter, r *http.Request) {
	s3.Do(func () {
		var err error
		stmt3, err = db.Prepare("SELECT posts.id, `user_id`, `body`, `mime`, posts.created_at, users.account_name, users.authority FROM `posts` JOIN users ON posts.user_id = users.id WHERE posts.created_at <= ? AND users.del_flg = 0 ORDER BY posts.created_at DESC LIMIT 20")
		if err != nil {
			fmt.Println(err)
			return
		}
		stmt4, err = db.Prepare("SELECT id, post_id, user_id, comment, created_at, account_name FROM comments WHERE post_id IN (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ORDER BY created_at DESC")
		if err != nil {
			fmt.Println(err)
			return
		}
	})

	m, parseErr := url.ParseQuery(r.URL.RawQuery)
	if parseErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println(parseErr)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, terr := time.Parse(ISO8601_FORMAT, maxCreatedAt)
	if terr != nil {
		fmt.Println(terr)
		return
	}

	results := []Post{}

	rows, err := stmt3.Query(t.Format(ISO8601_FORMAT))
	if err != nil {
		fmt.Println(err)
		return
	}
	count := 0
	args := make([]interface{}, 20)
	for rows.Next() {
		p := Post{}
		e := rows.Scan(&p.ID, &p.UserID, &p.Body, &p.Mime, &p.CreatedAt, &p.User.AccountName, &p.User.Authority)
		if e != nil {
			fmt.Println(e)
			return
		}
		args[count] = p.ID
		count += 1
		p.User.ID = p.UserID
		p.CSRFToken = getCSRFToken(r)

		results = append(results, p)
	}
	rows.Close()

	var rows2 *sql.Rows
	if count < 20 {
		q := ""
		for _, p := range results {
			if q == "" {
				q = strconv.Itoa(p.ID)
			} else {
				q += ", " + strconv.Itoa(p.ID)
			}
		}
		rows2, err = db.Query("SELECT id, post_id, user_id, comment, created_at, account_name FROM comments WHERE post_id IN (" + q + ") ORDER BY created_at DESC")
		if err != nil {
			fmt.Println(err)
			return
		}
	} else {
		rows2, err = stmt4.Query(args...)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	commentMap := make(map[int][]Comment, 20)
	countMap := make(map[int]int, 20)
	for rows2.Next() {
		c := Comment{}
		e := rows2.Scan(&c.ID, &c.PostID, &c.UserID, &c.Comment, &c.CreatedAt, &c.User.AccountName)
		c.User.ID = c.UserID
		if e != nil {
			fmt.Println(e)
			return
		}
		if cs, ok := commentMap[c.PostID]; ok {
			countMap[c.PostID] += 1
			if len(cs) > 2 {
				continue
			}
			commentMap[c.PostID] = append(cs, c)
		} else {
			countMap[c.PostID] = 1
			cs := []Comment{c}
			commentMap[c.PostID] = cs
		}
	}
	rows2.Close()

	for i := range results {
		// reverse
		comments := commentMap[results[i].ID]
		for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
			comments[i], comments[j] = comments[j], comments[i]
		}
		results[i].Comments = comments
		results[i].CommentCount = countMap[results[i].ID]
	}

	if len(results) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	writeserveposts(w, results, getCSRFToken(r))
}

func getPostsID(c web.C, w http.ResponseWriter, r *http.Request) {
	pid, err := strconv.Atoi(c.URLParams["id"])
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}
	rerr := db.Select(&results, "SELECT * FROM `posts` WHERE `id` = ?", pid)
	if rerr != nil {
		fmt.Println(rerr)
		return
	}

	posts, merr := makePosts(results, getCSRFToken(r), true)
	if merr != nil {
		fmt.Println(merr)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	p := posts[0]

	me := getSessionUser(r)

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("post_id.html"),
		getTemplPath("post.html"),
	)).Execute(w, struct {
		Post Post
		Me   User
	}{p, me})
}

func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(StatusUnprocessableEntity)
		return
	}

	file, header, ferr := r.FormFile("file")
	if ferr != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	filedata, rerr := ioutil.ReadAll(file)
	if rerr != nil {
		fmt.Println(rerr.Error())
	}

	if len(filedata) > UploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	query := "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (?,?,?,?)"
	result, eerr := db.Exec(
		query,
		me.ID,
		mime,
		[]byte(""),
		r.FormValue("body"),
	)
	if eerr != nil {
		fmt.Println(eerr.Error())
		return
	}

	pid, lerr := result.LastInsertId()
	if lerr != nil {
		fmt.Println(lerr.Error())
		return
	}

	ext := ""
	if mime == "image/jpeg" {
		ext = "jpg"
	}
	if mime == "image/png" {
		ext = "png"
	}
	if mime == "image/gif" {
		ext = "gif"
	}
	name := filepath.Join("../public/image", strconv.FormatInt(pid, 10) + "." + ext)
	f, err := os.Create(name)
	if err != nil {
		log.Fatal(err)
	}

	f.Write(filedata)
	f.Close()

	err = exec.Command("gzip", name).Run()

	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
	return
}

func getImage(c web.C, w http.ResponseWriter, r *http.Request) {
	pidStr := c.URLParams["id"]
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	post := Post{}
	derr := db.Get(&post, "SELECT * FROM `posts` WHERE `id` = ?", pid)
	if derr != nil {
		fmt.Println(derr.Error())
		return
	}

	ext := c.URLParams["ext"]

	if ext == "jpg" && post.Mime == "image/jpeg" ||
		ext == "png" && post.Mime == "image/png" ||
		ext == "gif" && post.Mime == "image/gif" {
		w.Header().Set("Content-Type", post.Mime)
		_, err := w.Write(post.Imgdata)
		if err != nil {
			fmt.Println(err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNotFound)
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(StatusUnprocessableEntity)
		return
	}

	postID, ierr := strconv.Atoi(r.FormValue("post_id"))
	if ierr != nil {
		fmt.Println("post_idは整数のみです")
		return
	}

	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`, `account_name`) VALUES (?,?,?,?)"
	db.Exec(query, postID, me.ID, r.FormValue("comment"), me.AccountName)

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []User{}
	err := db.Select(&users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		fmt.Println(err)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("banned.html")),
	).Execute(w, struct {
		Users     []User
		Me        User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(StatusUnprocessableEntity)
		return
	}

	query := "UPDATE `users` SET `del_flg` = 1 WHERE `id` = ?"

	r.ParseForm()
	for _, id := range r.Form["uid[]"] {
		db.Exec(query, id)
	}

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

func main() {
	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}

	db.SetMaxIdleConns(8)
	db.SetMaxOpenConns(8)

	defer db.Close()

	if os.Getenv("POST_EXTRACT") != "" {
		rows, err := db.Query("select id, mime, imgdata from posts")
		if err != nil {
			log.Fatal(err)
		}
		defer rows.Close()
		fmt.Println("a")
		for rows.Next() {
			var ID int
			var mime string
			var data []byte

			err = rows.Scan(&ID, &mime, &data)
			if err != nil {
				log.Fatal(err)
			}

			ext := ""
			if mime == "image/jpeg" {
				ext = "jpg"
			}
			if mime == "image/png" {
				ext = "png"
			}
			if mime == "image/gif" {
				ext = "gif"
			}
			name := filepath.Join("../public/image", strconv.Itoa(ID) + "." + ext)
			file, err := os.Create(name)
			if err != nil {
				log.Fatal(err)
			}

			_, err = file.Write(data)
			if err != nil {
				log.Fatal(err)
			}
			file.Close()

			err = exec.Command("gzip", name).Run()
		}
		return
	}

	if os.Getenv("PPROF") != "" {
		go func() {
			http.ListenAndServe(":6060", nil)
		}()
	} else {
		goji.Abandon(middleware.Logger)
	}

	goji.Get("/initialize", getInitialize)
	goji.Get("/login", getLogin)
	goji.Post("/login", postLogin)
	goji.Get("/register", getRegister)
	goji.Post("/register", postRegister)
	goji.Get("/logout", getLogout)
	goji.Get("/", getIndex)
	goji.Get(regexp.MustCompile(`^/@(?P<accountName>[a-zA-Z]+)$`), getAccountName)
	goji.Get("/posts", getPosts)
	goji.Get("/posts/:id", getPostsID)
	goji.Post("/", postIndex)
	goji.Get("/image/:id.:ext", getImage)
	goji.Post("/comment", postComment)
	goji.Get("/admin/banned", getAdminBanned)
	goji.Post("/admin/banned", postAdminBanned)
	goji.Get("/*", http.FileServer(http.Dir("../public")))
	flag.Set("bind", "./app.sock")
	goji.Serve()
}
