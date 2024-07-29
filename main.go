package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"
	"unicode"

	_ "github.com/mattn/go-sqlite3"
)

//var templates = template.Must(template.ParseFiles("templates/home.html"))

var db *sql.DB

func initDB() {
	os.Setenv("UMASK", "022")
	tmp_db, err := sql.Open("sqlite3", "./movie-night.db")
	if err != nil {
		panic(err)
	}
	sql_make_tables := "CREATE TABLE IF NOT EXISTS users (user_id INTEGER PRIMARY KEY ASC, first_name TEXT, last_name TEXT, phone TEXT unique, is_admin bool);" +
		"INSERT OR IGNORE INTO users (first_name, last_name, phone, is_admin) VALUES (\"Carter\", \"Schmidt\", \"3605261610\", true);" +
		"CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY, user_id integer, authenticated bool, otp integer, otp_expiration TEXT, FOREIGN KEY (user_id) REFERENCES users(user_id) );" +
		"CREATE TABLE IF NOT EXISTS events (event_id INTEGER PRIMARY KEY ASC, event_time TEXT);" +
		//"INSERT OR IGNORE INTO events (event_id, event_time) VALUES (1, '" + time.Now().AddDate(0, 0, 1).Format(time.RFC3339) + "');" +
		"CREATE TABLE IF NOT EXISTS reservations (event_id INTEGER, user_id INTEGER, PRIMARY KEY (event_id, user_id) FOREIGN KEY (event_id) REFERENCES events(event_id), FOREIGN KEY (user_id) REFERENCES users(user_id));" +
		"CREATE TABLE IF NOT EXISTS suggestions (suggestion_id INTEGER PRIMARY KEY ASC, event_id INTEGER, user_id INTEGER, movie_title TEXT, movie_year TEXT, runtime INTEGER, poster_url TEXT, FOREIGN KEY (event_id) REFERENCES events(event_id), FOREIGN KEY (user_id) REFERENCES users(user_id));" +
		"CREATE TABLE IF NOT EXISTS votes (user_id INTEGER, suggestion_id INTEGER, vote INTEGER, PRIMARY KEY (user_id, suggestion_id) FOREIGN KEY (user_id) REFERENCES users(user_id) FOREIGN KEY (suggestion_id) REFERENCES suggestions(suggestion_id));"

	_, err = tmp_db.Exec(sql_make_tables)
	if err != nil {
		panic(err)
	}
	db = tmp_db
}

func main() {
	prod := flag.Bool("prod", false, "Run in production mode")
	flag.Parse()

	initDB()
	defer db.Close()
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/vote", voteHandler)
	http.HandleFunc("/attendees", attendeesHandler)
	http.HandleFunc("/directions", directionsHandler)
	http.HandleFunc("/otp", otpPageHandler)
	http.HandleFunc("/admin", adminHandler)

	http.HandleFunc("POST /api/register", registrationHandler)
	http.HandleFunc("POST /api/sign-in", signinHandler)
	http.HandleFunc("POST /api/logout", logoutHandler)
	http.HandleFunc("POST /api/rsvp/{type}", rsvpHandler)
	http.HandleFunc("POST /api/otp", otpApiHandler)
	http.HandleFunc("POST /api/admin/add-movie", adminSuggestionHandler)
	http.HandleFunc("POST /api/admin/schedule-event/{time}", adminScheduleHandler)

	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "favicon.ico") })

	http.Handle("/styles/", http.StripPrefix("/styles/", http.FileServer(http.Dir("styles"))))
	http.Handle("/scripts/", http.StripPrefix("/scripts/", http.FileServer(http.Dir("scripts"))))
	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("img"))))

	var err error
	if *prod {
		err = http.ListenAndServeTLS(":4343", "/etc/letsencrypt/live/movies.fyrecean.com/fullchain.pem", "/etc/letsencrypt/live/movies.fyrecean.com/privkey.pem", nil)
	} else {
		err = http.ListenAndServeTLS(":4443", "secrets/carter-server.crt", "secrets/carter-server.key", nil)
	}
	panic(err)
}

func generateToken(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func generateOTP() (int, error) {
	max := new(big.Int)
	max.SetInt64(89999)
	bigRando, err := rand.Int(rand.Reader, max)
	return int(bigRando.Int64()) + 10000, err
}

func signin(w http.ResponseWriter, r *http.Request, phone string) {
	q := db.QueryRow("SELECT user_id FROM users WHERE phone=?", phone)
	var user_id string
	err := q.Scan(&user_id)
	if err != nil || user_id == "" {
		http.Error(w, "{\"field\": \"phone\", \"error\": \"User not found\"}", http.StatusBadRequest)
		fmt.Println("User not found")
		return
	}

	sessionToken, err := generateToken(32)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		fmt.Println("generateToken failed")
		return
	}

	// otp, err := generateOTP()
	// if err != nil {
	// 	http.Error(w, "Internal server error", http.StatusInternalServerError)
	// 	fmt.Println("generateOTP failed")
	// 	return
	// }

	stmt := "INSERT OR REPLACE INTO sessions (session_id, user_id, authenticated, otp, otp_expiration) VALUES (?, ?, ?, ?, ?);"
	// TODO - replace 0 with otp and uncomment
	db.Exec(stmt, sessionToken, user_id, true, 0, time.Now().Add(time.Minute*5).Format(time.RFC3339))
	//fmt.Println("OTP", otp, "for", sessionToken, "-", user_id)
	// Set the session token in a cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "Session",
		Value:    sessionToken,
		Expires:  time.Now().AddDate(0, 6, 0),
		Path:     "/",  // Cookie is accessible throughout the site
		HttpOnly: true, // Helps mitigate risk of client side script accessing the protected cookie
		Secure:   true, // Ensure the cookie is sent over HTTPS
	})
}

func getUserFromSession(r *http.Request) (sessionFound bool, user_id int, first_name string) {
	cookie, err := r.Cookie("Session")
	if err != nil {
		return false, 0, ""
	}
	stmt := "SELECT users.user_id, users.first_name FROM sessions INNER JOIN users ON users.user_id=sessions.user_id " +
		"WHERE session_id = ? AND authenticated=true;"
	q := db.QueryRow(stmt, cookie.Value)
	err = q.Scan(&user_id, &first_name)
	if err != nil {
		return false, 0, ""
	}
	return true, user_id, first_name
}

func parseTimeToEventDate(event_time time.Time) string {
	day := event_time.Day()
	var ordinal string
	if day >= 11 && day <= 13 {
		ordinal = "th"
	}
	switch day % 10 {
	case 1:
		ordinal = "st"
	case 2:
		ordinal = "nd"
	case 3:
		ordinal = "rd"
	default:
		ordinal = "th"
	}
	formattedDate := event_time.Format("Monday, January 2")
	formattedDateWithOrdinal := fmt.Sprintf("%s%s", formattedDate, ordinal)

	return formattedDateWithOrdinal
}

func getNextEvent() (event_id int, event_time time.Time, err error) {
	q := db.QueryRow("SELECT event_id, event_time FROM events WHERE event_time > ? ORDER BY event_time ASC LIMIT 1;", time.Now().Format(time.RFC3339))
	var event_time_str string
	err = q.Scan(&event_id, &event_time_str)
	if err != nil {
		return 0, event_time, err
	}
	event_time, err = time.Parse(time.RFC3339, event_time_str)
	return event_id, event_time, err
}

func userIsRSVPed(event_id int, user_id int) bool {
	q := db.QueryRow("SELECT user_id FROM reservations WHERE user_id=? AND event_id=?", event_id, user_id)
	return q.Scan() != sql.ErrNoRows
}

func phoneNumberValidator(phone string) (string, error) {
	var digits []rune
	for _, char := range phone {
		if unicode.IsDigit(char) {
			digits = append(digits, char)
		}
	}

	if len(digits) != 10 {
		return "", errors.New("phone number must be 10 digits long")
	}

	return string(digits), nil
}

func registrationHandler(w http.ResponseWriter, r *http.Request) {
	first_name := r.FormValue("first_name")
	last_name := r.FormValue("last_name")
	phone := r.FormValue("phone")
	phone, err := phoneNumberValidator(phone)
	if err != nil {
		http.Error(w, "Invalid phone number", http.StatusBadRequest)
	}
	stmt := "INSERT INTO users (first_name, last_name, phone) VALUES (?, ?, ?);"
	_, err = db.Exec(stmt, first_name, last_name, phone)
	if err != nil && err.Error() == "UNIQUE constraint failed: users.phone" {
		http.Error(w, "{\"field\": \"phone\", \"error\": \"Phone number in use. Try signing in\"}", http.StatusBadRequest)
		return
	} else if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		fmt.Println("Inserting user failed:", err)
		return
	}
	signin(w, r, phone)
}

func signinHandler(w http.ResponseWriter, r *http.Request) {
	phone := r.FormValue("phone")
	phone, err := phoneNumberValidator(phone)
	if err != nil {
		http.Error(w, "{\"field\": \"phone\", \"error\": \""+err.Error()+"\"}", http.StatusBadRequest)
	}
	signin(w, r, phone)
}

type tmpl_OTP struct {
	Expired bool
	Phone   string
}

func otpPageHandler(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("templates/boilerplate.tmpl", "templates/otp.tmpl")
	if err != nil {
		panic("Failed to parse otpPage")
	}
	cookie, err := r.Cookie("Session")
	if err != nil {
		http.Error(w, "Not logged in", http.StatusBadRequest)
		return
	}
	stmt := "SELECT authenticated, otp, otp_expiration FROM sessions WHERE session_id=?;"
	q := db.QueryRow(stmt, cookie.Value)
	var authenticated bool
	var otp int
	var otp_expiration_str string
	err = q.Scan(&authenticated, &otp, &otp_expiration_str)
	if err != nil {
		http.Error(w, "Not logged in", http.StatusBadRequest)
		return
	}
	otp_expiration, err := time.Parse(time.RFC3339, otp_expiration_str)
	if authenticated || err != nil {
		fmt.Println(authenticated, err, otp_expiration)
		http.Error(w, "No code available", http.StatusBadRequest)
		return
	}

	p := tmpl_OTP{
		Expired: time.Now().After(otp_expiration),
	}

	t.ExecuteTemplate(w, "otp.tmpl", p)
}

func otpApiHandler(w http.ResponseWriter, r *http.Request) {
	otp, _ := strconv.Atoi(r.FormValue("otp"))
	cookie, err := r.Cookie("Session")
	sessionToken := cookie.Value
	if err != nil {
		http.Error(w, "{\"field\": \"phone\", \"error\": \""+err.Error()+"\"}", http.StatusBadRequest)
		return
	}
	stmt := "SELECT otp, otp_expiration FROM sessions WHERE session_id = ?;"
	q := db.QueryRow(stmt, sessionToken)
	var db_otp int
	var otp_expiration_str string
	err = q.Scan(&db_otp, &otp_expiration_str)
	if err != nil {
		http.Error(w, "{\"field\": \"phone\", \"error\": \""+err.Error()+"\"}", http.StatusBadRequest)
		return
	}
	otp_expiration, err := time.Parse(time.RFC3339, otp_expiration_str)
	if err != nil || time.Now().After(otp_expiration) {
		http.Error(w, "{\"field\": \"otp\", \"error\": \"Session expired. Try signing in again.\"}", http.StatusBadRequest)
		return
	}
	if otp != db_otp {
		http.Error(w, "{\"field\": \"otp\", \"error\": \"Incorrect code.\"}", http.StatusBadRequest)
		return
	}
	stmt = "UPDATE sessions SET authenticated = true WHERE session_id = ?;"
	_, err = db.Exec(stmt, sessionToken)
	if err != nil {
		http.Error(w, "Server failed to do it's job, sorry", http.StatusInternalServerError)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("Session")
	if err != nil {
		return
	}
	stmt := "DELETE FROM sessions WHERE session_id = ?"
	db.Exec(stmt, cookie.Value)

	cookie.Expires = time.Unix(0, 0)
	fmt.Println(cookie)
	http.SetCookie(w, cookie)
}

func rsvpHandler(w http.ResponseWriter, r *http.Request) {
	attending := r.PathValue("type")
	found, user_id, _ := getUserFromSession(r)
	if !found {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}
	event_id, _, err := getNextEvent()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		fmt.Println("rsvp handler - Failed to retrieve next event:", err)
		return
	}
	if attending == "yes" {
		db.Exec("INSERT OR IGNORE INTO reservations (event_id, user_id) VALUES (?, ?)", event_id, user_id)
	} else if attending == "no" {
		db.Exec("DELETE FROM reservations WHERE event_id=? AND user_id=?", event_id, user_id)
	}
}

type tmpl_Home struct {
	IsSignedIn bool
	IsRSVPed   bool
	DoorTime   string
	StartTime  string
	EventDate  string
	Name       string
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	//err := templates.ExecuteTemplate(w, "home.html", Page{Body: "Hello World!"})

	event_id, event_time, err := getNextEvent()
	if err != nil {
		// http.Error(w, err.Error(), http.StatusInternalServerError)
		// fmt.Println("rsvp handler - Failed to retrieve next event:", err)
		t, err := template.ParseFiles("templates/boilerplate.tmpl", "templates/nothing.tmpl")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		t.ExecuteTemplate(w, "nothing.tmpl", nil)
		return
	}

	t, err := template.ParseFiles("templates/boilerplate.tmpl", "templates/home.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	isSignedIn, user_id, first_name := getUserFromSession(r)

	p := tmpl_Home{
		IsSignedIn: isSignedIn,
		IsRSVPed:   userIsRSVPed(user_id, event_id),
		Name:       first_name,
		EventDate:  parseTimeToEventDate(event_time),
		StartTime:  event_time.Format("3:04PM"),
		DoorTime:   event_time.Add(-time.Minute * 30).Format("3:04PM"),
	}
	t.ExecuteTemplate(w, "home.tmpl", p)
}

type tmpl_Directions struct {
	IsSignedIn bool
}

func directionsHandler(w http.ResponseWriter, r *http.Request) {
	//err := templates.ExecuteTemplate(w, "home.html", Page{Body: "Hello World!"})
	isSignedIn, _, _ := getUserFromSession(r)
	t, err := template.ParseFiles("templates/boilerplate.tmpl", "templates/directions.tmpl")
	if !isSignedIn || err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	p := tmpl_Directions{
		IsSignedIn: true,
	}
	t.ExecuteTemplate(w, "directions.tmpl", p)
}

type tmpl_Attendees struct {
	IsSignedIn bool
	Attendees  []string
}

func attendeesHandler(w http.ResponseWriter, r *http.Request) {
	//err := templates.ExecuteTemplate(w, "home.html", Page{Body: "Hello World!"})
	t, err := template.ParseFiles("templates/boilerplate.tmpl", "templates/attendees.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	event_id, _, _ := getNextEvent()

	rows, _ := db.Query("SELECT first_name, last_name FROM users INNER JOIN reservations ON users.user_id=reservations.user_id WHERE reservations.event_id=?;", event_id)
	defer rows.Close()

	var attendees []string
	for rows.Next() {
		var first_name string
		var last_name string
		if err := rows.Scan(&first_name, &last_name); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		attendees = append(attendees, first_name+" "+last_name)
	}

	p := tmpl_Attendees{
		IsSignedIn: true,
		Attendees:  attendees,
	}
	t.ExecuteTemplate(w, "attendees.tmpl", p)
}

type Movie struct {
	PosterURL string
	Title     string
	Year      string
	Runtime   string
	votes     int
}

type tmpl_Vote struct {
	IsSignedIn bool
	ShowTime   string
	Movies     []Movie
}

func voteHandler(w http.ResponseWriter, r *http.Request) {
	//err := templates.ExecuteTemplate(w, "home.html", Page{Body: "Hello World!"})
	t, err := template.ParseFiles("templates/boilerplate.tmpl", "templates/vote.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	event_id, event_time, _ := getNextEvent()

	stmt := "SELECT s.poster_url, s.movie_title, s.movie_year, s.runtime, IFNULL(v.total_votes, 0) AS total_votes " +
		"FROM suggestions s " +
		"LEFT JOIN ( " +
		"	SELECT suggestion_id, SUM(vote) AS total_votes " +
		"	FROM votes " +
		"	GROUP BY suggestion_id " +
		") v ON s.suggestion_id = v.suggestion_id " +
		"WHERE s.event_id = ?;"

	//rows, err := db.Query("SELECT poster_url, movie_title, movie_year, runtime FROM suggestions WHERE event_id=?;", event_id)
	rows, err := db.Query(stmt, event_id)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer rows.Close()

	var movies []Movie
	for rows.Next() {
		var movie Movie
		if err := rows.Scan(&movie.PosterURL, &movie.Title, &movie.Year, &movie.Runtime, &movie.votes); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		movies = append(movies, movie)
	}

	p := tmpl_Vote{
		IsSignedIn: true,
		ShowTime:   event_time.Format("3:04PM"),
		Movies:     movies,
	}
	t.ExecuteTemplate(w, "vote.tmpl", p)
}

type tmpl_Admin struct {
	MovieAPIKey string
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	//err := templates.ExecuteTemplate(w, "home.html", Page{Body: "Hello World!"})
	_, user_id, _ := getUserFromSession(r)
	stmt := "SELECT is_admin FROM users WHERE user_id = ?;"
	q := db.QueryRow(stmt, user_id)
	var is_admin bool
	if err := q.Scan(&is_admin); err != nil || !is_admin {
		http.Error(w, "Not authorized!", http.StatusBadRequest)
		return
	}

	t, err := template.ParseFiles("templates/boilerplate.tmpl", "templates/admin.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	p := tmpl_Admin{
		MovieAPIKey: "5214fb5def4b1a9c2282c6aad7b83ebb",
	}
	t.ExecuteTemplate(w, "admin.tmpl", p)
}

func adminScheduleHandler(w http.ResponseWriter, r *http.Request) {
	_, user_id, _ := getUserFromSession(r)
	stmt := "SELECT is_admin FROM users WHERE user_id = ?;"
	q := db.QueryRow(stmt, user_id)
	var is_admin bool
	if err := q.Scan(&is_admin); err != nil || !is_admin {
		http.Error(w, "Not authorized!", http.StatusBadRequest)
		return
	}
	time_str := r.PathValue("time")
	fmt.Println("Received admin event", time_str)
	_, err := time.Parse(time.RFC3339, time_str)
	if err != nil {
		http.Error(w, "Time didn't parse: "+err.Error(), http.StatusBadRequest)
	}
	_, err = db.Exec("INSERT INTO events (event_time) VALUES (?);", time_str)
	if err != nil {
		http.Error(w, "DB failed: "+err.Error(), http.StatusBadRequest)
	}
}

func adminSuggestionHandler(w http.ResponseWriter, r *http.Request) {
	_, user_id, _ := getUserFromSession(r)
	stmt := "SELECT is_admin FROM users WHERE user_id = ?;"
	q := db.QueryRow(stmt, user_id)
	var is_admin bool
	if err := q.Scan(&is_admin); err != nil || !is_admin {
		http.Error(w, "Not authorized!", http.StatusBadRequest)
		return
	}

	event_id, _, _ := getNextEvent()

	//movie_id := r.PathValue("id")
	title := r.FormValue("title")
	year := r.FormValue("year")
	runtime, _ := strconv.Atoi(r.FormValue("runtime"))
	path := r.FormValue("path")
	_, err := db.Exec("INSERT INTO suggestions (user_id, event_id, movie_title, movie_year, runtime, poster_url) VALUES (?,?,?,?,?,?);",
		1, event_id, title, year, runtime, path)
	if err != nil {
		fmt.Println("Fucky wucky", title, year, runtime, path)
		fmt.Println(err.Error())
		return
	}

}
