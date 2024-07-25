package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

//var templates = template.Must(template.ParseFiles("templates/home.html"))

var db *sql.DB

func initDB() {
	tmp_db, err := sql.Open("sqlite3", "./movie-night.db")
	if err != nil {
		panic(err)
	}
	sql_make_tables := "CREATE TABLE IF NOT EXISTS users (user_id INTEGER PRIMARY KEY ASC, first_name string, last_name string, phone string unique);" +
		"CREATE TABLE IF NOT EXISTS sessions (session_id STRING PRIMARY KEY, user_id integer, FOREIGN KEY (user_id) REFERENCES users(user_id) );" +
		"CREATE TABLE IF NOT EXISTS events (event_id INTEGER PRIMARY KEY ASC, event_time TEXT);" +
		"INSERT OR IGNORE INTO events (event_id, event_time) VALUES (1, '" + time.Now().AddDate(0, 0, 1).Format(time.RFC3339) + "');" +
		"CREATE TABLE IF NOT EXISTS reservations (event_id INTEGER, user_id INTEGER, PRIMARY KEY (event_id, user_id) FOREIGN KEY (event_id) REFERENCES events(event_id), FOREIGN KEY (user_id) REFERENCES users(user_id));"

	_, err = tmp_db.Exec(sql_make_tables)
	if err != nil {
		panic(err)
	}
	db = tmp_db
}

func main() {
	initDB()
	defer db.Close()
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/vote", voteHandler)
	http.HandleFunc("/attendees", attendeesHandler)
	http.HandleFunc("/directions", directionsHandler)
	// http.HandleFunc("/admin", homeHandler)

	http.HandleFunc("POST /api/register", registrationHandler)
	http.HandleFunc("POST /api/sign-in", signinHandler)
	http.HandleFunc("POST /api/logout", logoutHandler)
	http.HandleFunc("POST /api/rsvp/{type}", rsvpHandler)

	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "favicon.ico") })

	http.Handle("/styles/", http.StripPrefix("/styles/", http.FileServer(http.Dir("styles"))))
	http.Handle("/scripts/", http.StripPrefix("/scripts/", http.FileServer(http.Dir("scripts"))))
	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("img"))))

	err := http.ListenAndServeTLS(":4343", "secrets/carter-server.crt", "secrets/carter-server.key", nil)
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

func signin(w http.ResponseWriter, phone string) {
	q := db.QueryRow("SELECT user_id FROM users WHERE phone=?", phone)
	var user_id string
	err := q.Scan(&user_id)
	if err != nil || user_id == "" {
		// TODO - respond with a "user not found"
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	sessionToken, err := generateToken(32)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	stmt := "INSERT INTO sessions (session_id, user_id) VALUES (?, ?);"
	db.Exec(stmt, sessionToken, user_id)

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
		"WHERE session_id = ?;"
	q := db.QueryRow(stmt, cookie.Value)
	err = q.Scan(&user_id, &first_name)
	fmt.Println("Signed in:", user_id, err, cookie.Value)
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

func registrationHandler(w http.ResponseWriter, r *http.Request) {
	first_name := r.FormValue("first_name")
	last_name := r.FormValue("last_name")
	phone := r.FormValue("phone")
	stmt := "INSERT INTO users (first_name, last_name, phone) VALUES (?, ?, ?);"
	_, err := db.Exec(stmt, first_name, last_name, phone)
	if err != nil {
		log.Fatalln("Inserting user failed:", err)
	}
	signin(w, phone)
}

func signinHandler(w http.ResponseWriter, r *http.Request) {
	phone := r.FormValue("phone")
	signin(w, phone)
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
	t, err := template.ParseFiles("templates/boilerplate.tmpl", "templates/home.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	event_id, event_time, err := getNextEvent()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	isSignedIn, user_id, first_name := getUserFromSession(r)

	p := tmpl_Home{
		IsSignedIn: isSignedIn,
		IsRSVPed:   userIsRSVPed(user_id, event_id),
		Name:       first_name,
		EventDate:  parseTimeToEventDate(event_time),
		StartTime:  event_time.Format("3:00PM"),
		DoorTime:   event_time.Add(-time.Hour).Format("3:00PM"),
	}
	t.ExecuteTemplate(w, "home.tmpl", p)
}

type tmpl_Directions struct {
}

func directionsHandler(w http.ResponseWriter, r *http.Request) {
	//err := templates.ExecuteTemplate(w, "home.html", Page{Body: "Hello World!"})
	t, err := template.ParseFiles("templates/boilerplate.tmpl", "templates/directions.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	p := tmpl_Directions{}
	t.ExecuteTemplate(w, "directions.tmpl", p)
}

type tmpl_Attendees struct {
	Attendees []string
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
		Attendees: attendees,
	}
	t.ExecuteTemplate(w, "attendees.tmpl", p)
}

type tmpl_Vote struct {
}

func voteHandler(w http.ResponseWriter, r *http.Request) {
	//err := templates.ExecuteTemplate(w, "home.html", Page{Body: "Hello World!"})
	t, err := template.ParseFiles("templates/boilerplate.tmpl", "templates/vote.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	p := tmpl_Vote{}
	t.ExecuteTemplate(w, "vote.tmpl", p)
}
