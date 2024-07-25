package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

//var templates = template.Must(template.ParseFiles("templates/home.html"))

type tmpl_Home struct {
	StartTime string
	DoorTime  string
}

var db *sql.DB

func initDB() {
	tmp_db, err := sql.Open("sqlite3", "./movie-night.db")
	if err != nil {
		panic(err)
	}
	sql_make_tables := "CREATE TABLE IF NOT EXISTS Users (user_id INTEGER PRIMARY KEY ASC, first_name string, last_name string, phone string unique);" +
		""
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
	http.HandleFunc("/vote", homeHandler)
	http.HandleFunc("/attendees", homeHandler)
	http.HandleFunc("/directions", homeHandler)
	http.HandleFunc("/admin", homeHandler)

	http.HandleFunc("POST /api/register", registrationHandler)

	http.Handle("/styles/", http.StripPrefix("/styles/", http.FileServer(http.Dir("styles"))))

	err := http.ListenAndServe(":8080", nil)
	panic(err)
}

func registrationHandler(w http.ResponseWriter, r *http.Request) {
	first_name := r.FormValue("first_name")
	last_name := r.FormValue("last_name")
	phone := r.FormValue("phone")
	stmt := "INSERT INTO Users (first_name, last_name, phone) VALUES (?, ?, ?);"
	_, err := db.Exec(stmt, first_name, last_name, phone)
	if err != nil {
		log.Fatalln("Insert:", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:  "Registration",
		Value: phone,
	})
	http.Redirect(w, r, "/", http.StatusCreated)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	p := tmpl_Home{StartTime: "7:00pm", DoorTime: "6:00pm"}
	//err := templates.ExecuteTemplate(w, "home.html", Page{Body: "Hello World!"})
	t, err := template.ParseFiles("templates/boilerplate.tmpl", "templates/home.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t.ExecuteTemplate(w, "home.tmpl", p)
}
