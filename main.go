package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ==========================================
// 1. DATA MODELS & IN-MEMORY STORAGE
// ==========================================

type User struct {
	ID       string
	Username string
	Password string // bcrypt hashed password
	Role     string // "user" หรือ "admin"
}

type Note struct {
	ID        string
	Title     string
	Content   string
	OwnerID   string
	OwnerName string
	CreatedAt string
}

type Store struct {
	mu       sync.RWMutex
	Users    map[string]User   // Key: Username
	Notes    map[string]Note   // Key: Note ID
	Sessions map[string]string // Key: SessionToken -> Value: Username
	UserCSRF map[string]string // Key: SessionToken -> Value: CSRFToken
	nextID   int
}

var db = &Store{
	Users:    make(map[string]User),
	Notes:    make(map[string]Note),
	Sessions: make(map[string]string),
	UserCSRF: make(map[string]string),
	nextID:   1,
}

// ==========================================
// 2. HELPER & SECURITY FUNCTIONS
// ==========================================

func generateRandomToken() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func getCurrentUser(r *http.Request) (*User, string) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return nil, ""
	}

	db.mu.RLock()
	defer db.mu.RUnlock()

	username, exists := db.Sessions[cookie.Value]
	if !exists {
		return nil, ""
	}

	user, exists := db.Users[username]
	if !exists {
		return nil, ""
	}

	csrfToken := db.UserCSRF[cookie.Value]
	return &user, csrfToken
}

func validateCSRF(r *http.Request) bool {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return false
	}

	formCSRF := r.FormValue("csrf_token")

	db.mu.RLock()
	defer db.mu.RUnlock()

	expectedCSRF, exists := db.UserCSRF[cookie.Value]
	return exists && formCSRF == expectedCSRF
}

// ==========================================
// 3. HTML TEMPLATE (PROTECTS AGAINST XSS)
// ==========================================

var tpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="th">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{.Title}} - NoteBoard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f0f2f5; margin: 0; color: #1c1e21; }
        header { background: #0d6efd; color: white; padding: 16px 8%; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }
        header a { color: white; text-decoration: none; margin-left: 12px; font-weight: 500; }
        main { max-width: 900px; margin: 30px auto; padding: 0 16px; }
        .card { background: white; border-radius: 10px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        input, textarea, button { padding: 10px 14px; margin: 6px 0; border: 1px solid #ced4da; border-radius: 6px; font-size: 14px; width: 100%; box-sizing: border-box; }
        button { background: #0d6efd; color: white; border: none; cursor: pointer; font-weight: bold; }
        button:hover { background: #0b5ed7; }
        button.danger { background: #dc3545; }
        button.danger:hover { background: #bb2d3b; }
        .msg { padding: 12px; background: #fff3cd; color: #664d03; border-radius: 6px; margin-bottom: 16px; border: 1px solid #ffecb5; }
        .note-item { border-bottom: 1px solid #e9ecef; padding: 12px 0; }
        .note-item:last-child { border-bottom: none; }
        .badge { display: inline-block; padding: 4px 8px; font-size: 12px; border-radius: 4px; background: #e7f1ff; color: #0c63e4; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #dee2e6; }
        th { background: #f8f9fa; }
        form.inline { display: inline; }
    </style>
</head>
<body>
    <header>
        <h2>📝 Simple NoteBoard</h2>
        <div>
            {{if .User}}
                สวัสดีคุณ <b>{{.User.Username}}</b> <span class="badge">{{.User.Role}}</span> |
                <a href="/">หน้าหลัก/บันทึก</a>
                {{if eq .User.Role "admin"}}
                    <a href="/admin">ผู้ดูแลระบบ</a>
                {{end}}
                <form method="post" action="/logout" class="inline" style="margin-left: 10px;">
                    <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                    <button type="submit" style="width: auto; padding: 6px 12px; background: #6c757d;">ออกจากระบบ</button>
                </form>
            {{else}}
                <a href="/login">เข้าสู่ระบบ</a> |
                <a href="/register">สมัครสมาชิก</a>
            {{end}}
        </div>
    </header>
    <main>
        {{if .Message}}<div class="msg">{{.Message}}</div>{{end}}

        {{if eq .View "login"}}
            <div class="card" style="max-width: 400px; margin: 40px auto;">
                <h2>เข้าสู่ระบบ</h2>
                <form method="post" action="/login">
                    <input name="username" placeholder="ชื่อผู้ใช้" required>
                    <input type="password" name="password" placeholder="รหัสผ่าน" required>
                    <button type="submit">เข้าสู่ระบบ</button>
                </form>
            </div>

        {{else if eq .View "register"}}
            <div class="card" style="max-width: 400px; margin: 40px auto;">
                <h2>สมัครสมาชิก</h2>
                <form method="post" action="/register">
                    <input name="username" placeholder="ชื่อผู้ใช้ (อย่างน้อย 3 ตัวอักษร)" minlength="3" required>
                    <input type="password" name="password" placeholder="รหัสผ่าน (อย่างน้อย 6 ตัวอักษร)" minlength="6" required>
                    <button type="submit">สมัครสมาชิก</button>
                </form>
            </div>

        {{else if eq .View "notes"}}
            {{if .User}}
                <div class="card">
                    <h3>➕ สร้างบันทึกใหม่ (ฟอร์มบันทึกข้อมูล)</h3>
                    <form method="post" action="/notes/create">
                        <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                        <input name="title" placeholder="หัวข้อบันทึก" required maxlength="100">
                        <textarea name="content" placeholder="เนื้อหาบันทึก..." rows="3" required></textarea>
                        <button type="submit">บันทึกข้อมูล</button>
                    </form>
                </div>
            {{end}}

            <div class="card">
                <h3>📌 บันทึกทั้งหมดในระบบ</h3>
                {{if .Notes}}
                    {{range .Notes}}
                        <div class="note-item">
                            <h4>{{.Title}}</h4>
                            <p>{{.Content}}</p>
                            <small style="color: #6c757d;">โดย: {{.OwnerName}} | เมื่อ: {{.CreatedAt}}</small>
                            
                            {{if $.User}}
                                {{if or (eq $.User.ID .OwnerID) (eq $.User.Role "admin")}}
                                    <div style="margin-top: 8px;">
                                        <details>
                                            <summary style="cursor: pointer; color: #0d6efd;">✏️ แก้ไขบันทึกนี้</summary>
                                            <form method="post" action="/notes/update" style="margin-top: 10px;">
                                                <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                                                <input type="hidden" name="id" value="{{.ID}}">
                                                <input name="title" value="{{.Title}}" required>
                                                <textarea name="content" rows="2" required>{{.Content}}</textarea>
                                                <button type="submit" style="width: auto;">บันทึกการแก้ไข</button>
                                            </form>
                                        </details>
                                        
                                        <form method="post" action="/notes/delete" style="margin-top: 6px;">
                                            <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                                            <input type="hidden" name="id" value="{{.ID}}">
                                            <button type="submit" class="danger" style="width: auto; padding: 4px 10px; font-size: 12px;">🗑️ ลบบันทึก</button>
                                        </form>
                                    </div>
                                {{end}}
                            {{end}}
                        </div>
                    {{end}}
                {{else}}
                    <p style="color: #6c757d;">ยังไม่มีข้อมูลบันทึกในระบบ</p>
                {{end}}
            </div>

        {{else if eq .View "admin"}}
            <div class="card">
                <h2>🛠️ หน้าผู้ดูแลระบบ (Admin Dashboard)</h2>
                <p>จัดการผู้ใช้และสิทธิ์การใช้งานทั้งหมดในระบบ</p>
                
                <h3>รายชื่อผู้ใช้ทั้งหมด</h3>
                <table>
                    <tr>
                        <th>ID</th>
                        <th>ชื่อผู้ใช้</th>
                        <th>บทบาทปัจจุบัน</th>
                        <th>จัดการสิทธิ์</th>
                    </tr>
                    {{range .AllUsers}}
                    <tr>
                        <td>{{.ID}}</td>
                        <td>{{.Username}}</td>
                        <td><span class="badge">{{.Role}}</span></td>
                        <td>
                            {{if eq .ID $.User.ID}}
                                (บัญชีของคุณ)
                            {{else}}
                                <form method="post" action="/admin/role" class="inline">
                                    <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                                    <input type="hidden" name="user_id" value="{{.ID}}">
                                    <select name="role" style="width: auto; padding: 4px;">
                                        <option value="user" {{if eq .Role "user"}}selected{{end}}>user</option>
                                        <option value="admin" {{if eq .Role "admin"}}selected{{end}}>admin</option>
                                    </select>
                                    <button type="submit" style="width: auto; padding: 4px 8px;">อัปเดต</button>
                                </form>
                            {{end}}
                        </td>
                    </tr>
                    {{end}}
                </table>
            </div>
        {{end}}
    </main>
</body>
</html>`))

func render(w http.ResponseWriter, view string, title string, msg string, user *User, csrfToken string, extra map[string]interface{}) {
	data := map[string]interface{}{
		"View":      view,
		"Title":     title,
		"Message":   msg,
		"User":      user,
		"CSRFToken": csrfToken,
	}
	for k, v := range extra {
		data[k] = v
	}
	tpl.Execute(w, data)
}

// ==========================================
// 4. HTTP HANDLERS
// ==========================================

func indexHandler(w http.ResponseWriter, r *http.Request) {
	user, csrfToken := getCurrentUser(r)

	db.mu.RLock()
	var notesList []Note
	for _, note := range db.Notes {
		notesList = append(notesList, note)
	}
	db.mu.RUnlock()

	render(w, "notes", "หน้าหลัก", r.URL.Query().Get("msg"), user, csrfToken, map[string]interface{}{
		"Notes": notesList,
	})
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		render(w, "register", "สมัครสมาชิก", "", nil, "", nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if len(username) < 3 || len(password) < 6 {
		render(w, "register", "สมัครสมาชิก", "ชื่อผู้ใช้หรือรหัสผ่านสั้นเกินไป", nil, "", nil)
		return
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.Users[username]; exists {
		render(w, "register", "สมัครสมาชิก", "ชื่อผู้ใช้นี้ถูกใช้งานแล้ว", nil, "", nil)
		return
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		render(w, "register", "สมัครสมาชิก", "เกิดข้อผิดพลาดในการประมวลผล", nil, "", nil)
		return
	}

	// กำหนดผู้ใช้คนแรกให้เป็น admin อัตโนมัติ เพื่อความสะดวกในการทดสอบ
	role := "user"
	if len(db.Users) == 0 {
		role = "admin"
	}

	newUser := User{
		ID:       strconv.Itoa(len(db.Users) + 1),
		Username: username,
		Password: hashedPassword,
		Role:     role,
	}
	db.Users[username] = newUser

	http.Redirect(w, r, "/login?msg=สมัครสมาชิกสำเร็จ+กรุณาเข้าสู่ระบบ", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		render(w, "login", "เข้าสู่ระบบ", r.URL.Query().Get("msg"), nil, "", nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	db.mu.Lock()
	user, exists := db.Users[username]
	db.mu.Unlock()

	if !exists || !checkPassword(password, user.Password) {
		render(w, "login", "เข้าสู่ระบบ", "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง", nil, "", nil)
		return
	}

	sessionToken := generateRandomToken()
	csrfToken := generateRandomToken()

	db.mu.Lock()
	db.Sessions[sessionToken] = username
	db.UserCSRF[sessionToken] = csrfToken
	db.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true, // ป้องกัน XSS อ่าน Cookie
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if !validateCSRF(r) {
		http.Error(w, "403 Invalid CSRF Token", http.StatusForbidden)
		return
	}

	cookie, err := r.Cookie("session_token")
	if err == nil {
		db.mu.Lock()
		delete(db.Sessions, cookie.Value)
		delete(db.UserCSRF, cookie.Value)
		db.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Now().Add(-1 * time.Hour),
		Path:    "/",
	})

	http.Redirect(w, r, "/login?msg=ออกจากระบบเรียบร้อย", http.StatusSeeOther)
}

func createNoteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if !validateCSRF(r) {
		http.Error(w, "403 Invalid CSRF Token", http.StatusForbidden)
		return
	}

	user, _ := getCurrentUser(r)
	if user == nil {
		http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
		return
	}

	title := r.FormValue("title")
	content := r.FormValue("content")

	db.mu.Lock()
	newNote := Note{
		ID:        strconv.Itoa(db.nextID),
		Title:     title,
		Content:   content,
		OwnerID:   user.ID,
		OwnerName: user.Username,
		CreatedAt: time.Now().Format("02/01/2006 15:04"),
	}
	db.Notes[newNote.ID] = newNote
	db.nextID++
	db.mu.Unlock()

	http.Redirect(w, r, "/?msg=บันทึกข้อมูลสำเร็จ", http.StatusSeeOther)
}

func updateNoteHandler(w http.ResponseWriter, r *http.Request) {
	if !validateCSRF(r) {
		http.Error(w, "403 Invalid CSRF Token", http.StatusForbidden)
		return
	}

	user, _ := getCurrentUser(r)
	if user == nil {
		http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
		return
	}

	noteID := r.FormValue("id")
	title := r.FormValue("title")
	content := r.FormValue("content")

	db.mu.Lock()
	note, exists := db.Notes[noteID]

	// 🔒 ตรวจสอบสิทธิ์ความเป็นเจ้าของข้อมูล (Owner Check)
	if !exists || (note.OwnerID != user.ID && user.Role != "admin") {
		db.mu.Unlock()
		http.Error(w, "403 Forbidden: คุณไม่มีสิทธิ์แก้ไขบันทึกนี้", http.StatusForbidden)
		return
	}

	note.Title = title
	note.Content = content
	db.Notes[noteID] = note
	db.mu.Unlock()

	http.Redirect(w, r, "/?msg=แก้ไขบันทึกสำเร็จ", http.StatusSeeOther)
}

func deleteNoteHandler(w http.ResponseWriter, r *http.Request) {
	if !validateCSRF(r) {
		http.Error(w, "403 Invalid CSRF Token", http.StatusForbidden)
		return
	}

	user, _ := getCurrentUser(r)
	if user == nil {
		http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
		return
	}

	noteID := r.FormValue("id")

	db.mu.Lock()
	note, exists := db.Notes[noteID]

	// 🔒 ตรวจสอบสิทธิ์ความเป็นเจ้าของข้อมูล (Owner Check)
	if !exists || (note.OwnerID != user.ID && user.Role != "admin") {
		db.mu.Unlock()
		http.Error(w, "403 Forbidden: คุณไม่มีสิทธิ์ลบบันทึกนี้", http.StatusForbidden)
		return
	}

	delete(db.Notes, noteID)
	db.mu.Unlock()

	http.Redirect(w, r, "/?msg=ลบบันทึกสำเร็จ", http.StatusSeeOther)
}

func adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	user, csrfToken := getCurrentUser(r)

	// 🔒 ตรวจสอบสิทธิ์ Role Admin
	if user == nil || user.Role != "admin" {
		http.Error(w, "403 Forbidden: เฉพาะผู้ดูแลระบบเท่านั้น", http.StatusForbidden)
		return
	}

	db.mu.RLock()
	var usersList []User
	for _, u := range db.Users {
		usersList = append(usersList, u)
	}
	db.mu.RUnlock()

	render(w, "admin", "ผู้ดูแลระบบ", r.URL.Query().Get("msg"), user, csrfToken, map[string]interface{}{
		"AllUsers": usersList,
	})
}

func adminChangeRoleHandler(w http.ResponseWriter, r *http.Request) {
	if !validateCSRF(r) {
		http.Error(w, "403 Invalid CSRF Token", http.StatusForbidden)
		return
	}

	user, _ := getCurrentUser(r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "403 Forbidden: เฉพาะผู้ดูแลระบบเท่านั้น", http.StatusForbidden)
		return
	}

	targetUserID := r.FormValue("user_id")
	newRole := r.FormValue("role")

	db.mu.Lock()
	for username, u := range db.Users {
		if u.ID == targetUserID {
			u.Role = newRole
			db.Users[username] = u
			break
		}
	}
	db.mu.Unlock()

	http.Redirect(w, r, "/admin?msg=อัปเดตสิทธิ์เรียบร้อย", http.StatusSeeOther)
}

// ==========================================
// 5. MAIN FUNCTION
// ==========================================

func main() {
	// รัน Routing
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)

	http.HandleFunc("/notes/create", createNoteHandler)
	http.HandleFunc("/notes/update", updateNoteHandler)
	http.HandleFunc("/notes/delete", deleteNoteHandler)

	http.HandleFunc("/admin", adminDashboardHandler)
	http.HandleFunc("/admin/role", adminChangeRoleHandler)

	fmt.Println("🚀 Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}