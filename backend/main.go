package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/GCET-Open-Source-Foundation/auth"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	conn  *pgxpool.Pool
	auth1 *auth.Auth
)

// Permission spaces and role constants
const (
	SpaceSuperadmins = "superadmins"
	SpaceAdmins      = "admins"
	SpaceUsers       = "SpaceUsers" // default user space
	MemberRole       = "member"
)

// ---------------- Models ----------------

type Project struct {
	PID         int       `json:"p_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatorID   int       `json:"creator_id"`
	CreatorName string    `json:"creator_name"`
	StartDate   time.Time `json:"start_date"`
	Status      string    `json:"status"`
	Image       string    `json:"image,omitempty"` // base64 encoded
}

type BufferProject struct {
	RID         int       `json:"r_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatorID   int       `json:"creator_id"`
	CreatorName string    `json:"creator_name"`
	Status      string    `json:"status"`
	SubmittedAt time.Time `json:"submitted_at"`
	Image       string    `json:"image,omitempty"`
}

type DeletedProject struct {
	PID         int       `json:"p_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatorID   int       `json:"creator_id"`
	CreatorName string    `json:"creator_name"`
	DeletedDate time.Time `json:"deleted_date"`
	Image       string    `json:"image,omitempty"`
}

type proj_info struct {
	PID         int        `json:"p_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	CreatorID   int        `json:"creator_id"`
	CreatorName string     `json:"creator_name"`
	StartDate   *time.Time `json:"start_date,omitempty"`
	Status      string     `json:"status"`
	EndDate     *time.Time `json:"end_date,omitempty"`
}

// ---------------- Request structs ----------------

type registerReq struct {
	Username string `json:"username" form:"username" binding:"required"`
	Password string `json:"password" form:"password" binding:"required"`
}

type createProjectReq struct {
	Name        string `form:"name" binding:"required"`
	Description string `form:"description" binding:"required"`
}

type addMaintainerReq struct {
	UserID   int    `json:"user_id" binding:"required"`
	UserName string `json:"user_name" binding:"required"`
}

type addContributorReq struct {
	UserID   int    `json:"user_id" binding:"required"`
	UserName string `json:"user_name" binding:"required"`
}

type updateProjectStatusReq struct {
	NewStatus string `json:"new_status" binding:"required"`
}

type assignUserReq struct {
	UserID   int    `json:"user_id" binding:"required"`
	UserName string `json:"user_name" binding:"required"`
}

type revokeUserReq struct {
	UserID int `json:"user_id" binding:"required"`
}

// ---------------- Helpers ----------------

func respondErr(c *gin.Context, code int, msg string, err error) {
	if err != nil {
		log.Printf("Error: %s: %v\n", msg, err)
	} else {
		log.Printf("Error: %s\n", msg)
	}
	c.JSON(code, gin.H{"error": msg})
}

func uidToStr(id int) string { return strconv.Itoa(id) }

func getIntParam(c *gin.Context, name string) (int, error) {
	p := c.Param(name)
	return strconv.Atoi(p)
}

// getUserIDFromContext attempts to find numeric user id in context (user_id_int or user_id).
// Returns (id, true) if found and parseable to int, otherwise (-1,false)
func getUserIDFromContext(c *gin.Context) (int, bool) {
	// check user_id_int set by middleware
	if v, ok := c.Get("user_id_int"); ok {
		switch t := v.(type) {
		case int:
			return t, true
		case int32:
			return int(t), true
		case int64:
			return int(t), true
		case string:
			if n, err := strconv.Atoi(t); err == nil {
				return n, true
			}
		}
	}

	// check user_id (string)
	if v, ok := c.Get("user_id"); ok {
		switch t := v.(type) {
		case string:
			if n, err := strconv.Atoi(t); err == nil {
				return n, true
			}
		case int:
			return t, true
		case int32:
			return int(t), true
		case int64:
			return int(t), true
		}
	}
	return -1, false
}

// HasRole checks permission via auth.Check_permissions for superadmin/admin, returns true for "user"
func HasRole(userIDStr string, require string) bool {
	if require == "superadmin" {
		return auth1.Check_permissions(userIDStr, SpaceSuperadmins, MemberRole)
	}
	if require == "admin" {
		return auth1.Check_permissions(userIDStr, SpaceAdmins, MemberRole)
	}
	if require == "user" {
		return true
	}
	return false
}

// AssignMemberToSpace upserts into names table and creates permission in auth DB
func AssignMemberToSpace(userID interface{}, userName, space string) error {
	// upsert into names table using TEXT id (to support string and numeric ids)
	_, err := conn.Exec(context.Background(),
		`INSERT INTO names (id, name) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name`,
		userID, userName)
	if err != nil {
		return fmt.Errorf("upsert names failed: %w", err)
	}

	// ensure we pass a string user id to auth.Create_permissions
	var uidStr string
	switch v := userID.(type) {
	case int:
		uidStr = strconv.Itoa(v)
	case int32:
		uidStr = fmt.Sprintf("%d", v)
	case int64:
		uidStr = fmt.Sprintf("%d", v)
	case string:
		uidStr = v
	default:
		uidStr = fmt.Sprintf("%v", v)
	}

	if err := auth1.Create_permissions(uidStr, space, MemberRole); err != nil {
		return fmt.Errorf("auth.Create_permissions failed: %w", err)
	}
	return nil
}

func RemoveMemberFromSpace(userID int, space string) error {
	if err := auth1.Delete_permission(uidToStr(userID), space, MemberRole); err != nil {
		return fmt.Errorf("auth.Delete_permission failed: %w", err)
	}
	return nil
}

// ---------------- Permission helpers ----------------

func isProjectAdminOrCreator(authedUserID int, p_id int) (bool, error) {
	authedUserIDStr := uidToStr(authedUserID)
	if HasRole(authedUserIDStr, "superadmin") || HasRole(authedUserIDStr, "admin") {
		return true, nil
	}

	var creatorID int
	err := conn.QueryRow(context.Background(),
		"SELECT creator_id FROM approved_projects WHERE p_id = $1", p_id).Scan(&creatorID)

	if err == pgx.ErrNoRows {
		return false, fmt.Errorf("project not found")
	}
	if err != nil {
		return false, fmt.Errorf("failed to check project ownership: %w", err)
	}

	return creatorID == authedUserID, nil
}

func isProjectCreatorOrMaintainer(authedUserID int, p_id int) (bool, error) {
	var creatorID int
	err := conn.QueryRow(context.Background(),
		"SELECT creator_id FROM approved_projects WHERE p_id = $1", p_id).Scan(&creatorID)
	if err == pgx.ErrNoRows {
		return false, fmt.Errorf("project not found")
	}
	if err != nil {
		return false, fmt.Errorf("db error checking creator: %w", err)
	}
	if creatorID == authedUserID {
		return true, nil
	}

	var isMaintainer bool
	err = conn.QueryRow(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM maintainers WHERE p_id = $1 AND user_id = $2)",
		p_id, authedUserID).Scan(&isMaintainer)
	if err != nil {
		return false, fmt.Errorf("db error checking maintainer: %w", err)
	}

	return isMaintainer, nil
}

func isProjectAdminOrCreatorOrMaintainer(authedUserID int, p_id int) (bool, error) {
	authedUserIDStr := uidToStr(authedUserID)
	if HasRole(authedUserIDStr, "superadmin") || HasRole(authedUserIDStr, "admin") {
		return true, nil
	}

	isAllowed, err := isProjectCreatorOrMaintainer(authedUserID, p_id)
	if err != nil {
		return false, err
	}

	return isAllowed, nil
}

// ---------------- Middleware ----------------

// AuthMiddleware validates JWT from Authorization header and sets user_id and user_id_int in context.
// Falls back to X-Dummy-User header for local testing.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authH := c.GetHeader("Authorization")
		if authH != "" {
			parts := strings.Fields(authH)
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
				claims, err := auth1.Login_jwt(parts[1])
				if err != nil {
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
					return
				}
				c.Set("user_id", claims.UserID)
				if n, err := strconv.Atoi(claims.UserID); err == nil {
					c.Set("user_id_int", n)
				}
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header"})
			return
		}

		// fallback for local testing
		dummy := c.GetHeader("X-Dummy-User")
		if dummy != "" {
			c.Set("user_id", dummy)
			if n, err := strconv.Atoi(dummy); err == nil {
				c.Set("user_id_int", n)
			}
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization"})
	}
}

// RequireRole checks if current user has the provided high-level role.
func RequireRole(required string) gin.HandlerFunc {
	return func(c *gin.Context) {
		val, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing user context"})
			c.Abort()
			return
		}
		userIDStr := fmt.Sprintf("%v", val)
		if userIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
			c.Abort()
			return
		}
		if !HasRole(userIDStr, required) {
			c.JSON(http.StatusForbidden, gin.H{"error": "permission denied for this role"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// ---------------- Handlers ----------------

// Register endpoint: register user in auth DB, upsert to names (TEXT id) and assign SpaceUsers permission
func registerUser(c *gin.Context) {
	var req registerReq
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON/form body - username and password required"})
		return
	}

	// Register user in auth DB
	if err := auth1.Register_user(req.Username, req.Password); err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to register user", err)
		return
	}

	// Upsert into names table using TEXT id (supports numeric and non-numeric usernames)
	if _, err := conn.Exec(context.Background(),
		`INSERT INTO names (id, name) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`,
		req.Username, req.Username); err != nil {
		// warn but do not fail registration
		log.Printf("warning: failed to upsert into names table: %v", err)
	}

	// Assign default user permission in auth DB (using username string as user_id)
	if err := auth1.Create_permissions(req.Username, SpaceUsers, MemberRole); err != nil {
		log.Printf("warning: failed to add default user permission: %v", err)
	}

	c.JSON(http.StatusCreated, gin.H{"message": "user registered and default permissions assigned", "username": req.Username})
}

// Login endpoint: validate credentials and return JWT (2 weeks expiry)
func loginUser(c *gin.Context) {
	var req registerReq
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON/form body - username and password required"})
		return
	}

	if !auth1.Login_user(req.Username, req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}

	token, err := auth1.Generate_token(req.Username, time.Hour*24*14) // 2 weeks
	if err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to generate token", err)
		return
	}

	// Return token in response and set cookie (optional)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		Domain:   "",
		MaxAge:   int((14 * 24 * time.Hour).Seconds()),
		Secure:   false, // set true in production with HTTPS
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	c.JSON(http.StatusOK, gin.H{"message": "login successful", "token": token})
}

// helper: read uploaded file into []byte safely
func readUploadedFileBytes(fh *multipart.FileHeader) ([]byte, error) {
	if fh == nil {
		return nil, nil
	}
	f, err := fh.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// get_All_Proj returns all approved projects (includes base64 image)
func get_All_Proj(c *gin.Context) {
	rows, err := conn.Query(context.Background(),
		"SELECT p_id, name, description, creator_id, creator_name, start_date, status, image FROM approved_projects")
	if err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to fetch projects", err)
		return
	}
	defer rows.Close()

	var out []Project
	for rows.Next() {
		var p Project
		var sd time.Time
		var imgBytes []byte
		if err := rows.Scan(&p.PID, &p.Name, &p.Description, &p.CreatorID, &p.CreatorName, &sd, &p.Status, &imgBytes); err != nil {
			respondErr(c, http.StatusInternalServerError, "scan failed", err)
			return
		}
		p.StartDate = sd
		if len(imgBytes) > 0 {
			p.Image = base64.StdEncoding.EncodeToString(imgBytes)
		}
		out = append(out, p)
	}
	c.JSON(http.StatusOK, out)
}

// createProject accepts multipart form: name, description, image (optional) and stores image as BYTEA.
// Admins/superadmins: directly into approved_projects. Regular users: into buffer_projects.
func createProject(c *gin.Context) {
	creatorID, ok := getUserIDFromContext(c)
	if !ok {
		respondErr(c, http.StatusUnauthorized, "invalid user ID in context", nil)
		return
	}

	// Parse multipart form (max memory ephemeral); Gin's c.FormFile works without explicit ParseMultipartForm
	name := c.PostForm("name")
	desc := c.PostForm("description")
	if name == "" || desc == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and description are required"})
		return
	}

	// read uploaded file (optional)
	var imageBytes []byte
	if fh, err := c.FormFile("image"); err == nil && fh != nil {
		if b, err := readUploadedFileBytes(fh); err == nil {
			imageBytes = b
		} else {
			respondErr(c, http.StatusInternalServerError, "failed to read uploaded image", err)
			return
		}
	}

	val, _ := c.Get("user_id")
	creatorIDStr := fmt.Sprintf("%v", val)
	isSuperAdmin := auth1.Check_permissions(creatorIDStr, SpaceSuperadmins, MemberRole)
	isAdmin := auth1.Check_permissions(creatorIDStr, SpaceAdmins, MemberRole)

	if isSuperAdmin || isAdmin {
		row := conn.QueryRow(context.Background(),
			`INSERT INTO approved_projects (name, description, creator_id, creator_name, start_date, status, image)
			 VALUES ($1,$2,$3,(SELECT COALESCE(name,'Unknown') FROM names WHERE id=$3), CURRENT_DATE, 'in_progress', $4) RETURNING p_id`,
			name, desc, creatorID, imageBytes)

		var pid int
		if err := row.Scan(&pid); err != nil {
			respondErr(c, http.StatusInternalServerError, "direct insert failed", err)
			return
		}
		c.JSON(http.StatusCreated, gin.H{"p_id": pid, "status": "approved"})
		return
	}

	// regular user: insert into buffer_projects
	row := conn.QueryRow(context.Background(),
		`INSERT INTO buffer_projects (name, description, creator_id, creator_name, status, submitted_at, image)
		 VALUES ($1, $2, $3, (SELECT COALESCE(name,'Unknown') FROM names WHERE id=$3), 'pending', CURRENT_DATE, $4) RETURNING r_id`,
		name, desc, creatorID, imageBytes)

	var rid int
	if err := row.Scan(&rid); err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to submit project", err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"r_id": rid, "status": "pending"})
}

// deleteProject: move approved project to deleted_projects (with image) and delete from approved_projects
func deleteProject(c *gin.Context) {
	pid, err := getIntParam(c, "id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid project id"})
		return
	}

	userID, ok := getUserIDFromContext(c)
	if !ok {
		respondErr(c, http.StatusUnauthorized, "invalid user ID in context", nil)
		return
	}
	val, _ := c.Get("user_id")
	userIDStr := fmt.Sprintf("%v", val)

	isSuperAdmin := auth1.Check_permissions(userIDStr, SpaceSuperadmins, MemberRole)
	isAdmin := auth1.Check_permissions(userIDStr, SpaceAdmins, MemberRole)

	var projectCreatorID int
	var name, desc, creatorName string
	var startDate time.Time
	var status string
	var imgBytes []byte

	err = conn.QueryRow(context.Background(),
		`SELECT name, description, creator_id, creator_name, start_date, status, image FROM approved_projects WHERE p_id=$1`, pid).
		Scan(&name, &desc, &projectCreatorID, &creatorName, &startDate, &status, &imgBytes)
	if err == pgx.ErrNoRows {
		respondErr(c, http.StatusNotFound, "project not found", nil)
		return
	}
	if err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to fetch project", err)
		return
	}

	canDelete := isSuperAdmin || isAdmin || (userID == projectCreatorID)
	if !canDelete {
		respondErr(c, http.StatusForbidden, "you do not have permission to delete this project", nil)
		return
	}

	tx, err := conn.Begin(context.Background())
	if err != nil {
		respondErr(c, http.StatusInternalServerError, "tx begin failed", err)
		return
	}
	defer tx.Rollback(context.Background())

	// insert into deleted_projects (keep image)
	_, err = tx.Exec(context.Background(),
		`INSERT INTO deleted_projects (p_id, name, description, creator_id, creator_name, deleted_date, image)
		 VALUES ($1,$2,$3,$4,$5,CURRENT_DATE,$6)`,
		pid, name, desc, projectCreatorID, creatorName, imgBytes)
	if err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to insert into deleted_projects", err)
		return
	}

	// delete from approved_projects
	cmdTag, err := tx.Exec(context.Background(), `DELETE FROM approved_projects WHERE p_id=$1`, pid)
	if err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to delete approved project", err)
		return
	}
	if cmdTag.RowsAffected() == 0 {
		respondErr(c, http.StatusNotFound, "project not found during delete", nil)
		return
	}

	if err := tx.Commit(context.Background()); err != nil {
		respondErr(c, http.StatusInternalServerError, "tx commit failed", err)
		return
	}

	c.Status(http.StatusNoContent)
}

// addMaintainer
func addMaintainer(c *gin.Context) {
	authedUserID, ok := getUserIDFromContext(c)
	if !ok {
		respondErr(c, http.StatusUnauthorized, "invalid user ID in context", nil)
		return
	}

	p_id, err := getIntParam(c, "id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid project id"})
		return
	}

	var req addMaintainerReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body, user_id and user_name are required"})
		return
	}

	hasPermission, err := isProjectAdminOrCreator(authedUserID, p_id)
	if err != nil {
		if err.Error() == "project not found" {
			respondErr(c, http.StatusNotFound, "project not found", nil)
		} else {
			respondErr(c, http.StatusInternalServerError, "failed to check permissions", err)
		}
		return
	}
	if !hasPermission {
		respondErr(c, http.StatusForbidden, "user is not authorized to add maintainers", nil)
		return
	}

	tx, err := conn.Begin(context.Background())
	if err != nil {
		respondErr(c, http.StatusInternalServerError, "tx begin failed", err)
		return
	}
	defer tx.Rollback(context.Background())

	if _, err := tx.Exec(context.Background(),
		`INSERT INTO names (id, name) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name`,
		req.UserID, req.UserName); err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to upsert user in names table", err)
		return
	}

	row := tx.QueryRow(context.Background(),
		`INSERT INTO maintainers (p_id, user_id, m_name) 
         VALUES ($1, $2, $3) 
         RETURNING m_id`,
		p_id, req.UserID, req.UserName)

	var m_id int
	if err := row.Scan(&m_id); err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			respondErr(c, http.StatusConflict, "user is already a maintainer for this project", err)
			return
		}
		respondErr(c, http.StatusInternalServerError, "failed to add maintainer", err)
		return
	}

	if err := tx.Commit(context.Background()); err != nil {
		respondErr(c, http.StatusInternalServerError, "tx commit failed", err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"m_id":    m_id,
		"p_id":    p_id,
		"user_id": req.UserID,
		"status":  "maintainer added",
	})
}

// deleteMaintainer
func deleteMaintainer(c *gin.Context) {
	authedUserID, ok := getUserIDFromContext(c)
	if !ok {
		respondErr(c, http.StatusUnauthorized, "invalid user ID in context", nil)
		return
	}

	p_id, err := getIntParam(c, "id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid project id"})
		return
	}

	user_id_to_remove, err := getIntParam(c, "user_id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id to remove"})
		return
	}

	hasPermission, err := isProjectAdminOrCreator(authedUserID, p_id)
	if err != nil {
		if err.Error() == "project not found" {
			respondErr(c, http.StatusNotFound, "project not found", nil)
		} else {
			respondErr(c, http.StatusInternalServerError, "failed to check permissions", err)
		}
		return
	}
	if !hasPermission {
		respondErr(c, http.StatusForbidden, "user is not authorized to remove maintainers", nil)
		return
	}

	cmdTag, err := conn.Exec(context.Background(),
		`DELETE FROM maintainers WHERE p_id = $1 AND user_id = $2`,
		p_id, user_id_to_remove)

	if err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to remove maintainer", err)
		return
	}

	if cmdTag.RowsAffected() == 0 {
		respondErr(c, http.StatusNotFound, "maintainer not found for this project", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "maintainer removed",
		"p_id":    p_id,
		"user_id": user_id_to_remove,
	})
}

// getAllDeletedProjects
func getAllDeletedProjects(c *gin.Context) {
	rows, err := conn.Query(context.Background(),
		"SELECT p_id, name, description, creator_id, creator_name, deleted_date, image FROM deleted_projects")
	if err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to fetch deleted projects", err)
		return
	}
	defer rows.Close()

	var out []DeletedProject
	for rows.Next() {
		var d DeletedProject
		var imgBytes []byte
		if err := rows.Scan(&d.PID, &d.Name, &d.Description, &d.CreatorID, &d.CreatorName, &d.DeletedDate, &imgBytes); err != nil {
			respondErr(c, http.StatusInternalServerError, "scan failed", err)
			return
		}
		if len(imgBytes) > 0 {
			d.Image = base64.StdEncoding.EncodeToString(imgBytes)
		}
		out = append(out, d)
	}

	c.JSON(http.StatusOK, out)
}

// getMyDeletedProjects
func getMyDeletedProjects(c *gin.Context) {
	creatorID, ok := getUserIDFromContext(c)
	if !ok {
		respondErr(c, http.StatusUnauthorized, "invalid user ID in context", nil)
		return
	}

	rows, err := conn.Query(context.Background(),
		"SELECT p_id, name, description, creator_id, creator_name, deleted_date, image FROM deleted_projects WHERE creator_id=$1", creatorID)
	if err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to fetch your deleted projects", err)
		return
	}
	defer rows.Close()

	var out []DeletedProject
	for rows.Next() {
		var d DeletedProject
		var imgBytes []byte
		if err := rows.Scan(&d.PID, &d.Name, &d.Description, &d.CreatorID, &d.CreatorName, &d.DeletedDate, &imgBytes); err != nil {
			respondErr(c, http.StatusInternalServerError, "scan failed", err)
			return
		}
		if len(imgBytes) > 0 {
			d.Image = base64.StdEncoding.EncodeToString(imgBytes)
		}
		out = append(out, d)
	}

	c.JSON(http.StatusOK, out)
}

// addContributor
func addContributor(c *gin.Context) {
	authedUserID, ok := getUserIDFromContext(c)
	if !ok {
		respondErr(c, http.StatusUnauthorized, "invalid user ID in context", nil)
		return
	}

	p_id, err := getIntParam(c, "id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid project id"})
		return
	}

	var req addContributorReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body, user_id and user_name are required"})
		return
	}

	hasPermission, err := isProjectAdminOrCreatorOrMaintainer(authedUserID, p_id)
	if err != nil {
		if err.Error() == "project not found" {
			respondErr(c, http.StatusNotFound, "project not found", nil)
		} else {
			respondErr(c, http.StatusInternalServerError, "failed to check permissions", err)
		}
		return
	}
	if !hasPermission {
		respondErr(c, http.StatusForbidden, "Only the Project Creator, Maintainer, Admin, or Superadmin can add a contributor.", nil)
		return
	}

	tx, err := conn.Begin(context.Background())
	if err != nil {
		respondErr(c, http.StatusInternalServerError, "tx begin failed", err)
		return
	}
	defer tx.Rollback(context.Background())

	if _, err := tx.Exec(context.Background(),
		`INSERT INTO names (id, name) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name`,
		req.UserID, req.UserName); err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to upsert user in names table", err)
		return
	}

	row := tx.QueryRow(context.Background(),
		`INSERT INTO contributors (p_id, user_id, c_name)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, p_id) DO NOTHING 
        RETURNING c_id`,
		p_id, req.UserID, req.UserName)

	var c_id int
	if err := row.Scan(&c_id); err != nil {
		if err == pgx.ErrNoRows {
			respondErr(c, http.StatusConflict, "user is already a contributor for this project", nil)
			return
		}
		respondErr(c, http.StatusInternalServerError, "failed to add contributor", err)
		return
	}

	if err := tx.Commit(context.Background()); err != nil {
		respondErr(c, http.StatusInternalServerError, "tx commit failed", err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"c_id":    c_id,
		"p_id":    p_id,
		"user_id": req.UserID,
		"status":  "contributor added",
	})
}

// deleteContributor
func deleteContributor(c *gin.Context) {
	authedUserID, ok := getUserIDFromContext(c)
	if !ok {
		respondErr(c, http.StatusUnauthorized, "invalid user ID in context", nil)
		return
	}

	p_id, err := getIntParam(c, "id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid project id"})
		return
	}

	user_id_to_remove, err := getIntParam(c, "user_id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id to remove"})
		return
	}

	hasPermission, err := isProjectAdminOrCreatorOrMaintainer(authedUserID, p_id)
	if err != nil {
		if err.Error() == "project not found" {
			respondErr(c, http.StatusNotFound, "project not found", nil)
		} else {
			respondErr(c, http.StatusInternalServerError, "failed to check permissions", err)
		}
		return
	}
	if !hasPermission {
		respondErr(c, http.StatusForbidden, "Only the Project Creator, Maintainer, Admin, or Superadmin can remove a contributor.", nil)
		return
	}

	cmdTag, err := conn.Exec(context.Background(),
		`DELETE FROM contributors WHERE p_id = $1 AND user_id = $2`,
		p_id, user_id_to_remove)

	if err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to remove contributor", err)
		return
	}

	if cmdTag.RowsAffected() == 0 {
		respondErr(c, http.StatusNotFound, "contributor not found for this project", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "contributor removed",
		"p_id":    p_id,
		"user_id": user_id_to_remove,
	})
}

// getPendingProjects
func getPendingProjects(c *gin.Context) {
	rows, err := conn.Query(context.Background(),
		"SELECT r_id, name, description, creator_id, creator_name, status, submitted_at, image FROM buffer_projects WHERE status='pending'")
	if err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to fetch pending projects", err)
		return
	}
	defer rows.Close()

	var out []BufferProject
	for rows.Next() {
		var b BufferProject
		var imgBytes []byte
		if err := rows.Scan(&b.RID, &b.Name, &b.Description, &b.CreatorID, &b.CreatorName, &b.Status, &b.SubmittedAt, &imgBytes); err != nil {
			respondErr(c, http.StatusInternalServerError, "scan failed", err)
			return
		}
		if len(imgBytes) > 0 {
			b.Image = base64.StdEncoding.EncodeToString(imgBytes)
		}
		out = append(out, b)
	}
	c.JSON(http.StatusOK, out)
}

// approveProject: move buffer -> approved (including image) in a transaction
func approveProject(c *gin.Context) {
	val, ok := c.Get("user_id")
	if !ok {
		respondErr(c, http.StatusUnauthorized, "invalid user ID in context", nil)
		return
	}
	userIDStr := fmt.Sprintf("%v", val)

	isSuperAdmin := auth1.Check_permissions(userIDStr, SpaceSuperadmins, MemberRole)
	isAdmin := auth1.Check_permissions(userIDStr, SpaceAdmins, MemberRole)

	if !(isSuperAdmin || isAdmin) {
		respondErr(c, http.StatusForbidden, "permission denied: requires admin or superadmin", nil)
		return
	}

	rid, err := getIntParam(c, "id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid buffer project id"})
		return
	}

	tx, err := conn.Begin(context.Background())
	if err != nil {
		respondErr(c, http.StatusInternalServerError, "tx begin failed", err)
		return
	}
	defer tx.Rollback(context.Background())

	// fetch buffer row
	var name, desc, creatorName, status string
	var creatorID int
	var submittedAt time.Time
	var imgBytes []byte
	err = tx.QueryRow(context.Background(),
		"SELECT name, description, creator_id, creator_name, status, submitted_at, image FROM buffer_projects WHERE r_id=$1 AND status='pending'",
		rid).Scan(&name, &desc, &creatorID, &creatorName, &status, &submittedAt, &imgBytes)
	if err == pgx.ErrNoRows {
		respondErr(c, http.StatusNotFound, "project not found or not pending", nil)
		return
	}
	if err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to fetch buffer project", err)
		return
	}

	// insert into approved_projects (preserve image)
	var newPID int
	err = tx.QueryRow(context.Background(),
		`INSERT INTO approved_projects (name, description, creator_id, creator_name, start_date, status, image)
		 VALUES ($1,$2,$3,$4,CURRENT_DATE,'in_progress',$5) RETURNING p_id`,
		name, desc, creatorID, creatorName, imgBytes).Scan(&newPID)
	if err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to move to approved_projects", err)
		return
	}

	// delete from buffer_projects
	if _, err := tx.Exec(context.Background(), `DELETE FROM buffer_projects WHERE r_id=$1`, rid); err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to delete buffer project", err)
		return
	}

	if err := tx.Commit(context.Background()); err != nil {
		respondErr(c, http.StatusInternalServerError, "tx commit failed", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Project approved successfully",
		"r_id":    rid,
		"p_id":    newPID,
		"status":  "approved",
	})
}

// rejectProject: mark buffer project as rejected (keeps image)
func rejectProject(c *gin.Context) {
	rid, err := getIntParam(c, "id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid buffer project id"})
		return
	}

	cmdTag, err := conn.Exec(context.Background(),
		`UPDATE buffer_projects SET status='rejected' WHERE r_id=$1 AND status='pending'`, rid)
	if err != nil {
		respondErr(c, http.StatusInternalServerError, "reject failed", err)
		return
	}
	if cmdTag.RowsAffected() == 0 {
		respondErr(c, http.StatusNotFound, "project not found or not pending", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "rejected"})
}

// assignSuperAdmin
func assignSuperAdmin(c *gin.Context) {
	val, exists := c.Get("user_id")
	if !exists {
		respondErr(c, http.StatusUnauthorized, "missing user context", nil)
		return
	}
	authedUserIDStr := fmt.Sprintf("%v", val)

	if !HasRole(authedUserIDStr, "superadmin") {
		respondErr(c, http.StatusForbidden, "permission denied: only a superadmin can assign this role", nil)
		return
	}

	var req assignUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if req.UserName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_name is required"})
		return
	}

	if err := AssignMemberToSpace(req.UserID, req.UserName, SpaceSuperadmins); err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to assign superadmin role", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Superadmin role assigned successfully",
		"user_id": req.UserID,
		"space":   SpaceSuperadmins,
	})
}

// assignAdmin
func assignAdmin(c *gin.Context) {

	val, exists := c.Get("user_id")
	if !exists {
		respondErr(c, http.StatusUnauthorized, "missing user context", nil)
		return
	}
	authedUserIDStr := fmt.Sprintf("%v", val)

	if !HasRole(authedUserIDStr, "superadmin") {
		respondErr(c, http.StatusForbidden, "permission denied: only a superadmin can assign this role", nil)
		return
	}

	var req assignUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if req.UserName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_name is required"})
		return
	}

	if err := AssignMemberToSpace(req.UserID, req.UserName, SpaceAdmins); err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to assign admin role", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Admin role assigned successfully",
		"user_id": req.UserID,
		"space":   SpaceAdmins,
	})
}

// revokeAdmin
func revokeAdmin(c *gin.Context) {
	val, exists := c.Get("user_id")
	if !exists {
		respondErr(c, http.StatusUnauthorized, "missing user context", nil)
		return
	}
	authedUserIDStr := fmt.Sprintf("%v", val)

	if !HasRole(authedUserIDStr, "superadmin") {
		respondErr(c, http.StatusForbidden, "permission denied: only a superadmin can revoke this role", nil)
		return
	}

	var req revokeUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body, user_id is required"})
		return
	}

	if err := RemoveMemberFromSpace(req.UserID, SpaceAdmins); err != nil {
		respondErr(c, http.StatusInternalServerError, "failed to revoke admin role", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Admin role revoked successfully",
		"user_id": req.UserID,
		"space":   SpaceAdmins,
	})
}

// updateProjectStatus
func updateProjectStatus(c *gin.Context) {
	authedUserID, ok := getUserIDFromContext(c)
	if !ok {
		respondErr(c, http.StatusUnauthorized, "invalid user ID in context", nil)
		return
	}

	p_id, err := getIntParam(c, "id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid project id"})
		return
	}

	var req updateProjectStatusReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload", "details": err.Error()})
		return
	}

	validStatuses := map[string]bool{"in_progress": true, "completed": true, "upcoming": true}
	if _, ok := validStatuses[req.NewStatus]; !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid status value. Must be 'in_progress', 'completed', or 'upcoming'."})
		return
	}

	hasPermission, err := isProjectAdminOrCreatorOrMaintainer(authedUserID, p_id)
	if err != nil {
		if err.Error() == "project not found" {
			respondErr(c, http.StatusNotFound, "project not found", nil)
		} else {
			respondErr(c, http.StatusInternalServerError, "failed to check permissions", err)
		}
		return
	}
	if !hasPermission {
		respondErr(c, http.StatusForbidden, "Access denied. Only the Creator, Maintainer, Admin, or Superadmin can update this project's status.", nil)
		return
	}

	result, err := conn.Exec(context.Background(),
		`UPDATE approved_projects SET status = $1 WHERE p_id = $2`,
		req.NewStatus, p_id)

	if err != nil {
		respondErr(c, http.StatusInternalServerError, "Failed to update project status", err)
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Project not found or status is already the same."})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Project status updated successfully to " + req.NewStatus, "p_id": p_id})
}

// get_Ongoing
func get_Ongoing(c *gin.Context) {
	rows, err := conn.Query(context.Background(),
		"SELECT p_id, name, description, creator_id, creator_name, start_date, status, image FROM approved_projects WHERE status = 'in_progress'")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch projects"})
		return
	}
	defer rows.Close()

	var projects []Project
	for rows.Next() {
		var u Project
		var sd time.Time
		var img []byte
		if err := rows.Scan(&u.PID, &u.Name, &u.Description, &u.CreatorID, &u.CreatorName, &sd, &u.Status, &img); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan a project"})
			return
		}
		u.StartDate = sd
		if len(img) > 0 {
			u.Image = base64.StdEncoding.EncodeToString(img)
		}
		projects = append(projects, u)
	}

	c.JSON(http.StatusOK, projects)
}

// get_Past_Proj
func get_Past_Proj(c *gin.Context) {
	rows, err := conn.Query(context.Background(),
		"SELECT p_id, name, description, creator_id, creator_name, start_date, status, image FROM approved_projects WHERE status = 'completed'")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch projects"})
		return
	}
	defer rows.Close()

	var projects []Project
	for rows.Next() {
		var u Project
		var sd time.Time
		var img []byte
		if err := rows.Scan(&u.PID, &u.Name, &u.Description, &u.CreatorID, &u.CreatorName, &sd, &u.Status, &img); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan a project"})
			return
		}
		u.StartDate = sd
		if len(img) > 0 {
			u.Image = base64.StdEncoding.EncodeToString(img)
		}
		projects = append(projects, u)
	}

	c.JSON(http.StatusOK, projects)
}

// get_UpComing
func get_UpComing(c *gin.Context) {
	rows, err := conn.Query(context.Background(),
		"SELECT p_id, name, description, creator_id, creator_name, start_date, status, image FROM approved_projects WHERE status = 'upcoming'")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch projects"})
		return
	}
	defer rows.Close()

	var projects []Project
	for rows.Next() {
		var u Project
		var sd time.Time
		var img []byte
		if err := rows.Scan(&u.PID, &u.Name, &u.Description, &u.CreatorID, &u.CreatorName, &sd, &u.Status, &img); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan a project"})
			return
		}
		u.StartDate = sd
		if len(img) > 0 {
			u.Image = base64.StdEncoding.EncodeToString(img)
		}
		projects = append(projects, u)
	}

	c.JSON(http.StatusOK, projects)
}

// ---------------- Routes ----------------

func registerRoutes(r *gin.Engine) {
	public := r.Group("/")
	{
		public.POST("/register", registerUser)
		public.POST("/login", loginUser)

		// public read endpoints
		public.GET("/projects/all", get_All_Proj)
		public.GET("/projects/ongoing", get_Ongoing)
		public.GET("/projects/upcoming", get_UpComing)
		public.GET("/projects/past", get_Past_Proj)
		public.GET("/deleted/all", getAllDeletedProjects) // admin-only also exists under protected route
	}

	protected := r.Group("/", AuthMiddleware())

	// user-level
	userRoutes := protected.Group("/", RequireRole("user"))
	{
		// create project expects multipart/form-data with optional 'image' file
		userRoutes.POST("/projects", createProject)
		userRoutes.DELETE("/projects/:id", deleteProject)
		userRoutes.GET("/deleted/my", getMyDeletedProjects)

		userRoutes.POST("/projects/:id/maintainers", addMaintainer)
		userRoutes.DELETE("/projects/:id/maintainers/:user_id", deleteMaintainer)

		userRoutes.POST("/projects/:id/contributors", addContributor)
		userRoutes.DELETE("/projects/:id/contributors/:user_id", deleteContributor)

		userRoutes.PATCH("/projects/:id/status", updateProjectStatus)
	}

	// admin-level
	adminRoutes := protected.Group("/admin", RequireRole("admin"))
	{
		adminRoutes.GET("/pending", getPendingProjects)
		adminRoutes.POST("/approve/:id", approveProject)
		adminRoutes.POST("/reject/:id", rejectProject)
		adminRoutes.GET("/deleted/all", getAllDeletedProjects)
	}

	// superadmin-level
	superadminRoutes := protected.Group("/superadmin", RequireRole("superadmin"))
	{
		superadminRoutes.GET("/admin/pending", getPendingProjects)
		superadminRoutes.POST("/admin/approve/:id", approveProject)
		superadminRoutes.POST("/admin/reject/:id", rejectProject)

		superadminRoutes.GET("/deleted/all", getAllDeletedProjects)

		superadminRoutes.POST("/roles/superadmin", assignSuperAdmin)
		superadminRoutes.POST("/roles/admin", assignAdmin)
		superadminRoutes.DELETE("/roles/admin", revokeAdmin)
	}
}

// ---------------- main ----------------

func main() {
	// Project DB connection string (used for both project tables and auth.Init)
	connString := os.Getenv("PF_DB_CONN")
	if connString == "" {
		connString = "postgres://postgres:postgres@localhost:5432/project_forum"
	}

	var err error
	conn, err = pgxpool.New(context.Background(), connString)
	if err != nil {
		log.Fatalf("Unable to connect to project DB: %v\n", err)
	}
	defer conn.Close()
	fmt.Println("Connected to project_forum DB")

	// Initialize auth library using the same DB (project_forum)
	// auth.Init(port uint16, db_user, db_pass, db_name string)
	auth1, err := auth.Init(context.Background(), 5432, "postgres", "postgres", "project_forum")
	if err != nil {
		log.Fatalf("auth.Init failed: %v\n", err)
	}
	fmt.Println("auth initialized")

	// JWT secret (env override supported)
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "gcet-secret"
		log.Println("JWT_SECRET not set; using default 'gcet-secret' (change for production)")
	}
	if err := auth1.JWT_init(jwtSecret); err != nil {
		log.Fatalf("auth.JWT_init failed: %v\n", err)
	}
	fmt.Println("auth JWT initialized")

	r := gin.Default()
	registerRoutes(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server starting on :%s\n", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v\n", err)
	}
}
