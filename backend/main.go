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