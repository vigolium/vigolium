package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()

	// Basic CRUD routes
	r.GET("/users", listUsers)
	r.POST("/users", createUser)
	r.GET("/users/:id", getUser)
	r.PUT("/users/:id", updateUser)
	r.DELETE("/users/:id", deleteUser)

	// Multiple methods
	r.Any("/health", healthCheck)

	// Route group with prefix
	api := r.Group("/api/v2")
	api.GET("/items", listItems)
	api.POST("/items", createItem)
	api.GET("/items/:id", getItem)

	// Nested group
	admin := api.Group("/admin")
	admin.GET("/stats", getStats)
	admin.DELETE("/cache", clearCache)

	r.Run(":8080")
}

func listUsers(c *gin.Context) {
	q := c.Query("q")
	page := c.DefaultQuery("page", "1")
	_ = q
	_ = page
}

func createUser(c *gin.Context) {
	var body struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	c.ShouldBindJSON(&body)
}

func getUser(c *gin.Context) {
	id := c.Param("id")
	_ = id
}

func updateUser(c *gin.Context) {
	id := c.Param("id")
	name := c.PostForm("name")
	_ = id
	_ = name
}

func deleteUser(c *gin.Context)  {}
func healthCheck(c *gin.Context) {}
func listItems(c *gin.Context)   {}
func createItem(c *gin.Context)  {}
func getItem(c *gin.Context)     {}
func getStats(c *gin.Context)    {}
func clearCache(c *gin.Context)  {}
