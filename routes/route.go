package routes

import (
	"SmartLib_Likod/handler"

	"github.com/gofiber/fiber/v2"
)

func Setup(app *fiber.App) {
	api := app.Group("/api")
	SetupAuthRoutes(api)
	SetupAdminRoutes(api)
	SetupTransactionRoutes(api)
	SetupBooks(api)

	users := api.Group("/users")
	users.Get("/registrations", handler.GetAllRegistrations)
	users.Put("/approve", handler.ApproveUser)
	users.Put("/reject", handler.RejectUser)
	users.Put("/status", handler.ChangeAccountStatus)
	users.Delete("/:id", handler.DeleteAccount)

	users.Get("/all", handler.GetAllAccounts)
	users.Post("/admin", handler.CreateAdminAccount)

	// ==========================================
	// 📊 DASHBOARD & ANALYTICS
	// ==========================================
	api.Get("/admin/stats", handler.GetDashboardStats)
	api.Get("/admin/analytics-full", handler.GetFullAnalytics)

	scanner := api.Group("/scanner")
	scanner.Get("/:school_id", handler.GetStudentScannerData)

	// ==========================================
	// 💬 STUDENT CONCERNS
	// Handler: concern_handler.go
	// ==========================================
	concerns := api.Group("/concerns")
	concerns.Get("/", handler.GetConcerns)      // Kunin lahat ng concerns
	concerns.Put("/:id", handler.UpdateConcern) // Mag-reply o mag-resolve

	// 🚀 BAGONG DAGDAG: Tatanggap ng forms galing sa Student Support Page!
	concerns.Post("/", handler.CreateConcern)
}
