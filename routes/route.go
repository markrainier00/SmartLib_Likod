package routes

import (
	"SmartLib_Likod/handler"

	"github.com/gofiber/fiber/v2"
)

func Setup(app *fiber.App) {
	// Base Group for API
	api := app.Group("/api")

	// 🔐 Authentication
	// Tatawagin nito ang SetupAuthRoutes mula sa auth_route.go
	SetupAuthRoutes(api)

	// ==========================================
	// 🚀 USERS MANAGEMENT (Approvals & Accounts)
	// Handler: user_handler.go
	// ==========================================
	users := api.Group("/users")
	users.Get("/registrations", handler.GetAllRegistrations)
	users.Put("/approve", handler.ApproveUser)
	users.Put("/reject", handler.RejectUser)

	// Manage Accounts Actions
	users.Put("/status", handler.ChangeAccountStatus) // Para sa Lock/Unlock
	users.Delete("/:id", handler.DeleteAccount)       // Para sa Delete

	// 🚀 BAGONG DAGDAG: SUPER ADMIN ROUTES
	users.Get("/all", handler.GetAllAccounts)        // Kukunin lahat ng accounts
	users.Post("/admin", handler.CreateAdminAccount) // Gagawa ng admin account

	// ==========================================
	// 💸 TRANSACTIONS GROUP
	// Handler: student_transaction_handler.go
	// ==========================================
	transactions := api.Group("/transactions")
	transactions.Post("/borrow", handler.BorrowBook)
	transactions.Get("/history", handler.GetStudentHistory)
	transactions.Get("/pending-all", handler.GetAllPending)
	transactions.Put("/release", handler.ReleaseBook)
	transactions.Put("/reject", handler.RejectBook)

	// 🚀 ITO YUNG MGA NAWAWALA KAYA NAG-E-ERROR ANG REACT:
	transactions.Get("/all", handler.GetAllTransactions) // 👈 Sinasalo ang listahan
	transactions.Put("/return", handler.ReturnBook)      // 👈 Sinasalo ang "Mark Returned"

	// ==========================================
	// 📊 DASHBOARD & ANALYTICS
	// ==========================================
	api.Get("/admin/stats", handler.GetDashboardStats)
	api.Get("/admin/analytics-full", handler.GetFullAnalytics)

	// ==========================================
	// 📚 BOOKS GROUP
	// Handler: book_handler.go
	// ==========================================
	books := api.Group("/books")
	books.Get("/", handler.GetAllBooks)
	books.Post("/", handler.AddBook)
	books.Put("/:id", handler.UpdateBook) // Pang-Edit ng libro
	books.Delete("/:id", handler.DeleteBook)

	// ==========================================
	// 🔍 SMART SCANNER
	// Handler: admin_scanner_handler.go
	// ==========================================
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
