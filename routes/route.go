package routes

import (
	"SmartLib_Likod/handler"

	"github.com/gofiber/fiber/v2"
)

func Setup(app *fiber.App) {
	api := app.Group("/api")

	// Iba pang sub-routes (Tiyaking defined ang mga ito sa ibang files mo)
	SetupAuthRoutes(api)
	SetupAdminRoutes(api)
	SetupTransactionRoutes(api)
	SetupBooks(api)

	// ==========================================
	// 👥 USER MANAGEMENT & REGISTRATIONS
	// Handler: admin_handler.go
	// ==========================================
	users := api.Group("/users")

	// Pending Registrations & Approvals
	users.Get("/registrations", handler.GetRegistrationHistoryHandler)
	users.Put("/approve", handler.ApproveUserHandler)
	users.Put("/reject", handler.RejectUserHandler)

	// Account Management
	users.Put("/status", handler.UpdateUserStatus)
	users.Delete("/:school_id", handler.DeleteUser) // Pinalitan ang :id ng :school_id base sa handler mo
	users.Get("/all", handler.GetAllUsers)
	users.Post("/admin", handler.CreateAdminAccountHandler)

	// ==========================================
	// 📊 DASHBOARD & ANALYTICS
	// ==========================================
	api.Get("/admin/stats", handler.GetDashboardStats)
	api.Get("/admin/analytics-full", handler.GetFullAnalytics)

	// ==========================================
	// 📷 SCANNER
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
	concerns.Post("/", handler.CreateConcern)   // Tatanggap ng forms galing sa Student Support Page

	// ==========================================
	// 🔔 REAL-TIME NOTIFICATIONS (SSE & HISTORY)
	// Handler: notification_handler.go
	// ==========================================
	notifications := api.Group("/notifications")
	notifications.Get("/stream/:school_id", handler.SseHandler)
	notifications.Get("/history/:school_id", handler.GetNotificationHistory)
	notifications.Delete("/clear/:school_id", handler.ClearNotificationsHandler)

	// 🚀 DITO IDINAGDAG YUNG PANG-SEEN NG ISANG NOTIFICATION!
	notifications.Put("/read/:id", handler.MarkNotificationAsReadHandler)

	// ==========================================
	// 💬 LIVE CHAT SUPPORT (NEW)
	// Handler: chat_handler.go
	// ==========================================
	chat := api.Group("/chat")
	chat.Get("/admin/all", handler.GetAllConversations)              // Para sa admin dashboard list
	chat.Get("/student/:student_id", handler.GetStudentConversation) // Para makuha yung chat box ni student
	chat.Post("/send", handler.SendMessage)                          // Mag-send ng message (Admin man o Student)
	chat.Post("/read", handler.MarkMessagesAsRead)                   // Para ma-update as "Seen" ang message
}
