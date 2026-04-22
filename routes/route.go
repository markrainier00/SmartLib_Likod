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

	api.Get("/admin/analytics-full", handler.GetAnalyticsFullHandler)

	concerns := api.Group("/concerns")
	concerns.Get("/", handler.GetConcerns)
	concerns.Put("/:id", handler.UpdateConcern)
	concerns.Post("/", handler.CreateConcern)

	notifications := api.Group("/notifications")
	notifications.Get("/stream/:school_id", handler.SseHandler)
	notifications.Get("/history/:school_id", handler.GetNotificationHistory)
	notifications.Delete("/clear/:school_id", handler.ClearNotificationsHandler)
	notifications.Put("/read/:id", handler.MarkNotificationAsReadHandler)

	chat := api.Group("/chat")
	chat.Get("/admin/all", handler.GetAllConversations)
	chat.Get("/student/:student_id", handler.GetStudentConversation)
	chat.Post("/send", handler.SendMessage)
	chat.Post("/read", handler.MarkMessagesAsRead)
}
