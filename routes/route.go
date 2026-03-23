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

	api.Get("/admin/stats", handler.GetDashboardStats)

	scanner := api.Group("/scanner")
	scanner.Get("/:school_id", handler.GetStudentScannerData)
}
