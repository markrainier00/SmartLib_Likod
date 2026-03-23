package routes

import (
	"SmartLib_Likod/handler"

	"github.com/gofiber/fiber/v2"
)

func SetupTransactionRoutes(api fiber.Router) {
	transactions := api.Group("/transactions")
	transactions.Post("/borrow", handler.BorrowBook)
	transactions.Get("/history", handler.GetStudentHistory)
	transactions.Get("/pending-all", handler.GetAllRequests)
	transactions.Put("/release", handler.ReleaseBook)
	transactions.Put("/reject", handler.RejectBook)
	transactions.Get("/all", handler.GetAllTransactions)
	transactions.Put("/return", handler.ReturnBook)
}
