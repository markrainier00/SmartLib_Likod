package routes

import (
	"SmartLib_Likod/handler"

	"github.com/gofiber/fiber/v2"
)

func SetupTransactionRoutes(api fiber.Router) {
	transactions := api.Group("/transactions")
	transactions.Post("/request", handler.RequestBook)
	transactions.Get("/getWishlist/:school_id", handler.GetWishlist)
	transactions.Post("/addWishlist", handler.AddWishlist)
	transactions.Post("/removeWishlist", handler.RemoveWishlist)
	transactions.Put("/reject/:id", handler.RejectBookHandler)
	// transactions.Post("/borrow", handler.BorrowBook)
	transactions.Get("/history", handler.GetStudentHistory)
	transactions.Get("/pending-all", handler.GetAllRequests)
	transactions.Put("/release", handler.ReleaseBook)
	transactions.Get("/all", handler.GetAllTransactions)
	transactions.Put("/return", handler.ReturnBook)
}
