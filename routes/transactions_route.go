package routes

import (
	"SmartLib_Likod/handler"

	"github.com/gofiber/fiber/v2"
)

func SetupTransactionRoutes(api fiber.Router) {
	transactions := api.Group("/transactions")
	transactions.Post("/request", handler.RequestBook)
	transactions.Get("/getWishlist/:school_id", handler.GetWishlistHandler)
	transactions.Post("/addWishlist", handler.AddWishlistHandler)
	transactions.Post("/removeWishlist", handler.RemoveWishlistHandler)
	transactions.Put("/rejectRequest/:id", handler.RejectRequestHandler)
	transactions.Put("/approveRequest/:id/:isbn", handler.ApproveRequestHandler)
	transactions.Get("/getBookBorrowRequest", handler.GetBookBorrowRequestHandler)
	transactions.Get("/getActiveBorrow", handler.GetActiveBorrowHandler)
	transactions.Put("/returnBook/:id", handler.ReturnBookHandler)
	// transactions.Post("/borrow", handler.BorrowBook)
	transactions.Get("/history", handler.GetStudentHistory)
	transactions.Get("/all", handler.GetAllTransactions)
}
