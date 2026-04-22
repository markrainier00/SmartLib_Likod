package routes

import (
	"SmartLib_Likod/handler"

	"github.com/gofiber/fiber/v2"
)

func SetupTransactionRoutes(api fiber.Router) {
	transactions := api.Group("/transactions")

	// Endpoints para sa Transactions
	transactions.Get("/getRequests/:school_id", handler.GetUserBorrowRequestHandler)
	transactions.Post("/request", handler.RequestBook)
	transactions.Post("/cancelRequest", handler.CancelRequestHandler)
	transactions.Get("/getWishlist/:school_id", handler.GetUserWishlistHandler)
	transactions.Post("/addWishlist", handler.AddWishlistHandler)
	transactions.Post("/removeWishlist", handler.RemoveWishlistHandler)
	transactions.Post("/toggleNotify", handler.ToggleWishlistNotifyHandler)
	transactions.Put("/approveBorrowRequest", handler.ApproveBorrowRequestHandler)
	transactions.Put("/rejectBorrowRequest", handler.RejectBorrowRequestHandler)

	// Ito yung hinahanap ng React mo kanina
	transactions.Get("/pending-all", handler.GetBookBorrowRequestHandler)

	transactions.Get("/getBookBorrowRequest", handler.GetBookBorrowRequestHandler)
	transactions.Get("/getActiveBorrow", handler.GetActiveBorrowHandler)
	transactions.Get("/getApprovedRequests", handler.GetApprovedRequestsHandler)
	transactions.Put("/returnBook/:id", handler.ReturnBookHandler)
	transactions.Put("/borrow/process", handler.ProcessBookBorrowHandler)
	// transactions.Post("/borrow/add", handler.AddBookBorrowHandler)
	transactions.Get("/details/:school_id", handler.GetStudentTransaction)
	transactions.Get("/allDetails/:school_id", handler.GetStudentAllTransaction)
	transactions.Get("/history/:school_id", handler.GetStudentHistory)
	transactions.Get("/getStaffHistory", handler.GetStaffHistory)
	transactions.Get("/getWholeHistory", handler.GetWholeHistory)
	transactions.Get("/all", handler.GetAllTransactions)
}
