package routes

import (
	"SmartLib_Likod/handler"

	"github.com/gofiber/fiber/v2"
)

func SetupBooks(api fiber.Router) {
	books := api.Group("/books")
	books.Get("/", handler.GetAllBooks)
	books.Post("/", handler.AddBook)
	books.Put("/:id", handler.UpdateBook)
	books.Delete("/:id", handler.DeleteBook)
}
