package handler

import (
	"fmt"

	// "SmartLib_Likod/model/status"
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"

	"github.com/gofiber/fiber/v2"
)

// GetAllBooks - Kinukuha ang mga libro sa Supabase
func GetAllBooks(c *fiber.Ctx) error {
	var books []model.Book
	if err := database.DB.Find(&books).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to fetch books",
		})
	}
	return c.JSON(fiber.Map{
		"isSuccess": true,
		"data":      books,
	})
}

// AddBook - Nagse-save ng bagong libro mula sa Admin papunta sa Supabase
func AddBook(c *fiber.Ctx) error {
	book := new(model.Book)

	// 1. Basahin ang pinadala ng Frontend
	if err := c.BodyParser(book); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Invalid input data",
		})
	}

	// 👁️ CCTV: I-print sa terminal kung ano yung natanggap mula sa Next.js
	fmt.Printf("📦 TANGKANG I-SAVE NA LIBRO: %+v\n", book)

	// 2. 🚀 I-SAVE SA SUPABASE
	result := database.DB.Create(&book)
	if result.Error != nil {
		// Kapag nag-error ang Supabase, i-print sa terminal ang dahilan!
		fmt.Println("🚨 SUPABASE SAVE ERROR:", result.Error)
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to save to database",
			"error":     result.Error.Error(),
		})
	}

	// 3. Success!
	fmt.Println("✅ SUCCESS! PUMASOK SA SUPABASE ANG LIBRO. ID:", book.ID)

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"message":   "Book added successfully",
		"data":      book,
	})
}

// DeleteBook - Binubura ang libro sa Supabase gamit ang ID
func DeleteBook(c *fiber.Ctx) error {
	id := c.Params("id") // Kukunin ang ID mula sa URL (halimbawa: /api/books/1)

	// 👁️ CCTV: Tingnan natin kung anong ID ang gustong burahin
	fmt.Println("🗑️ TANGKANG BURAHIN ANG LIBRO. ID:", id)

	// Uutusan ang GORM na burahin ang record sa database
	result := database.DB.Delete(&model.Book{}, id)

	if result.Error != nil {
		fmt.Println("🚨 SUPABASE DELETE ERROR:", result.Error)
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to delete book",
		})
	}

	// Success!
	fmt.Println("✅ SUCCESS! NABURA NA ANG LIBRO SA SUPABASE. ID:", id)

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"message":   "Book successfully deleted!",
	})
}

// func GetAllBook(c *fiber.Ctx) error {
// 	var books []services.BookOutput

// 	if err := services.GetAllBooksService(&books).Error; err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
// 			Message: "Failed to fetch books",
// 			IsSuccess: false,
// 			Error:   err,
// 		})
// 	}

// 	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
// 		RetCode: "200",
// 		Message: "Books fetched successfully",
// 		Data:    books,
// 	})
// }
// func AddBook(c *fiber.Ctx) error {
// 	var input services.AddBookInput

// 	if err := c.BodyParser(&input); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
// 			Message:   status.RetCode404,
// 			IsSuccess: false,
// 			Error:     err,
// 		})
// 	}

// 	// Validate required fields
// 	if input.Title == "" || input.Author == "" || input.ISBN == "" {
// 		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
// 			Message:   status.RetCode401,
// 			IsSuccess: false,
// 			Error:     nil,
// 		})
// 	}

// 	book, err := services.AddBookService(input)
// 	if err != nil {
// 		fmt.Println("🚨 DATABASE SAVE ERROR:", err)
// 		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
// 			Message:   err.Error(),
// 			IsSuccess: false,
// 			Error:     err,
// 		})
// 	}

// 	fmt.Println("✅ SUCCESS! BOOK ADDED. ID:", book.ID)

// 	return c.Status(fiber.StatusCreated).JSON(response.ResponseModel{
// 		RetCode: "201",
// 		Message: "Book added successfully",
// 		Data:    book,
// 	})
// }

// func DeleteBook(c *fiber.Ctx) error {
// 	id := c.Params("id")
// 	if id == "" {
// 		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
// 			Message:   status.RetCode401,
// 			IsSuccess: false,
// 			Error:     nil,
// 		})
// 	}

// 	if err := services.DeleteBookService(id); err != nil {
// 		fmt.Println("🚨 DATABASE DELETE ERROR:", err)
// 		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
// 			Message:   err.Error(),
// 			IsSuccess: false,
// 			Error:     err,
// 		})
// 	}

// 	fmt.Println("✅ SUCCESS! BOOK DELETED. ID:", id)

// 	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
// 		RetCode: "200",
// 		Message: "Book successfully deleted",
// 		Data:    nil,
// 	})
// }
