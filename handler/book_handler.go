package handler

import (
	"fmt"
	"os"
	"time"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	errormodel "SmartLib_Likod/model/error"
	"SmartLib_Likod/model/response"
	"SmartLib_Likod/model/status"
	"SmartLib_Likod/services"

	"github.com/gofiber/fiber/v2"
	storage_go "github.com/supabase-community/storage-go"
)

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

func AddBookHandler(c *fiber.Ctx) error {
	var savedPath string

	// 1. Handle image upload to Supabase Storage
	file, err := c.FormFile("actual_image")
	if err == nil {
		src, err := file.Open()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
				Message:   "Failed to open image",
				IsSuccess: false,
				Error:     err,
			})
		}
		defer src.Close()

		client := storage_go.NewClient(
			os.Getenv("DB_URL")+"/storage/v1",
			os.Getenv("DB_SERVICE_KEY"),
			nil,
		)

		filename := fmt.Sprintf("%d_%s", time.Now().Unix(), file.Filename)

		_, err = client.UploadFile("book-covers", filename, src, storage_go.FileOptions{
			ContentType: &file.Header["Content-Type"][0],
		})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
				Message:   "Failed to upload image",
				IsSuccess: false,
				Error:     err,
			})
		}

		savedPath = os.Getenv("DB_URL") + "/storage/v1/object/public/book-covers/" + filename
	}

	// 2. Build input
	input := services.BookInput{
		Title:           c.FormValue("title"),
		Author:          c.FormValue("author"),
		ISBN:            c.FormValue("isbn"),
		Publisher:       c.FormValue("publisher"),
		PublicationDate: c.FormValue("publication_date"),
		Edition:         c.FormValue("edition"),
		Category:        c.FormValue("category"),
		Pages:           c.FormValue("pages"),
		Copies:          c.FormValue("copies"),
		Description:     c.FormValue("description"),
		ActualImage:     savedPath,
	}

	// 3. Validate required fields
	if input.Title == "" || input.Author == "" || input.ISBN == "" ||
		input.Edition == "" || input.Pages == "" || input.Copies == "" || input.Description == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	// 4. Call service
	book, err := services.BookInputService(input)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	// 5. Send response
	return c.Status(fiber.StatusCreated).JSON(response.ResponseModel{
		RetCode: "201",
		Message: "Book added to the library.",
		Data:    book,
	})
}

// func AddBook(c *fiber.Ctx) error {
// 	book := new(model.Book)

// 	if err := c.BodyParser(book); err != nil {
// 		return c.Status(400).JSON(fiber.Map{
// 			"isSuccess": false,
// 			"message":   "Invalid input data",
// 		})
// 	}

// 	fmt.Printf("📦 TANGKANG I-SAVE NA LIBRO: %+v\n", book)

// 	result := database.DB.Create(&book)
// 	if result.Error != nil {
// 		fmt.Println("🚨 SUPABASE SAVE ERROR:", result.Error)
// 		return c.Status(500).JSON(fiber.Map{
// 			"isSuccess": false,
// 			"message":   "Failed to save to database",
// 			"error":     result.Error.Error(),
// 		})
// 	}

// 	fmt.Println("✅ SUCCESS! PUMASOK SA SUPABASE ANG LIBRO. ID:", book.ID)

// 	return c.JSON(fiber.Map{
// 		"isSuccess": true,
// 		"message":   "Book added successfully",
// 		"data":      book,
// 	})
// }

// ==========================================
// 🚀 PUT: MAG-UPDATE NG EXISTING NA LIBRO
// ==========================================
func UpdateBook(c *fiber.Ctx) error {
	id := c.Params("id") // Kukunin ang ID mula sa URL (halimbawa: /api/books/1)
	var book model.Book

	// 1. Hanapin muna kung nag-e-exist yung libro sa database
	if err := database.DB.First(&book, id).Error; err != nil {
		fmt.Println("🚨 BOOK NOT FOUND SA PAG-UPDATE. ID:", id)
		return c.Status(404).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Book not found",
		})
	}

	// 2. Basahin ang bagong data na pinadala ng Frontend at i-overwrite ang lumang data
	if err := c.BodyParser(&book); err != nil {
		fmt.Println("🚨 Error sa Body Parser (Update):", err)
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Invalid input data",
		})
	}

	// 3. I-save ang mga pagbabago sa Supabase
	result := database.DB.Save(&book)
	if result.Error != nil {
		fmt.Println("🚨 SUPABASE UPDATE ERROR:", result.Error)
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to update book",
		})
	}

	fmt.Println("✅ SUCCESS! NA-UPDATE ANG LIBRO SA SUPABASE. ID:", id)

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"message":   "Book updated successfully!",
		"data":      book,
	})
}

// ==========================================
// 🚀 DELETE: BURAHIN ANG LIBRO
// ==========================================
func DeleteBook(c *fiber.Ctx) error {
	id := c.Params("id") // Kukunin ang ID mula sa URL

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
