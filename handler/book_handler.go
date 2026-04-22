package handler

import (
	"fmt"
	"os"
	"strings"
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

	if input.Title == "" || input.Author == "" || input.ISBN == "" ||
		input.Edition == "" || input.Pages == "" || input.Copies == "" || input.Description == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	book, err := services.BookInputService(input)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
				Message:   "A book with this ISBN already exists.",
				IsSuccess: false,
				Error:     nil,
			})
		}

		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	// ==========================================
	// 📢 TRIGGER: BROADCAST SA LAHAT NG STUDENTS
	// ==========================================
	// Kapag successful ang pag-add ng libro, magpapadala tayo ng notification sa lahat!
	broadcastMsg := fmt.Sprintf("New Arrival: Ang librong '%s' by %s ay available na ngayon sa library!", input.Title, input.Author)

	// Tinawag natin yung BroadcastToRole function na ginawa natin kanina
	// Papasok ito sa database ng lahat ng "Student" at tutunog nang live sa browser nila
	services.BroadcastToRole("Student", broadcastMsg)
	// ==========================================

	return c.Status(fiber.StatusCreated).JSON(response.ResponseModel{
		RetCode: "200",
		Data:    book,
	})
}

func UpdateBookHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	var book model.Book

	if err := database.DB.First(&book, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Book not found.",
		})
	}

	var input struct {
		Title           string `json:"title"`
		Author          string `json:"author"`
		ISBN            string `json:"isbn"`
		Publisher       string `json:"publisher"`
		PublicationDate string `json:"publication_date"`
		Edition         string `json:"edition"`
		Category        string `json:"category"`
		Pages           string `json:"pages"`
		Copies          string `json:"copies"`
		Description     string `json:"description"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Invalid input data",
		})
	}

	book.Title = input.Title
	book.Author = input.Author
	book.ISBN = input.ISBN
	book.Publisher = input.Publisher
	book.PublicationDate = input.PublicationDate
	book.Edition = input.Edition
	book.Category = input.Category
	book.Pages = input.Pages
	book.Copies = input.Copies
	book.Description = input.Description

	file, err := c.FormFile("actual_image")
	if err == nil {
		src, err := file.Open()
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"isSuccess": false,
				"message":   "Failed to open image",
			})
		}
		defer src.Close()

		client := storage_go.NewClient(os.Getenv("DB_URL")+"/storage/v1", os.Getenv("DB_SERVICE_KEY"), nil)
		filename := fmt.Sprintf("%d_%s", time.Now().Unix(), file.Filename)

		_, err = client.UploadFile("book-covers", filename, src, storage_go.FileOptions{
			ContentType: &file.Header["Content-Type"][0],
		})
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"isSuccess": false,
				"message":   "Failed to upload image",
			})
		}

		book.ActualImage = os.Getenv("DB_URL") + "/storage/v1/object/public/book-covers/" + filename
	}

	result := database.DB.Save(&book)
	if result.Error != nil {
		if strings.Contains(result.Error.Error(), "duplicate") || strings.Contains(result.Error.Error(), "unique") {
			return c.Status(400).JSON(fiber.Map{
				"isSuccess": false,
				"message":   "A book with this ISBN already exists.",
			})
		}

		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to update book",
		})
	}

	return c.Status(200).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Book updated successfully.",
		Data:    book,
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
