package handler

import (
	"fmt"
	"os"
	"strconv"
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

	oldCopiesStr := book.Copies
	newCopiesStr := input.Copies

	oldCopies, err := strconv.Atoi(oldCopiesStr)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Invalid existing copies value.",
		})
	}

	newCopies, err := strconv.Atoi(newCopiesStr)
	if err != nil || newCopies < 0 {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Invalid copies value.",
		})
	}

	beforeAvailable := book.Available
	diff := newCopies - oldCopies

	if diff > 0 {
		book.Available += diff

	} else if diff < 0 {
		reduction := -diff
		if book.Available < reduction {
			return c.Status(400).JSON(fiber.Map{
				"isSuccess": false,
				"message":   fmt.Sprintf("Cannot reduce copies by %d. Only %d available.", reduction, book.Available),
			})
		}
		book.Available -= reduction
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

	if beforeAvailable == 0 && book.Available > 0 {
		go services.NotifyWishlistUsers(book.ISBN, book.Title)
	}

	return c.Status(200).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Book updated successfully.",
		Data:    book,
	})
}

func DeleteBook(c *fiber.Ctx) error {
	id := c.Params("id")

	var book model.Book
	if err := database.DB.First(&book, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Book not found.",
		})
	}

	copies, _ := strconv.Atoi(book.Copies)
	if book.Available != copies {
		borrowed := copies - book.Available
		unit := "copies"
		if borrowed == 1 {
			unit = "copy"
		}
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   fmt.Sprintf("Cannot delete this book. %d %s are currently borrowed.", borrowed, unit),
		})
	}

	result := database.DB.Delete(&model.Book{}, id)
	if result.Error != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to delete book",
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"message":   "Book successfully deleted!",
	})
}
